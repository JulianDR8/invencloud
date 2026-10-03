require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const cfg = { host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD };
let db;

async function init() {
  const boot = await mysql.createConnection(cfg);
  await boot.query(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME}\``);
  await boot.end();
  db = mysql.createPool({ ...cfg, database: process.env.DB_NAME, connectionLimit: 10 });
  await db.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL, role ENUM('admin','empleado') NOT NULL)`);
  await db.query(`CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2) NOT NULL, stock INT NOT NULL DEFAULT 0, min_stock INT NOT NULL DEFAULT 5)`);
  await db.query(`CREATE TABLE IF NOT EXISTS movements (
    id INT AUTO_INCREMENT PRIMARY KEY, product_id INT NOT NULL, type ENUM('entrada','salida') NOT NULL,
    quantity INT NOT NULL, user_id INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE)`);
  await db.query(`CREATE TABLE IF NOT EXISTS sales (
    id INT AUTO_INCREMENT PRIMARY KEY, product_id INT NOT NULL, quantity INT NOT NULL,
    total DECIMAL(10,2) NOT NULL, user_id INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE)`);
  const [[{ n }]] = await db.query('SELECT COUNT(*) n FROM users');
  if (!n) {
    await db.query('INSERT INTO users (username,password,role) VALUES (?,?,?),(?,?,?)', [
      'admin', await bcrypt.hash('admin123', 10), 'admin',
      'empleado', await bcrypt.hash('empleado123', 10), 'empleado']);
    console.log('Usuarios iniciales creados: admin/admin123 y empleado/empleado123');
  }
}

const auth = (roles) => (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    if (roles && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Sin permiso' });
    next();
  } catch { res.status(401).json({ error: 'Sesión inválida' }); }
};
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Error del servidor' }); });

app.post('/api/login', wrap(async (req, res) => {
  const [[u]] = await db.query('SELECT * FROM users WHERE username=?', [req.body.username]);
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password)))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, username: u.username, role: u.role });
}));

app.get('/api/products', auth(), wrap(async (req, res) => {
  const [rows] = await db.query('SELECT * FROM products ORDER BY name');
  res.json(rows);
}));
app.post('/api/products', auth(['admin']), wrap(async (req, res) => {
  const { name, price, stock, min_stock } = req.body;
  if (!name || price < 0) return res.status(400).json({ error: 'Datos inválidos' });
  await db.query('INSERT INTO products (name,price,stock,min_stock) VALUES (?,?,?,?)', [name, price, stock || 0, min_stock || 5]);
  res.json({ ok: true });
}));
app.delete('/api/products/:id', auth(['admin']), wrap(async (req, res) => {
  await db.query('DELETE FROM products WHERE id=?', [req.params.id]);
  res.json({ ok: true });
}));

app.post('/api/movements', auth(), wrap(async (req, res) => {
  const { product_id, type, quantity } = req.body;
  const q = parseInt(quantity);
  if (!['entrada', 'salida'].includes(type) || !(q > 0)) return res.status(400).json({ error: 'Datos inválidos' });
  const sign = type === 'entrada' ? q : -q;
  const [r] = await db.query('UPDATE products SET stock=stock+? WHERE id=? AND stock+?>=0', [sign, product_id, sign]);
  if (!r.affectedRows) return res.status(400).json({ error: 'Stock insuficiente o producto inexistente' });
  await db.query('INSERT INTO movements (product_id,type,quantity,user_id) VALUES (?,?,?,?)', [product_id, type, q, req.user.id]);
  res.json({ ok: true });
}));

app.post('/api/sales', auth(), wrap(async (req, res) => {
  const { product_id } = req.body;
  const q = parseInt(req.body.quantity);
  if (!(q > 0)) return res.status(400).json({ error: 'Cantidad inválida' });
  const [r] = await db.query('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?', [q, product_id, q]);
  if (!r.affectedRows) return res.status(400).json({ error: 'Stock insuficiente' });
  const [[p]] = await db.query('SELECT price FROM products WHERE id=?', [product_id]);
  await db.query('INSERT INTO sales (product_id,quantity,total,user_id) VALUES (?,?,?,?)', [product_id, q, p.price * q, req.user.id]);
  await db.query('INSERT INTO movements (product_id,type,quantity,user_id) VALUES (?,?,?,?)', [product_id, 'salida', q, req.user.id]);
  res.json({ ok: true });
}));

app.get('/api/reports', auth(), wrap(async (req, res) => {
  const [low] = await db.query('SELECT name,stock,min_stock FROM products WHERE stock<=min_stock ORDER BY stock');
  const [sales] = await db.query(`SELECT p.name, SUM(s.quantity) units, SUM(s.total) total
    FROM sales s JOIN products p ON p.id=s.product_id GROUP BY p.id ORDER BY total DESC`);
  const [recent] = await db.query(`SELECT p.name, s.quantity, s.total, s.created_at
    FROM sales s JOIN products p ON p.id=s.product_id ORDER BY s.id DESC LIMIT 10`);
  res.json({ low, sales, recent });
}));

init().then(() => app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Invencloud en puerto ' + (process.env.PORT || 3000))))
  .catch((e) => { console.error('No se pudo iniciar:', e.message); process.exit(1); });
