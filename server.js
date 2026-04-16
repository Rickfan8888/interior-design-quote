const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// 確保資料目錄存在
const dataDir = path.join(__dirname, '.data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// 初始化資料庫
const db = new Database(path.join(dataDir, 'quotes.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS quotes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    quote_no TEXT,
    client_name TEXT,
    total_amount REAL DEFAULT 0,
    data TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    contact_person TEXT,
    phone TEXT,
    mobile TEXT,
    email TEXT,
    specialty TEXT,
    address TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    company TEXT,
    phone TEXT,
    mobile TEXT,
    email TEXT,
    address TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS price_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    item_name TEXT NOT NULL,
    spec TEXT,
    unit TEXT,
    unit_price REAL NOT NULL,
    notes TEXT,
    source TEXT,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// 若無任何使用者，建立預設管理員
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const hashed = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password, display_name, role) VALUES (?, ?, ?, ?)')
    .run('admin', hashed, '管理員', 'admin');
  console.log('已建立預設管理員帳號：admin / admin123');
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'qs-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 } // 8小時
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── 驗證中介 ──────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  if (req.headers['content-type'] === 'application/json' || req.path.startsWith('/api/')) {
    return res.status(401).json({ error: '請先登入' });
  }
  res.redirect('/login.html');
}

function requireAdmin(req, res, next) {
  if (req.session.role === 'admin') return next();
  res.status(403).json({ error: '權限不足，需要管理員身份' });
}

// ── 首頁導向 ──────────────────────────────────────────────
app.get('/', (req, res) => {
  if (!req.session.userId) return res.redirect('/login.html');
  res.redirect('/index.html');
});

// ── 驗證 API ──────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: '請填寫帳號與密碼' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: '帳號或密碼錯誤' });

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.displayName = user.display_name;
  req.session.role = user.role;
  res.json({ success: true, displayName: user.display_name, role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: '未登入' });
  res.json({
    id: req.session.userId,
    username: req.session.username,
    displayName: req.session.displayName,
    role: req.session.role
  });
});

// ── 報價單 API ─────────────────────────────────────────────
app.get('/api/quotes', requireLogin, (req, res) => {
  let quotes;
  if (req.session.role === 'admin') {
    quotes = db.prepare(`
      SELECT q.id, q.quote_no, q.client_name, q.total_amount, q.created_at, q.updated_at,
             u.display_name as creator_name
      FROM quotes q JOIN users u ON q.user_id = u.id
      ORDER BY q.updated_at DESC
    `).all();
  } else {
    quotes = db.prepare(`
      SELECT q.id, q.quote_no, q.client_name, q.total_amount, q.created_at, q.updated_at,
             u.display_name as creator_name
      FROM quotes q JOIN users u ON q.user_id = u.id
      WHERE q.user_id = ?
      ORDER BY q.updated_at DESC
    `).all(req.session.userId);
  }
  res.json(quotes);
});

app.get('/api/quotes/:id', requireLogin, (req, res) => {
  const q = db.prepare('SELECT * FROM quotes WHERE id = ?').get(req.params.id);
  if (!q) return res.status(404).json({ error: '找不到此報價單' });
  if (q.user_id !== req.session.userId && req.session.role !== 'admin')
    return res.status(403).json({ error: '無權限查看' });
  q.data = JSON.parse(q.data);
  res.json(q);
});

app.post('/api/quotes', requireLogin, (req, res) => {
  const { quote_no, client_name, total_amount, data } = req.body;
  const result = db.prepare(`
    INSERT INTO quotes (user_id, quote_no, client_name, total_amount, data)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.session.userId, quote_no || '', client_name || '', total_amount || 0, JSON.stringify(data));
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/quotes/:id', requireLogin, (req, res) => {
  const q = db.prepare('SELECT * FROM quotes WHERE id = ?').get(req.params.id);
  if (!q) return res.status(404).json({ error: '找不到此報價單' });
  if (q.user_id !== req.session.userId && req.session.role !== 'admin')
    return res.status(403).json({ error: '無權限修改' });
  const { quote_no, client_name, total_amount, data } = req.body;
  db.prepare(`
    UPDATE quotes SET quote_no=?, client_name=?, total_amount=?, data=?, updated_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(quote_no || '', client_name || '', total_amount || 0, JSON.stringify(data), req.params.id);
  res.json({ success: true });
});

app.delete('/api/quotes/:id', requireLogin, (req, res) => {
  const q = db.prepare('SELECT * FROM quotes WHERE id = ?').get(req.params.id);
  if (!q) return res.status(404).json({ error: '找不到此報價單' });
  if (q.user_id !== req.session.userId && req.session.role !== 'admin')
    return res.status(403).json({ error: '無權限刪除' });
  db.prepare('DELETE FROM quotes WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ── 廠商資料庫 API ─────────────────────────────────────────
app.get('/api/vendors', requireLogin, (req, res) => {
  const vendors = db.prepare('SELECT * FROM vendors ORDER BY name').all();
  res.json(vendors);
});

app.get('/api/vendors/:id', requireLogin, (req, res) => {
  const v = db.prepare('SELECT * FROM vendors WHERE id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: '找不到此廠商' });
  res.json(v);
});

app.post('/api/vendors', requireLogin, (req, res) => {
  const { name, contact_person, phone, mobile, email, specialty, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: '請填寫廠商名稱' });
  const result = db.prepare(`
    INSERT INTO vendors (name, contact_person, phone, mobile, email, specialty, address, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(name, contact_person || '', phone || '', mobile || '', email || '', specialty || '', address || '', notes || '');
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/vendors/:id', requireLogin, (req, res) => {
  const { name, contact_person, phone, mobile, email, specialty, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: '請填寫廠商名稱' });
  db.prepare(`
    UPDATE vendors SET name=?, contact_person=?, phone=?, mobile=?, email=?, specialty=?, address=?, notes=?
    WHERE id=?
  `).run(name, contact_person || '', phone || '', mobile || '', email || '', specialty || '', address || '', notes || '', req.params.id);
  res.json({ success: true });
});

app.delete('/api/vendors/:id', requireLogin, (req, res) => {
  db.prepare('DELETE FROM vendors WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ── 業主資料庫 API ─────────────────────────────────────────
app.get('/api/clients', requireLogin, (req, res) => {
  const clients = db.prepare('SELECT * FROM clients ORDER BY name').all();
  res.json(clients);
});

app.get('/api/clients/:id', requireLogin, (req, res) => {
  const c = db.prepare('SELECT * FROM clients WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ error: '找不到此業主' });
  res.json(c);
});

app.post('/api/clients', requireLogin, (req, res) => {
  const { name, company, phone, mobile, email, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: '請填寫業主姓名' });
  const result = db.prepare(`
    INSERT INTO clients (name, company, phone, mobile, email, address, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(name, company || '', phone || '', mobile || '', email || '', address || '', notes || '');
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/clients/:id', requireLogin, (req, res) => {
  const { name, company, phone, mobile, email, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: '請填寫業主姓名' });
  db.prepare(`
    UPDATE clients SET name=?, company=?, phone=?, mobile=?, email=?, address=?, notes=?
    WHERE id=?
  `).run(name, company || '', phone || '', mobile || '', email || '', address || '', notes || '', req.params.id);
  res.json({ success: true });
});

app.delete('/api/clients/:id', requireLogin, (req, res) => {
  db.prepare('DELETE FROM clients WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ── 歷史單價資料庫 API ─────────────────────────────────────
app.get('/api/prices', requireLogin, (req, res) => {
  const { category, q } = req.query;
  let sql = 'SELECT * FROM price_history WHERE 1=1';
  const params = [];
  if (category) { sql += ' AND category = ?'; params.push(category); }
  if (q) { sql += ' AND (item_name LIKE ? OR spec LIKE ?)'; params.push('%'+q+'%', '%'+q+'%'); }
  sql += ' ORDER BY category, item_name, created_at DESC';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/prices', requireLogin, (req, res) => {
  const { category, item_name, spec, unit, unit_price, notes, source } = req.body;
  if (!category || !item_name || unit_price === undefined)
    return res.status(400).json({ error: '請填寫必要欄位（類別、品項、單價）' });
  const result = db.prepare(`
    INSERT INTO price_history (category, item_name, spec, unit, unit_price, notes, source, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(category, item_name, spec || '', unit || '式', parseFloat(unit_price) || 0, notes || '', source || '', req.session.userId);
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/prices/:id', requireLogin, (req, res) => {
  const { category, item_name, spec, unit, unit_price, notes, source } = req.body;
  if (!category || !item_name || unit_price === undefined)
    return res.status(400).json({ error: '請填寫必要欄位' });
  db.prepare(`
    UPDATE price_history SET category=?, item_name=?, spec=?, unit=?, unit_price=?, notes=?, source=?
    WHERE id=?
  `).run(category, item_name, spec || '', unit || '式', parseFloat(unit_price) || 0, notes || '', source || '', req.params.id);
  res.json({ success: true });
});

app.delete('/api/prices/:id', requireLogin, (req, res) => {
  db.prepare('DELETE FROM price_history WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// 批次新增（從報價單匯入）
app.post('/api/prices/batch', requireLogin, (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: '無資料' });
  const stmt = db.prepare(`
    INSERT INTO price_history (category, item_name, spec, unit, unit_price, notes, source, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertMany = db.transaction((rows) => {
    for (const r of rows) {
      stmt.run(r.category, r.item_name, r.spec || '', r.unit || '式',
               parseFloat(r.unit_price) || 0, r.notes || '', r.source || '', req.session.userId);
    }
  });
  insertMany(items);
  res.json({ success: true, count: items.length });
});

// ── 使用者管理 API（管理員） ───────────────────────────────
app.get('/api/users', requireLogin, requireAdmin, (req, res) => {
  const users = db.prepare(
    'SELECT id, username, display_name, role, created_at FROM users ORDER BY created_at'
  ).all();
  res.json(users);
});

app.post('/api/users', requireLogin, requireAdmin, (req, res) => {
  const { username, password, display_name, role } = req.body;
  if (!username || !password || !display_name)
    return res.status(400).json({ error: '請填寫所有欄位' });
  if (password.length < 6)
    return res.status(400).json({ error: '密碼至少需要6個字元' });
  try {
    const hashed = bcrypt.hashSync(password, 10);
    const result = db.prepare(
      'INSERT INTO users (username, password, display_name, role) VALUES (?, ?, ?, ?)'
    ).run(username, hashed, display_name, role || 'user');
    res.json({ success: true, id: result.lastInsertRowid });
  } catch {
    res.status(400).json({ error: '帳號已存在' });
  }
});

app.delete('/api/users/:id', requireLogin, requireAdmin, (req, res) => {
  if (parseInt(req.params.id) === req.session.userId)
    return res.status(400).json({ error: '不能刪除自己的帳號' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.put('/api/users/:id/password', requireLogin, (req, res) => {
  if (parseInt(req.params.id) !== req.session.userId && req.session.role !== 'admin')
    return res.status(403).json({ error: '權限不足' });
  const { password } = req.body;
  if (!password || password.length < 6)
    return res.status(400).json({ error: '密碼至少需要6個字元' });
  db.prepare('UPDATE users SET password = ? WHERE id = ?')
    .run(bcrypt.hashSync(password, 10), req.params.id);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`室內設計報價系統啟動，連接埠：${PORT}`);
});
