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
  if (req.headers['content-type'] === 'application/json') {
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
// 取得列表
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

// 取得單一報價單
app.get('/api/quotes/:id', requireLogin, (req, res) => {
  const q = db.prepare('SELECT * FROM quotes WHERE id = ?').get(req.params.id);
  if (!q) return res.status(404).json({ error: '找不到此報價單' });
  if (q.user_id !== req.session.userId && req.session.role !== 'admin')
    return res.status(403).json({ error: '無權限查看' });
  q.data = JSON.parse(q.data);
  res.json(q);
});

// 新增報價單
app.post('/api/quotes', requireLogin, (req, res) => {
  const { quote_no, client_name, total_amount, data } = req.body;
  const result = db.prepare(`
    INSERT INTO quotes (user_id, quote_no, client_name, total_amount, data)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.session.userId, quote_no || '', client_name || '', total_amount || 0, JSON.stringify(data));
  res.json({ success: true, id: result.lastInsertRowid });
});

// 更新報價單
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

// 刪除報價單
app.delete('/api/quotes/:id', requireLogin, (req, res) => {
  const q = db.prepare('SELECT * FROM quotes WHERE id = ?').get(req.params.id);
  if (!q) return res.status(404).json({ error: '找不到此報價單' });
  if (q.user_id !== req.session.userId && req.session.role !== 'admin')
    return res.status(403).json({ error: '無權限刪除' });
  db.prepare('DELETE FROM quotes WHERE id = ?').run(req.params.id);
  res.json({ success: true });
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

// 修改密碼（本人或管理員）
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
