const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// åå§å PostgreSQL é£ç·æ± 
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// åå§åè³æåº«è¡¨æ ¼
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS quotes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        quote_no TEXT,
        client_name TEXT,
        total_amount REAL DEFAULT 0,
        data TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS vendors (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        contact_person TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        mobile TEXT DEFAULT '',
        email TEXT DEFAULT '',
        specialty TEXT DEFAULT '',
        address TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS clients (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        company TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        mobile TEXT DEFAULT '',
        email TEXT DEFAULT '',
        address TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS price_history (
        id SERIAL PRIMARY KEY,
        category TEXT NOT NULL,
        item_name TEXT NOT NULL,
        spec TEXT DEFAULT '',
        unit TEXT DEFAULT 'å¼',
        unit_price REAL NOT NULL,
        notes TEXT DEFAULT '',
        source TEXT DEFAULT '',
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS case_closings (
        id SERIAL PRIMARY KEY,
        quote_id INTEGER NOT NULL UNIQUE REFERENCES quotes(id),
        closed_by INTEGER NOT NULL REFERENCES users(id),
        cost_total REAL DEFAULT 0,
        client_total REAL DEFAULT 0,
        actual_cost REAL DEFAULT 0,
        absorbed_amount REAL DEFAULT 0,
        extra_billed REAL DEFAULT 0,
        gross_profit REAL DEFAULT 0,
        items TEXT DEFAULT '[]',
        notes TEXT DEFAULT '',
        status TEXT DEFAULT 'draft',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // è¥ç¡ä»»ä½ä½¿ç¨èï¼å»ºç«é è¨­ç®¡çå¡
    const countResult = await client.query('SELECT COUNT(*) as count FROM users');
    if (parseInt(countResult.rows[0].count) === 0) {
      const hashed = bcrypt.hashSync('admin123', 10);
      await client.query(
        'INSERT INTO users (username, password, display_name, role) VALUES ($1, $2, $3, $4)',
        ['admin', hashed, 'ç®¡çå¡', 'admin']
      );
      console.log('å·²å»ºç«é è¨­ç®¡çå¡å¸³èï¼admin / admin123');
    }

    console.log('è³æåº«åå§åå®æ');
  } finally {
    client.release();
  }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'qs-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 } // 8å°æ
}));
app.use(express.static(path.join(__dirname, 'public')));

// ââ é©è­ä¸­ä» ââââââââââââââââââââââââââââââââââââââââââââââ
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  if (req.headers['content-type'] === 'application/json' || req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'è«åç»å¥' });
  }
  res.redirect('/login.html');
}

function requireAdmin(req, res, next) {
  if (req.session.role === 'admin') return next();
  res.status(403).json({ error: 'æ¬éä¸è¶³ï¼éè¦ç®¡çå¡èº«ä»½' });
}

// ââ é¦é å°å ââââââââââââââââââââââââââââââââââââââââââââââ
app.get('/', (req, res) => {
  if (!req.session.userId) return res.redirect('/login.html');
  res.redirect('/index.html');
});

// ââ é©è­ API ââââââââââââââââââââââââââââââââââââââââââââââ
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'è«å¡«å¯«å¸³èèå¯ç¢¼' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'å¸³èæå¯ç¢¼é¯èª¤' });
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.displayName = user.display_name;
    req.session.role = user.role;
    res.json({ success: true, displayName: user.display_name, role: user.role });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'æªç»å¥' });
  res.json({
    id: req.session.userId,
    username: req.session.username,
    displayName: req.session.displayName,
    role: req.session.role
  });
});

// ââ å ±å¹å® API âââââââââââââââââââââââââââââââââââââââââââââ
app.get('/api/quotes', requireLogin, async (req, res) => {
  try {
    let result;
    if (req.session.role === 'admin') {
      result = await pool.query(`
        SELECT q.id, q.quote_no, q.client_name, q.total_amount, q.created_at, q.updated_at,
               u.display_name as creator_name,
               c.status as closing_status, c.gross_profit
        FROM quotes q JOIN users u ON q.user_id = u.id
        LEFT JOIN case_closings c ON c.quote_id = q.id
        ORDER BY q.updated_at DESC
      `);
    } else {
      result = await pool.query(`
        SELECT q.id, q.quote_no, q.client_name, q.total_amount, q.created_at, q.updated_at,
               u.display_name as creator_name,
               c.status as closing_status, c.gross_profit
        FROM quotes q JOIN users u ON q.user_id = u.id
        LEFT JOIN case_closings c ON c.quote_id = q.id
        WHERE q.user_id = $1
        ORDER BY q.updated_at DESC
      `, [req.session.userId]);
    }
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' });
  }
});

app.get('/api/quotes/:id', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM quotes WHERE id = $1', [req.params.id]);
    const q = result.rows[0];
    if (!q) return res.status(404).json({ error: 'æ¾ä¸å°æ­¤å ±å¹å®' });
    if (q.user_id !== req.session.userId && req.session.role !== 'admin')
      return res.status(403).json({ error: 'ç¡æ¬éæ¥ç' });
    q.data = JSON.parse(q.data);
    res.json(q);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' });
  }
});

app.post('/api/quotes', requireLogin, async (req, res) => {
  const { quote_no, client_name, total_amount, data } = req.body;
  try {
    const result = await pool.query(`
      INSERT INTO quotes (user_id, quote_no, client_name, total_amount, data)
      VALUES ($1, $2, $3, $4, $5) RETURNING id
    `, [req.session.userId, quote_no || '', client_name || '', total_amount || 0, JSON.stringify(data)]);
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' });
  }
});

app.put('/api/quotes/:id', requireLogin, async (req, res) => {
  try {
    const qResult = await pool.query('SELECT * FROM quotes WHERE id = $1', [req.params.id]);
    const q = qResult.rows[0];
    if (!q) return res.status(404).json({ error: 'æ¾ä¸å°æ­¤å ±å¹å®' });
    if (q.user_id !== req.session.userId && req.session.role !== 'admin')
      return res.status(403).json({ error: 'ç¡æ¬éä¿®æ¹' });
    const { quote_no, client_name, total_amount, data } = req.body;
    await pool.query(`
      UPDATE quotes SET quote_no=$1, client_name=$2, total_amount=$3, data=$4, updated_at=CURRENT_TIMESTAMP
      WHERE id=$5
    `, [quote_no || '', client_name || '', total_amount || 0, JSON.stringify(data), req.params.id]);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' });
  }
});

app.delete('/api/quotes/:id', requireLogin, async (req, res) => {
  try {
    const qResult = await pool.query('SELECT * FROM quotes WHERE id = $1', [req.params.id]);
    const q = qResult.rows[0];
    if (!q) return res.status(404).json({ error: 'æ¾ä¸å°æ­¤å ±å¹å®' });
    if (q.user_id !== req.session.userId && req.session.role !== 'admin')
      return res.status(403).json({ error: 'ç¡æ¬éåªé¤' });
    await pool.query('DELETE FROM quotes WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' });
  }
});

// ââ å» åè³æåº« API âââââââââââââââââââââââââââââââââââââââââ
app.get('/api/vendors', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM vendors ORDER BY name');
    res.json(result.rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.get('/api/vendors/:id', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM vendors WHERE id = $1', [req.params.id]);
    const v = result.rows[0];
    if (!v) return res.status(404).json({ error: 'æ¾ä¸å°æ­¤å» å' });
    res.json(v);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.post('/api/vendors', requireLogin, async (req, res) => {
  const { name, contact_person, phone, mobile, email, specialty, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'è«å¡«å¯«å» ååç¨±' });
  try {
    const result = await pool.query(`
      INSERT INTO vendors (name, contact_person, phone, mobile, email, specialty, address, notes)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
    `, [name, contact_person||'', phone||'', mobile||'', email||'', specialty||'', address||'', notes||'']);
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.put('/api/vendors/:id', requireLogin, async (req, res) => {
  const { name, contact_person, phone, mobile, email, specialty, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'è«å¡«å¯«å» ååç¨±' });
  try {
    await pool.query(`
      UPDATE vendors SET name=$1, contact_person=$2, phone=$3, mobile=$4, email=$5,
        specialty=$6, address=$7, notes=$8 WHERE id=$9
    `, [name, contact_person||'', phone||'', mobile||'', email||'', specialty||'', address||'', notes||'', req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.delete('/api/vendors/:id', requireLogin, async (req, res) => {
  try {
    await pool.query('DELETE FROM vendors WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

// ââ æ¥­ä¸»è³æåº« API âââââââââââââââââââââââââââââââââââââââââ
app.get('/api/clients', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clients ORDER BY name');
    res.json(result.rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.get('/api/clients/:id', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clients WHERE id = $1', [req.params.id]);
    const c = result.rows[0];
    if (!c) return res.status(404).json({ error: 'æ¾ä¸å°æ­¤æ¥­ä¸»' });
    res.json(c);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.post('/api/clients', requireLogin, async (req, res) => {
  const { name, company, phone, mobile, email, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'è«å¡«å¯«æ¥­ä¸»å§å' });
  try {
    const result = await pool.query(`
      INSERT INTO clients (name, company, phone, mobile, email, address, notes)
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
    `, [name, company||'', phone||'', mobile||'', email||'', address||'', notes||'']);
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.put('/api/clients/:id', requireLogin, async (req, res) => {
  const { name, company, phone, mobile, email, address, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'è«å¡«å¯«æ¥­ä¸»å§å' });
  try {
    await pool.query(`
      UPDATE clients SET name=$1, company=$2, phone=$3, mobile=$4, email=$5, address=$6, notes=$7
      WHERE id=$8
    `, [name, company||'', phone||'', mobile||'', email||'', address||'', notes||'', req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.delete('/api/clients/:id', requireLogin, async (req, res) => {
  try {
    await pool.query('DELETE FROM clients WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

// ââ æ­·å²å®å¹è³æåº« API âââââââââââââââââââââââââââââââââââââ
app.get('/api/prices', requireLogin, async (req, res) => {
  const { category, q } = req.query;
  try {
    let sql = 'SELECT * FROM price_history WHERE 1=1';
    const params = [];
    let idx = 1;
    if (category) { sql += ` AND category = $${idx++}`; params.push(category); }
    if (q) { sql += ` AND (item_name ILIKE $${idx} OR spec ILIKE $${idx+1})`; params.push('%'+q+'%', '%'+q+'%'); idx += 2; }
    sql += ' ORDER BY category, item_name, created_at DESC';
    const result = await pool.query(sql, params);
    res.json(result.rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.post('/api/prices', requireLogin, async (req, res) => {
  const { category, item_name, spec, unit, unit_price, notes, source } = req.body;
  if (!category || !item_name || unit_price === undefined)
    return res.status(400).json({ error: 'è«å¡«å¯«å¿è¦æ¬ä½ï¼é¡å¥ãåé ãå®å¹ï¼' });
  try {
    const result = await pool.query(`
      INSERT INTO price_history (category, item_name, spec, unit, unit_price, notes, source, user_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
    `, [category, item_name, spec||'', unit||'å¼', parseFloat(unit_price)||0, notes||'', source||'', req.session.userId]);
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.put('/api/prices/:id', requireLogin, async (req, res) => {
  const { category, item_name, spec, unit, unit_price, notes, source } = req.body;
  if (!category || !item_name || unit_price === undefined)
    return res.status(400).json({ error: 'è«å¡«å¯«å¿è¦æ¬ä½' });
  try {
    await pool.query(`
      UPDATE price_history SET category=$1, item_name=$2, spec=$3, unit=$4, unit_price=$5, notes=$6, source=$7
      WHERE id=$8
    `, [category, item_name, spec||'', unit||'å¼', parseFloat(unit_price)||0, notes||'', source||'', req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.delete('/api/prices/:id', requireLogin, async (req, res) => {
  try {
    await pool.query('DELETE FROM price_history WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

// æ¹æ¬¡æ°å¢ï¼å¾å ±å¹å®å¯å¥ï¼
app.post('/api/prices/batch', requireLogin, async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'ç¡è³æ' });
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const r of items) {
        await client.query(`
          INSERT INTO price_history (category, item_name, spec, unit, unit_price, notes, source, user_id)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [r.category, r.item_name, r.spec||'', r.unit||'å¼', parseFloat(r.unit_price)||0, r.notes||'', r.source||'', req.session.userId]);
      }
      await client.query('COMMIT');
      res.json({ success: true, count: items.length });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

// ââ çµæ¡ç³»çµ± API âââââââââââââââââââââââââââââââââââââââââââ
app.get('/api/closings', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, q.quote_no, q.client_name, u.display_name as closer_name
      FROM case_closings c
      JOIN quotes q ON c.quote_id = q.id
      JOIN users u ON c.closed_by = u.id
      ORDER BY c.updated_at DESC
    `);
    const rows = result.rows;
    rows.forEach(r => { try { r.items = JSON.parse(r.items); } catch { r.items = []; } });
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.get('/api/closings/:quoteId', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, q.quote_no, q.client_name, q.data as quote_data
      FROM case_closings c
      JOIN quotes q ON c.quote_id = q.id
      WHERE c.quote_id = $1
    `, [req.params.quoteId]);
    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: 'å°æªçµæ¡' });
    try { row.items = JSON.parse(row.items); } catch { row.items = []; }
    try { row.quote_data = JSON.parse(row.quote_data); } catch { row.quote_data = null; }
    res.json(row);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.post('/api/closings', requireLogin, async (req, res) => {
  const { quote_id, cost_total, client_total, actual_cost, absorbed_amount, extra_billed, gross_profit, items, notes, status } = req.body;
  if (!quote_id) return res.status(400).json({ error: 'ç¼ºå° quote_id' });
  try {
    const existResult = await pool.query('SELECT id FROM case_closings WHERE quote_id = $1', [quote_id]);
    const existing = existResult.rows[0];
    if (existing) {
      await pool.query(`
        UPDATE case_closings SET
          closed_by=$1, cost_total=$2, client_total=$3, actual_cost=$4, absorbed_amount=$5, extra_billed=$6,
          gross_profit=$7, items=$8, notes=$9, status=$10, updated_at=CURRENT_TIMESTAMP WHERE id=$11
      `, [req.session.userId, cost_total||0, client_total||0, actual_cost||0,
          absorbed_amount||0, extra_billed||0, gross_profit||0,
          JSON.stringify(items||[]), notes||'', status||'draft', existing.id]);
      return res.json({ success: true, id: existing.id });
    }
    const result = await pool.query(`
      INSERT INTO case_closings
        (quote_id, closed_by, cost_total, client_total, actual_cost, absorbed_amount, extra_billed, gross_profit, items, notes, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id
    `, [quote_id, req.session.userId, cost_total||0, client_total||0, actual_cost||0,
        absorbed_amount||0, extra_billed||0, gross_profit||0,
        JSON.stringify(items||[]), notes||'', status||'draft']);
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.put('/api/closings/:id', requireLogin, async (req, res) => {
  const { cost_total, client_total, actual_cost, absorbed_amount, extra_billed, gross_profit, items, notes, status } = req.body;
  try {
    await pool.query(`
      UPDATE case_closings SET
        closed_by=$1, cost_total=$2, client_total=$3, actual_cost=$4, absorbed_amount=$5, extra_billed=$6,
        gross_profit=$7, items=$8, notes=$9, status=$10, updated_at=CURRENT_TIMESTAMP WHERE id=$11
    `, [req.session.userId, cost_total||0, client_total||0, actual_cost||0,
        absorbed_amount||0, extra_billed||0, gross_profit||0,
        JSON.stringify(items||[]), notes||'', status||'draft', req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.delete('/api/closings/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM case_closings WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

// ââ ä½¿ç¨èç®¡ç APIï¼ç®¡çå¡ï¼ âââââââââââââââââââââââââââââââ
app.get('/api/users', requireLogin, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, display_name, role, created_at FROM users ORDER BY created_at'
    );
    res.json(result.rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.post('/api/users', requireLogin, requireAdmin, async (req, res) => {
  const { username, password, display_name, role } = req.body;
  if (!username || !password || !display_name)
    return res.status(400).json({ error: 'è«å¡«å¯«æææ¬ä½' });
  if (password.length < 6)
    return res.status(400).json({ error: 'å¯ç¢¼è³å°éè¦6åå­å' });
  try {
    const hashed = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password, display_name, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [username, hashed, display_name, role || 'user']
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'å¸³èå·²å­å¨' });
    console.error(e);
    res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' });
  }
});

app.delete('/api/users/:id', requireLogin, requireAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.session.userId)
    return res.status(400).json({ error: 'ä¸è½åªé¤èªå·±çå¸³è' });
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

app.put('/api/users/:id/password', requireLogin, async (req, res) => {
  if (parseInt(req.params.id) !== req.session.userId && req.session.role !== 'admin')
    return res.status(403).json({ error: 'æ¬éä¸è¶³' });
  const { password } = req.body;
  if (!password || password.length < 6)
    return res.status(400).json({ error: 'å¯ç¢¼è³å°éè¦6åå­å' });
  try {
    await pool.query('UPDATE users SET password = $1 WHERE id = $2',
      [bcrypt.hashSync(password, 10), req.params.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ä¼ºæå¨é¯èª¤' }); }
});

// ââ ååä¼ºæå¨ âââââââââââââââââââââââââââââââââââââââââââââ
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`å¤§äºè¨­è¨å ±å¹ç³»çµ±ååï¼é£æ¥å ï¼${PORT}`);
  });
}).catch(err => {
  console.error('è³æåº«åå§åå¤±æï¼', err);
  process.exit(1);
});

