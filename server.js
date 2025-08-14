
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { stringify } from 'csv-stringify';
import PDFDocument from 'pdfkit';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';
import twilio from 'twilio';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;
const CLIENT_REDIRECT_URL_DEFAULT = "https://go.interestreporting.com/aff_ad?campaign_id=152&hostNameId=22392&aff_id=182";

// Middleware
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(morgan('dev'));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
});
app.use(limiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// SQLite setup
let db;
async function initDb() {
  db = await open({
    filename: path.join(__dirname, 'propjoiner.db'),
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT,
      phone TEXT UNIQUE,
      ip TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS otp_codes (
      phone TEXT PRIMARY KEY,
      code TEXT,
      expires_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS admins (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS visits (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      ip TEXT,
      user_agent TEXT,
      path TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS clicks (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      button TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS reg_attempts (
      id TEXT PRIMARY KEY,
      phone TEXT,
      started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS contacts (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT,
      message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed initial settings
  const urlSetting = await db.get('SELECT value FROM settings WHERE key = ?', ['CLIENT_REDIRECT_URL']);
  if (!urlSetting) {
    await db.run('INSERT INTO settings (key, value) VALUES (?,?)', ['CLIENT_REDIRECT_URL', process.env.CLIENT_REDIRECT_URL || CLIENT_REDIRECT_URL_DEFAULT]);
  }
}

function signAdminToken(admin) {
  return jwt.sign({ sub: admin.id, email: admin.email, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || '2d' });
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== 'admin') throw new Error('Not admin');
    req.admin = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Twilio client (optional)
let twilioClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
}

// Utilities
async function getClientUrl() {
  const row = await db.get('SELECT value FROM settings WHERE key=?', ['CLIENT_REDIRECT_URL']);
  return row?.value || CLIENT_REDIRECT_URL_DEFAULT;
}

// ===== Public API =====

// Track visit middleware for public pages
app.use(async (req, res, next) => {
  try {
    if (req.method === 'GET' && (req.path === '/' || req.path.startsWith('/page/'))) {
      const id = uuidv4();
      await db.run('INSERT INTO visits (id, user_id, ip, user_agent, path) VALUES (?,?,?,?,?)',
        [id, req.headers['x-user-id'] || null, req.ip, req.headers['user-agent'] || '', req.path]);
    }
  } catch (e) {
    // ignore
  }
  next();
});

// Simple health
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Current redirect URL
app.get('/api/redirect-url', async (req, res) => {
  res.json({ url: await getClientUrl() });
});

// Track a CTA click and redirect
app.get('/api/redirect/:button', async (req, res) => {
  const { button } = req.params;
  const id = uuidv4();
  try {
    await db.run('INSERT INTO clicks (id, user_id, button) VALUES (?,?,?)',
      [id, req.headers['x-user-id'] || null, button]);
  } catch (e) {}
  const url = await getClientUrl();
  res.redirect(url);
});

// Contact form
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body || {};
  if (!name || !email || !message) return res.status(400).json({ error: 'Missing fields' });
  const id = uuidv4();
  await db.run('INSERT INTO contacts (id, name, email, message) VALUES (?,?,?,?)',
    [id, name, email, message]);
  res.json({ ok: true });
});

// OTP - start
app.post('/api/auth/send-otp', async (req, res) => {
  const { phone } = req.body || {};
  if (!phone) return res.status(400).json({ error: 'Phone required' });
  const attemptId = uuidv4();
  await db.run('INSERT INTO reg_attempts (id, phone, completed) VALUES (?,?,0)', [attemptId, phone]);

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await db.run('INSERT INTO otp_codes (phone, code, expires_at) VALUES (?,?,?) ON CONFLICT(phone) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at',
    [phone, code, expiresAt]);

  if (twilioClient && process.env.TWILIO_FROM_NUMBER) {
    try {
      await twilioClient.messages.create({
        body: `Your PropJoiner verification code is: ${code}`,
        to: phone,
        from: process.env.TWILIO_FROM_NUMBER
      });
    } catch (e) {
      console.error('Twilio error:', e.message);
    }
  } else {
    console.log(`[DEV OTP] ${phone} -> ${code} (valid 10 min)`);
  }

  res.json({ ok: true, attemptId });
});

// OTP - verify and register
app.post('/api/auth/verify-otp', async (req, res) => {
  const { attemptId, phone, code, name, email } = req.body || {};
  if (!attemptId || !phone || !code) return res.status(400).json({ error: 'Missing fields' });
  const row = await db.get('SELECT code, expires_at FROM otp_codes WHERE phone=?', [phone]);
  if (!row) return res.status(400).json({ error: 'Code not found' });
  if (row.code !== code) return res.status(400).json({ error: 'Invalid code' });
  if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).json({ error: 'Code expired' });

  let user = await db.get('SELECT * FROM users WHERE phone=?', [phone]);
  if (!user) {
    const id = uuidv4();
    await db.run('INSERT INTO users (id, name, email, phone, ip) VALUES (?,?,?,?,?)',
      [id, name || null, email || null, phone, '']);
    user = await db.get('SELECT * FROM users WHERE id=?', [id]);
  }
  await db.run('UPDATE reg_attempts SET completed=1 WHERE id=?', [attemptId]);
  await db.run('DELETE FROM otp_codes WHERE phone=?', [phone]);

  res.json({ ok: true, userId: user.id });
});

// ===== Admin API =====

// Seed admin if not present
async function ensureAdmin() {
  const email = process.env.ADMIN_EMAIL || 'admin@propjoiner.com';
  const pass = process.env.ADMIN_PASSWORD || 'ChangeThisAdminPass123!';
  const existing = await db.get('SELECT * FROM admins WHERE email=?', [email]);
  if (!existing) {
    const hash = await bcrypt.hash(pass, 10);
    await db.run('INSERT INTO admins (id, email, password_hash) VALUES (?,?,?)', [uuidv4(), email, hash]);
    console.log(`Seeded admin: ${email} / (your .env password)`);
  }
}

app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing' });
  const admin = await db.get('SELECT * FROM admins WHERE email=?', [email]);
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, admin.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signAdminToken(admin);
  res.json({ token });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const totalVisitors = (await db.get('SELECT COUNT(*) as c FROM visits')).c;
  const totalUsers = (await db.get('SELECT COUNT(*) as c FROM users')).c;
  const totalClicks = (await db.get('SELECT COUNT(*) as c FROM clicks')).c;
  const attempts = (await db.get('SELECT COUNT(*) as c FROM reg_attempts')).c;
  const completed = (await db.get('SELECT COUNT(*) as c FROM reg_attempts WHERE completed=1')).c;
  const dropOff = attempts - completed;

  // Time series (last 30 days)
  const visitsByDay = await db.all(`
    SELECT date(created_at) as day, COUNT(*) as c FROM visits
    WHERE created_at >= date('now','-29 day')
    GROUP BY day ORDER BY day ASC
  `);
  const regsByDay = await db.all(`
    SELECT date(created_at) as day, COUNT(*) as c FROM users
    WHERE created_at >= date('now','-29 day')
    GROUP BY day ORDER BY day ASC
  `);
  const clicksByDay = await db.all(`
    SELECT date(created_at) as day, COUNT(*) as c FROM clicks
    WHERE created_at >= date('now','-29 day')
    GROUP BY day ORDER BY day ASC
  `);

  res.json({
    totalVisitors, totalUsers, totalClicks, dropOff,
    timeseries: { visitsByDay, regsByDay, clicksByDay }
  });
});

app.post('/api/admin/redirect-url', requireAdmin, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'Missing url' });
  await db.run('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
    ['CLIENT_REDIRECT_URL', url]);
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const users = await db.all('SELECT * FROM users ORDER BY created_at DESC LIMIT 1000');
  res.json({ users });
});

app.get('/api/admin/contacts', requireAdmin, async (req, res) => {
  const contacts = await db.all('SELECT * FROM contacts ORDER BY created_at DESC LIMIT 1000');
  res.json({ contacts });
});

// CSV export
app.get('/api/admin/export/csv', requireAdmin, async (req, res) => {
  const users = await db.all('SELECT * FROM users');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="propjoiner_users.csv"');
  const stringifier = stringify({ header: true });
  stringifier.on('readable', () => {
    let row;
    while (row = stringifier.read()) res.write(row);
  });
  stringifier.on('finish', () => res.end());
  users.forEach(u => stringifier.write(u));
  stringifier.end();
});

// PDF export (summary)
app.get('/api/admin/export/summary.pdf', requireAdmin, async (req, res) => {
  const totalVisitors = (await db.get('SELECT COUNT(*) as c FROM visits')).c;
  const totalUsers = (await db.get('SELECT COUNT(*) as c FROM users')).c;
  const totalClicks = (await db.get('SELECT COUNT(*) as c FROM clicks')).c;
  const attempts = (await db.get('SELECT COUNT(*) as c FROM reg_attempts')).c;
  const completed = (await db.get('SELECT COUNT(*) as c FROM reg_attempts WHERE completed=1')).c;
  const dropOff = attempts - completed;

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="propjoiner_summary.pdf"');

  const doc = new PDFDocument();
  doc.pipe(res);
  doc.fontSize(20).text('PropJoiner Analytics Summary', { underline: true });
  doc.moveDown();
  doc.fontSize(12).text(`Total Visitors: ${totalVisitors}`);
  doc.text(`Total Registrations: ${totalUsers}`);
  doc.text(`Total Redirect Clicks: ${totalClicks}`);
  doc.text(`Drop-Offs: ${dropOff}`);
  doc.end();
});

// ===== Frontend Routes =====
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Boot
initDb().then(() => ensureAdmin()).then(() => {
  app.listen(PORT, () => console.log(`PropJoiner running on http://localhost:${PORT}`));
});
