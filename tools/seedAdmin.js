
import 'dotenv/config';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const email = process.env.ADMIN_EMAIL || 'admin@propjoiner.com';
const pass = process.env.ADMIN_PASSWORD || 'ChangeThisAdminPass123!';

const db = await open({
  filename: path.join(__dirname, '..', 'propjoiner.db'),
  driver: sqlite3.Database
});

await db.exec(`
  CREATE TABLE IF NOT EXISTS admins (id TEXT PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
`);
const existing = await db.get('SELECT * FROM admins WHERE email=?', [email]);
if (!existing) {
  const hash = await bcrypt.hash(pass, 10);
  await db.run('INSERT INTO admins (id, email, password_hash) VALUES (?,?,?)', [uuidv4(), email, hash]);
  console.log(`Seeded admin: ${email}`);
} else {
  console.log('Admin already exists.');
}
process.exit(0);
