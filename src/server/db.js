import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';
import { hashPassword, hashToken, nowIso, randomToken } from './security.js';

fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });

export const db = new DatabaseSync(config.dbPath);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('admin', 'user')) DEFAULT 'user',
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  ssh_username TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_target_permissions (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES ssh_targets(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, target_id)
);

CREATE TABLE IF NOT EXISTS access_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT '',
  expires_at TEXT,
  max_uses INTEGER NOT NULL DEFAULT 0,
  used_count INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_link_id INTEGER NOT NULL REFERENCES access_links(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS terminal_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES ssh_targets(id) ON DELETE CASCADE,
  access_link_id INTEGER NOT NULL REFERENCES access_links(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mfa_enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_link_id INTEGER NOT NULL REFERENCES access_links(id) ON DELETE CASCADE,
  encrypted_secret TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
`);

export function sanitizeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role,
    totpEnabled: Boolean(row.totp_enabled),
    disabled: Boolean(row.disabled),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function createUser({ username, displayName = '', role = 'user', password }) {
  const now = nowIso();
  const result = db.prepare(`
    INSERT INTO users (username, display_name, role, password_hash, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(username, displayName, role, hashPassword(password), now, now);
  return getUserById(Number(result.lastInsertRowid));
}

export function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

export function getUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

export function createAccessLink({ userId, label = '', expiresAt = null, maxUses = 0, createdBy = null }) {
  const token = randomToken(36);
  db.prepare(`
    INSERT INTO access_links (token_hash, user_id, label, expires_at, max_uses, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(hashToken(token), userId, label, expiresAt, maxUses, createdBy, nowIso());
  return { token, link: getAccessLinkByToken(token) };
}

export function getAccessLinkByToken(token) {
  return db.prepare(`
    SELECT access_links.*, users.username, users.display_name, users.role, users.password_hash,
      users.totp_secret, users.totp_enabled, users.disabled AS user_disabled
    FROM access_links
    JOIN users ON users.id = access_links.user_id
    WHERE access_links.token_hash = ?
  `).get(hashToken(token));
}

export function isAccessLinkUsable(link) {
  if (!link || link.disabled || link.user_disabled) return false;
  if (link.expires_at && new Date(link.expires_at).getTime() <= Date.now()) return false;
  if (link.max_uses > 0 && link.used_count >= link.max_uses) return false;
  return true;
}

export function audit({ userId = null, type, details = {}, req = null }) {
  db.prepare(`
    INSERT INTO audit_events (actor_user_id, type, details_json, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    userId,
    type,
    JSON.stringify(details),
    req?.ip || req?.socket?.remoteAddress || '',
    req?.headers?.['user-agent'] || '',
    nowIso()
  );
}
