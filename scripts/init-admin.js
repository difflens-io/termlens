#!/usr/bin/env node
import { createAccessLink, createUser, db, getUserByUsername, sanitizeUser } from '../src/server/db.js';
import { hashPassword, randomToken, nowIso } from '../src/server/security.js';
import { config } from '../src/server/config.js';

const args = parseArgs(process.argv.slice(2));
const username = args.username || process.env.TERMLENS_ADMIN_USERNAME || 'admin';
const displayName = args.displayName || process.env.TERMLENS_ADMIN_DISPLAY_NAME || 'TermLens Admin';
const password = args.password || process.env.TERMLENS_ADMIN_PASSWORD || randomToken(18);

let user = getUserByUsername(username);
let created = false;

if (!user) {
  user = createUser({ username, displayName, role: 'admin', password });
  created = true;
} else {
  db.prepare(`
    UPDATE users
    SET role = 'admin', disabled = 0, password_hash = ?, updated_at = ?
    WHERE id = ?
  `).run(hashPassword(password), nowIso(), user.id);
  user = getUserByUsername(username);
}

const accessLink = createAccessLink({ userId: user.id, label: 'bootstrap-admin', createdBy: user.id });
const accessUrl = absoluteAppUrl(`access/${accessLink.token}`);

console.log(JSON.stringify({
  ok: true,
  created,
  user: sanitizeUser(user),
  password,
  accessUrl,
  note: 'TOTP enrollment is required on first browser login.'
}, null, 2));

function parseArgs(values) {
  const output = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith('--')) continue;
    const key = value.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    output[key] = values[index + 1];
    index += 1;
  }
  return output;
}

function absoluteAppUrl(relativePath) {
  const clean = relativePath.replace(/^\/+/, '');
  if (config.publicUrl) return new URL(clean, config.publicUrl).toString();
  return `${config.basePath}${clean}`;
}
