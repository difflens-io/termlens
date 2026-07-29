import crypto from 'node:crypto';

const PASSWORD_ALGORITHM = 'scrypt';
const PASSWORD_KEY_LENGTH = 64;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function nowIso() {
  return new Date().toISOString();
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

export function hashPassword(password) {
  const salt = randomToken(18);
  const key = crypto.scryptSync(String(password), salt, PASSWORD_KEY_LENGTH).toString('base64url');
  return `${PASSWORD_ALGORITHM}$${salt}$${key}`;
}

export function verifyPassword(password, storedHash) {
  const [algorithm, salt, storedKey] = String(storedHash || '').split('$');
  if (algorithm !== PASSWORD_ALGORITHM || !salt || !storedKey) return false;
  const key = crypto.scryptSync(String(password), salt, PASSWORD_KEY_LENGTH);
  const stored = Buffer.from(storedKey, 'base64url');
  if (key.length !== stored.length) return false;
  return crypto.timingSafeEqual(key, stored);
}

export function createTotpSecret(username) {
  const secret = base32Encode(crypto.randomBytes(20));
  const service = 'TermLens';
  return {
    secret,
    otpauthUrl:
      `otpauth://totp/${encodeURIComponent(service)}:${encodeURIComponent(username)}` +
      `?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(service)}&algorithm=SHA1&digits=6&period=30`
  };
}

export function verifyTotp(code, secret) {
  if (!code || !secret) return false;
  const cleanCode = String(code).replace(/\s+/g, '');
  if (!/^[0-9]{6}$/.test(cleanCode)) return false;
  const secretBytes = base32Decode(secret);
  const step = Math.floor(Date.now() / 1000 / 30);
  for (const offset of [-1, 0, 1]) {
    const expected = hotp(secretBytes, step + offset);
    if (crypto.timingSafeEqual(Buffer.from(cleanCode), Buffer.from(expected))) return true;
  }
  return false;
}

export function generateTotpCode(secret, timestamp = Date.now()) {
  return hotp(base32Decode(secret), Math.floor(timestamp / 1000 / 30));
}

export function encryptSecret(value, secretKey) {
  if (!value) return '';
  if (!secretKey) {
    throw new Error('TERMLENS_SECRET_KEY is required to encrypt sensitive values.');
  }
  const key = crypto.createHash('sha256').update(secretKey).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64url')}:${tag.toString('base64url')}:${encrypted.toString('base64url')}`;
}

export function decryptSecret(payload, secretKey) {
  if (!payload) return '';
  if (!secretKey) {
    throw new Error('TERMLENS_SECRET_KEY is required to decrypt sensitive values.');
  }
  const [version, ivRaw, tagRaw, encryptedRaw] = String(payload).split(':');
  if (version !== 'v1' || !ivRaw || !tagRaw || !encryptedRaw) {
    throw new Error('Unsupported encrypted secret payload.');
  }
  const key = crypto.createHash('sha256').update(secretKey).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivRaw, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagRaw, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedRaw, 'base64url')),
    decipher.final()
  ]).toString('utf8');
}

export function parseCookies(cookieHeader = '') {
  const cookies = new Map();
  for (const part of cookieHeader.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (!name) continue;
    cookies.set(name, decodeURIComponent(rest.join('=')));
  }
  return cookies;
}

function base32Encode(buffer) {
  let bits = '';
  let output = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  for (let index = 0; index < bits.length; index += 5) {
    const chunk = bits.slice(index, index + 5).padEnd(5, '0');
    output += BASE32_ALPHABET[Number.parseInt(chunk, 2)];
  }
  return output;
}

function base32Decode(value) {
  const clean = String(value).toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  let bits = '';
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error('Invalid base32 secret.');
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function hotp(secretBytes, counter) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', secretBytes).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}
