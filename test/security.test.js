import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createTotpSecret,
  generateTotpCode,
  hashPassword,
  hashToken,
  randomToken,
  verifyPassword,
  verifyTotp
} from '../src/server/security.js';

test('password hashes verify only the original password', () => {
  const hash = hashPassword('correct horse battery staple');
  assert.equal(verifyPassword('correct horse battery staple', hash), true);
  assert.equal(verifyPassword('wrong password', hash), false);
});

test('random tokens are URL-safe and hashes are stable', () => {
  const token = randomToken(32);
  assert.match(token, /^[a-zA-Z0-9_-]+$/);
  assert.equal(hashToken(token), hashToken(token));
  assert.notEqual(hashToken(token), token);
});

test('TOTP codes verify against generated secrets', () => {
  const { secret, otpauthUrl } = createTotpSecret('admin');
  const code = generateTotpCode(secret);
  assert.match(otpauthUrl, /^otpauth:\/\/totp\/TermLens:admin/);
  assert.equal(verifyTotp(code, secret), true);
  assert.equal(verifyTotp('000000', secret), code === '000000');
});
