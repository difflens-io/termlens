import crypto from 'node:crypto';

export function normalizeHostKeyFingerprint(value) {
  const fingerprint = String(value || '').trim();
  if (!/^SHA256:[A-Za-z0-9+/]+$/.test(fingerprint)) return '';
  return fingerprint;
}

export function fingerprintSshHostKey(key) {
  const encoded = Buffer.isBuffer(key) ? key : Buffer.from(String(key || '').trim(), 'base64');
  if (!encoded.length) return '';
  const digest = crypto.createHash('sha256').update(encoded).digest('base64').replace(/=+$/g, '');
  return `SHA256:${digest}`;
}

export function sshHostKeyType(key) {
  const encoded = Buffer.isBuffer(key) ? key : Buffer.from(String(key || '').trim(), 'base64');
  if (encoded.length < 5) return '';
  const length = encoded.readUInt32BE(0);
  if (length <= 0 || length > 64 || encoded.length < 4 + length) return '';
  return encoded.subarray(4, 4 + length).toString('ascii');
}

export function createHostKeyVerifier(target, state = {}) {
  const policy = String(target?.host_key_policy || 'strict');
  const expected = normalizeHostKeyFingerprint(target?.host_key_fingerprint_sha256);
  return (key) => {
    const fingerprint = fingerprintSshHostKey(key);
    state.fingerprint = fingerprint;
    state.keyBase64 = Buffer.isBuffer(key) ? key.toString('base64') : String(key || '').trim();
    state.keyType = sshHostKeyType(key);
    state.verified = false;
    if (policy === 'disabled') {
      state.verified = false;
      return true;
    }
    if (!expected) {
      state.errorCode = 'host_key_unknown';
      return false;
    }
    if (fingerprint !== expected) {
      state.errorCode = 'host_key_changed';
      return false;
    }
    state.verified = true;
    state.errorCode = '';
    return true;
  };
}
