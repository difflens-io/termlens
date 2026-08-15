import { db } from './db.js';
import { hashToken, nowIso, randomToken } from './security.js';

const DEFAULT_ACCESS_TTL_SECONDS = 10 * 60;
const DEFAULT_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

export function createMobileAuthChallenge({
  userId,
  accessLinkId,
  deviceId,
  deviceName = '',
  clientVersion = '',
  encryptedSecret = '',
  mfaSetupRequired = false,
  expiresAt
}) {
  const challenge = randomToken(24);
  db.prepare(`
    INSERT INTO mobile_auth_challenges (
      challenge_hash, user_id, access_link_id, device_id_hash, device_name,
      client_version, encrypted_secret, mfa_setup_required, expires_at, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    hashToken(challenge),
    userId,
    accessLinkId,
    hashToken(deviceId),
    String(deviceName).slice(0, 120),
    String(clientVersion).slice(0, 64),
    encryptedSecret,
    mfaSetupRequired ? 1 : 0,
    expiresAt,
    nowIso()
  );
  return { challenge, expiresAt };
}

export function getMobileAuthChallenge(challenge) {
  if (!challenge) return null;
  return db.prepare(`
    SELECT mobile_auth_challenges.*, users.password_hash, users.totp_secret,
      users.totp_enabled, users.disabled AS user_disabled,
      access_links.disabled AS access_link_disabled,
      access_links.expires_at AS access_link_expires_at,
      access_links.max_uses AS access_link_max_uses,
      access_links.used_count AS access_link_used_count
    FROM mobile_auth_challenges
    JOIN users ON users.id = mobile_auth_challenges.user_id
    JOIN access_links ON access_links.id = mobile_auth_challenges.access_link_id
    WHERE mobile_auth_challenges.challenge_hash = ?
  `).get(hashToken(challenge));
}

export function incrementMobileAuthFailure(id) {
  db.prepare(`
    UPDATE mobile_auth_challenges
    SET failed_attempts = failed_attempts + 1
    WHERE id = ?
  `).run(id);
}

export function deleteMobileAuthChallenge(id) {
  db.prepare('DELETE FROM mobile_auth_challenges WHERE id = ?').run(id);
}

export function createDeviceSession({
  userId,
  accessLinkId,
  deviceId,
  deviceName = '',
  clientVersion = '',
  accessTtlSeconds = DEFAULT_ACCESS_TTL_SECONDS,
  refreshTtlSeconds = DEFAULT_REFRESH_TTL_SECONDS
}) {
  const now = nowIso();
  const refreshExpiresAt = new Date(Date.now() + refreshTtlSeconds * 1000).toISOString();
  const familySecret = randomToken(24);
  const familyHash = hashToken(familySecret);
  const device = db.prepare(`
    INSERT INTO device_sessions (
      user_id, access_link_id, device_id_hash, device_name, client_version,
      refresh_token_family_hash, refresh_expires_at, last_seen_at, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    userId,
    accessLinkId,
    hashToken(deviceId),
    String(deviceName).slice(0, 120),
    String(clientVersion).slice(0, 64),
    familyHash,
    refreshExpiresAt,
    now,
    now,
    now
  );
  const deviceSessionId = Number(device.lastInsertRowid);
  return issueMobileTokens({
    deviceSessionId,
    userId,
    familyHash,
    refreshExpiresAt,
    accessTtlSeconds,
    refreshTtlSeconds
  });
}

export function findMobileAccessToken(token) {
  if (!token) return null;
  const row = db.prepare(`
    SELECT mobile_access_tokens.*, device_sessions.access_link_id,
      device_sessions.device_id_hash, device_sessions.device_name,
      device_sessions.client_version, device_sessions.revoked_at,
      device_sessions.refresh_expires_at,
      users.username, users.display_name, users.role, users.disabled AS user_disabled,
      users.totp_enabled,
      access_links.disabled AS access_link_disabled,
      access_links.expires_at AS access_link_expires_at
    FROM mobile_access_tokens
    JOIN device_sessions ON device_sessions.id = mobile_access_tokens.device_session_id
    JOIN users ON users.id = mobile_access_tokens.user_id
    JOIN access_links ON access_links.id = device_sessions.access_link_id
    WHERE mobile_access_tokens.token_hash = ?
  `).get(hashToken(token));
  if (!row) return null;
  if (row.revoked_at || row.user_disabled || row.access_link_disabled) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) return null;
  if (row.access_link_expires_at && new Date(row.access_link_expires_at).getTime() <= Date.now()) return null;
  db.prepare(`
    UPDATE mobile_access_tokens
    SET last_seen_at = ?
    WHERE id = ?
  `).run(nowIso(), row.id);
  db.prepare(`
    UPDATE device_sessions
    SET last_seen_at = ?, updated_at = ?
    WHERE id = ?
  `).run(nowIso(), nowIso(), row.device_session_id);
  return row;
}

export function rotateMobileRefreshToken(token, {
  accessTtlSeconds = DEFAULT_ACCESS_TTL_SECONDS,
  refreshTtlSeconds = DEFAULT_REFRESH_TTL_SECONDS
} = {}) {
  if (!token) return { ok: false, reason: 'invalid' };
  const current = db.prepare(`
    SELECT mobile_refresh_tokens.*, device_sessions.user_id,
      device_sessions.revoked_at AS device_revoked_at,
      device_sessions.refresh_expires_at,
      users.disabled AS user_disabled,
      access_links.disabled AS access_link_disabled,
      access_links.expires_at AS access_link_expires_at
    FROM mobile_refresh_tokens
    JOIN device_sessions ON device_sessions.id = mobile_refresh_tokens.device_session_id
    JOIN users ON users.id = device_sessions.user_id
    JOIN access_links ON access_links.id = device_sessions.access_link_id
    WHERE mobile_refresh_tokens.token_hash = ?
  `).get(hashToken(token));
  if (!current) return { ok: false, reason: 'invalid' };

  const now = Date.now();
  const absoluteRefreshExpiry = new Date(current.refresh_expires_at).getTime();
  const expired =
    new Date(current.expires_at).getTime() <= now ||
    !Number.isFinite(absoluteRefreshExpiry) ||
    absoluteRefreshExpiry <= now ||
    (current.access_link_expires_at && new Date(current.access_link_expires_at).getTime() <= now);
  if (
    current.used_at ||
    current.revoked_at ||
    expired ||
    current.device_revoked_at ||
    current.user_disabled ||
    current.access_link_disabled
  ) {
    if (current.used_at) revokeRefreshFamily(current.family_hash);
    return { ok: false, reason: current.used_at ? 'replay' : 'invalid' };
  }

  // Rotation must not extend the device session's original refresh lifetime.
  const refreshExpiresAt = current.refresh_expires_at;
  const accessExpiresAt = new Date(now + accessTtlSeconds * 1000).toISOString();
  const nextRefresh = randomToken(36);
  const accessToken = randomToken(36);
  const timestamp = nowIso();

  db.exec('BEGIN');
  try {
    db.prepare('UPDATE mobile_refresh_tokens SET used_at = ? WHERE id = ?')
      .run(timestamp, current.id);
    db.prepare(`
      INSERT INTO mobile_refresh_tokens (
        token_hash, family_hash, device_session_id, expires_at, created_at
      )
      VALUES (?, ?, ?, ?, ?)
    `).run(hashToken(nextRefresh), current.family_hash, current.device_session_id, refreshExpiresAt, timestamp);
    db.prepare(`
      INSERT INTO mobile_access_tokens (
        token_hash, device_session_id, user_id, expires_at, last_seen_at, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(hashToken(accessToken), current.device_session_id, current.user_id, accessExpiresAt, timestamp, timestamp);
    db.prepare(`
      UPDATE device_sessions
      SET last_seen_at = ?, updated_at = ?
      WHERE id = ?
    `).run(timestamp, timestamp, current.device_session_id);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  return {
    ok: true,
    accessToken,
    accessTokenExpiresAt: accessExpiresAt,
    refreshToken: nextRefresh,
    refreshTokenExpiresAt: refreshExpiresAt,
    deviceSessionId: current.device_session_id,
    userId: current.user_id
  };
}

export function revokeDeviceSession(deviceSessionId) {
  const timestamp = nowIso();
  db.prepare('UPDATE device_sessions SET revoked_at = ?, updated_at = ? WHERE id = ?')
    .run(timestamp, timestamp, deviceSessionId);
  db.prepare('UPDATE mobile_refresh_tokens SET revoked_at = ? WHERE device_session_id = ? AND revoked_at IS NULL')
    .run(timestamp, deviceSessionId);
  db.prepare('DELETE FROM mobile_access_tokens WHERE device_session_id = ?').run(deviceSessionId);
}

export function revokeRefreshFamily(familyHash) {
  const timestamp = nowIso();
  db.prepare('UPDATE mobile_refresh_tokens SET revoked_at = ? WHERE family_hash = ? AND revoked_at IS NULL')
    .run(timestamp, familyHash);
  db.prepare(`
    UPDATE device_sessions
    SET revoked_at = ?, updated_at = ?
    WHERE refresh_token_family_hash = ? AND revoked_at IS NULL
  `).run(timestamp, timestamp, familyHash);
  db.prepare(`
    DELETE FROM mobile_access_tokens
    WHERE device_session_id IN (
      SELECT id FROM device_sessions WHERE refresh_token_family_hash = ?
    )
  `).run(familyHash);
}

export function listDeviceSessions(userId) {
  return db.prepare(`
    SELECT id, device_name, client_version, last_seen_at, revoked_at, created_at, updated_at
    FROM device_sessions
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(userId);
}

function issueMobileTokens({
  deviceSessionId,
  userId,
  familyHash,
  refreshExpiresAt,
  accessTtlSeconds,
  refreshTtlSeconds
}) {
  const accessToken = randomToken(36);
  const refreshToken = randomToken(36);
  const timestamp = nowIso();
  const accessExpiresAt = new Date(Date.now() + accessTtlSeconds * 1000).toISOString();
  const refreshExpiry = refreshExpiresAt ||
    new Date(Date.now() + refreshTtlSeconds * 1000).toISOString();

  db.exec('BEGIN');
  try {
    db.prepare(`
      INSERT INTO mobile_access_tokens (
        token_hash, device_session_id, user_id, expires_at, last_seen_at, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(hashToken(accessToken), deviceSessionId, userId, accessExpiresAt, timestamp, timestamp);
    db.prepare(`
      INSERT INTO mobile_refresh_tokens (
        token_hash, family_hash, device_session_id, expires_at, created_at
      )
      VALUES (?, ?, ?, ?, ?)
    `).run(hashToken(refreshToken), familyHash, deviceSessionId, refreshExpiry, timestamp);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  return {
    accessToken,
    accessTokenExpiresAt: accessExpiresAt,
    refreshToken,
    refreshTokenExpiresAt: refreshExpiry,
    deviceSessionId
  };
}
