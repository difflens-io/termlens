import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import helmet from 'helmet';
import QRCode from 'qrcode';
import { Client as SshClient } from 'ssh2';
import { WebSocket, WebSocketServer } from 'ws';
import { config, mountPath } from './config.js';
import {
  audit,
  createAccessLink,
  createUser,
  db,
  getAccessLinkByToken,
  getUserById,
  getUserByUsername,
  isAccessLinkUsable,
  sanitizeUser
} from './db.js';
import {
  createDeviceSession,
  createMobileAuthChallenge,
  deleteMobileAuthChallenge,
  findMobileAccessToken,
  getMobileAuthChallenge,
  incrementMobileAuthFailure,
  listDeviceSessions,
  revokeDeviceSession,
  rotateMobileRefreshToken
} from './mobile-session.js';
import {
  createTotpSecret,
  decryptSecret,
  encryptSecret,
  hashPassword,
  hashToken,
  nowIso,
  parseCookies,
  randomToken,
  verifyPassword,
  verifyTotp
} from './security.js';
import { createHostKeyVerifier, normalizeHostKeyFingerprint } from './ssh-host-key.js';
import { createPrivateRelay } from './private-relay.js';
import { createTerminalSettingsStore } from './terminal-settings.js';

if (!config.secretKey) {
  throw new Error('TERMLENS_SECRET_KEY must be set before starting TermLens.');
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const loginAttempts = new Map();
const TERMINAL_ACTIVITY_TOUCH_INTERVAL_MS = 30_000;
const TERMINAL_IDLE_CHECK_INTERVAL_MS = 30_000;
const MOBILE_TERMINAL_REPLAY_LIMIT_BYTES = 8 * 1024 * 1024;
const MOBILE_TERMINAL_DETACHED_TTL_MS = 30 * 60 * 1000;

const mobileTerminalSessions = new Map();
const mobileTerminalResumeTickets = new Map();

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    },
    referrerPolicy: { policy: 'same-origin' }
  })
);
app.use(express.json({ limit: '64kb' }));
app.use(requireTrustedOrigin);

app.get(mountPath, (req, res, next) => {
  if (req.path === mountPath) return res.redirect(config.basePath);
  next();
});
const router = express.Router();
app.use(mountPath, router);
const privateRelay = createPrivateRelay({ config, db, audit, mountPath });
const terminalSettingsStore = createTerminalSettingsStore({ config, db, nowIso });

router.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

router.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'termlens' });
});

router.post('/api/mobile/v1/auth/start', async (req, res) => {
  const inviteToken = String(req.body?.inviteToken || req.body?.accessToken || '');
  const deviceId = String(req.body?.deviceId || '').trim();
  const deviceName = String(req.body?.deviceName || '').trim();
  const clientVersion = String(req.body?.clientVersion || '').trim();
  const link = getAccessLinkByToken(inviteToken);
  if (!isAccessLinkUsable(link)) {
    return res.status(404).json({ error: '移动端邀请无效或已失效' });
  }
  if (deviceId.length < 8 || deviceId.length > 256) {
    return res.status(400).json({ error: '设备标识无效' });
  }

  const expiresAt = new Date(Date.now() + config.mfaEnrollmentTtlSeconds * 1000).toISOString();
  let encryptedSecret = '';
  let qrDataUrl = '';
  let mfaSetupRequired = false;
  if (!link.totp_enabled) {
    const { secret, otpauthUrl } = createTotpSecret(link.username);
    encryptedSecret = encryptSecret(secret, config.secretKey);
    qrDataUrl = await QRCode.toDataURL(otpauthUrl, { margin: 1, width: 220 });
    mfaSetupRequired = true;
  }

  const challenge = createMobileAuthChallenge({
    userId: link.user_id,
    accessLinkId: link.id,
    deviceId,
    deviceName,
    clientVersion,
    encryptedSecret,
    mfaSetupRequired,
    expiresAt
  });
  audit({
    userId: link.user_id,
    type: mfaSetupRequired ? 'mobile_mfa_setup_started' : 'mobile_auth_started',
    details: { accessLinkId: link.id, deviceName, clientVersion },
    req
  });

  res.json({
    challenge: challenge.challenge,
    expiresAt: challenge.expiresAt,
    mfaSetupRequired,
    qrDataUrl
  });
});

router.post('/api/mobile/v1/auth/verify', (req, res) => {
  const challengeToken = String(req.body?.challenge || '');
  const password = String(req.body?.password || '');
  const totpCode = String(req.body?.totpCode || '');
  const deviceId = String(req.body?.deviceId || '').trim();
  const challenge = getMobileAuthChallenge(challengeToken);
  if (!isMobileChallengeUsable(challenge)) {
    return res.status(401).json({ error: '移动端登录会话无效或已过期' });
  }
  if (challenge.failed_attempts >= 10) {
    deleteMobileAuthChallenge(challenge.id);
    audit({ userId: challenge.user_id, type: 'mobile_auth_locked', req });
    return res.status(429).json({ error: '移动端登录尝试过多，请重新开始' });
  }
  if (!deviceId || hashToken(deviceId) !== challenge.device_id_hash) {
    incrementMobileAuthFailure(challenge.id);
    return res.status(401).json({ error: '设备验证失败' });
  }
  if (!password || !verifyPassword(password, challenge.password_hash)) {
    incrementMobileAuthFailure(challenge.id);
    audit({ userId: challenge.user_id, type: 'mobile_login_failed', details: { reason: 'password' }, req });
    return res.status(401).json({ error: '登录失败' });
  }

  let totpSecret = '';
  if (challenge.mfa_setup_required) {
    totpSecret = decryptSecret(challenge.encrypted_secret, config.secretKey);
  } else {
    totpSecret = decryptSecret(challenge.totp_secret, config.secretKey);
  }
  if (!verifyTotp(totpCode, totpSecret)) {
    incrementMobileAuthFailure(challenge.id);
    audit({ userId: challenge.user_id, type: 'mobile_login_failed', details: { reason: 'totp' }, req });
    return res.status(401).json({ error: '双因子验证码无效' });
  }

  if (challenge.mfa_setup_required) {
    db.prepare(`
      UPDATE users
      SET totp_secret = ?, totp_enabled = 1, updated_at = ?
      WHERE id = ?
    `).run(encryptSecret(totpSecret, config.secretKey), nowIso(), challenge.user_id);
    audit({ userId: challenge.user_id, type: 'mobile_mfa_setup_success', req });
  }

  deleteMobileAuthChallenge(challenge.id);
  db.prepare('UPDATE access_links SET used_count = used_count + 1 WHERE id = ?').run(challenge.access_link_id);
  const tokens = createDeviceSession({
    userId: challenge.user_id,
    accessLinkId: challenge.access_link_id,
    deviceId,
    deviceName: challenge.device_name,
    clientVersion: challenge.client_version
  });
  audit({
    userId: challenge.user_id,
    type: 'mobile_login_success',
    details: { deviceSessionId: tokens.deviceSessionId, accessLinkId: challenge.access_link_id },
    req
  });
  res.status(201).json({
    ok: true,
    user: sanitizeUser(getUserById(challenge.user_id)),
    accessToken: tokens.accessToken,
    accessTokenExpiresAt: tokens.accessTokenExpiresAt,
    refreshToken: tokens.refreshToken,
    refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
    deviceSessionId: tokens.deviceSessionId
  });
});

router.post('/api/mobile/v1/token/refresh', (req, res) => {
  const refreshToken = String(req.body?.refreshToken || '');
  const result = rotateMobileRefreshToken(refreshToken);
  if (!result.ok) {
    audit({ type: 'mobile_token_refresh_failed', details: { reason: result.reason }, req });
    return res.status(401).json({ error: '移动端刷新凭据无效' });
  }
  audit({
    userId: result.userId,
    type: 'mobile_token_refreshed',
    details: { deviceSessionId: result.deviceSessionId },
    req
  });
  res.json({
    accessToken: result.accessToken,
    accessTokenExpiresAt: result.accessTokenExpiresAt,
    refreshToken: result.refreshToken,
    refreshTokenExpiresAt: result.refreshTokenExpiresAt,
    deviceSessionId: result.deviceSessionId
  });
});

router.post('/api/mobile/v1/token/revoke', requireMobileAuth, (req, res) => {
  revokeDeviceSession(req.mobileAuth.session.id);
  audit({
    userId: req.mobileAuth.user.id,
    type: 'mobile_token_revoked',
    details: { deviceSessionId: req.mobileAuth.session.id },
    req
  });
  res.json({ ok: true });
});

router.get('/api/mobile/v1/devices', requireMobileAuth, (req, res) => {
  res.json({
    devices: listDeviceSessions(req.mobileAuth.user.id).map(publicDeviceSession)
  });
});

router.post('/api/mobile/v1/devices/:id/revoke', requireMobileAuth, (req, res) => {
  const deviceSessionId = Number(req.params.id);
  const device = listDeviceSessions(req.mobileAuth.user.id).find((item) => item.id === deviceSessionId);
  if (!device) return res.status(404).json({ error: '设备不存在' });
  revokeDeviceSession(deviceSessionId);
  audit({
    userId: req.mobileAuth.user.id,
    type: 'mobile_device_revoked',
    details: { deviceSessionId },
    req
  });
  res.json({ ok: true });
});

router.get('/api/mobile/v1/targets', requireMobileAuth, (req, res) => {
  res.json({
    targets: [
      ...getAllowedTargets(req.mobileAuth.user.id),
      ...privateRelay.getAllowedEndpoints(req.mobileAuth.user.id)
    ]
  });
});

router.post('/api/mobile/v1/terminal/tickets', requireMobileAuth, (req, res) => {
  const targetId = Number(req.body?.targetId);
  const targetKind = req.body?.targetKind === 'private' ? 'private' : 'ssh';
  const expiresAt = new Date(Date.now() + config.ticketTtlSeconds * 1000).toISOString();

  if (targetKind === 'private') {
    const endpoint = privateRelay.getAllowedEndpoint(req.mobileAuth.user.id, targetId);
    if (!endpoint) return res.status(403).json({ error: '没有该私有终端的连接权限' });
    if (!privateRelay.onlineEndpointIds().has(endpoint.id)) {
      return res.status(409).json({ error: '私有终端 Agent 不在线' });
    }
    const ticket = privateRelay.createTerminalTicket({
      userId: req.mobileAuth.user.id,
      endpointId: endpoint.id,
      accessLinkId: req.mobileAuth.session.accessLinkId,
      channel: 'mobile',
      expiresAt
    });
    audit({
      userId: req.mobileAuth.user.id,
      type: 'mobile_private_terminal_ticket_created',
      details: { endpointId: endpoint.id, deviceSessionId: req.mobileAuth.session.id },
      req
    });
    return res.json({
      ticket,
      expiresAt,
      webSocketPath: `${config.basePath}ws/mobile/v1/terminal`,
      protocol: 'TLTP/1'
    });
  }

  const target = getAllowedTarget(req.mobileAuth.user.id, targetId);
  if (!target) return res.status(403).json({ error: '没有该目标的连接权限' });

  const ticket = randomToken(36);
  db.prepare(`
    INSERT INTO terminal_tickets (
      ticket_hash, user_id, target_id, access_link_id, channel, expires_at, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    hashToken(ticket),
    req.mobileAuth.user.id,
    target.id,
    req.mobileAuth.session.accessLinkId,
    'mobile',
    expiresAt,
    nowIso()
  );

  audit({
    userId: req.mobileAuth.user.id,
    type: 'mobile_terminal_ticket_created',
    details: { targetId: target.id, deviceSessionId: req.mobileAuth.session.id },
    req
  });

  res.json({
    ticket,
    expiresAt,
    webSocketPath: `${config.basePath}ws/mobile/v1/terminal`,
    protocol: 'TLTP/1'
  });
});

router.get('/api/mobile/v1/terminal/sessions', requireMobileAuth, (req, res) => {
  const sessions = [];
  for (const session of mobileTerminalSessions.values()) {
    if (!canUseMobileManagedTerminal(session, req.mobileAuth)) continue;
    sessions.push(session.publicInfo());
  }
  res.json({ sessions });
});

router.post('/api/mobile/v1/terminal/sessions/:id/tickets', requireMobileAuth, (req, res) => {
  const sessionId = String(req.params.id || '');
  const session = mobileTerminalSessions.get(sessionId);
  if (!session || !canUseMobileManagedTerminal(session, req.mobileAuth)) {
    return res.status(404).json({ error: '移动终端会话不存在或无权恢复' });
  }

  const ticket = randomToken(36);
  const expiresAt = new Date(Date.now() + config.ticketTtlSeconds * 1000).toISOString();
  mobileTerminalResumeTickets.set(hashToken(ticket), {
    userId: req.mobileAuth.user.id,
    deviceSessionId: req.mobileAuth.session.id,
    sessionId,
    expiresAt
  });
  audit({
    userId: req.mobileAuth.user.id,
    type: 'mobile_terminal_resume_ticket_created',
    details: { sessionId, targetId: session.targetId },
    req
  });
  res.json({
    ticket,
    expiresAt,
    webSocketPath: `${config.basePath}ws/mobile/v1/terminal`,
    protocol: 'TLTP/1',
    session: session.publicInfo()
  });
});

router.post('/api/mobile/v1/terminal/sessions/:id/close', requireMobileAuth, (req, res) => {
  const sessionId = String(req.params.id || '');
  const session = mobileTerminalSessions.get(sessionId);
  if (!session || !canUseMobileManagedTerminal(session, req.mobileAuth)) {
    return res.status(404).json({ error: '移动终端会话不存在或无权关闭' });
  }
  session.close(1000, 'mobile session closed');
  audit({
    userId: req.mobileAuth.user.id,
    type: 'mobile_terminal_session_closed',
    details: { sessionId, targetId: session.targetId },
    req
  });
  res.json({ ok: true });
});

router.get('/api/me', (req, res) => {
  const auth = authenticateRequest(req);
  if (!auth) return res.json({ authenticated: false });
  res.json({
    authenticated: true,
    user: sanitizeUser(auth.user),
    accessLinkId: auth.session.access_link_id,
    features: {
      privateRelay: privateRelay.enabled
    }
  });
});

router.post('/api/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(req.auth.session.id);
  audit({ userId: req.auth.user.id, type: 'logout', req });
  clearSessionCookie(res);
  res.json({ ok: true });
});

router.get('/api/access/:token', (req, res) => {
  const link = getAccessLinkByToken(req.params.token);
  if (!isAccessLinkUsable(link)) {
    return res.status(404).json({ error: '访问链接无效或已失效' });
  }

  const auth = authenticateRequest(req);
  const authenticated = Boolean(auth && auth.user.id === link.user_id);
  res.json({
    username: link.username,
    displayName: link.display_name,
    authenticated,
    totpEnabled: Boolean(link.totp_enabled)
  });
});

router.post('/api/access/:token/login', (req, res) => {
  const link = getAccessLinkByToken(req.params.token);
  if (!isAccessLinkUsable(link)) {
    return res.status(404).json({ error: '访问链接无效或已失效' });
  }
  if (!allowLoginAttempt(req)) {
    return res.status(429).json({ error: '登录尝试过多，请稍后再试' });
  }

  const password = String(req.body?.password || '');
  const totpCode = String(req.body?.totpCode || '');
  if (!password || !verifyPassword(password, link.password_hash)) {
    audit({ userId: link.user_id, type: 'login_failed', details: { reason: 'password' }, req });
    return res.status(401).json({ error: '登录失败' });
  }

  if (!link.totp_enabled) {
    return createMfaEnrollmentResponse(req, res, link);
  }

  const totpSecret = decryptSecret(link.totp_secret, config.secretKey);
  if (!verifyTotp(totpCode, totpSecret)) {
    audit({ userId: link.user_id, type: 'login_failed', details: { reason: 'totp' }, req });
    return res.status(401).json({ error: '双因子验证码无效' });
  }

  const session = createSession(link);
  db.prepare('UPDATE access_links SET used_count = used_count + 1 WHERE id = ?').run(link.id);
  audit({ userId: link.user_id, type: 'login_success', details: { accessLinkId: link.id }, req });
  setSessionCookie(res, session.token);
  res.json({ ok: true, user: sanitizeUser(getUserById(link.user_id)) });
});

router.post('/api/access/:token/mfa/setup/verify', (req, res) => {
  const link = getAccessLinkByToken(req.params.token);
  if (!isAccessLinkUsable(link)) {
    return res.status(404).json({ error: '访问链接无效或已失效' });
  }
  const challenge = String(req.body?.challenge || '');
  const code = String(req.body?.totpCode || '');
  const enrollment = db.prepare(`
    SELECT * FROM mfa_enrollments
    WHERE challenge_hash = ? AND user_id = ? AND access_link_id = ?
  `).get(hashToken(challenge), link.user_id, link.id);

  if (!enrollment || new Date(enrollment.expires_at).getTime() <= Date.now()) {
    return res.status(401).json({ error: '双因子设置会话已过期' });
  }

  const secret = decryptSecret(enrollment.encrypted_secret, config.secretKey);
  if (!verifyTotp(code, secret)) {
    audit({ userId: link.user_id, type: 'mfa_setup_failed', req });
    return res.status(401).json({ error: '双因子验证码无效' });
  }

  const encryptedSecret = encryptSecret(secret, config.secretKey);
  db.prepare(`
    UPDATE users
    SET totp_secret = ?, totp_enabled = 1, updated_at = ?
    WHERE id = ?
  `).run(encryptedSecret, nowIso(), link.user_id);
  db.prepare('DELETE FROM mfa_enrollments WHERE user_id = ?').run(link.user_id);
  db.prepare('UPDATE access_links SET used_count = used_count + 1 WHERE id = ?').run(link.id);

  const session = createSession(link);
  audit({ userId: link.user_id, type: 'mfa_setup_success', req });
  setSessionCookie(res, session.token);
  res.json({ ok: true, user: sanitizeUser(getUserById(link.user_id)) });
});

router.get('/api/launch/:token', requireAuth, (req, res) => {
  const link = getAccessLinkByToken(req.params.token);
  if (!isAccessLinkUsable(link) || link.user_id !== req.auth.user.id) {
    return res.status(403).json({ error: '访问链接和登录用户不匹配' });
  }
  res.json({
    user: sanitizeUser(req.auth.user),
    targets: [
      ...getAllowedTargets(req.auth.user.id),
      ...privateRelay.getAllowedEndpoints(req.auth.user.id)
    ]
  });
});

router.post('/api/terminal/tickets', requireAuth, (req, res) => {
  const accessToken = String(req.body?.accessToken || '');
  const targetId = Number(req.body?.targetId);
  const targetKind = req.body?.targetKind === 'private' ? 'private' : 'ssh';
  const link = getAccessLinkByToken(accessToken);
  if (!isAccessLinkUsable(link) || link.user_id !== req.auth.user.id) {
    return res.status(403).json({ error: '访问链接无效' });
  }

  if (targetKind === 'private') {
    const endpoint = privateRelay.getAllowedEndpoint(req.auth.user.id, targetId);
    if (!endpoint) return res.status(403).json({ error: '没有该私有终端的连接权限' });
    if (!privateRelay.onlineEndpointIds().has(endpoint.id)) {
      return res.status(409).json({ error: '私有终端 Agent 不在线' });
    }
    const expiresAt = new Date(Date.now() + config.ticketTtlSeconds * 1000).toISOString();
    const ticket = privateRelay.createTerminalTicket({
      userId: req.auth.user.id,
      endpointId: endpoint.id,
      accessLinkId: link.id,
      expiresAt
    });
    audit({
      userId: req.auth.user.id,
      type: 'private_terminal_ticket_created',
      details: { endpointId: endpoint.id, accessLinkId: link.id },
      req
    });
    return res.json({
      ticket,
      terminalUrl: `${config.basePath}terminal?ticket=${encodeURIComponent(ticket)}`
    });
  }

  const target = getAllowedTarget(req.auth.user.id, targetId);
  if (!target) return res.status(403).json({ error: '没有该目标的连接权限' });

  const ticket = randomToken(36);
  const expiresAt = new Date(Date.now() + config.ticketTtlSeconds * 1000).toISOString();
  db.prepare(`
    INSERT INTO terminal_tickets (ticket_hash, user_id, target_id, access_link_id, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(hashToken(ticket), req.auth.user.id, target.id, link.id, expiresAt, nowIso());

  audit({
    userId: req.auth.user.id,
    type: 'terminal_ticket_created',
    details: { targetId: target.id, accessLinkId: link.id },
    req
  });

  res.json({
    ticket,
    terminalUrl: `${config.basePath}terminal?ticket=${encodeURIComponent(ticket)}`
  });
});

router.get('/api/terminal/tickets/:ticket', requireAuth, (req, res) => {
  const context = findTerminalTicketContext(req.params.ticket, req.auth.user.id);
  if (!context || !isTicketFresh(context.ticket)) {
    return res.status(404).json({ error: '终端票据无效或已过期' });
  }
  res.json({
    target: context.publicTarget,
    expiresAt: context.ticket.expires_at
  });
});

router.get('/api/admin/users', requireAdmin, (_req, res) => {
  const users = db.prepare('SELECT * FROM users ORDER BY id ASC').all().map(sanitizeUser);
  const links = db.prepare(`
    SELECT id, user_id, label, expires_at, max_uses, used_count, disabled, created_at
    FROM access_links
    ORDER BY created_at DESC
  `).all();
  res.json({ users, links });
});

router.get('/api/admin/settings/terminal', requireAdmin, (_req, res) => {
  res.json({ settings: terminalSettingsStore.get({ force: true }) });
});

router.put('/api/admin/settings/terminal', requireAdmin, (req, res) => {
  const settings = terminalSettingsStore.set(req.body || {});
  audit({ userId: req.auth.user.id, type: 'admin_terminal_settings_updated', details: settings, req });
  res.json({ settings });
});

router.post('/api/admin/users', requireAdmin, (req, res) => {
  const username = cleanIdentifier(req.body?.username);
  const displayName = String(req.body?.displayName || '').trim();
  const role = req.body?.role === 'admin' ? 'admin' : 'user';
  const password = String(req.body?.password || '');
  if (!username || password.length < 12) {
    return res.status(400).json({ error: '用户名必填，初始密码至少 12 位' });
  }
  if (getUserByUsername(username)) {
    return res.status(409).json({ error: '用户已存在' });
  }
  const user = createUser({ username, displayName, role, password });
  const accessLink = createAccessLink({ userId: user.id, label: 'default', createdBy: req.auth.user.id });
  audit({ userId: req.auth.user.id, type: 'admin_user_created', details: { userId: user.id }, req });
  res.status(201).json({
    user: sanitizeUser(user),
    accessUrl: absoluteAppUrl(`access/${accessLink.token}`)
  });
});

router.post('/api/admin/users/:id/password', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const password = String(req.body?.password || '');
  if (password.length < 12) return res.status(400).json({ error: '新密码至少 12 位' });
  db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?')
    .run(hashPassword(password), nowIso(), userId);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  audit({ userId: req.auth.user.id, type: 'admin_password_reset', details: { userId }, req });
  res.json({ ok: true });
});

router.post('/api/admin/users/:id/totp/reset', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  db.prepare(`
    UPDATE users SET totp_secret = '', totp_enabled = 0, updated_at = ? WHERE id = ?
  `).run(nowIso(), userId);
  db.prepare('DELETE FROM mfa_enrollments WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  audit({ userId: req.auth.user.id, type: 'admin_totp_reset', details: { userId }, req });
  res.json({ ok: true });
});

router.post('/api/admin/users/:id/disabled', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const disabled = req.body?.disabled ? 1 : 0;
  db.prepare('UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?').run(disabled, nowIso(), userId);
  if (disabled) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  audit({ userId: req.auth.user.id, type: 'admin_user_disabled_changed', details: { userId, disabled }, req });
  res.json({ ok: true });
});

router.post('/api/admin/users/:id/access-links', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const user = getUserById(userId);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const label = String(req.body?.label || 'manual').trim();
  const accessLink = createAccessLink({ userId, label, createdBy: req.auth.user.id });
  audit({ userId: req.auth.user.id, type: 'admin_access_link_created', details: { userId }, req });
  res.status(201).json({ accessUrl: absoluteAppUrl(`access/${accessLink.token}`) });
});

router.get('/api/admin/targets', requireAdmin, (_req, res) => {
  const targets = db.prepare('SELECT * FROM ssh_targets ORDER BY id ASC').all().map(publicTarget);
  res.json({ targets });
});

router.post('/api/admin/targets', requireAdmin, (req, res) => {
  const name = String(req.body?.name || '').trim();
  const host = String(req.body?.host || '').trim();
  const port = Number(req.body?.port || 22);
  const sshUsername = cleanIdentifier(req.body?.sshUsername);
  if (!name || !host || !sshUsername || !Number.isInteger(port) || port < 1 || port > 65535) {
    return res.status(400).json({ error: '目标名称、Host、端口和 SSH 用户必填' });
  }
  const now = nowIso();
  const result = db.prepare(`
    INSERT INTO ssh_targets (name, host, port, ssh_username, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(name, host, port, sshUsername, now, now);
  const target = db.prepare('SELECT * FROM ssh_targets WHERE id = ?').get(Number(result.lastInsertRowid));
  audit({ userId: req.auth.user.id, type: 'admin_target_created', details: { targetId: target.id }, req });
  res.status(201).json({ target: publicTarget(target) });
});

router.post('/api/admin/targets/:id/disabled', requireAdmin, (req, res) => {
  const targetId = Number(req.params.id);
  const disabled = req.body?.disabled ? 1 : 0;
  db.prepare('UPDATE ssh_targets SET disabled = ?, updated_at = ? WHERE id = ?')
    .run(disabled, nowIso(), targetId);
  audit({ userId: req.auth.user.id, type: 'admin_target_disabled_changed', details: { targetId, disabled }, req });
  res.json({ ok: true });
});

router.put('/api/admin/targets/:id/host-key', requireAdmin, (req, res) => {
  const targetId = Number(req.params.id);
  const target = db.prepare('SELECT * FROM ssh_targets WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: '目标不存在' });
  let input;
  try {
    input = normalizeHostKeyUpdate(req.body || {});
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  db.prepare(`
    UPDATE ssh_targets
    SET host_key_policy = ?, host_key_type = ?,
      host_key_fingerprint_sha256 = ?, updated_at = ?
    WHERE id = ?
  `).run(input.policy, input.keyType, input.fingerprintSha256, nowIso(), target.id);
  audit({
    userId: req.auth.user.id,
    type: 'admin_target_host_key_updated',
    details: { targetId: target.id, policy: input.policy },
    req
  });
  res.json({ target: publicTarget(db.prepare('SELECT * FROM ssh_targets WHERE id = ?').get(target.id)) });
});

router.get('/api/admin/users/:id/permissions', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const targetIds = db.prepare('SELECT target_id FROM user_target_permissions WHERE user_id = ?')
    .all(userId)
    .map((row) => row.target_id);
  res.json({ targetIds });
});

router.put('/api/admin/users/:id/permissions', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const targetIds = Array.isArray(req.body?.targetIds)
    ? req.body.targetIds.map(Number).filter(Number.isInteger)
    : [];
  const now = nowIso();
  db.exec('BEGIN');
  try {
    db.prepare('DELETE FROM user_target_permissions WHERE user_id = ?').run(userId);
    const insert = db.prepare(`
      INSERT OR IGNORE INTO user_target_permissions (user_id, target_id, created_at)
      VALUES (?, ?, ?)
    `);
    for (const targetId of targetIds) insert.run(userId, targetId, now);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  audit({ userId: req.auth.user.id, type: 'admin_permissions_updated', details: { userId, targetIds }, req });
  res.json({ ok: true });
});

privateRelay.installRoutes(router, { requireAuth, requireAdmin });

if (fs.existsSync(config.distDir)) {
  router.use(express.static(config.distDir, { index: false, maxAge: '1h', redirect: false }));
}

router.get(/.*/, (_req, res) => {
  const indexPath = path.join(config.distDir, 'index.html');
  if (!fs.existsSync(indexPath)) {
    return res.status(503).send('TermLens frontend has not been built yet.');
  }
  res.sendFile(indexPath);
});

server.on('upgrade', (req, socket, head) => {
  if (privateRelay.handleAgentUpgrade(req, socket, head)) return;

  const url = new URL(req.url || '/', 'http://localhost');
  if (url.pathname === `${mountPath}/ws/mobile/v1/terminal`) {
    const auth = authenticateMobileRequest(req);
    if (!auth) {
      rejectUpgrade(req, socket, 401, 'Mobile access token is required.');
      return;
    }
    if (firstHeader(req.headers['x-termlane-protocol']) !== '1') {
      rejectUpgrade(req, socket, 426, 'TLTP/1 is required.', auth.user.id, { reason: 'protocol_required' });
      return;
    }
    const ticketToken = firstHeader(req.headers['x-termlane-ticket']);
    const resumeContext = findMobileTerminalResumeContext(ticketToken, auth);
    if (resumeContext) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req, { auth, ...resumeContext, mobile: true });
      });
      return;
    }

    const context = findTerminalTicketContext(ticketToken, auth.user.id, 'mobile');
    if (!context || !isTicketFresh(context.ticket) || context.ticket.channel !== 'mobile') {
      rejectUpgrade(req, socket, 403, 'Terminal ticket is invalid, used, or expired.', auth.user.id, {
        reason: 'invalid_mobile_ticket'
      });
      return;
    }
    if (context.kind === 'ssh') {
      db.prepare('UPDATE terminal_tickets SET used_at = ? WHERE id = ?').run(nowIso(), context.ticket.id);
    } else {
      privateRelay.markTicketUsed(context.ticket.id);
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req, { auth, ...context, mobile: true });
    });
    return;
  }

  if (url.pathname !== `${mountPath}/ws/terminal`) {
    rejectUpgrade(req, socket, 404, 'Unknown WebSocket endpoint.');
    return;
  }

  const auth = authenticateRequest(req);
  if (!auth) {
    rejectUpgrade(req, socket, 401, 'Login session is required.');
    return;
  }

  const ticketToken = url.searchParams.get('ticket') || '';
  const context = findTerminalTicketContext(ticketToken, auth.user.id, 'browser');
  if (!context || !isTicketFresh(context.ticket) || context.ticket.channel === 'mobile') {
    rejectUpgrade(req, socket, 403, 'Terminal ticket is invalid, used, or expired.', auth.user.id, {
      reason: 'invalid_ticket'
    });
    return;
  }
  if (context.kind === 'ssh') {
    db.prepare('UPDATE terminal_tickets SET used_at = ? WHERE id = ?').run(nowIso(), context.ticket.id);
  } else {
    privateRelay.markTicketUsed(context.ticket.id);
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req, { auth, ...context });
  });
});

wss.on('connection', (ws, req, context) => {
  handleTerminalSocket(ws, req, context);
});

server.listen(config.port, config.host, () => {
  console.log(`TermLens listening on http://${config.host}:${config.port}${config.basePath}`);
});

function requireTrustedOrigin(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (!origin) return next();
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const expected = `${proto}://${host}`;
  if (origin !== expected) {
    return res.status(403).json({ error: '请求来源无效' });
  }
  next();
}

function authenticateRequest(req) {
  const token = parseCookies(req.headers.cookie || '').get(config.cookieName);
  if (!token) return null;
  const session = db.prepare(`
    SELECT sessions.*, users.username, users.display_name, users.role, users.disabled,
      users.totp_enabled, users.created_at AS user_created_at, users.updated_at AS user_updated_at
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).get(hashToken(token));
  if (!session || session.disabled || new Date(session.expires_at).getTime() <= Date.now()) {
    return null;
  }
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(nowIso(), session.id);
  return {
    session,
    user: {
      id: session.user_id,
      username: session.username,
      display_name: session.display_name,
      role: session.role,
      disabled: session.disabled,
      totp_enabled: session.totp_enabled,
      created_at: session.user_created_at,
      updated_at: session.user_updated_at
    }
  };
}

function authenticateMobileRequest(req) {
  const token = bearerToken(req.headers.authorization);
  const access = findMobileAccessToken(token);
  if (!access) return null;
  return {
    session: {
      id: access.device_session_id,
      accessLinkId: access.access_link_id,
      deviceName: access.device_name,
      clientVersion: access.client_version
    },
    user: {
      id: access.user_id,
      username: access.username,
      display_name: access.display_name,
      role: access.role,
      disabled: access.user_disabled,
      totp_enabled: access.totp_enabled
    }
  };
}

function requireAuth(req, res, next) {
  const auth = authenticateRequest(req);
  if (!auth) return res.status(401).json({ error: '需要登录' });
  req.auth = auth;
  next();
}

function requireMobileAuth(req, res, next) {
  const auth = authenticateMobileRequest(req);
  if (!auth) return res.status(401).json({ error: '需要移动端登录' });
  req.mobileAuth = auth;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.auth.user.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
    next();
  });
}

async function createMfaEnrollmentResponse(req, res, link) {
  const { secret, otpauthUrl } = createTotpSecret(link.username);
  const challenge = randomToken(24);
  const expiresAt = new Date(Date.now() + config.mfaEnrollmentTtlSeconds * 1000).toISOString();
  db.prepare('DELETE FROM mfa_enrollments WHERE user_id = ?').run(link.user_id);
  db.prepare(`
    INSERT INTO mfa_enrollments (challenge_hash, user_id, access_link_id, encrypted_secret, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(hashToken(challenge), link.user_id, link.id, encryptSecret(secret, config.secretKey), expiresAt, nowIso());
  audit({ userId: link.user_id, type: 'mfa_setup_started', req });
  res.json({
    mfaSetupRequired: true,
    challenge,
    qrDataUrl: await QRCode.toDataURL(otpauthUrl, { margin: 1, width: 220 }),
    expiresAt
  });
}

function createSession(link) {
  const token = randomToken(36);
  const now = nowIso();
  const expiresAt = new Date(Date.now() + config.sessionTtlSeconds * 1000).toISOString();
  const result = db.prepare(`
    INSERT INTO sessions (token_hash, user_id, access_link_id, expires_at, last_seen_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(hashToken(token), link.user_id, link.id, expiresAt, now, now);
  return { id: Number(result.lastInsertRowid), token, expiresAt };
}

function setSessionCookie(res, token) {
  const parts = [
    `${config.cookieName}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Strict',
    `Path=${config.basePath}`,
    `Max-Age=${config.sessionTtlSeconds}`
  ];
  if (config.cookieSecure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res) {
  const parts = [
    `${config.cookieName}=`,
    'HttpOnly',
    'SameSite=Strict',
    `Path=${config.basePath}`,
    'Max-Age=0'
  ];
  if (config.cookieSecure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function allowLoginAttempt(req) {
  const key = `${req.ip}:${req.params.token}`;
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const current = loginAttempts.get(key) || [];
  const recent = current.filter((time) => now - time < windowMs);
  recent.push(now);
  loginAttempts.set(key, recent);
  return recent.length <= 12;
}

function cleanIdentifier(value) {
  const text = String(value || '').trim();
  return /^[a-zA-Z0-9._-]{1,64}$/.test(text) ? text : '';
}

function absoluteAppUrl(relativePath) {
  const clean = relativePath.replace(/^\/+/, '');
  if (config.publicUrl) return new URL(clean, config.publicUrl).toString();
  return `${config.basePath}${clean}`;
}

function getAllowedTargets(userId) {
  return db.prepare(`
    SELECT ssh_targets.*
    FROM ssh_targets
    JOIN user_target_permissions ON user_target_permissions.target_id = ssh_targets.id
    WHERE user_target_permissions.user_id = ? AND ssh_targets.disabled = 0
    ORDER BY ssh_targets.id ASC
  `).all(userId).map(publicTarget);
}

function getAllowedTarget(userId, targetId) {
  return db.prepare(`
    SELECT ssh_targets.*
    FROM ssh_targets
    JOIN user_target_permissions ON user_target_permissions.target_id = ssh_targets.id
    WHERE user_target_permissions.user_id = ? AND ssh_targets.id = ? AND ssh_targets.disabled = 0
  `).get(userId, targetId);
}

function publicTarget(row) {
  return {
    kind: 'ssh',
    id: row.id,
    name: row.name,
    host: row.host,
    port: row.port,
    sshUsername: row.ssh_username,
    hostKeyPolicy: row.host_key_policy || 'strict',
    hostKeyType: row.host_key_type || '',
    hostKeyFingerprintSha256: row.host_key_fingerprint_sha256 || '',
    allowedAuthMethods: parseAllowedAuthMethods(row.allowed_auth_methods),
    defaultTerm: row.default_term || 'xterm-256color',
    disabled: Boolean(row.disabled),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function findTicket(ticketToken) {
  if (!ticketToken) return null;
  return db.prepare('SELECT * FROM terminal_tickets WHERE ticket_hash = ?').get(hashToken(ticketToken));
}

function findTerminalTicketContext(ticketToken, userId, channel = '') {
  const ticket = findTicket(ticketToken);
  if (ticket && ticket.user_id === userId) {
    if (channel && ticket.channel !== channel) return null;
    const target = getAllowedTarget(userId, ticket.target_id);
    if (!target) return null;
    return {
      kind: 'ssh',
      ticket,
      target,
      publicTarget: publicTarget(target)
    };
  }

  const privateTicket = privateRelay.findTerminalTicket(ticketToken);
  if (privateTicket && privateTicket.user_id === userId) {
    if (channel && privateTicket.channel !== channel) return null;
    const endpoint = privateRelay.getAllowedEndpoint(userId, privateTicket.endpoint_id);
    if (!endpoint) return null;
    return {
      kind: 'private',
      ticket: privateTicket,
      target: endpoint,
      publicTarget: privateRelay.publicEndpoint(endpoint)
    };
  }

  return null;
}

function isTicketFresh(ticket) {
  return ticket && !ticket.used_at && new Date(ticket.expires_at).getTime() > Date.now();
}

function findMobileTerminalResumeContext(ticketToken, auth) {
  if (!ticketToken || !auth) return null;
  const ticketHash = hashToken(ticketToken);
  const entry = mobileTerminalResumeTickets.get(ticketHash);
  mobileTerminalResumeTickets.delete(ticketHash);
  if (!entry || entry.userId !== auth.user.id || entry.deviceSessionId !== auth.session.id) return null;
  if (new Date(entry.expiresAt).getTime() <= Date.now()) return null;
  const session = mobileTerminalSessions.get(entry.sessionId);
  if (!session || !canUseMobileManagedTerminal(session, auth)) return null;
  return {
    kind: session.kind,
    target: session.target,
    publicTarget: session.publicTarget,
    resumeSessionId: session.id
  };
}

function canUseMobileManagedTerminal(session, auth) {
  if (!session || session.closed || !auth) return false;
  if (session.userId !== auth.user.id || session.deviceSessionId !== auth.session.id) return false;
  return canUseMobileSshTerminal(
    auth.user.id,
    session.accessLinkId,
    session.targetId,
    auth.session.id
  );
}

function sweepDetachedMobileTerminalSessions() {
  const now = Date.now();
  for (const [ticketHash, ticket] of mobileTerminalResumeTickets.entries()) {
    if (new Date(ticket.expiresAt).getTime() <= now) {
      mobileTerminalResumeTickets.delete(ticketHash);
    }
  }
  for (const session of mobileTerminalSessions.values()) {
    if (!session.attached && now - session.detachedAt >= MOBILE_TERMINAL_DETACHED_TTL_MS) {
      session.close(4000, 'detached session expired');
    }
  }
}

setInterval(sweepDetachedMobileTerminalSessions, 60_000).unref?.();

class MobileManagedTerminalSession {
  constructor({ auth, target, publicTarget, ticket, size, req }) {
    this.id = `s_${randomToken(18)}`;
    this.kind = 'ssh';
    this.userId = auth.user.id;
    this.deviceSessionId = auth.session.id;
    this.accessLinkId = ticket.access_link_id;
    this.targetId = target.id;
    this.target = target;
    this.publicTarget = publicTarget;
    this.size = size;
    this.req = req;
    this.ssh = null;
    this.stream = null;
    this.ws = null;
    this.ready = false;
    this.closed = false;
    this.attached = false;
    this.detachedAt = Date.now();
    this.createdAt = nowIso();
    this.updatedAt = this.createdAt;
    this.closedAt = '';
    this.hostKey = null;
    this.backlog = [];
    this.backlogBytes = 0;
  }

  publicInfo() {
    return {
      id: this.id,
      kind: this.kind,
      targetId: this.targetId,
      targetKind: this.publicTarget?.kind || this.kind,
      targetName: this.publicTarget?.name || this.target.name || '',
      host: this.publicTarget?.host || this.target.host || '',
      port: this.publicTarget?.port || this.target.port || 22,
      sshUsername: this.publicTarget?.sshUsername || this.target.ssh_username || '',
      attached: this.attached,
      ready: this.ready,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };
  }

  attach(ws) {
    if (this.closed) return false;
    if (this.ws && this.ws.readyState === WebSocket.OPEN && this.ws !== ws) {
      this.ws.close(4001, 'terminal attached elsewhere');
    }
    this.ws = ws;
    this.attached = true;
    this.updatedAt = nowIso();
    if (this.ready) {
      this.sendReady();
      this.replayBacklog();
    }
    return true;
  }

  markReady({ ssh, stream, hostKey }) {
    this.ssh = ssh;
    this.stream = stream;
    this.hostKey = hostKey || null;
    this.ready = true;
    this.updatedAt = nowIso();
    this.sendReady();
  }

  sendReady() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    sendTerminalJson(this.ws, {
      type: 'ready',
      version: 1,
      sessionId: this.id,
      targetId: this.targetId,
      targetKind: this.publicTarget?.kind || this.kind,
      hostKey: this.hostKey || undefined,
      capabilities: {
        binaryData: true,
        resize: true,
        resume: true,
        replay: true
      }
    });
  }

  accept(data) {
    if (this.closed) return;
    const buffer = Buffer.from(data);
    this.backlog.push(buffer);
    this.backlogBytes += buffer.length;
    while (this.backlogBytes > MOBILE_TERMINAL_REPLAY_LIMIT_BYTES && this.backlog.length > 0) {
      this.backlogBytes -= this.backlog.shift().length;
    }
    this.updatedAt = nowIso();
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      sendTerminalData(this.ws, true, buffer);
    }
  }

  replayBacklog() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    for (const buffer of this.backlog) {
      sendTerminalData(this.ws, true, buffer);
    }
  }

  write(data) {
    if (this.closed || !this.stream) return;
    this.stream.write(Buffer.from(data));
    this.updatedAt = nowIso();
  }

  resize(size) {
    this.size = size;
    this.updatedAt = nowIso();
    if (this.stream) {
      this.stream.setWindow(size.rows, size.cols, 0, 0);
    }
  }

  detach(ws) {
    if (this.ws !== ws) return;
    this.ws = null;
    this.attached = false;
    this.detachedAt = Date.now();
    this.updatedAt = nowIso();
  }

  remoteClosed() {
    if (this.closed) return;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      sendTerminalJson(this.ws, { type: 'closed', version: 1, sessionId: this.id });
      this.ws.close(1000, 'ssh closed');
    }
    this.close(1000, 'ssh closed');
  }

  close(code = 1000, reason = 'session closed') {
    if (this.closed) return;
    this.closed = true;
    this.closedAt = nowIso();
    mobileTerminalSessions.delete(this.id);
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      sendTerminalJson(this.ws, { type: 'closed', version: 1, sessionId: this.id });
      this.ws.close(code, reason);
    }
    if (this.stream) {
      this.stream.end();
    }
    if (this.ssh) {
      this.ssh.end();
    }
    this.ws = null;
    this.stream = null;
    this.ssh = null;
  }
}

function rejectUpgrade(req, socket, statusCode, message, userId = null, details = {}) {
  audit({
    userId,
    type: 'terminal_upgrade_rejected',
    details: {
      ...details,
      statusCode,
      path: req.url || ''
    },
    req
  });
  const body = `${message}\n`;
  socket.write(
    `HTTP/1.1 ${statusCode} ${message}\r\n` +
      'Connection: close\r\n' +
      'Content-Type: text/plain; charset=utf-8\r\n' +
      `Content-Length: ${Buffer.byteLength(body)}\r\n` +
      '\r\n' +
      body
  );
  socket.destroy();
}

function canUseSshTerminal(sessionId, userId, accessLinkId, targetId) {
  const now = nowIso();
  const session = db.prepare(`
    SELECT sessions.id
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    JOIN access_links AS session_link ON session_link.id = sessions.access_link_id
    JOIN access_links AS ticket_link ON ticket_link.id = ?
    JOIN user_target_permissions ON user_target_permissions.user_id = sessions.user_id
    JOIN ssh_targets ON ssh_targets.id = user_target_permissions.target_id
    WHERE sessions.id = ?
      AND sessions.user_id = ?
      AND ticket_link.user_id = sessions.user_id
      AND user_target_permissions.target_id = ?
      AND sessions.expires_at > ?
      AND users.disabled = 0
      AND session_link.disabled = 0
      AND ticket_link.disabled = 0
      AND (ticket_link.expires_at IS NULL OR ticket_link.expires_at > ?)
      AND ssh_targets.disabled = 0
  `).get(accessLinkId, sessionId, userId, targetId, now, now);
  return Boolean(session);
}

function canUseMobileSshTerminal(userId, accessLinkId, targetId, deviceSessionId) {
  const now = nowIso();
  const access = db.prepare(`
    SELECT device_sessions.id
    FROM device_sessions
    JOIN users ON users.id = device_sessions.user_id
    JOIN access_links AS device_link ON device_link.id = device_sessions.access_link_id
    JOIN access_links AS ticket_link ON ticket_link.id = ?
    JOIN user_target_permissions ON user_target_permissions.user_id = device_sessions.user_id
    JOIN ssh_targets ON ssh_targets.id = user_target_permissions.target_id
    WHERE device_sessions.id = ?
      AND device_sessions.user_id = ?
      AND ticket_link.user_id = device_sessions.user_id
      AND user_target_permissions.target_id = ?
      AND device_sessions.revoked_at IS NULL
      AND device_sessions.refresh_expires_at > ?
      AND users.disabled = 0
      AND device_link.disabled = 0
      AND ticket_link.disabled = 0
      AND (ticket_link.expires_at IS NULL OR ticket_link.expires_at > ?)
      AND ssh_targets.disabled = 0
  `).get(accessLinkId, deviceSessionId, userId, targetId, now, now);
  return Boolean(access);
}

function sendTerminalJson(ws, message) {
  const clean = Object.fromEntries(Object.entries(message).filter(([, value]) => value !== undefined));
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(clean));
}

function sendTerminalData(ws, mobile, data) {
  if (ws.readyState !== WebSocket.OPEN) return;
  if (mobile) {
    ws.send(Buffer.from(data));
  } else {
    ws.send(JSON.stringify({ type: 'data', data: data.toString('utf8') }));
  }
}

function hostKeyErrorMessage(code) {
  if (code === 'host_key_unknown') return 'SSH host key is not enrolled.';
  if (code === 'host_key_changed') return 'SSH host key changed.';
  return '';
}

function handleTerminalSocket(ws, req, { auth, kind, ticket, target, mobile = false, resumeSessionId = '' }) {
  let ssh = null;
  let stream = null;
  let connected = false;
  let closing = false;
  let managedMobileSession = null;
  let size = { cols: 100, rows: 30 };
  let lastTerminalActivityAt = Date.now();
  let lastSessionRenewedAt = 0;

  if (mobile && resumeSessionId) {
    managedMobileSession = mobileTerminalSessions.get(resumeSessionId) || null;
    if (!managedMobileSession || !canUseMobileManagedTerminal(managedMobileSession, auth)) {
      sendTerminalJson(ws, {
        type: 'error',
        version: 1,
        code: 'session_expired',
        message: 'Mobile terminal session is unavailable.'
      });
      ws.close(4004, 'mobile terminal session unavailable');
      return;
    }
    connected = true;
    size = managedMobileSession.size;
    managedMobileSession.attach(ws);
  }

  const canUseCurrentTerminal = () => {
    if (managedMobileSession) {
      return canUseMobileManagedTerminal(managedMobileSession, auth);
    }
    if (mobile) {
      return kind === 'private'
        ? privateRelay.canUseMobileTerminal(auth.user.id, ticket.access_link_id, target.id, auth.session.id)
        : canUseMobileSshTerminal(auth.user.id, ticket.access_link_id, target.id, auth.session.id);
    }
    return kind === 'private'
      ? privateRelay.canUseTerminal(auth.session.id, auth.user.id, ticket.access_link_id, target.id)
      : canUseSshTerminal(auth.session.id, auth.user.id, ticket.access_link_id, target.id);
  };

  const closeTerminal = (code, reason, message) => {
    if (closing) return true;
    closing = true;
    clearInterval(idleTimer);
    if (message && ws.readyState === WebSocket.OPEN) {
      sendTerminalJson(ws, { type: 'error', message });
    }
    if (managedMobileSession) {
      managedMobileSession.close(code, reason);
      return true;
    }
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close(code, reason);
    }
    return true;
  };

  const renewSessionIfNeeded = () => {
    const settings = terminalSettingsStore.get();
    if (!settings.activityRenewalEnabled) return;
    const now = Date.now();
    if (now - lastSessionRenewedAt < TERMINAL_ACTIVITY_TOUCH_INTERVAL_MS) return;
    if (!canUseCurrentTerminal()) return;
    const current = nowIso();
    if (mobile) {
      db.prepare('UPDATE device_sessions SET last_seen_at = ?, updated_at = ? WHERE id = ?')
        .run(current, current, auth.session.id);
      lastSessionRenewedAt = now;
      return;
    }
    const expiresAt = new Date(now + settings.idleTimeoutSeconds * 1000).toISOString();
    db.prepare('UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?')
      .run(current, expiresAt, auth.session.id);
    lastSessionRenewedAt = now;
  };

  const recordTerminalActivity = () => {
    lastTerminalActivityAt = Date.now();
    renewSessionIfNeeded();
  };

  const denyIfUnauthorized = () => {
    if (canUseCurrentTerminal()) return false;
    return closeTerminal(4003, 'permission revoked', '登录状态或连接权限已失效');
  };

  const idleTimer = setInterval(() => {
    if (closing || ws.readyState !== WebSocket.OPEN) return;
    const settings = terminalSettingsStore.get();
    if (
      settings.idleTimeoutEnabled &&
      Date.now() - lastTerminalActivityAt >= settings.idleTimeoutSeconds * 1000
    ) {
      audit({
        userId: auth.user.id,
        type: kind === 'private' ? 'private_terminal_idle_timeout' : 'terminal_idle_timeout',
        details: {
          timeoutSeconds: settings.idleTimeoutSeconds,
          endpointId: kind === 'private' ? target.id : undefined,
          targetId: kind === 'private' ? undefined : target.id
        },
        req
      });
      closeTerminal(4000, 'terminal idle timeout', '终端已超过空闲超时时间，连接已断开。');
      return;
    }
    denyIfUnauthorized();
  }, TERMINAL_IDLE_CHECK_INTERVAL_MS);

  ws.on('message', (raw, isBinary) => {
    if (denyIfUnauthorized()) return;

    if (mobile && isBinary) {
      if (raw.length > 64 * 1024) {
        closeTerminal(1009, 'message too large', 'TLTP/1 binary frame is too large');
        return;
      }
      recordTerminalActivity();
      if (managedMobileSession) {
        managedMobileSession.write(raw);
      } else if (stream) {
        stream.write(Buffer.from(raw));
      }
      return;
    }

    let message;
    try {
      message = JSON.parse(String(raw));
    } catch {
      sendTerminalJson(ws, { type: 'error', message: '终端消息格式无效' });
      return;
    }

    if (mobile && message.type === 'close') {
      closeTerminal(1000, 'client closed');
      return;
    }

    if (message.type === 'resize') {
      recordTerminalActivity();
      size = normalizeTerminalSize(message);
      if (managedMobileSession) {
        managedMobileSession.resize(size);
      } else if (stream) {
        stream.setWindow(size.rows, size.cols, 0, 0);
      }
      return;
    }

    if (message.type === 'connect' || (mobile && message.type === 'open')) {
      if (connected) return;
      connected = true;
      recordTerminalActivity();
      size = normalizeTerminalSize(message);
      const assignSession = (client, shellStream) => {
        ssh = client;
        stream = shellStream;
      };
      if (kind === 'private') {
        privateRelay
          .startSshSession(
            ws,
            req,
            auth,
            target,
            message.auth || {},
            size,
            assignSession,
            recordTerminalActivity,
            { mobile }
          )
          .catch(() => {
            if (ws.readyState === WebSocket.OPEN) {
              sendTerminalJson(ws, { type: 'error', message: '私有终端连接初始化失败。' });
              ws.close(1011, 'private terminal init failed');
            }
          });
      } else if (mobile) {
        managedMobileSession = startManagedMobileSshSession(
          ws,
          req,
          auth,
          ticket,
          target,
          message.auth || {},
          size,
          recordTerminalActivity
        );
      } else {
        startSshSession(
          ws,
          req,
          auth,
          target,
          message.auth || {},
          size,
          assignSession,
          recordTerminalActivity,
          { mobile }
        );
      }
      return;
    }

    if (!mobile && message.type === 'data') {
      recordTerminalActivity();
      if (stream && typeof message.data === 'string') stream.write(message.data);
    }
  });

  ws.on('close', () => {
    closing = true;
    clearInterval(idleTimer);
    if (managedMobileSession) {
      managedMobileSession.detach(ws);
      return;
    }
    if (stream) stream.end();
    if (ssh) ssh.end();
    audit({
      userId: auth.user.id,
      type: mobile
        ? (kind === 'private' ? 'mobile_private_terminal_socket_closed' : 'mobile_terminal_socket_closed')
        : (kind === 'private' ? 'private_terminal_socket_closed' : 'terminal_socket_closed'),
      details: kind === 'private' ? { endpointId: target.id } : { targetId: target.id },
      req
    });
  });
}

function startSshSession(ws, req, auth, target, sshAuth, size, assignSession, recordActivity = () => {}, options = {}) {
  const client = new SshClient();
  const hostKeyState = {};
  const authMethod = sshAuth.method === 'privateKey' ? 'privateKey' : 'password';
  if (!parseAllowedAuthMethods(target.allowed_auth_methods).includes(authMethod)) {
    sendTerminalJson(ws, {
      type: 'error',
      code: 'auth_method_not_allowed',
      message: 'SSH authentication method is not allowed for this target.'
    });
    ws.close(1008, 'auth method not allowed');
    return;
  }

  const connectConfig = {
    host: target.host,
    port: target.port,
    username: target.ssh_username,
    readyTimeout: 20000,
    keepaliveInterval: 15000,
    keepaliveCountMax: 3,
    hostVerifier: createHostKeyVerifier(target, hostKeyState)
  };

  if (sshAuth.method === 'privateKey') {
    connectConfig.privateKey = String(sshAuth.privateKey || '');
    if (sshAuth.passphrase) connectConfig.passphrase = String(sshAuth.passphrase);
  } else {
    connectConfig.password = String(sshAuth.password || '');
  }

  client
    .on('ready', () => {
      recordActivity();
      audit({ userId: auth.user.id, type: 'ssh_connected', details: { targetId: target.id }, req });
      client.shell(
        {
          term: target.default_term || 'xterm-256color',
          cols: size.cols,
          rows: size.rows
        },
        (error, shellStream) => {
          if (error) {
            sendTerminalJson(ws, {
              type: 'error',
              code: 'ssh_shell_failed',
              message: 'SSH shell could not be opened.'
            });
            ws.close(1011, 'ssh shell failed');
            client.end();
            return;
          }
          assignSession(client, shellStream);
          sendTerminalJson(ws, {
            type: 'ready',
            version: options.mobile ? 1 : undefined,
            hostKey: {
              type: hostKeyState.keyType || target.host_key_type || '',
              fingerprintSha256: hostKeyState.fingerprint || '',
              verified: Boolean(hostKeyState.verified)
            }
          });
          shellStream.on('data', (data) => {
            recordActivity();
            if (ws.readyState === WebSocket.OPEN) {
              sendTerminalData(ws, options.mobile, data);
            }
          });
          shellStream.stderr.on('data', (data) => {
            recordActivity();
            if (ws.readyState === WebSocket.OPEN) {
              sendTerminalData(ws, options.mobile, data);
            }
          });
          shellStream.on('close', () => {
            sendTerminalJson(ws, {
              type: 'closed',
              version: options.mobile ? 1 : undefined
            });
            ws.close(1000, 'ssh closed');
            client.end();
          });
        }
      );
    })
    .on('error', (error) => {
      audit({ userId: auth.user.id, type: 'ssh_connect_failed', details: { targetId: target.id, code: error.code }, req });
      if (ws.readyState === WebSocket.OPEN) {
        sendTerminalJson(ws, {
          type: 'error',
          version: options.mobile ? 1 : undefined,
          code: hostKeyState.errorCode || 'ssh_failed',
          message: hostKeyErrorMessage(hostKeyState.errorCode) ||
            'SSH connection failed. Check the target host and credentials.'
        });
        ws.close(1011, 'ssh failed');
      }
    })
    .on('close', () => {
      audit({ userId: auth.user.id, type: 'ssh_disconnected', details: { targetId: target.id }, req });
    });

  client.connect(connectConfig);
}

function startManagedMobileSshSession(ws, req, auth, ticket, target, sshAuth, size, recordActivity = () => {}) {
  const client = new SshClient();
  const hostKeyState = {};
  const authMethod = sshAuth.method === 'privateKey' ? 'privateKey' : 'password';
  const managedSession = new MobileManagedTerminalSession({
    auth,
    target,
    publicTarget: publicTarget(target),
    ticket,
    size,
    req
  });

  if (!parseAllowedAuthMethods(target.allowed_auth_methods).includes(authMethod)) {
    sendTerminalJson(ws, {
      type: 'error',
      version: 1,
      code: 'auth_method_not_allowed',
      message: 'SSH authentication method is not allowed for this target.'
    });
    ws.close(1008, 'auth method not allowed');
    return managedSession;
  }

  mobileTerminalSessions.set(managedSession.id, managedSession);
  managedSession.attach(ws);

  const connectConfig = {
    host: target.host,
    port: target.port,
    username: target.ssh_username,
    readyTimeout: 20000,
    keepaliveInterval: 15000,
    keepaliveCountMax: 3,
    hostVerifier: createHostKeyVerifier(target, hostKeyState)
  };

  if (sshAuth.method === 'privateKey') {
    connectConfig.privateKey = String(sshAuth.privateKey || '');
    if (sshAuth.passphrase) connectConfig.passphrase = String(sshAuth.passphrase);
  } else {
    connectConfig.password = String(sshAuth.password || '');
  }

  client
    .on('ready', () => {
      recordActivity();
      audit({
        userId: auth.user.id,
        type: 'mobile_ssh_connected',
        details: { targetId: target.id, sessionId: managedSession.id },
        req
      });
      client.shell(
        {
          term: target.default_term || 'xterm-256color',
          cols: size.cols,
          rows: size.rows
        },
        (error, shellStream) => {
          if (error) {
            sendTerminalJson(ws, {
              type: 'error',
              version: 1,
              code: 'ssh_shell_failed',
              message: 'SSH shell could not be opened.'
            });
            ws.close(1011, 'ssh shell failed');
            managedSession.close(1011, 'ssh shell failed');
            return;
          }
          managedSession.markReady({
            ssh: client,
            stream: shellStream,
            hostKey: {
              type: hostKeyState.keyType || target.host_key_type || '',
              fingerprintSha256: hostKeyState.fingerprint || '',
              verified: Boolean(hostKeyState.verified)
            }
          });
          shellStream.on('data', (data) => {
            recordActivity();
            managedSession.accept(data);
          });
          shellStream.stderr.on('data', (data) => {
            recordActivity();
            managedSession.accept(data);
          });
          shellStream.on('close', () => {
            managedSession.remoteClosed();
          });
        }
      );
    })
    .on('error', (error) => {
      audit({
        userId: auth.user.id,
        type: 'mobile_ssh_connect_failed',
        details: { targetId: target.id, sessionId: managedSession.id, code: error.code },
        req
      });
      if (ws.readyState === WebSocket.OPEN) {
        sendTerminalJson(ws, {
          type: 'error',
          version: 1,
          code: hostKeyState.errorCode || 'ssh_failed',
          message: hostKeyErrorMessage(hostKeyState.errorCode) ||
            'SSH connection failed. Check the target host and credentials.'
        });
        ws.close(1011, 'ssh failed');
      }
      managedSession.close(1011, 'ssh failed');
    })
    .on('close', () => {
      audit({
        userId: auth.user.id,
        type: 'mobile_ssh_disconnected',
        details: { targetId: target.id, sessionId: managedSession.id },
        req
      });
    });

  client.connect(connectConfig);
  return managedSession;
}

function normalizeTerminalSize(message) {
  const cols = Number(message.cols);
  const rows = Number(message.rows);
  return {
    cols: Number.isInteger(cols) && cols > 0 && cols < 400 ? cols : 100,
    rows: Number.isInteger(rows) && rows > 0 && rows < 200 ? rows : 30
  };
}

function isMobileChallengeUsable(challenge) {
  if (!challenge || challenge.user_disabled || challenge.access_link_disabled) return false;
  if (new Date(challenge.expires_at).getTime() <= Date.now()) return false;
  if (
    challenge.access_link_expires_at &&
    new Date(challenge.access_link_expires_at).getTime() <= Date.now()
  ) {
    return false;
  }
  if (
    challenge.access_link_max_uses > 0 &&
    challenge.access_link_used_count >= challenge.access_link_max_uses
  ) {
    return false;
  }
  return true;
}

function publicDeviceSession(row) {
  return {
    id: row.id,
    deviceName: row.device_name,
    clientVersion: row.client_version,
    lastSeenAt: row.last_seen_at,
    revoked: Boolean(row.revoked_at),
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function normalizeHostKeyUpdate(input) {
  const policy = ['strict', 'disabled'].includes(input.policy)
    ? input.policy
    : ['strict', 'disabled'].includes(input.hostKeyPolicy)
      ? input.hostKeyPolicy
      : 'strict';
  const fingerprintSha256 = normalizeHostKeyFingerprint(
    input.fingerprintSha256 || input.hostKeyFingerprintSha256
  );
  const keyType = String(input.keyType || input.hostKeyType || '').trim().slice(0, 64);
  if (policy === 'strict' && !fingerprintSha256) {
    throw new Error('strict host key policy requires a SHA256 fingerprint');
  }
  return { policy, keyType, fingerprintSha256 };
}

function parseAllowedAuthMethods(value) {
  try {
    const methods = JSON.parse(String(value || '[]'));
    if (!Array.isArray(methods)) return ['password', 'privateKey'];
    const allowed = methods.filter((method) => method === 'password' || method === 'privateKey');
    return allowed.length > 0 ? allowed : ['password', 'privateKey'];
  } catch {
    return ['password', 'privateKey'];
  }
}

function firstHeader(value) {
  if (Array.isArray(value)) return value[0] || '';
  return String(value || '').split(',')[0].trim();
}

function bearerToken(value) {
  const header = firstHeader(value);
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1].trim() : '';
}
