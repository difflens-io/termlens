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
  const context = findTerminalTicketContext(ticketToken, auth.user.id);
  if (!context || !isTicketFresh(context.ticket)) {
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

function requireAuth(req, res, next) {
  const auth = authenticateRequest(req);
  if (!auth) return res.status(401).json({ error: '需要登录' });
  req.auth = auth;
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
    disabled: Boolean(row.disabled),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function findTicket(ticketToken) {
  if (!ticketToken) return null;
  return db.prepare('SELECT * FROM terminal_tickets WHERE ticket_hash = ?').get(hashToken(ticketToken));
}

function findTerminalTicketContext(ticketToken, userId) {
  const ticket = findTicket(ticketToken);
  if (ticket && ticket.user_id === userId) {
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

function handleTerminalSocket(ws, req, { auth, kind, ticket, target }) {
  let ssh = null;
  let stream = null;
  let connected = false;
  let closing = false;
  let size = { cols: 100, rows: 30 };
  let lastTerminalActivityAt = Date.now();
  let lastSessionRenewedAt = 0;

  const canUseCurrentTerminal = () => kind === 'private'
    ? privateRelay.canUseTerminal(auth.session.id, auth.user.id, ticket.access_link_id, target.id)
    : canUseSshTerminal(auth.session.id, auth.user.id, ticket.access_link_id, target.id);

  const closeTerminal = (code, reason, message) => {
    if (closing) return true;
    closing = true;
    clearInterval(idleTimer);
    if (message && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'error', message }));
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

  ws.on('message', (raw) => {
    if (denyIfUnauthorized()) return;

    let message;
    try {
      message = JSON.parse(String(raw));
    } catch {
      ws.send(JSON.stringify({ type: 'error', message: '终端消息格式无效' }));
      return;
    }

    if (message.type === 'resize') {
      recordTerminalActivity();
      size = normalizeTerminalSize(message);
      if (stream) stream.setWindow(size.rows, size.cols, 0, 0);
      return;
    }

    if (message.type === 'connect') {
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
          .startSshSession(ws, req, auth, target, message.auth || {}, size, assignSession, recordTerminalActivity)
          .catch(() => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'error', message: '私有终端连接初始化失败。' }));
              ws.close(1011, 'private terminal init failed');
            }
          });
      } else {
        startSshSession(ws, req, auth, target, message.auth || {}, size, assignSession, recordTerminalActivity);
      }
      return;
    }

    if (message.type === 'data') {
      recordTerminalActivity();
      if (stream && typeof message.data === 'string') stream.write(message.data);
    }
  });

  ws.on('close', () => {
    closing = true;
    clearInterval(idleTimer);
    if (stream) stream.end();
    if (ssh) ssh.end();
    audit({
      userId: auth.user.id,
      type: kind === 'private' ? 'private_terminal_socket_closed' : 'terminal_socket_closed',
      details: kind === 'private' ? { endpointId: target.id } : { targetId: target.id },
      req
    });
  });
}

function startSshSession(ws, req, auth, target, sshAuth, size, assignSession, recordActivity = () => {}) {
  const client = new SshClient();
  const connectConfig = {
    host: target.host,
    port: target.port,
    username: target.ssh_username,
    readyTimeout: 20000,
    keepaliveInterval: 15000,
    keepaliveCountMax: 3
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
          term: 'xterm-256color',
          cols: size.cols,
          rows: size.rows
        },
        (error, shellStream) => {
          if (error) {
            ws.send(JSON.stringify({ type: 'error', message: 'SSH shell could not be opened.' }));
            ws.close(1011, 'ssh shell failed');
            client.end();
            return;
          }
          assignSession(client, shellStream);
          ws.send(JSON.stringify({ type: 'ready' }));
          shellStream.on('data', (data) => {
            recordActivity();
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'data', data: data.toString('utf8') }));
            }
          });
          shellStream.stderr.on('data', (data) => {
            recordActivity();
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'data', data: data.toString('utf8') }));
            }
          });
          shellStream.on('close', () => {
            ws.send(JSON.stringify({ type: 'closed' }));
            ws.close(1000, 'ssh closed');
            client.end();
          });
        }
      );
    })
    .on('error', (error) => {
      audit({ userId: auth.user.id, type: 'ssh_connect_failed', details: { targetId: target.id, code: error.code }, req });
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'error', message: 'SSH connection failed. Check the target host and credentials.' }));
        ws.close(1011, 'ssh failed');
      }
    })
    .on('close', () => {
      audit({ userId: auth.user.id, type: 'ssh_disconnected', details: { targetId: target.id }, req });
    });

  client.connect(connectConfig);
}

function normalizeTerminalSize(message) {
  const cols = Number(message.cols);
  const rows = Number(message.rows);
  return {
    cols: Number.isInteger(cols) && cols > 0 && cols < 400 ? cols : 100,
    rows: Number.isInteger(rows) && rows > 0 && rows < 200 ? rows : 30
  };
}
