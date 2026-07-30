import { Duplex } from 'node:stream';
import { Client as SshClient } from 'ssh2';
import { WebSocket, WebSocketServer } from 'ws';
import { hashToken, nowIso, randomToken } from './security.js';
import {
  isAllowedPrivateRelayHost,
  normalizePrivateRelayHost
} from '../shared/private-relay-validation.js';

const STREAM_ID_PATTERN = /^[a-zA-Z0-9_-]{8,64}$/;

export { isAllowedPrivateRelayHost } from '../shared/private-relay-validation.js';

export function normalizePrivateEndpointInput(input = {}, options = {}) {
  const name = String(input.name || '').trim();
  const localHost = normalizePrivateRelayHost(input.localHost || input.local_host || '127.0.0.1');
  const localPort = Number(input.localPort || input.local_port || 22);
  const sshUsername = cleanIdentifier(input.sshUsername || input.ssh_username);

  if (!name || name.length > 120) {
    throw new Error('私有终端名称必填，且不能超过 120 个字符');
  }
  if (!isAllowedPrivateRelayHost(localHost, options.allowNonLoopback)) {
    throw new Error('默认只允许私有 Agent 连接本机 loopback 地址');
  }
  if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
    throw new Error('本地 SSH 端口必须在 1 到 65535 之间');
  }
  if (!sshUsername) {
    throw new Error('SSH 用户必填，且只能包含字母、数字、点、下划线和短横线');
  }

  return { name, localHost, localPort, sshUsername };
}

export function createPrivateRelay({ config, db, audit, mountPath }) {
  const enabled = Boolean(config.privateRelay?.enabled);
  const agentWss = new WebSocketServer({ noServer: true });
  const agents = new Map();

  if (enabled) initSchema(db);

  agentWss.on('connection', (ws, req, endpoint) => {
    const existing = agents.get(endpoint.id);
    if (existing) existing.close(4001, 'agent replaced');

    const connection = new AgentConnection({
      ws,
      req,
      endpoint,
      db,
      audit,
      heartbeatMs: Math.max(5, config.privateRelay.agentHeartbeatSeconds) * 1000,
      maxStreams: Math.max(1, config.privateRelay.maxStreamsPerAgent),
      streamOpenTimeoutMs: Math.max(3, config.privateRelay.streamOpenTimeoutSeconds) * 1000,
      onClose: () => {
        if (agents.get(endpoint.id) === connection) agents.delete(endpoint.id);
      }
    });
    agents.set(endpoint.id, connection);
    db.prepare('UPDATE private_endpoints SET last_seen_at = ?, updated_at = ? WHERE id = ?')
      .run(nowIso(), nowIso(), endpoint.id);
    audit({ type: 'private_agent_connected', details: { endpointId: endpoint.id }, req });
  });

  return {
    enabled,
    installRoutes(router, { requireAuth, requireAdmin }) {
      router.get('/api/private-relay/status', requireAuth, (_req, res) => {
        res.json({ enabled });
      });

      if (!enabled) return;

      router.get('/api/admin/private-endpoints', requireAdmin, (_req, res) => {
        const endpoints = db.prepare('SELECT * FROM private_endpoints ORDER BY id ASC').all();
        res.json({ endpoints: endpoints.map((endpoint) => publicPrivateEndpoint(endpoint, agents)) });
      });

      router.post('/api/admin/private-endpoints', requireAdmin, (req, res) => {
        let input;
        try {
          input = normalizePrivateEndpointInput(req.body, {
            allowNonLoopback: config.privateRelay.allowNonLoopback
          });
        } catch (error) {
          return res.status(400).json({ error: error.message });
        }

        const now = nowIso();
        const result = db.prepare(`
          INSERT INTO private_endpoints (
            name, local_host, local_port, ssh_username, created_by, created_at, updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(input.name, input.localHost, input.localPort, input.sshUsername, req.auth.user.id, now, now);
        const endpoint = getPrivateEndpoint(Number(result.lastInsertRowid));
        const enrollment = createEnrollment(endpoint.id, req.auth.user.id, req);
        audit({
          userId: req.auth.user.id,
          type: 'admin_private_endpoint_created',
          details: { endpointId: endpoint.id },
          req
        });
        res.status(201).json({
          endpoint: publicPrivateEndpoint(endpoint, agents),
          enrollment
        });
      });

      router.post('/api/admin/private-endpoints/:id/enrollment', requireAdmin, (req, res) => {
        const endpoint = getPrivateEndpoint(Number(req.params.id));
        if (!endpoint) return res.status(404).json({ error: '私有终端不存在' });
        const enrollment = createEnrollment(endpoint.id, req.auth.user.id, req);
        audit({
          userId: req.auth.user.id,
          type: 'admin_private_endpoint_enrollment_created',
          details: { endpointId: endpoint.id },
          req
        });
        res.status(201).json({ enrollment });
      });

      router.post('/api/admin/private-endpoints/:id/disabled', requireAdmin, (req, res) => {
        const endpointId = Number(req.params.id);
        const disabled = req.body?.disabled ? 1 : 0;
        db.prepare('UPDATE private_endpoints SET disabled = ?, updated_at = ? WHERE id = ?')
          .run(disabled, nowIso(), endpointId);
        if (disabled) agents.get(endpointId)?.close(4002, 'endpoint disabled');
        audit({
          userId: req.auth.user.id,
          type: 'admin_private_endpoint_disabled_changed',
          details: { endpointId, disabled },
          req
        });
        res.json({ ok: true });
      });

      router.get('/api/admin/users/:id/private-permissions', requireAdmin, (req, res) => {
        const userId = Number(req.params.id);
        const endpointIds = db.prepare('SELECT endpoint_id FROM user_private_endpoint_permissions WHERE user_id = ?')
          .all(userId)
          .map((row) => row.endpoint_id);
        res.json({ endpointIds });
      });

      router.put('/api/admin/users/:id/private-permissions', requireAdmin, (req, res) => {
        const userId = Number(req.params.id);
        const endpointIds = Array.isArray(req.body?.endpointIds)
          ? req.body.endpointIds.map(Number).filter(Number.isInteger)
          : [];
        const now = nowIso();
        db.exec('BEGIN');
        try {
          db.prepare('DELETE FROM user_private_endpoint_permissions WHERE user_id = ?').run(userId);
          const insert = db.prepare(`
            INSERT OR IGNORE INTO user_private_endpoint_permissions (user_id, endpoint_id, created_at)
            VALUES (?, ?, ?)
          `);
          for (const endpointId of endpointIds) insert.run(userId, endpointId, now);
          db.exec('COMMIT');
        } catch (error) {
          db.exec('ROLLBACK');
          throw error;
        }
        audit({
          userId: req.auth.user.id,
          type: 'admin_private_permissions_updated',
          details: { userId, endpointIds },
          req
        });
        res.json({ ok: true });
      });

      router.post('/api/private-agent/enroll', (req, res) => {
        const token = String(req.body?.token || '');
        const tokenHash = hashToken(token);
        const endpoint = db.prepare(`
          SELECT * FROM private_endpoints
          WHERE enrollment_token_hash = ? AND disabled = 0
        `).get(tokenHash);
        if (!endpoint || !endpoint.enrollment_expires_at || new Date(endpoint.enrollment_expires_at).getTime() <= Date.now()) {
          return res.status(404).json({ error: 'Agent 注册 token 无效或已过期' });
        }

        const agentToken = randomToken(36);
        const now = nowIso();
        db.prepare(`
          UPDATE private_endpoints
          SET agent_token_hash = ?, agent_enrolled_at = ?, enrollment_token_hash = '',
            enrollment_expires_at = NULL, updated_at = ?
          WHERE id = ?
        `).run(hashToken(agentToken), now, now, endpoint.id);
        agents.get(endpoint.id)?.close(4001, 'agent re-enrolled');
        audit({ type: 'private_agent_enrolled', details: { endpointId: endpoint.id }, req });

        res.status(201).json({
          endpoint: publicPrivateEndpoint(getPrivateEndpoint(endpoint.id), agents),
          agentToken,
          agentWebSocketUrl: agentWebSocketUrl(config, mountPath, req)
        });
      });
    },

    handleAgentUpgrade(req, socket, head) {
      const url = new URL(req.url || '/', 'http://localhost');
      if (url.pathname !== `${mountPath}/ws/private-agent`) return false;
      if (!enabled) {
        rejectUpgrade(socket, 404, 'Private relay is disabled.');
        return true;
      }

      const endpointId = Number(firstHeader(req.headers['x-termlens-endpoint-id']) || url.searchParams.get('endpointId'));
      const token = bearerToken(req.headers.authorization) || url.searchParams.get('token') || '';
      const endpoint = getPrivateEndpoint(endpointId);
      if (!endpoint || endpoint.disabled || !endpoint.agent_token_hash || endpoint.agent_token_hash !== hashToken(token)) {
        rejectUpgrade(socket, 403, 'Private agent credential is invalid.');
        return true;
      }

      agentWss.handleUpgrade(req, socket, head, (ws) => {
        agentWss.emit('connection', ws, req, endpoint);
      });
      return true;
    },

    getAllowedEndpoints(userId) {
      if (!enabled) return [];
      return db.prepare(`
        SELECT private_endpoints.*
        FROM private_endpoints
        JOIN user_private_endpoint_permissions ON user_private_endpoint_permissions.endpoint_id = private_endpoints.id
        WHERE user_private_endpoint_permissions.user_id = ? AND private_endpoints.disabled = 0
        ORDER BY private_endpoints.id ASC
      `).all(userId).map((endpoint) => publicPrivateEndpoint(endpoint, agents));
    },

    getAllowedEndpoint(userId, endpointId) {
      if (!enabled) return null;
      return db.prepare(`
        SELECT private_endpoints.*
        FROM private_endpoints
        JOIN user_private_endpoint_permissions ON user_private_endpoint_permissions.endpoint_id = private_endpoints.id
        WHERE user_private_endpoint_permissions.user_id = ?
          AND private_endpoints.id = ?
          AND private_endpoints.disabled = 0
      `).get(userId, endpointId);
    },

    createTerminalTicket({ userId, endpointId, accessLinkId, expiresAt }) {
      if (!enabled) return null;
      const ticket = randomToken(36);
      db.prepare(`
        INSERT INTO private_terminal_tickets (ticket_hash, user_id, endpoint_id, access_link_id, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(hashToken(ticket), userId, endpointId, accessLinkId, expiresAt, nowIso());
      return ticket;
    },

    findTerminalTicket(ticketToken) {
      if (!enabled || !ticketToken) return null;
      return db.prepare('SELECT * FROM private_terminal_tickets WHERE ticket_hash = ?').get(hashToken(ticketToken));
    },

    markTicketUsed(ticketId) {
      if (!enabled) return;
      db.prepare('UPDATE private_terminal_tickets SET used_at = ? WHERE id = ?').run(nowIso(), ticketId);
    },

    canUseTerminal(sessionId, userId, accessLinkId, endpointId) {
      if (!enabled) return false;
      const now = nowIso();
      const session = db.prepare(`
        SELECT sessions.id
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        JOIN access_links AS session_link ON session_link.id = sessions.access_link_id
        JOIN access_links AS ticket_link ON ticket_link.id = ?
        JOIN user_private_endpoint_permissions ON user_private_endpoint_permissions.user_id = sessions.user_id
        JOIN private_endpoints ON private_endpoints.id = user_private_endpoint_permissions.endpoint_id
        WHERE sessions.id = ?
          AND sessions.user_id = ?
          AND ticket_link.user_id = sessions.user_id
          AND user_private_endpoint_permissions.endpoint_id = ?
          AND sessions.expires_at > ?
          AND users.disabled = 0
          AND session_link.disabled = 0
          AND ticket_link.disabled = 0
          AND (ticket_link.expires_at IS NULL OR ticket_link.expires_at > ?)
          AND private_endpoints.disabled = 0
      `).get(accessLinkId, sessionId, userId, endpointId, now, now);
      return Boolean(session);
    },

    publicEndpoint(endpoint) {
      if (!enabled || !endpoint) return null;
      return publicPrivateEndpoint(endpoint, agents);
    },

    async startSshSession(ws, req, auth, endpoint, sshAuth, size, assignSession, recordActivity = () => {}) {
      const agent = agents.get(endpoint.id);
      if (!agent || !agent.isOpen()) {
        ws.send(JSON.stringify({ type: 'error', message: '私有终端 Agent 不在线，请先在本地电脑启动 Agent。' }));
        ws.close(1011, 'private agent offline');
        return;
      }

      let relayStream;
      try {
        relayStream = await agent.openStream();
      } catch (error) {
        ws.send(JSON.stringify({ type: 'error', message: '私有终端隧道打开失败。' }));
        ws.close(1011, 'private tunnel failed');
        return;
      }

      startSshOverRelay(ws, req, auth, endpoint, sshAuth, size, relayStream, audit, assignSession, recordActivity);
    },

    onlineEndpointIds() {
      return new Set(agents.keys());
    }
  };

  function getPrivateEndpoint(endpointId) {
    return db.prepare('SELECT * FROM private_endpoints WHERE id = ?').get(endpointId);
  }

  function createEnrollment(endpointId, userId, req) {
    const token = randomToken(36);
    const expiresAt = new Date(Date.now() + config.privateRelay.enrollmentTtlSeconds * 1000).toISOString();
    db.prepare(`
      UPDATE private_endpoints
      SET enrollment_token_hash = ?, enrollment_expires_at = ?, updated_at = ?
      WHERE id = ?
    `).run(hashToken(token), expiresAt, nowIso(), endpointId);

    return {
      token,
      expiresAt,
      command: agentEnrollCommand(config, mountPath, token, req)
    };
  }
}

class AgentConnection {
  constructor({ ws, req, endpoint, db, audit, heartbeatMs, maxStreams, streamOpenTimeoutMs, onClose }) {
    this.ws = ws;
    this.req = req;
    this.endpoint = endpoint;
    this.db = db;
    this.audit = audit;
    this.maxStreams = maxStreams;
    this.streamOpenTimeoutMs = streamOpenTimeoutMs;
    this.onClose = onClose;
    this.streams = new Map();
    this.pending = new Map();
    this.closed = false;

    this.heartbeat = setInterval(() => {
      if (!this.isOpen()) return;
      this.send({ type: 'ping' });
      this.touch();
    }, heartbeatMs);

    ws.on('message', (raw) => this.handleMessage(raw));
    ws.on('close', () => this.closeStreams());
    ws.on('error', () => this.closeStreams());
  }

  isOpen() {
    return !this.closed && this.ws.readyState === WebSocket.OPEN;
  }

  close(code, reason) {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.close(code, reason);
    this.closeStreams();
  }

  openStream() {
    if (!this.isOpen()) return Promise.reject(new Error('Agent is offline.'));
    if (this.streams.size + this.pending.size >= this.maxStreams) {
      return Promise.reject(new Error('Agent stream limit reached.'));
    }

    const streamId = randomToken(12);
    const stream = new RelayDuplexStream({
      streamId,
      send: (payload) => this.send(payload),
      onDestroy: () => {
        this.streams.delete(streamId);
        this.pending.delete(streamId);
      }
    });

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(streamId);
        stream.destroy(new Error('Timed out opening private relay stream.'));
        reject(new Error('Timed out opening private relay stream.'));
      }, this.streamOpenTimeoutMs);
      this.pending.set(streamId, { stream, resolve, reject, timer });
      this.send({ type: 'stream-open', streamId });
    });
  }

  handleMessage(raw) {
    let message;
    try {
      message = JSON.parse(String(raw));
    } catch {
      return;
    }
    if (!message || typeof message.type !== 'string') return;
    this.touch();

    if (message.type === 'pong' || message.type === 'hello') return;

    const streamId = String(message.streamId || '');
    if (!STREAM_ID_PATTERN.test(streamId)) return;

    if (message.type === 'stream-opened') {
      const pending = this.pending.get(streamId);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(streamId);
      this.streams.set(streamId, pending.stream);
      pending.resolve(pending.stream);
      return;
    }

    const stream = this.streams.get(streamId) || this.pending.get(streamId)?.stream;
    if (!stream) return;

    if (message.type === 'stream-data' && typeof message.data === 'string') {
      stream.accept(Buffer.from(message.data, 'base64'));
      return;
    }

    if (message.type === 'stream-error') {
      const error = new Error(String(message.message || 'Private relay stream error.'));
      const pending = this.pending.get(streamId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(streamId);
        pending.reject(error);
        pending.stream.destroy(error);
        return;
      }
      stream.destroy(error);
      return;
    }

    if (message.type === 'stream-closed') {
      const pending = this.pending.get(streamId);
      if (pending) {
        const error = new Error('Private relay stream closed before opening.');
        clearTimeout(pending.timer);
        this.pending.delete(streamId);
        pending.reject(error);
        pending.stream.destroy(error);
        return;
      }
      stream.closeFromRemote();
    }
  }

  touch() {
    this.db.prepare('UPDATE private_endpoints SET last_seen_at = ? WHERE id = ?')
      .run(nowIso(), this.endpoint.id);
  }

  send(payload) {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(payload));
  }

  closeStreams() {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.heartbeat);
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Agent disconnected.'));
      pending.stream.destroy(new Error('Agent disconnected.'));
    }
    for (const stream of this.streams.values()) stream.destroy(new Error('Agent disconnected.'));
    this.pending.clear();
    this.streams.clear();
    this.audit({ type: 'private_agent_disconnected', details: { endpointId: this.endpoint.id }, req: this.req });
    this.onClose?.();
  }
}

class RelayDuplexStream extends Duplex {
  constructor({ streamId, send, onDestroy }) {
    super();
    this.streamId = streamId;
    this.send = send;
    this.onDestroy = onDestroy;
    this.remoteClosed = false;
  }

  _read() {}

  _write(chunk, _encoding, callback) {
    if (this.destroyed || this.remoteClosed) {
      callback(new Error('Private relay stream is closed.'));
      return;
    }
    try {
      this.send({
        type: 'stream-data',
        streamId: this.streamId,
        data: Buffer.from(chunk).toString('base64')
      });
      callback();
    } catch (error) {
      callback(error);
    }
  }

  _destroy(error, callback) {
    if (!this.remoteClosed) {
      try {
        this.send({ type: 'stream-close', streamId: this.streamId });
      } catch {}
    }
    this.onDestroy?.();
    callback(error);
  }

  accept(data) {
    if (!this.destroyed) this.push(data);
  }

  closeFromRemote() {
    this.remoteClosed = true;
    if (!this.destroyed) this.push(null);
    this.destroy();
  }
}

function initSchema(db) {
  db.exec(`
  CREATE TABLE IF NOT EXISTS private_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    local_host TEXT NOT NULL DEFAULT '127.0.0.1',
    local_port INTEGER NOT NULL DEFAULT 22,
    ssh_username TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    enrollment_token_hash TEXT NOT NULL DEFAULT '',
    enrollment_expires_at TEXT,
    agent_token_hash TEXT NOT NULL DEFAULT '',
    agent_enrolled_at TEXT,
    last_seen_at TEXT,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS user_private_endpoint_permissions (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint_id INTEGER NOT NULL REFERENCES private_endpoints(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, endpoint_id)
  );

  CREATE TABLE IF NOT EXISTS private_terminal_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint_id INTEGER NOT NULL REFERENCES private_endpoints(id) ON DELETE CASCADE,
    access_link_id INTEGER NOT NULL REFERENCES access_links(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  );
  `);
}

function publicPrivateEndpoint(endpoint, agents) {
  const online = Boolean(agents.get(endpoint.id)?.isOpen());
  return {
    id: endpoint.id,
    kind: 'private',
    name: endpoint.name,
    host: endpoint.local_host,
    port: endpoint.local_port,
    sshUsername: endpoint.ssh_username,
    online,
    disabled: Boolean(endpoint.disabled),
    agentEnrolled: Boolean(endpoint.agent_token_hash),
    agentEnrolledAt: endpoint.agent_enrolled_at,
    lastSeenAt: endpoint.last_seen_at,
    createdAt: endpoint.created_at,
    updatedAt: endpoint.updated_at
  };
}

function startSshOverRelay(ws, req, auth, endpoint, sshAuth, size, relayStream, audit, assignSession, recordActivity = () => {}) {
  const client = new SshClient();
  const connectConfig = {
    sock: relayStream,
    username: endpoint.ssh_username,
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
      audit({ userId: auth.user.id, type: 'private_ssh_connected', details: { endpointId: endpoint.id }, req });
      client.shell(
        {
          term: 'xterm-256color',
          cols: size.cols,
          rows: size.rows
        },
        (error, shellStream) => {
          if (error) {
            ws.send(JSON.stringify({ type: 'error', message: 'Private SSH shell could not be opened.' }));
            ws.close(1011, 'private ssh shell failed');
            client.end();
            relayStream.destroy();
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
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'closed' }));
              ws.close(1000, 'private ssh closed');
            }
            client.end();
            relayStream.destroy();
          });
        }
      );
    })
    .on('error', (error) => {
      audit({
        userId: auth.user.id,
        type: 'private_ssh_connect_failed',
        details: { endpointId: endpoint.id, code: error.code },
        req
      });
      relayStream.destroy();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'error', message: 'Private SSH connection failed. Check the local SSH service and credentials.' }));
        ws.close(1011, 'private ssh failed');
      }
    })
    .on('close', () => {
      audit({ userId: auth.user.id, type: 'private_ssh_disconnected', details: { endpointId: endpoint.id }, req });
      relayStream.destroy();
    });

  ws.on('close', () => {
    client.end();
    relayStream.destroy();
  });

  client.connect(connectConfig);
}

function agentWebSocketUrl(config, mountPath, req) {
  const baseUrl = publicBaseUrl(config, mountPath, req);
  if (!isAbsoluteUrl(baseUrl)) return `${mountPath}/ws/private-agent`;
  const url = new URL('ws/private-agent', ensureTrailingSlash(baseUrl));
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.toString();
}

function agentEnrollCommand(config, mountPath, token, req) {
  const server = publicBaseUrl(config, mountPath, req);
  return `TERMLENS_AGENT_SERVER=${shellQuote(server)} TERMLENS_AGENT_ENROLL_TOKEN=${shellQuote(token)} npm run private-agent -- enroll`;
}

function cleanIdentifier(value) {
  const text = String(value || '').trim();
  return /^[a-zA-Z0-9._-]{1,64}$/.test(text) ? text : '';
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function publicBaseUrl(config, mountPath, req) {
  if (config.publicUrl) return ensureTrailingSlash(config.publicUrl);
  const host = firstHeader(req?.headers?.['x-forwarded-host']) || firstHeader(req?.headers?.host);
  if (!host) return `${mountPath}/`;
  const proto = firstHeader(req?.headers?.['x-forwarded-proto']) || req?.protocol || 'http';
  return ensureTrailingSlash(`${proto}://${host}${config.basePath}`);
}

function ensureTrailingSlash(value) {
  return String(value || '').endsWith('/') ? String(value || '') : `${String(value || '')}/`;
}

function isAbsoluteUrl(value) {
  return /^https?:\/\//i.test(String(value || ''));
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

function rejectUpgrade(socket, statusCode, message) {
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
