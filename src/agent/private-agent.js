#!/usr/bin/env node
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { WebSocket } from 'ws';
import { isAllowedPrivateRelayHost, normalizePrivateRelayHost } from '../shared/private-relay-validation.js';

const STREAM_ID_PATTERN = /^[a-zA-Z0-9_-]{8,64}$/;
const DEFAULT_CONFIG_PATH = path.join(os.homedir(), '.termlens-agent.json');

const command = process.argv[2] || 'run';

if (command === 'enroll') {
  enroll().catch((error) => fail(error));
} else if (command === 'run') {
  run().catch((error) => fail(error));
} else {
  fail(new Error('Usage: npm run private-agent -- enroll|run'));
}

async function enroll() {
  const server = requiredEnv('TERMLENS_AGENT_SERVER');
  const enrollToken = requiredEnv('TERMLENS_AGENT_ENROLL_TOKEN');
  const response = await fetch(new URL('api/private-agent/enroll', normalizeServerUrl(server)), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: enrollToken })
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Enrollment failed: ${response.status}`);

  const config = normalizeAgentConfig({
    server,
    webSocketUrl: payload.agentWebSocketUrl,
    endpointId: payload.endpoint?.id,
    agentToken: payload.agentToken,
    localHost: payload.endpoint?.host,
    localPort: payload.endpoint?.port
  });
  writeConfig(config);
  console.log(`TermLens private agent enrolled for endpoint ${config.endpointId}.`);
  console.log(`Config saved to ${configPath()}. Keep this file private.`);
}

async function run() {
  const fileConfig = readConfig();
  const config = normalizeAgentConfig({
    ...fileConfig,
    server: process.env.TERMLENS_AGENT_SERVER || fileConfig.server,
    webSocketUrl: process.env.TERMLENS_AGENT_WS_URL || fileConfig.webSocketUrl,
    endpointId: process.env.TERMLENS_AGENT_ENDPOINT_ID || fileConfig.endpointId,
    agentToken: process.env.TERMLENS_AGENT_TOKEN || fileConfig.agentToken,
    localHost: process.env.TERMLENS_AGENT_LOCAL_HOST || fileConfig.localHost,
    localPort: process.env.TERMLENS_AGENT_LOCAL_PORT || fileConfig.localPort
  });

  let retry = 1000;
  for (;;) {
    try {
      await connectAgent(config);
      retry = 1000;
    } catch (error) {
      console.error(`TermLens private agent disconnected: ${error.message}`);
    }
    await delay(retry);
    retry = Math.min(retry * 1.8, 30000);
  }
}

function connectAgent(config) {
  return new Promise((resolve, reject) => {
    const streams = new Map();
    const url = agentWebSocketUrl(config);
    const ws = new WebSocket(url, {
      headers: {
        Authorization: `Bearer ${config.agentToken}`,
        'X-TermLens-Endpoint-Id': String(config.endpointId)
      }
    });
    let opened = false;

    ws.on('open', () => {
      opened = true;
      retryLog(`TermLens private agent connected to ${safeUrl(url)}.`);
      send(ws, { type: 'hello', endpointId: config.endpointId });
    });

    ws.on('message', (raw) => {
      let message;
      try {
        message = JSON.parse(String(raw));
      } catch {
        return;
      }
      if (!message || typeof message.type !== 'string') return;

      if (message.type === 'ping') {
        send(ws, { type: 'pong' });
        return;
      }

      const streamId = String(message.streamId || '');
      if (!STREAM_ID_PATTERN.test(streamId)) return;

      if (message.type === 'stream-open') {
        openLocalStream(ws, streams, streamId, config);
        return;
      }

      const socket = streams.get(streamId);
      if (!socket) return;

      if (message.type === 'stream-data' && typeof message.data === 'string') {
        socket.write(Buffer.from(message.data, 'base64'));
        return;
      }

      if (message.type === 'stream-close') {
        socket.end();
      }
    });

    ws.on('close', () => {
      closeStreams(streams);
      if (opened) resolve();
      else reject(new Error('WebSocket closed before opening.'));
    });

    ws.on('error', (error) => {
      closeStreams(streams);
      if (!opened) reject(error);
    });
  });
}

function openLocalStream(ws, streams, streamId, config) {
  if (streams.has(streamId)) return;
  const socket = net.connect({
    host: config.localHost,
    port: config.localPort,
    noDelay: true
  });
  streams.set(streamId, socket);

  socket.on('connect', () => {
    send(ws, { type: 'stream-opened', streamId });
  });

  socket.on('data', (data) => {
    send(ws, {
      type: 'stream-data',
      streamId,
      data: data.toString('base64')
    });
  });

  socket.on('error', (error) => {
    send(ws, { type: 'stream-error', streamId, message: error.message });
    streams.delete(streamId);
  });

  socket.on('close', () => {
    send(ws, { type: 'stream-closed', streamId });
    streams.delete(streamId);
  });
}

function closeStreams(streams) {
  for (const socket of streams.values()) socket.destroy();
  streams.clear();
}

function normalizeAgentConfig(input) {
  const server = String(input.server || '').trim();
  const webSocketUrl = String(input.webSocketUrl || '').trim();
  const endpointId = Number(input.endpointId);
  const agentToken = String(input.agentToken || '').trim();
  const localHost = normalizePrivateRelayHost(input.localHost || '127.0.0.1');
  const localPort = Number(input.localPort || 22);
  const allowNonLoopback = process.env.TERMLENS_AGENT_ALLOW_NON_LOOPBACK === 'true';

  if (!server && !webSocketUrl) throw new Error('TERMLENS_AGENT_SERVER or TERMLENS_AGENT_WS_URL is required.');
  if (!Number.isInteger(endpointId) || endpointId < 1) throw new Error('A valid endpoint id is required.');
  if (!agentToken) throw new Error('A valid agent token is required.');
  if (!isAllowedPrivateRelayHost(localHost, allowNonLoopback)) {
    throw new Error('The agent only forwards loopback SSH by default. Set TERMLENS_AGENT_ALLOW_NON_LOOPBACK=true to opt in.');
  }
  if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
    throw new Error('A valid local SSH port is required.');
  }

  return { server, webSocketUrl, endpointId, agentToken, localHost, localPort };
}

function agentWebSocketUrl(config) {
  const url = config.webSocketUrl
    ? new URL(config.webSocketUrl, normalizeServerUrl(config.server || 'http://localhost/'))
    : new URL('ws/private-agent', normalizeServerUrl(config.server));
  url.protocol = url.protocol === 'https:' ? 'wss:' : url.protocol === 'http:' ? 'ws:' : url.protocol;
  url.searchParams.delete('endpointId');
  url.searchParams.delete('token');
  return url.toString();
}

function normalizeServerUrl(value) {
  const url = new URL(value);
  if (!url.pathname.endsWith('/')) url.pathname = `${url.pathname}/`;
  return url;
}

function readConfig() {
  const file = configPath();
  if (!fs.existsSync(file)) return {};
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeConfig(config) {
  const file = configPath();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(file, 0o600);
  } catch {}
}

function configPath() {
  return process.env.TERMLENS_AGENT_CONFIG || DEFAULT_CONFIG_PATH;
}

function send(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeUrl(value) {
  const url = new URL(value);
  if (url.searchParams.has('token')) url.searchParams.set('token', 'redacted');
  return url.toString();
}

function retryLog(message) {
  console.log(`${new Date().toISOString()} ${message}`);
}

function fail(error) {
  console.error(error.message);
  process.exit(1);
}
