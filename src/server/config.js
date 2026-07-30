import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '../..');
const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;

function normalizeBasePath(value) {
  let basePath = value || '/project/termlens/';
  if (!basePath.startsWith('/')) basePath = `/${basePath}`;
  if (!basePath.endsWith('/')) basePath = `${basePath}/`;
  return basePath;
}

function numberFromEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return parsed;
}

function booleanFromEnv(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return raw === 'true' || raw === '1';
}

const sessionTtlSeconds = numberFromEnv('TERMLENS_SESSION_TTL_SECONDS', DEFAULT_SESSION_TTL_SECONDS);

export const config = {
  projectRoot,
  distDir: path.resolve(projectRoot, 'dist/client'),
  dataDir: process.env.TERMLENS_DATA_DIR || path.resolve(projectRoot, 'data'),
  dbPath:
    process.env.TERMLENS_DB_PATH ||
    path.resolve(process.env.TERMLENS_DATA_DIR || path.resolve(projectRoot, 'data'), 'termlens.sqlite'),
  host: process.env.TERMLENS_HOST || process.env.HOST || '127.0.0.1',
  port: numberFromEnv('TERMLENS_PORT', numberFromEnv('PORT', 7682)),
  basePath: normalizeBasePath(process.env.TERMLENS_BASE_PATH),
  publicUrl: process.env.TERMLENS_PUBLIC_URL || '',
  sessionTtlSeconds,
  ticketTtlSeconds: numberFromEnv('TERMLENS_TICKET_TTL_SECONDS', 10 * 60),
  mfaEnrollmentTtlSeconds: numberFromEnv('TERMLENS_MFA_ENROLLMENT_TTL_SECONDS', 10 * 60),
  cookieName: process.env.TERMLENS_COOKIE_NAME || 'tl_session',
  cookieSecure: process.env.TERMLENS_COOKIE_SECURE
    ? process.env.TERMLENS_COOKIE_SECURE === 'true'
    : process.env.NODE_ENV === 'production',
  secretKey: process.env.TERMLENS_SECRET_KEY || '',
  privateRelay: {
    enabled: booleanFromEnv('TERMLENS_PRIVATE_RELAY_ENABLED', false),
    allowNonLoopback: booleanFromEnv('TERMLENS_PRIVATE_RELAY_ALLOW_NON_LOOPBACK', false),
    enrollmentTtlSeconds: numberFromEnv('TERMLENS_PRIVATE_RELAY_ENROLLMENT_TTL_SECONDS', 10 * 60),
    agentHeartbeatSeconds: numberFromEnv('TERMLENS_PRIVATE_RELAY_AGENT_HEARTBEAT_SECONDS', 30),
    maxStreamsPerAgent: numberFromEnv('TERMLENS_PRIVATE_RELAY_MAX_STREAMS_PER_AGENT', 4),
    streamOpenTimeoutSeconds: numberFromEnv('TERMLENS_PRIVATE_RELAY_STREAM_OPEN_TIMEOUT_SECONDS', 15)
  },
  terminal: {
    idleTimeoutEnabled: booleanFromEnv('TERMLENS_TERMINAL_IDLE_TIMEOUT_ENABLED', true),
    activityRenewalEnabled: booleanFromEnv('TERMLENS_TERMINAL_ACTIVITY_RENEWAL_ENABLED', true),
    idleTimeoutSeconds: numberFromEnv('TERMLENS_TERMINAL_IDLE_TIMEOUT_SECONDS', sessionTtlSeconds)
  }
};

export const mountPath = config.basePath.slice(0, -1);
