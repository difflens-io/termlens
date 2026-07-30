const TERMINAL_IDLE_TIMEOUT_MIN_SECONDS = 60;
const TERMINAL_IDLE_TIMEOUT_MAX_SECONDS = 7 * 24 * 60 * 60;
const TERMINAL_SETTINGS_CACHE_MS = 10_000;
const SETTING_KEYS = {
  idleTimeoutEnabled: 'terminal.idle_timeout_enabled',
  activityRenewalEnabled: 'terminal.activity_renewal_enabled',
  idleTimeoutSeconds: 'terminal.idle_timeout_seconds'
};

export function defaultTerminalSettings(config) {
  return normalizeTerminalSettings({
    idleTimeoutEnabled: config.terminal?.idleTimeoutEnabled,
    activityRenewalEnabled: config.terminal?.activityRenewalEnabled,
    idleTimeoutSeconds: config.terminal?.idleTimeoutSeconds
  });
}

export function normalizeTerminalSettings(input = {}, fallback = {}) {
  const defaults = {
    idleTimeoutEnabled: true,
    activityRenewalEnabled: true,
    idleTimeoutSeconds: 8 * 60 * 60,
    ...fallback
  };
  return {
    idleTimeoutEnabled: booleanValue(input.idleTimeoutEnabled, defaults.idleTimeoutEnabled),
    activityRenewalEnabled: booleanValue(input.activityRenewalEnabled, defaults.activityRenewalEnabled),
    idleTimeoutSeconds: normalizeTimeoutSeconds(input.idleTimeoutSeconds, defaults.idleTimeoutSeconds)
  };
}

export function createTerminalSettingsStore({ db, config, nowIso }) {
  let cached = null;
  let cacheExpiresAt = 0;

  const defaults = defaultTerminalSettings(config);

  function get({ force = false } = {}) {
    const now = Date.now();
    if (!force && cached && cacheExpiresAt > now) return cached;

    const rows = db.prepare(`
      SELECT key, value
      FROM app_settings
      WHERE key LIKE 'terminal.%'
    `).all();
    const values = Object.fromEntries(rows.map((row) => [row.key, row.value]));
    cached = normalizeTerminalSettings({
      idleTimeoutEnabled: values[SETTING_KEYS.idleTimeoutEnabled],
      activityRenewalEnabled: values[SETTING_KEYS.activityRenewalEnabled],
      idleTimeoutSeconds: values[SETTING_KEYS.idleTimeoutSeconds]
    }, defaults);
    cacheExpiresAt = now + TERMINAL_SETTINGS_CACHE_MS;
    return cached;
  }

  function set(input) {
    const settings = normalizeTerminalSettings(input, get({ force: true }));
    const now = nowIso();
    const upsert = db.prepare(`
      INSERT INTO app_settings (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `);
    upsert.run(SETTING_KEYS.idleTimeoutEnabled, String(settings.idleTimeoutEnabled), now);
    upsert.run(SETTING_KEYS.activityRenewalEnabled, String(settings.activityRenewalEnabled), now);
    upsert.run(SETTING_KEYS.idleTimeoutSeconds, String(settings.idleTimeoutSeconds), now);
    cached = settings;
    cacheExpiresAt = Date.now() + TERMINAL_SETTINGS_CACHE_MS;
    return settings;
  }

  return { get, set, defaults };
}

function normalizeTimeoutSeconds(value, fallback) {
  const parsed = Number(value);
  const candidate = Number.isFinite(parsed) ? Math.round(parsed) : Number(fallback);
  return Math.min(
    TERMINAL_IDLE_TIMEOUT_MAX_SECONDS,
    Math.max(TERMINAL_IDLE_TIMEOUT_MIN_SECONDS, candidate)
  );
}

function booleanValue(value, fallback) {
  if (typeof value === 'boolean') return value;
  if (value === 'true' || value === '1' || value === 1) return true;
  if (value === 'false' || value === '0' || value === 0) return false;
  return Boolean(fallback);
}
