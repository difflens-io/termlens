const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

export function normalizePrivateRelayHost(host) {
  const value = String(host || '').trim();
  if (value.toLowerCase() === '[::1]') return '::1';
  return value;
}

export function isAllowedPrivateRelayHost(host, allowNonLoopback = false) {
  const value = normalizePrivateRelayHost(host).toLowerCase();
  if (!value) return false;
  if (allowNonLoopback) return /^[a-z0-9._:-]{1,253}$/.test(value);
  return LOOPBACK_HOSTS.has(value);
}
