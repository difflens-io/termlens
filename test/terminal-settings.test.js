import test from 'node:test';
import assert from 'node:assert/strict';
import {
  defaultTerminalSettings,
  normalizeTerminalSettings
} from '../src/server/terminal-settings.js';

test('terminal settings default to active renewal and idle timeout', () => {
  assert.deepEqual(defaultTerminalSettings({
    terminal: {
      idleTimeoutEnabled: true,
      activityRenewalEnabled: true,
      idleTimeoutSeconds: 28800
    }
  }), {
    idleTimeoutEnabled: true,
    activityRenewalEnabled: true,
    idleTimeoutSeconds: 28800
  });
});

test('terminal settings parse booleans and timeout seconds', () => {
  assert.deepEqual(normalizeTerminalSettings({
    idleTimeoutEnabled: 'false',
    activityRenewalEnabled: '1',
    idleTimeoutSeconds: '1800'
  }), {
    idleTimeoutEnabled: false,
    activityRenewalEnabled: true,
    idleTimeoutSeconds: 1800
  });
});

test('terminal idle timeout is clamped to a safe range', () => {
  assert.equal(normalizeTerminalSettings({ idleTimeoutSeconds: 1 }).idleTimeoutSeconds, 60);
  assert.equal(normalizeTerminalSettings({ idleTimeoutSeconds: 999999999 }).idleTimeoutSeconds, 604800);
});
