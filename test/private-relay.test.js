import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isAllowedPrivateRelayHost,
  normalizePrivateEndpointInput
} from '../src/server/private-relay.js';

test('private relay only allows loopback hosts by default', () => {
  assert.equal(isAllowedPrivateRelayHost('127.0.0.1'), true);
  assert.equal(isAllowedPrivateRelayHost('localhost'), true);
  assert.equal(isAllowedPrivateRelayHost('::1'), true);
  assert.equal(isAllowedPrivateRelayHost('[::1]'), true);
  assert.equal(isAllowedPrivateRelayHost('192.168.1.5'), false);
  assert.equal(isAllowedPrivateRelayHost('example.com'), false);
});

test('private relay can explicitly allow non-loopback hosts', () => {
  assert.equal(isAllowedPrivateRelayHost('192.168.1.5', true), true);
  assert.equal(isAllowedPrivateRelayHost('example.com', true), true);
  assert.equal(isAllowedPrivateRelayHost('bad host name', true), false);
});

test('private endpoint input is normalized and constrained', () => {
  assert.deepEqual(
    normalizePrivateEndpointInput({
      name: 'Laptop',
      localHost: '127.0.0.1',
      localPort: '22',
      sshUsername: 'dev_user'
    }),
    {
      name: 'Laptop',
      localHost: '127.0.0.1',
      localPort: 22,
      sshUsername: 'dev_user'
    }
  );

  assert.equal(normalizePrivateEndpointInput({
    name: 'IPv6 local',
    localHost: '[::1]',
    sshUsername: 'dev'
  }).localHost, '::1');

  assert.throws(() => normalizePrivateEndpointInput({ name: 'LAN', localHost: '192.168.1.5', sshUsername: 'dev' }));
  assert.throws(() => normalizePrivateEndpointInput({ name: 'Bad user', sshUsername: 'bad user' }));
});
