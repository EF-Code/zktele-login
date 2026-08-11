import test from 'node:test';
import assert from 'node:assert/strict';
import { MemorySessionStore, hashSessionToken } from '../lib/session-store.mjs';

test('session tokens are high entropy, hashed at rest, and revocable', async () => {
  const store = new MemorySessionStore();
  const created = await store.create({
    nullifierHash: 'nullifier',
    issuer: 'issuer',
    appDomain: 'app',
    actionId: 'login',
    idleTtlSec: 60,
    absoluteTtlSec: 300,
    now: 1_000,
  });
  assert.equal(created.token.length >= 43, true);
  assert.equal(hashSessionToken(created.token).includes(created.token), false);
  assert.equal((await store.get(created.token, 1_010)).nullifierHash, 'nullifier');
  assert.equal(await store.revoke(created.token), true);
  assert.equal(await store.get(created.token, 1_011), null);
});

test('expired sessions cannot be read', async () => {
  const store = new MemorySessionStore();
  const created = await store.create({
    nullifierHash: 'nullifier', issuer: 'issuer', appDomain: 'app', actionId: 'login',
    idleTtlSec: 60, absoluteTtlSec: 300, now: 1_000,
  });
  assert.equal(await store.get(created.token, 1_061), null);
});
