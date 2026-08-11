import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryChallengeStore, hashChallenge } from '../lib/challenge-store.mjs';

test('challenge is random, scoped, hashed, and single-use', async () => {
  const store = new MemoryChallengeStore();
  const created = await store.create({ audience: 'aud', appDomain: 'app', actionId: 'login', ttlSec: 60, now: 100 });
  assert.equal(created.challenge.length >= 43, true);
  assert.match(hashChallenge(created.challenge), /^[0-9a-f]{64}$/);
  assert.equal((await store.consume(created.challenge, { audience: 'wrong', appDomain: 'app', actionId: 'login' }, 101)).consumed, false);
  assert.equal((await store.consume(created.challenge, { audience: 'aud', appDomain: 'app', actionId: 'login' }, 101)).consumed, true);
  assert.equal((await store.consume(created.challenge, { audience: 'aud', appDomain: 'app', actionId: 'login' }, 101)).consumed, false);
});

test('expired challenge cannot be consumed', async () => {
  const store = new MemoryChallengeStore();
  const created = await store.create({ audience: 'aud', appDomain: 'app', actionId: 'login', ttlSec: 60, now: 100 });
  const result = await store.consume(created.challenge, { audience: 'aud', appDomain: 'app', actionId: 'login' }, 161);
  assert.equal(result.consumed, false);
  assert.match(result.reason, /expired|not found/);
});
