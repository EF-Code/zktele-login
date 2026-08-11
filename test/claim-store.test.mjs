import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryClaimStore } from '../lib/claim-store.mjs';

test('claim store rejects a duplicate scoped nullifier', async () => {
  const store = new MemoryClaimStore();
  const metadata = { issuer: 'issuer', appDomain: 'app', actionId: 'action' };
  assert.deepEqual(await store.claim('nullifier', metadata), { claimed: true, claims: 1 });
  assert.deepEqual(await store.claim('nullifier', metadata), { claimed: false, claims: 1 });
});
