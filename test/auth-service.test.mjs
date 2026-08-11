import test from 'node:test';
import assert from 'node:assert/strict';
import { createGatewayKeys, signAttestation } from '../lib/attestation.mjs';
import { createAuthService, deriveActionIssuerSecret } from '../lib/auth-service.mjs';
import { signTelegramInitData } from '../lib/telegram.mjs';
import { NullifierDeriver } from 'zk-tele-auth/dist/sdk/nullifier.js';

const NOW = 1_800_000_000;
const BOT_TOKEN = '123456:test-token';

function config() {
  return {
    botToken: BOT_TOKEN,
    appDomain: 'example.app',
    actionId: 'claim-v1',
    issuer: 'example-gateway',
    keyId: 'key-1',
    audience: 'example.app',
    circuitId: 'telegram-auth',
    circuitVersion: '2',
    artifactSetId: 'test-artifacts',
    environmentId: 'test',
    maxAuthAgeSec: 300,
    proofTtlSec: 120,
    requirePremium: false,
    nullifierSecret: Buffer.alloc(32, 7),
    gatewayPrivateKey: null,
  };
}

function initData(userId = 42) {
  return signTelegramInitData({
    auth_date: String(NOW - 1),
    query_id: `query-${userId}`,
    user: JSON.stringify({ id: userId, first_name: 'Test' }),
  }, BOT_TOKEN);
}

test('requires a signed gateway envelope and fixed domain/freshness policy', async () => {
  const keys = createGatewayKeys();
  const capturedInputs = [];
  const issuerKeyHash = await NullifierDeriver.deriveIssuerKeyHash(
    deriveActionIssuerSecret(Buffer.alloc(32, 7), 'example-gateway', 'example.app', 'claim-v1', 'test'),
  );
  const service = createAuthService(config(), {
    keys,
    clock: () => NOW,
    generateProof: async (inputs) => {
      capturedInputs.push(inputs);
      return {
        proof: { pi_a: ['proof'] },
        publicSignals: ['1234', '1', '9999', String(NOW), '300', '0', issuerKeyHash],
      };
    },
    verifyProof: async (_payload, policy) => ({
      isValid: true,
      nullifierHash: '1234',
      appDomainHash: '9999',
      issuerKeyHash: policy.expectedIssuerKeyHash,
    }),
  });

  const context = { challenge: 'test-challenge', audience: 'example.app', appDomain: 'example.app', actionId: 'claim-v1' };
  const first = await service.authenticate(initData(42), context);
  const second = await service.authenticate(initData(42), { ...context, challenge: 'test-challenge-2' });
  assert.equal(capturedInputs[0].issuerSecret, capturedInputs[1].issuerSecret, 'issuer secret must be stable for an action');
  assert.equal(capturedInputs[0].issuerSecret, deriveActionIssuerSecret(Buffer.alloc(32, 7), 'example-gateway', 'example.app', 'claim-v1', 'test'));
  assert.equal((await service.verify(first)).isValid, true);
  assert.match((await service.verify(first, 'other.example')).error, /different application domain/);

  const forged = { ...first, signature: '' };
  assert.match((await service.verify(forged)).error, /signature/);

  const tampered = structuredClone(first);
  tampered.proofPayload.publicSignals[0] = '9876';
  assert.match((await service.verify(tampered)).error, /signature/);

  const wrongPolicy = signAttestation({
    ...first,
    proofPayload: { ...first.proofPayload, publicSignals: ['1234', '1', '9999', String(NOW), '999', '0', issuerKeyHash] },
  }, keys.privateKey);
  assert.match((await service.verify(wrongPolicy)).error, /freshness policy/);
  assert.equal(second.actionId, 'claim-v1');
});
