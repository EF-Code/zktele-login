import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthService } from '../lib/auth-service.mjs';
import { deriveActionIssuerSecret } from '../lib/auth-service.mjs';
import { createGatewayKeys, publicKeyPem, signAttestation } from '../lib/attestation.mjs';
import { loadConfig } from '../lib/config.mjs';
import { createRelyingService } from '../lib/relying-service.mjs';
import { signTelegramInitData } from '../lib/telegram.mjs';
import { ZkAuthProofGenerator } from 'zk-tele-auth/dist/sdk/proof-generator.js';
import { ZkAuthProofVerifier } from 'zk-tele-auth/dist/sdk/proof-verifier.js';
import { NullifierDeriver } from 'zk-tele-auth/dist/sdk/nullifier.js';

test('real Groth16 proof is accepted only inside an untampered gateway attestation', { timeout: 120_000 }, async () => {
  const config = loadConfig({
    NODE_ENV: 'test',
    TELEGRAM_BOT_TOKEN: '123456:integration-token',
    NULLIFIER_SECRET: Buffer.alloc(32, 9).toString('base64'),
    APP_DOMAIN: 'integration.example',
    ACTION_ID: 'claim-v1',
    GATEWAY_KEY_ID: 'integration-key',
    ATTESTATION_AUDIENCE: 'integration.example',
    ARTIFACT_SET_ID: 'integration-artifacts',
  });
  const service = createAuthService(config);
  const now = Math.floor(Date.now() / 1000);
  const initData = signTelegramInitData({
    auth_date: String(now),
    query_id: 'integration-query',
    user: JSON.stringify({ id: 424242, first_name: 'Integration' }),
  }, config.botToken);

  const attestation = await service.authenticate(initData, {
    challenge: 'integration-challenge',
    audience: config.audience,
    appDomain: config.appDomain,
    actionId: config.actionId,
  });
  const verified = await service.verify(attestation);
  assert.equal(verified.isValid, true);

  const unsigned = structuredClone(attestation);
  delete unsigned.signature;
  assert.match((await service.verify(unsigned)).error, /malformed|signature/);

  const tampered = structuredClone(attestation);
  tampered.proofPayload.proof.pi_a[0] = '1';
  assert.match((await service.verify(tampered)).error, /signature/);
});

test('a public-artifact proof with the wrong issuer secret is rejected by the pinned policy', { timeout: 120_000 }, async () => {
  const config = loadConfig({
    NODE_ENV: 'test',
    TELEGRAM_BOT_TOKEN: '123456:forge-test-token',
    NULLIFIER_SECRET: Buffer.alloc(32, 3).toString('base64'),
    APP_DOMAIN: 'forge.example',
    ACTION_ID: 'claim-v1',
    GATEWAY_KEY_ID: 'forge-key',
    ATTESTATION_AUDIENCE: 'forge.example',
    ARTIFACT_SET_ID: 'forge-artifacts',
  });
  const now = Math.floor(Date.now() / 1000);
  const authorizedSecret = deriveActionIssuerSecret(
    config.nullifierSecret,
    config.issuer,
    config.appDomain,
    config.actionId,
    config.environmentId,
  );
  const expectedIssuerKeyHash = await NullifierDeriver.deriveIssuerKeyHash(authorizedSecret);
  const forged = await ZkAuthProofGenerator.generateProof({
    userId: 999999,
    authDate: now,
    isPremium: false,
    appDomain: config.appDomain,
    currentTimestamp: now,
    maxTokenAgeSec: config.maxAuthAgeSec,
    isPremiumRequired: config.requirePremium,
    issuerSecret: '123456789',
  });
  const result = await ZkAuthProofVerifier.verifyProof(forged, {
    expectedAppDomain: config.appDomain,
    expectedIssuerKeyHash,
    maxTokenAgeSec: config.maxAuthAgeSec,
    requirePremium: config.requirePremium,
  });
  assert.equal(result.isValid, false);
  assert.match(result.error, /issuerKeyHash|authorized issuer/);

  const gatewayKeys = createGatewayKeys();
  const relying = createRelyingService({
    keyId: config.keyId,
    issuer: config.issuer,
    audience: config.audience,
    appDomain: config.appDomain,
    actionId: config.actionId,
    circuitId: config.circuitId,
    circuitVersion: config.circuitVersion,
    artifactSetId: config.artifactSetId,
    issuerKeyHash: expectedIssuerKeyHash,
    maxAuthAgeSec: config.maxAuthAgeSec,
    proofTtlSec: config.proofTtlSec,
    requirePremium: config.requirePremium,
    gatewayPublicKeys: { [config.keyId]: publicKeyPem(gatewayKeys.publicKey) },
  }, { clock: () => now });
  const forgedAttestation = signAttestation({
    keyId: config.keyId,
    issuer: config.issuer,
    audience: config.audience,
    appDomain: config.appDomain,
    actionId: config.actionId,
    challenge: 'forge-challenge',
    issuedAt: now,
    expiresAt: now + config.proofTtlSec,
    circuitId: config.circuitId,
    circuitVersion: config.circuitVersion,
    artifactSetId: config.artifactSetId,
    issuerKeyHash: expectedIssuerKeyHash,
    proofPayload: forged,
  }, gatewayKeys.privateKey);
  const productionVerification = await relying.verify(forgedAttestation);
  assert.equal(productionVerification.isValid, false);
  assert.match(productionVerification.error, /issuer(?:KeyHash| policy)|authorized issuer/);
});
