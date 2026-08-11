import test from 'node:test';
import assert from 'node:assert/strict';
import { createGatewayKeys, publicKeyPem, signAttestation } from '../lib/attestation.mjs';
import { createRelyingService } from '../lib/relying-service.mjs';

function config(keys, issuerKeyHash) {
  return {
    keyId: 'gateway-key',
    issuer: 'gateway',
    audience: 'app',
    appDomain: 'app',
    actionId: 'login',
    circuitId: 'telegram-auth',
    circuitVersion: '2',
    artifactSetId: 'artifacts',
    issuerKeyHash,
    maxAuthAgeSec: 300,
    proofTtlSec: 300,
    requirePremium: false,
    gatewayPublicKeys: { 'gateway-key': publicKeyPem(keys.publicKey) },
  };
}

test('relying verifier requires the pinned key id and issuer policy', async () => {
  const gateway = createGatewayKeys();
  const relyingConfig = config(gateway, '12345');
  const verifier = createRelyingService(relyingConfig, {
    verifyProof: async (_payload, policy) => ({
      isValid: true,
      nullifierHash: 'n',
      appDomainHash: 'h',
      issuerKeyHash: policy.expectedIssuerKeyHash,
    }),
    clock: () => 1_000,
  });
  const envelope = signAttestation({
    keyId: 'gateway-key', issuer: 'gateway', audience: 'app', appDomain: 'app', actionId: 'login',
    challenge: 'challenge', issuedAt: 900, expiresAt: 1_200, circuitId: 'telegram-auth', circuitVersion: '2',
    artifactSetId: 'artifacts', issuerKeyHash: '12345',
    proofPayload: { proof: { pi_a: ['1'] }, publicSignals: ['1', '1', '1', '900', '300', '0', '12345'] },
  }, gateway.privateKey);
  assert.equal((await verifier.verify(envelope)).isValid, true);
  const unknown = signAttestation({ ...envelope, keyId: 'other-key' }, createGatewayKeys().privateKey);
  assert.equal((await verifier.verify(unknown)).isValid, false);
});
