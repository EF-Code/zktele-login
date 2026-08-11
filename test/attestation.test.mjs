import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalize,
  createGatewayKeys,
  signAttestation,
  verifyAttestationSignature,
} from '../lib/attestation.mjs';

test('canonical serialization is independent of object key order', () => {
  assert.equal(canonicalize({ b: 2, a: { d: 4, c: 3 } }), canonicalize({ a: { c: 3, d: 4 }, b: 2 }));
});

test('gateway signature covers every proof-envelope field', () => {
  const keys = createGatewayKeys();
  const attestation = signAttestation({
    keyId: 'key-1',
    issuer: 'issuer',
    audience: 'relying.example',
    appDomain: 'example.app',
    actionId: 'vote-1',
    challenge: 'challenge-1',
    issuedAt: 100,
    expiresAt: 200,
    circuitId: 'telegram-auth',
    circuitVersion: '2',
    artifactSetId: 'artifacts-1',
    issuerKeyHash: 'issuer-hash',
    proofPayload: { proof: { pi_a: ['1'] }, publicSignals: ['1', '1', '1', '1', '1', '0', '1'] },
  }, keys.privateKey);
  assert.equal(verifyAttestationSignature(attestation, keys.publicKey), true);

  const tampered = structuredClone(attestation);
  tampered.proofPayload.proof.pi_a[0] = '2';
  assert.equal(verifyAttestationSignature(tampered, keys.publicKey), false);
});

test('attestation verification rejects unknown fields and malformed signatures', () => {
  const keys = createGatewayKeys();
  const attestation = signAttestation({
    keyId: 'key-1',
    issuer: 'issuer',
    audience: 'relying.example',
    appDomain: 'example.app',
    actionId: 'vote-1',
    challenge: 'challenge-1',
    issuedAt: 100,
    expiresAt: 200,
    circuitId: 'telegram-auth',
    circuitVersion: '2',
    artifactSetId: 'artifacts-1',
    issuerKeyHash: 'issuer-hash',
    proofPayload: { proof: { pi_a: ['1'] }, publicSignals: ['1', '1', '1', '1', '1', '0', '1'] },
  }, keys.privateKey);
  assert.equal(verifyAttestationSignature({ ...attestation, extra: true }, keys.publicKey), false);
  assert.equal(verifyAttestationSignature({ ...attestation, signature: 'not-base64' }, keys.publicKey), false);
  const oldCircuit = structuredClone(attestation);
  oldCircuit.proofPayload.publicSignals = ['1', '1', '1', '100', '300', '0'];
  assert.equal(verifyAttestationSignature(oldCircuit, keys.publicKey), false);
});
