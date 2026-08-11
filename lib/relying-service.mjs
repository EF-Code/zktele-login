import * as crypto from 'crypto';
import { ZkAuthProofVerifier } from 'zk-tele-auth/dist/sdk/proof-verifier.js';
import { parseTelegramAuthPublicSignals } from 'zk-tele-auth/dist/sdk/public-signals.js';
import {
  publicKeyFingerprint,
  publicKeyPem,
  verifyAttestationSignature,
} from './attestation.mjs';

function fixedPolicy(config) {
  return {
    expectedAppDomain: config.appDomain,
    expectedIssuerKeyHash: config.issuerKeyHash,
    maxTokenAgeSec: config.maxAuthAgeSec,
    requirePremium: config.requirePremium,
    clockSkewSec: 30,
  };
}

export function createRelyingService(config, dependencies = {}) {
  const keys = new Map(Object.entries(config.gatewayPublicKeys || {}).map(([keyId, pem]) => [
    keyId,
    crypto.createPublicKey(pem),
  ]));
  if (!keys.has(config.keyId)) throw new Error(`no public key is pinned for gateway key id ${config.keyId}`);
  const verifyProof = dependencies.verifyProof || ((payload, policy) => ZkAuthProofVerifier.verifyProof(payload, policy));
  const clock = dependencies.clock || (() => Math.floor(Date.now() / 1000));

  async function verify(envelope, expectedDomain = config.appDomain) {
    const fail = (error) => ({ isValid: false, nullifierHash: '', error });
    try {
      if (!envelope || typeof envelope !== 'object' || envelope.keyId !== config.keyId) {
        return fail('unexpected gateway key id');
      }
      const publicKey = keys.get(envelope.keyId);
      if (!publicKey || !verifyAttestationSignature(envelope, publicKey)) {
        return fail('invalid gateway attestation signature');
      }
      if (envelope.issuer !== config.issuer) return fail('unexpected gateway issuer');
      if (envelope.audience !== config.audience) return fail('unexpected attestation audience');
      if (envelope.appDomain !== expectedDomain || expectedDomain !== config.appDomain) {
        return fail('attestation is for a different application domain');
      }
      if (envelope.actionId !== config.actionId) return fail('attestation is for a different action');
      if (envelope.circuitId !== config.circuitId || envelope.circuitVersion !== config.circuitVersion) {
        return fail('attestation uses an unexpected circuit version');
      }
      if (envelope.artifactSetId !== config.artifactSetId) return fail('attestation uses unexpected proof artifacts');
      const now = clock();
      if (envelope.issuedAt > now + 30) return fail('attestation timestamp is in the future');
      if (envelope.expiresAt < now) return fail('gateway attestation has expired');
      if (envelope.expiresAt - envelope.issuedAt !== config.proofTtlSec) {
        return fail('gateway attestation uses an unexpected lifetime');
      }
      const signals = parseTelegramAuthPublicSignals(envelope.proofPayload.publicSignals);
      const payloadMetadata = envelope.proofPayload;
      if (payloadMetadata.nullifierHash !== undefined && payloadMetadata.nullifierHash !== signals.nullifierHash) return fail('proof payload metadata is inconsistent');
      if (payloadMetadata.appDomainHash !== undefined && payloadMetadata.appDomainHash !== signals.appDomainHash) return fail('proof payload metadata is inconsistent');
      if (payloadMetadata.timestamp !== undefined && payloadMetadata.timestamp !== signals.currentTimestamp) return fail('proof payload metadata is inconsistent');
      if (payloadMetadata.maxTokenAgeSec !== undefined && payloadMetadata.maxTokenAgeSec !== signals.maxTokenAgeSec) return fail('proof payload metadata is inconsistent');
      if (payloadMetadata.isPremiumRequired !== undefined && payloadMetadata.isPremiumRequired !== signals.isPremiumRequired) return fail('proof payload metadata is inconsistent');
      if (payloadMetadata.issuerKeyHash !== undefined && payloadMetadata.issuerKeyHash !== signals.issuerKeyHash) return fail('proof payload metadata is inconsistent');
      if (payloadMetadata.isVerified !== undefined && payloadMetadata.isVerified !== signals.isVerified) return fail('proof payload metadata is inconsistent');
      if (signals.currentTimestamp !== envelope.issuedAt) return fail('proof timestamp is not bound to attestation');
      if (signals.maxTokenAgeSec !== config.maxAuthAgeSec) return fail('proof uses an unexpected freshness policy');
      if (signals.isPremiumRequired !== config.requirePremium) return fail('proof uses an unexpected Premium policy');
      const policy = fixedPolicy(config);
      if (envelope.issuerKeyHash !== policy.expectedIssuerKeyHash || signals.issuerKeyHash !== policy.expectedIssuerKeyHash) {
        return fail('proof uses an unexpected issuer policy');
      }
      const result = await verifyProof(envelope.proofPayload, policy);
      if (!result.isValid) return fail(result.error || 'zero-knowledge proof is invalid');
      return {
        isValid: true,
        nullifierHash: result.nullifierHash,
        appDomainHash: result.appDomainHash,
        issuerKeyHash: result.issuerKeyHash,
        issuer: envelope.issuer,
        audience: envelope.audience,
        challenge: envelope.challenge,
        actionId: envelope.actionId,
        circuitId: envelope.circuitId,
        circuitVersion: envelope.circuitVersion,
        artifactSetId: envelope.artifactSetId,
        expiresAt: envelope.expiresAt,
      };
    } catch (error) {
      return fail(error instanceof Error ? error.message : 'attestation verification failed');
    }
  }

  const firstKey = keys.get(config.keyId);
  return Object.freeze({
    verify,
    publicKey: publicKeyPem(firstKey),
    publicKeyFingerprint: publicKeyFingerprint(firstKey),
    keyId: config.keyId,
  });
}

export { fixedPolicy };
