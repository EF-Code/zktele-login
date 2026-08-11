import * as crypto from 'crypto';
import { ZkAuthProofGenerator } from 'zk-tele-auth/dist/sdk/proof-generator.js';
import { ZkAuthProofVerifier } from 'zk-tele-auth/dist/sdk/proof-verifier.js';
import { parseTelegramAuthPublicSignals } from 'zk-tele-auth/dist/sdk/public-signals.js';
import { NullifierDeriver } from 'zk-tele-auth/dist/sdk/nullifier.js';
import {
  createGatewayKeys,
  publicKeyFingerprint,
  publicKeyPem,
  signAttestation,
  verifyAttestationSignature,
} from './attestation.mjs';
import { validateTelegramInitData } from './telegram.mjs';

function deriveActionIssuerSecret(secret, issuer, appDomain, actionId, environmentId = '') {
  const digest = crypto
    .createHmac('sha256', secret)
    .update(`zktele-issuer-v2\0${environmentId}\0${issuer}\0${appDomain}\0${actionId}`)
    .digest()
    .subarray(0, 28);
  const value = BigInt(`0x${digest.toString('hex')}`);
  return (value === 0n ? 1n : value).toString();
}

export function createAuthService(config, dependencies = {}) {
  const keys = dependencies.keys || createGatewayKeys(config.gatewayPrivateKey);
  const generateProof = dependencies.generateProof || ((inputs) => ZkAuthProofGenerator.generateProof(inputs));
  const verifyProof = dependencies.verifyProof || ((payload, policy) => ZkAuthProofVerifier.verifyProof(payload, policy));
  const clock = dependencies.clock || (() => Math.floor(Date.now() / 1000));
  const issuerSecret = deriveActionIssuerSecret(
    config.nullifierSecret,
    config.issuer,
    config.appDomain,
    config.actionId,
    config.environmentId || '',
  );
  const issuerKeyHashPromise = NullifierDeriver.deriveIssuerKeyHash(issuerSecret);

  async function proofPolicy() {
    return {
      expectedAppDomain: config.appDomain,
      expectedIssuerKeyHash: await issuerKeyHashPromise,
      maxTokenAgeSec: config.maxAuthAgeSec,
      requirePremium: config.requirePremium,
      clockSkewSec: 30,
    };
  }

  function contextValue(name, value) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 512 || /[\u0000-\u001f\u007f\s]/.test(value)) {
      throw new Error(`${name} is required and must be a compact string`);
    }
    return value;
  }

  async function authenticate(initData, context = {}) {
    const telegram = validateInitData(initData);
    return authenticateValidated(telegram, context);
  }

  function validateInitData(initData) {
    return validateTelegramInitData(initData, {
      botToken: config.botToken,
      now: clock(),
      maxAgeSec: config.maxAuthAgeSec,
    });
  }

  async function authenticateValidated(telegram, context = {}) {
    const challenge = contextValue('challenge', context.challenge);
    const audience = contextValue('audience', context.audience);
    const appDomain = contextValue('appDomain', context.appDomain);
    const actionId = contextValue('actionId', context.actionId);
    if (audience !== config.audience) throw new Error('attestation audience is not allowed');
    if (appDomain !== config.appDomain) throw new Error('attestation app domain is not allowed');
    if (actionId !== config.actionId) throw new Error('attestation action is not allowed');
    const now = clock();
    if (config.requirePremium && !telegram.isPremium) throw new Error('Telegram Premium is required');

    const proofPayload = await generateProof({
      userId: telegram.userId,
      authDate: telegram.authDate,
      isPremium: telegram.isPremium,
      appDomain: config.appDomain,
      currentTimestamp: now,
      maxTokenAgeSec: config.maxAuthAgeSec,
      isPremiumRequired: config.requirePremium,
      issuerSecret,
    });
    const issuerKeyHash = await issuerKeyHashPromise;

    return signAttestation({
      keyId: config.keyId,
      issuer: config.issuer,
      appDomain: config.appDomain,
      actionId: config.actionId,
      audience: config.audience,
      challenge,
      issuedAt: now,
      expiresAt: now + config.proofTtlSec,
      circuitId: config.circuitId,
      circuitVersion: config.circuitVersion,
      artifactSetId: config.artifactSetId,
      issuerKeyHash,
      proofPayload,
    }, keys.privateKey);
  }

  async function verify(envelope, expectedDomain = config.appDomain) {
    const fail = (error) => ({ isValid: false, nullifierHash: '', error });
    try {
      if (!verifyAttestationSignature(envelope, keys.publicKey)) return fail('invalid gateway attestation signature');
      if (envelope.keyId !== config.keyId) return fail('unexpected gateway key id');
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
      const policy = await proofPolicy();
      if (envelope.issuerKeyHash !== policy.expectedIssuerKeyHash || signals.issuerKeyHash !== policy.expectedIssuerKeyHash) {
        return fail('proof uses an unexpected issuer policy');
      }

      const result = await verifyProof(envelope.proofPayload, policy);
      if (!result.isValid) return fail(result.error || 'zero-knowledge proof is invalid');
      if (result.nullifierHash !== signals.nullifierHash || result.appDomainHash !== signals.appDomainHash || result.issuerKeyHash !== policy.expectedIssuerKeyHash) {
        return fail('proof verifier returned inconsistent public signals');
      }
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
      return fail(error instanceof Error ? error.message : String(error));
    }
  }

  return Object.freeze({
    authenticate,
    validateInitData,
    authenticateValidated,
    verify,
    publicKey: publicKeyPem(keys.publicKey),
    publicKeyFingerprint: publicKeyFingerprint(keys.publicKey),
    keyId: config.keyId,
    issuerKeyHash: issuerKeyHashPromise,
  });
}

export { deriveActionIssuerSecret };
