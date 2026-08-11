import * as crypto from 'crypto';

const ATTESTATION_VERSION = 2;
const ENVELOPE_FIELDS = [
  'version',
  'keyId',
  'issuer',
  'audience',
  'appDomain',
  'actionId',
  'challenge',
  'issuedAt',
  'expiresAt',
  'circuitId',
  'circuitVersion',
  'artifactSetId',
  'issuerKeyHash',
  'proofPayload',
  'signature',
];
const MAX_CANONICAL_BYTES = 512 * 1024;

function assertCanonicalValue(value, path = 'value', depth = 0) {
  if (depth > 32) throw new Error(`${path} is too deeply nested`);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`${path} must be finite`);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 4096) throw new Error(`${path} is too large`);
    value.forEach((item, index) => assertCanonicalValue(item, `${path}[${index}]`, depth + 1));
    return;
  }
  if (typeof value === 'object') {
    if (Object.keys(value).length > 4096) throw new Error(`${path} has too many fields`);
    for (const key of Object.keys(value)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new Error(`${path} contains a forbidden key`);
      }
      if (key.length > 4096) throw new Error(`${path} contains an oversized key`);
      assertCanonicalValue(value[key], `${path}.${key}`, depth + 1);
    }
    return;
  }
  throw new Error(`${path} contains an unsupported value`);
}

function canonicalizeValue(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalizeValue).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeValue(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalize(value) {
  assertCanonicalValue(value);
  const result = canonicalizeValue(value);
  if (Buffer.byteLength(result, 'utf8') > MAX_CANONICAL_BYTES) throw new Error('canonical value is too large');
  return result;
}

function unsignedEnvelope(envelope) {
  const { signature: _signature, ...unsigned } = envelope;
  return unsigned;
}

function assertEnvelopeShape(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new Error('malformed gateway attestation');
  }
  const actualFields = Object.keys(envelope).sort();
  const expectedFields = [...ENVELOPE_FIELDS].sort();
  if (actualFields.length !== expectedFields.length || actualFields.some((field, index) => field !== expectedFields[index])) {
    throw new Error('gateway attestation has missing or unexpected fields');
  }
  const stringLimits = {
    keyId: 128,
    issuer: 255,
    audience: 255,
    appDomain: 255,
    actionId: 128,
    challenge: 512,
    circuitId: 128,
    circuitVersion: 32,
    artifactSetId: 255,
    issuerKeyHash: 100,
    signature: 128,
  };
  if (envelope.version !== ATTESTATION_VERSION || Object.entries(stringLimits).some(([key, max]) => (
    typeof envelope[key] !== 'string' || envelope[key].length === 0 || envelope[key].length > max || /[\u0000-\u001f\u007f\s]/.test(envelope[key])
  ))) {
    throw new Error('malformed gateway attestation');
  }
  if (!Number.isSafeInteger(envelope.issuedAt) || !Number.isSafeInteger(envelope.expiresAt)) {
    throw new Error('malformed gateway attestation timestamps');
  }
  if (envelope.issuedAt <= 0 || envelope.expiresAt <= envelope.issuedAt || envelope.expiresAt - envelope.issuedAt > 86_400) {
    throw new Error('invalid gateway attestation lifetime');
  }
  if (!envelope.proofPayload || typeof envelope.proofPayload !== 'object' || Array.isArray(envelope.proofPayload)) {
    throw new Error('malformed gateway proof payload');
  }
  const proofFields = Object.keys(envelope.proofPayload);
  const allowedProofFields = new Set([
    'proof', 'publicSignals', 'nullifierHash', 'appDomainHash', 'timestamp',
    'maxTokenAgeSec', 'isPremiumRequired', 'issuerKeyHash', 'isVerified',
  ]);
  if (!proofFields.includes('proof') || !proofFields.includes('publicSignals') || proofFields.some((field) => !allowedProofFields.has(field))) {
    throw new Error('malformed gateway proof payload');
  }
  if (!envelope.proofPayload.proof || typeof envelope.proofPayload.proof !== 'object' || Array.isArray(envelope.proofPayload.proof)) {
    throw new Error('malformed gateway proof');
  }
  if (!Array.isArray(envelope.proofPayload.publicSignals) || envelope.proofPayload.publicSignals.length !== 7 || envelope.proofPayload.publicSignals.some((value) => typeof value !== 'string' || value.length === 0 || value.length > 256)) {
    throw new Error('malformed issuer-bound public signals');
  }
  assertCanonicalValue(unsignedEnvelope(envelope));
}

export function createGatewayKeys(privateKeyPem = null) {
  if (privateKeyPem) {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('gateway private key must be Ed25519');
    return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
  }
  return crypto.generateKeyPairSync('ed25519');
}

export function publicKeyPem(publicKey) {
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

export function publicKeyFingerprint(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

export function signAttestation(fields, privateKey) {
  const { signature: _signature, version: _version, ...rest } = fields || {};
  const unsigned = { version: ATTESTATION_VERSION, ...rest };
  const signature = crypto.sign(null, Buffer.from(canonicalize(unsigned)), privateKey).toString('base64url');
  const envelope = { ...unsigned, signature };
  assertEnvelopeShape(envelope);
  return envelope;
}

export function verifyAttestationSignature(envelope, publicKey) {
  try {
    assertEnvelopeShape(envelope);
    if (!/^[A-Za-z0-9_-]+$/.test(envelope.signature)) return false;
    const signature = Buffer.from(envelope.signature, 'base64url');
    if (signature.length !== 64) return false;
    return crypto.verify(
      null,
      Buffer.from(canonicalize(unsignedEnvelope(envelope))),
      publicKey,
      signature,
    );
  } catch {
    return false;
  }
}

export { ATTESTATION_VERSION, ENVELOPE_FIELDS, canonicalize, assertEnvelopeShape };
