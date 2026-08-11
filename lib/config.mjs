import * as crypto from 'crypto';
import * as fs from 'fs';

const DEV_BOT_TOKEN = '123456:DEV-TOKEN-DO-NOT-USE-IN-PRODUCTION';

function booleanEnv(value, fallback = false) {
  if (value === undefined) return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`expected boolean environment value, got ${value}`);
}

function integerEnv(name, value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

function boundedIdentifier(name, value, fallback, maxLength = 255) {
  const result = value || fallback;
  if (!result || result.length > maxLength || !/^[a-zA-Z0-9._:-]+$/.test(result)) {
    throw new Error(`${name} contains unsupported characters or is too long`);
  }
  return result;
}

function requiredProductionIdentifier(name, value, fallback, maxLength = 255, production = false) {
  if (production && !value) throw new Error(`${name} is required in production`);
  const result = boundedIdentifier(name, value, fallback, maxLength);
  if (production && /^(?:example(?:[.-]|$)|dev(?:[.-]|$)|test(?:[.-]|$)|local(?:[.-]|$)|localhost$|change[-_]?me$|replace[-_]?me$|your[-_.])/.test(result.toLowerCase())) {
    throw new Error(`${name} must not use a placeholder production identity`);
  }
  return result;
}

function secretBytes(name, value, production) {
  if (!value) {
    if (production) throw new Error(`${name} is required in production`);
    return crypto.randomBytes(32);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error(`${name} must be base64 encoded`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) throw new Error(`${name} must be base64 encoded`);
  if (decoded.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
  return decoded;
}

function requiredSecretBytes(name, value) {
  if (!value) throw new Error(`${name} is required`);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error(`${name} must be base64 encoded`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) throw new Error(`${name} must be base64 encoded`);
  if (decoded.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
  return decoded;
}

function decodeBase64(name, value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error(`${name} must be base64 encoded`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) throw new Error(`${name} must be base64 encoded`);
  return decoded;
}

function gatewayPrivateKey(env, production) {
  const inline = env.GATEWAY_PRIVATE_KEY_BASE64;
  const keyFile = env.GATEWAY_PRIVATE_KEY_FILE;
  if (inline && keyFile) {
    throw new Error('set only one of GATEWAY_PRIVATE_KEY_BASE64 or GATEWAY_PRIVATE_KEY_FILE');
  }
  if (inline) return decodeBase64('GATEWAY_PRIVATE_KEY_BASE64', inline).toString('utf8');
  if (keyFile) return fs.readFileSync(keyFile, 'utf8');
  if (production) {
    throw new Error('GATEWAY_PRIVATE_KEY_BASE64 or GATEWAY_PRIVATE_KEY_FILE is required in production');
  }
  return null;
}

function publicKeyMap(env, keyId, required) {
  const inline = env.GATEWAY_PUBLIC_KEY_BASE64;
  const keyFile = env.GATEWAY_PUBLIC_KEY_FILE;
  const json = env.GATEWAY_PUBLIC_KEYS_JSON;
  const sources = [inline, keyFile, json].filter(Boolean);
  if (sources.length > 1) throw new Error('set only one gateway public-key source');
  if (json) {
    let parsed;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error('GATEWAY_PUBLIC_KEYS_JSON must be valid JSON');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('GATEWAY_PUBLIC_KEYS_JSON must be an object');
    }
    const result = {};
    for (const [id, value] of Object.entries(parsed)) {
      if (!/^[a-zA-Z0-9._:-]{1,128}$/.test(id) || typeof value !== 'string' || value.length > 8192) {
        throw new Error('GATEWAY_PUBLIC_KEYS_JSON contains an invalid key');
      }
      result[id] = value;
    }
    if (!result[keyId]) throw new Error(`GATEWAY_PUBLIC_KEYS_JSON must contain key id ${keyId}`);
    return Object.freeze(result);
  }
  if (inline) {
    const pem = decodeBase64('GATEWAY_PUBLIC_KEY_BASE64', inline).toString('utf8');
    if (!pem) throw new Error('GATEWAY_PUBLIC_KEY_BASE64 is empty');
    return Object.freeze({ [keyId]: pem });
  }
  if (keyFile) {
    const pem = fs.readFileSync(keyFile, 'utf8');
    if (!pem) throw new Error('GATEWAY_PUBLIC_KEY_FILE is empty');
    return Object.freeze({ [keyId]: pem });
  }
  if (required) throw new Error('GATEWAY_PUBLIC_KEY_FILE, GATEWAY_PUBLIC_KEY_BASE64, or GATEWAY_PUBLIC_KEYS_JSON is required');
  return Object.freeze({});
}

function originList(name, value, { required = false } = {}) {
  if (!value) {
    if (required) throw new Error(`${name} is required`);
    return Object.freeze(['http://localhost:3000']);
  }
  const origins = value.split(',').map((entry) => entry.trim()).filter(Boolean);
  if (origins.length === 0 || origins.length > 32) throw new Error(`${name} must contain one or more origins`);
  for (const origin of origins) {
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error(`${name} contains an invalid URL`);
    }
    if (parsed.origin !== origin || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      throw new Error(`${name} must contain canonical origins`);
    }
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && parsed.hostname === 'localhost')) {
      throw new Error(`${name} requires HTTPS except localhost development origins`);
    }
  }
  return Object.freeze([...new Set(origins)]);
}

function canonicalOrigin(name, value, production) {
  const raw = value || (production ? '' : 'http://localhost:3000');
  if (!raw) throw new Error(`${name} is required in production`);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`${name} must be a valid URL`);
  }
  if (parsed.origin !== raw || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error(`${name} must be a canonical origin`);
  }
  if (production && parsed.protocol !== 'https:') throw new Error(`${name} must use HTTPS in production`);
  return parsed.origin;
}

export function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  const production = nodeEnv === 'production';
  const role = env.SERVICE_ROLE || (production ? '' : 'combined');
  if (!['combined', 'gateway', 'relying'].includes(role)) {
    throw new Error('SERVICE_ROLE must be combined, gateway, or relying');
  }
  if (production && role === 'combined' && env.ALLOW_COMBINED_PRODUCTION !== 'true') {
    throw new Error('SERVICE_ROLE must be gateway or relying in production');
  }
  const allowDevInit = booleanEnv(env.ALLOW_DEV_INIT) && !production;
  const gatewayRole = role === 'gateway' || role === 'combined';
  const relyingRole = role === 'relying' || role === 'combined';
  const botToken = gatewayRole ? (env.TELEGRAM_BOT_TOKEN || (allowDevInit ? DEV_BOT_TOKEN : '')) : '';

  if (gatewayRole && !botToken) throw new Error('TELEGRAM_BOT_TOKEN is required on the gateway unless development simulation is enabled');
  if (production && botToken === DEV_BOT_TOKEN) throw new Error('the development bot token is forbidden in production');
  if (production && relyingRole && !env.DATABASE_URL) throw new Error('DATABASE_URL is required on the relying service in production');

  const appDomain = requiredProductionIdentifier('APP_DOMAIN', env.APP_DOMAIN, 'zktele-login.demo', 255, production);
  const actionId = requiredProductionIdentifier('ACTION_ID', env.ACTION_ID, 'login', 128, production);
  const issuer = requiredProductionIdentifier('GATEWAY_ISSUER', env.GATEWAY_ISSUER, appDomain, 255, production);
  const keyId = requiredProductionIdentifier('GATEWAY_KEY_ID', env.GATEWAY_KEY_ID, 'dev-key', 128, production);
  const audience = requiredProductionIdentifier('ATTESTATION_AUDIENCE', env.ATTESTATION_AUDIENCE, appDomain, 255, production);
  const circuitId = requiredProductionIdentifier('CIRCUIT_ID', env.CIRCUIT_ID, 'telegram-auth', 128, production);
  const circuitVersion = requiredProductionIdentifier('CIRCUIT_VERSION', env.CIRCUIT_VERSION, '2', 32, production);
  const artifactSetId = requiredProductionIdentifier('ARTIFACT_SET_ID', env.ARTIFACT_SET_ID, 'dev-artifacts', 255, production);
  const environmentId = requiredProductionIdentifier('ENVIRONMENT_ID', env.ENVIRONMENT_ID, 'development', 128, production);
  const appOrigin = canonicalOrigin('APP_ORIGIN', env.APP_ORIGIN, production);
  const maxAuthAgeSec = integerEnv('MAX_AUTH_AGE_SEC', env.MAX_AUTH_AGE_SEC, 300, {
    min: 30,
    max: 3600,
  });
  const proofTtlSec = integerEnv('PROOF_TTL_SEC', env.PROOF_TTL_SEC, 300, {
    min: 30,
    max: maxAuthAgeSec,
  });
  const challengeTtlSec = integerEnv('CHALLENGE_TTL_SEC', env.CHALLENGE_TTL_SEC, 300, {
    min: 30,
    max: proofTtlSec,
  });
  const sessionIdleTtlSec = integerEnv('SESSION_IDLE_TTL_SEC', env.SESSION_IDLE_TTL_SEC, 1800, {
    min: 60,
    max: 86_400,
  });
  const sessionAbsoluteTtlSec = integerEnv('SESSION_ABSOLUTE_TTL_SEC', env.SESSION_ABSOLUTE_TTL_SEC, 86_400, {
    min: sessionIdleTtlSec,
    max: 7 * 86_400,
  });
  const cleanupIntervalSec = integerEnv('CLEANUP_INTERVAL_SEC', env.CLEANUP_INTERVAL_SEC, 60, {
    min: 10,
    max: 3_600,
  });
  const metricsEnabled = booleanEnv(env.METRICS_ENABLED);
  const metricsToken = metricsEnabled && env.METRICS_TOKEN
    ? requiredSecretBytes('METRICS_TOKEN', env.METRICS_TOKEN)
    : null;
  if (production && metricsEnabled && !metricsToken) {
    throw new Error('METRICS_TOKEN is required when metrics are enabled in production');
  }
  const databaseCa = env.DATABASE_CA_FILE ? fs.readFileSync(env.DATABASE_CA_FILE, 'utf8') : undefined;
  const allowedOrigins = originList('ALLOWED_ORIGINS', env.ALLOWED_ORIGINS, { required: production });
  const gatewayOrigin = env.GATEWAY_ORIGIN ? canonicalOrigin('GATEWAY_ORIGIN', env.GATEWAY_ORIGIN, production) : '';
  if (production && role === 'relying' && !gatewayOrigin) throw new Error('GATEWAY_ORIGIN is required on the relying service in production');
  if (production && role === 'gateway' && env.DATABASE_URL) throw new Error('gateway service must not receive relying database credentials');
  const sessionSecret = relyingRole
    ? (env.SESSION_SECRET ? requiredSecretBytes('SESSION_SECRET', env.SESSION_SECRET) : (production ? (() => { throw new Error('SESSION_SECRET is required on the relying service in production'); })() : crypto.randomBytes(32)))
    : null;
  const issuerKeyHash = env.ISSUER_KEY_HASH || '';
  if ((role === 'relying' || production && role === 'combined') && !/^[0-9]+$/.test(issuerKeyHash)) {
    throw new Error('ISSUER_KEY_HASH is required on the relying service and must be a decimal field element');
  }
  const gatewayPublicKeys = publicKeyMap(env, keyId, role === 'relying' || production && role === 'combined');
  const nullifierSecret = gatewayRole ? secretBytes('NULLIFIER_SECRET', env.NULLIFIER_SECRET, production) : null;
  const privateKey = gatewayRole ? gatewayPrivateKey(env, production && gatewayRole) : null;
  if (role === 'relying' && (env.TELEGRAM_BOT_TOKEN || env.NULLIFIER_SECRET || env.GATEWAY_PRIVATE_KEY_FILE || env.GATEWAY_PRIVATE_KEY_BASE64)) {
    throw new Error('relying service must not receive gateway private secrets');
  }

  return Object.freeze({
    nodeEnv,
    production,
    allowDevInit,
    botToken,
    appDomain,
    actionId,
    role,
    environmentId,
    appOrigin,
    issuer,
    keyId,
    audience,
    circuitId,
    circuitVersion,
    artifactSetId,
    maxAuthAgeSec,
    proofTtlSec,
    challengeTtlSec,
    sessionIdleTtlSec,
    sessionAbsoluteTtlSec,
    cleanupIntervalSec,
    metricsEnabled,
    metricsToken,
    requirePremium: booleanEnv(env.REQUIRE_PREMIUM),
    port: integerEnv('PORT', env.PORT, 3000, { min: 1, max: 65535 }),
    bodyLimitBytes: integerEnv('BODY_LIMIT_BYTES', env.BODY_LIMIT_BYTES, 64 * 1024, {
      min: 1024,
      max: 1024 * 1024,
    }),
    proofConcurrency: integerEnv('PROOF_CONCURRENCY', env.PROOF_CONCURRENCY, 2, {
      min: 1,
      max: 16,
    }),
    rateLimitPerMinute: integerEnv('RATE_LIMIT_PER_MINUTE', env.RATE_LIMIT_PER_MINUTE, 20, {
      min: 1,
      max: 1000,
    }),
    databaseUrl: env.DATABASE_URL || '',
    databaseSsl: booleanEnv(env.DATABASE_SSL),
    databaseCa,
    allowedOrigins,
    gatewayOrigin,
    sessionSecret,
    issuerKeyHash,
    gatewayPublicKeys,
    nullifierSecret,
    gatewayPrivateKey: privateKey,
  });
}

export { DEV_BOT_TOKEN };
