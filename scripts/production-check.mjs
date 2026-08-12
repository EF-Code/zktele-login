import { loadConfig } from '../lib/config.mjs';

const config = loadConfig({ ...process.env, NODE_ENV: 'production' });
if (config.role === 'combined') throw new Error('production-check requires SERVICE_ROLE=gateway or SERVICE_ROLE=relying');

const requiredNames = config.role === 'gateway'
  ? ['TELEGRAM_BOT_TOKEN', 'NULLIFIER_SECRET']
  : ['SESSION_SECRET', 'DATABASE_URL'];
const missing = requiredNames.filter((name) => !process.env[name]);
const keySources = config.role === 'gateway'
  ? ['GATEWAY_PRIVATE_KEY_BASE64', 'GATEWAY_PRIVATE_KEY_FILE']
  : ['GATEWAY_PUBLIC_KEY_BASE64', 'GATEWAY_PUBLIC_KEY_FILE', 'GATEWAY_PUBLIC_KEYS_JSON'];
if (!keySources.some((name) => process.env[name])) missing.push(`one of ${keySources.join(', ')}`);
if (missing.length > 0) throw new Error(`missing production ${config.role} inputs: ${missing.join(', ')}`);

console.log(JSON.stringify({
  status: 'valid',
  role: config.role,
  environmentId: config.environmentId,
  appOrigin: config.appOrigin,
  appDomain: config.appDomain,
  audience: config.audience,
  actionId: config.actionId,
  issuer: config.issuer,
  keyId: config.keyId,
  circuitId: config.circuitId,
  circuitVersion: config.circuitVersion,
  artifactSetId: config.artifactSetId,
  databaseSsl: config.databaseSsl,
  allowedOrigins: config.allowedOrigins,
  devSimulationEnabled: config.allowDevInit,
  requiredInputsPresent: true,
}));
