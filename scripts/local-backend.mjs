import * as crypto from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createAuthService } from '../lib/auth-service.mjs';
import { loadConfig } from '../lib/config.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tokenFile = path.join(root, '.env.staging');
const relyingPort = Number(process.env.LOCAL_RELYING_PORT || 4000);
const gatewayPort = Number(process.env.LOCAL_GATEWAY_PORT || 4001);
const databaseUrl = process.env.LOCAL_DATABASE_URL
  || 'postgresql://zktele_runtime:runtime-local-only@127.0.0.1:55432/zktele';

function assertPort(name, value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} must be a valid port`);
}

assertPort('LOCAL_RELYING_PORT', relyingPort);
assertPort('LOCAL_GATEWAY_PORT', gatewayPort);
if (relyingPort === gatewayPort) throw new Error('local relying and gateway ports must differ');

async function readBotToken() {
  const stat = await fs.stat(tokenFile);
  if ((stat.mode & 0o077) !== 0) throw new Error('.env.staging must be mode 600 or stricter');
  const raw = (await fs.readFile(tokenFile, 'utf8')).trim();
  const line = raw.split(/\r?\n/).find((entry) => entry.startsWith('TELEGRAM_BOT_TOKEN='));
  const token = (line ? line.slice('TELEGRAM_BOT_TOKEN='.length) : raw.split(/\r?\n/)[0]).trim();
  if (!/^\d+:[A-Za-z0-9_-]{20,}$/.test(token)) throw new Error('staging bot token is malformed');
  return token;
}

function secret() {
  return crypto.randomBytes(32).toString('base64');
}

function keyMaterial() {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

async function waitReady(url, child, role) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`${role} exited before readiness`);
    try {
      const response = await fetch(`${url}/health/ready`, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch {
      // The service may still be loading the prover/artifacts.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`${role} did not become ready`);
}

const token = await readBotToken();
const keys = keyMaterial();
const nullifierSecret = secret();
const sessionSecret = secret();
const appDomain = 'local.zktele-login';
const actionId = 'login-v1';
const issuer = 'local-gateway';
const keyId = 'local-key';
const audience = appDomain;
const common = {
  NODE_ENV: 'test',
  ENVIRONMENT_ID: 'local-split',
  APP_ORIGIN: `http://localhost:${relyingPort}`,
  ALLOWED_ORIGINS: `http://localhost:${relyingPort}`,
  APP_DOMAIN: appDomain,
  ACTION_ID: actionId,
  GATEWAY_ISSUER: issuer,
  GATEWAY_KEY_ID: keyId,
  ATTESTATION_AUDIENCE: audience,
  CIRCUIT_ID: 'telegram-auth',
  CIRCUIT_VERSION: '2',
  ARTIFACT_SET_ID: 'local-artifacts',
  PROOF_CONCURRENCY: process.env.LOCAL_PROOF_CONCURRENCY || '2',
  RATE_LIMIT_PER_MINUTE: process.env.LOCAL_RATE_LIMIT_PER_MINUTE || '120',
};

const gatewayConfig = loadConfig({
  ...common,
  SERVICE_ROLE: 'gateway',
  PORT: String(gatewayPort),
  TELEGRAM_BOT_TOKEN: token,
  NULLIFIER_SECRET: nullifierSecret,
  GATEWAY_PRIVATE_KEY_BASE64: Buffer.from(keys.privateKey, 'utf8').toString('base64'),
});
const gatewayAuth = createAuthService(gatewayConfig);
const issuerKeyHash = await gatewayAuth.issuerKeyHash;

const relyingConfig = loadConfig({
  ...common,
  SERVICE_ROLE: 'relying',
  PORT: String(relyingPort),
  GATEWAY_ORIGIN: `http://localhost:${gatewayPort}`,
  DATABASE_URL: databaseUrl,
  DATABASE_SSL: 'false',
  SESSION_SECRET: sessionSecret,
  ISSUER_KEY_HASH: issuerKeyHash,
  GATEWAY_PUBLIC_KEY_BASE64: Buffer.from(keys.publicKey, 'utf8').toString('base64'),
});

function childEnvironment(roleConfig, role) {
  const env = { ...process.env, ...roleConfig };
  const gatewayOnly = ['TELEGRAM_BOT_TOKEN', 'NULLIFIER_SECRET', 'GATEWAY_PRIVATE_KEY_BASE64', 'GATEWAY_PRIVATE_KEY_FILE'];
  const relyingOnly = ['SESSION_SECRET', 'DATABASE_URL', 'DATABASE_SSL', 'DATABASE_CA_FILE', 'GATEWAY_PUBLIC_KEY_BASE64', 'GATEWAY_PUBLIC_KEYS_JSON', 'GATEWAY_PUBLIC_KEY_FILE'];
  for (const name of role === 'gateway' ? relyingOnly : gatewayOnly) delete env[name];
  return env;
}

function spawnRole(role, config) {
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: root,
    env: childEnvironment(config, role),
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  child.stderr.on('data', (chunk) => process.stderr.write(`[${role}] ${chunk}`));
  return child;
}

const gateway = spawnRole('gateway', {
  ...common,
  SERVICE_ROLE: 'gateway',
  PORT: String(gatewayPort),
  TELEGRAM_BOT_TOKEN: token,
  NULLIFIER_SECRET: nullifierSecret,
  GATEWAY_PRIVATE_KEY_BASE64: Buffer.from(keys.privateKey, 'utf8').toString('base64'),
});
const relying = spawnRole('relying', {
  ...common,
  SERVICE_ROLE: 'relying',
  PORT: String(relyingPort),
  GATEWAY_ORIGIN: `http://localhost:${gatewayPort}`,
  DATABASE_URL: databaseUrl,
  DATABASE_SSL: 'false',
  SESSION_SECRET: sessionSecret,
  ISSUER_KEY_HASH: issuerKeyHash,
  GATEWAY_PUBLIC_KEY_BASE64: Buffer.from(keys.publicKey, 'utf8').toString('base64'),
});

let stopping = false;
async function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of [gateway, relying]) {
    if (child.exitCode === null) child.kill('SIGTERM');
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
  for (const child of [gateway, relying]) {
    if (child.exitCode === null) child.kill('SIGKILL');
  }
  process.exit(code);
}

gateway.once('exit', (code) => { if (!stopping) { console.error(`gateway exited (${code ?? 'unknown'})`); void stop(1); } });
relying.once('exit', (code) => { if (!stopping) { console.error(`relying exited (${code ?? 'unknown'})`); void stop(1); } });
process.once('SIGINT', () => { void stop(0); });
process.once('SIGTERM', () => { void stop(0); });

try {
  await Promise.all([
    waitReady(`http://127.0.0.1:${gatewayPort}`, gateway, 'gateway'),
    waitReady(`http://127.0.0.1:${relyingPort}`, relying, 'relying'),
  ]);
  console.log(JSON.stringify({
    status: 'ready',
    relying: `http://localhost:${relyingPort}`,
    gateway: `http://localhost:${gatewayPort}`,
    database: 'local PostgreSQL runtime role',
    token: 'loaded from mode-600 ignored file (not printed)',
  }));
} catch (error) {
  console.error(error instanceof Error ? error.message : 'local backend failed');
  await stop(1);
}

await new Promise(() => {});
