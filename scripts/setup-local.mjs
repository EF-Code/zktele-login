import * as crypto from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const localEnvPath = path.join(root, '.env.local');
const stagingEnvPath = path.join(root, '.env.staging');

function secret() {
  return crypto.randomBytes(32).toString('base64');
}

function tokenFromText(text) {
  const line = text.split(/\r?\n/).find((entry) => entry.startsWith('TELEGRAM_BOT_TOKEN='));
  const token = (line ? line.slice('TELEGRAM_BOT_TOKEN='.length) : text.split(/\r?\n/)[0] || '').trim();
  return /^\d+:[A-Za-z0-9_-]{20,}$/.test(token) ? token : '';
}

async function readStagingToken() {
  try {
    const stat = await fs.stat(stagingEnvPath);
    if ((stat.mode & 0o077) !== 0) return '';
    return tokenFromText(await fs.readFile(stagingEnvPath, 'utf8'));
  } catch {
    return '';
  }
}

function envLine(name, value) {
  return `${name}=${value}\n`;
}

async function main() {
  try {
    const stat = await fs.stat(localEnvPath);
    if ((stat.mode & 0o077) !== 0) {
      throw new Error('.env.local exists but is readable by group/other; run chmod 600 .env.local');
    }
    console.log('.env.local already exists; leaving it unchanged');
    return;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  const token = await readStagingToken();
  const lines = [
    '# Local combined Telegram staging configuration. This file is ignored by Git.\n',
    '# It is suitable for local testing only; use the split production profile for deployment.\n',
    envLine('NODE_ENV', 'development'),
    envLine('SERVICE_ROLE', 'combined'),
    envLine('ALLOW_DEV_INIT', 'false'),
    envLine('ENVIRONMENT_ID', 'local-telegram'),
    envLine('PORT', '3000'),
    envLine('APP_ORIGIN', 'http://localhost:3000'),
    envLine('ALLOWED_ORIGINS', 'http://localhost:3000'),
    envLine('APP_DOMAIN', 'local.zktele-login'),
    envLine('ACTION_ID', 'login-v1'),
    envLine('GATEWAY_ISSUER', 'local-gateway'),
    envLine('GATEWAY_KEY_ID', 'local-key'),
    envLine('ATTESTATION_AUDIENCE', 'local.zktele-login'),
    envLine('CIRCUIT_ID', 'telegram-auth'),
    envLine('CIRCUIT_VERSION', '2'),
    envLine('ARTIFACT_SET_ID', 'local-artifacts'),
    envLine('TELEGRAM_BOT_TOKEN', token),
    envLine('NULLIFIER_SECRET', secret()),
    envLine('SESSION_SECRET', secret()),
    envLine('DATABASE_URL', 'postgresql://zktele_local:local-development-only@127.0.0.1:55432/zktele'),
    envLine('DATABASE_SSL', 'false'),
    envLine('PROOF_CONCURRENCY', '2'),
    envLine('RATE_LIMIT_PER_MINUTE', '120'),
  ].join('');
  await fs.writeFile(localEnvPath, lines, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await fs.chmod(localEnvPath, 0o600);
  console.log(`created .env.local${token ? ' and copied the mode-600 staging bot token' : '; add TELEGRAM_BOT_TOKEN before Telegram staging'}`);
}

await main();
