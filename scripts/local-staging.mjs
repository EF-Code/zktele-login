import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const envFile = path.join(root, '.env.local');
const composeFile = path.join(root, 'compose.local.yaml');
const command = process.argv[2] || 'up';

async function assertLocalEnv() {
  if (command === 'down' || command === 'reset') return;
  let stat;
  try {
    stat = await fs.stat(envFile);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error('missing .env.local; run npm run setup:local first');
    }
    throw error;
  }
  if ((stat.mode & 0o077) !== 0) throw new Error('.env.local must be mode 600 or stricter');
  const raw = await fs.readFile(envFile, 'utf8');
  const tokenLine = raw.split(/\r?\n/).find((line) => line.startsWith('TELEGRAM_BOT_TOKEN='));
  const token = tokenLine?.slice('TELEGRAM_BOT_TOKEN='.length).trim() || '';
  if (command === 'up' && !/^\d+:[A-Za-z0-9_-]{20,}$/.test(token)) {
    throw new Error('TELEGRAM_BOT_TOKEN is missing or malformed in .env.local');
  }
}

const argsByCommand = {
  up: ['up', '--build'],
  down: ['down'],
  logs: ['logs', '-f'],
  reset: ['down', '--volumes'],
};
if (!argsByCommand[command]) throw new Error(`unknown local staging command: ${command}`);
await assertLocalEnv();

const envFileArgs = command === 'down' || command === 'reset' ? [] : ['--env-file', envFile];
const child = spawn('docker', ['compose', ...envFileArgs, '--file', composeFile, ...argsByCommand[command]], {
  cwd: root,
  stdio: 'inherit',
});
child.once('error', (error) => {
  console.error(error.code === 'ENOENT' ? 'Docker is not installed or not on PATH' : error.message);
  process.exitCode = 1;
});
child.once('exit', (code, signal) => {
  if (signal) {
    process.exitCode = 1;
  } else {
    process.exitCode = code ?? 1;
  }
});
