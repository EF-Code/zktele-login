import * as fs from 'fs/promises';
import * as path from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const packageRoot = path.dirname(require.resolve('zk-tele-auth/package.json'));
const artifactNames = {
  r1cs: 'telegram_auth.r1cs',
  wasm: 'telegram_auth.wasm',
  zkey: 'telegram_auth_final.zkey',
  vkey: 'telegram_auth_vkey.json',
};

function artifactDirectory() {
  return process.env.ZK_TELE_AUTH_ARTIFACTS_DIR
    ? path.join(process.env.ZK_TELE_AUTH_ARTIFACTS_DIR, 'telegram_auth')
    : path.join(packageRoot, 'artifacts', 'telegram_auth');
}

/**
 * Fail closed before a production process advertises readiness if the pinned
 * proving/verifying artifacts are missing or unreadable.
 */
export async function assertRuntimeArtifacts({ production, role }) {
  if (!production) return;
  const names = role === 'relying' ? [artifactNames.vkey] : Object.values(artifactNames);
  const directory = artifactDirectory();
  await Promise.all(names.map(async (name) => {
    const file = path.join(directory, name);
    const handle = await fs.open(file, 'r');
    await handle.close();
  }));
}

export { artifactNames, artifactDirectory };
