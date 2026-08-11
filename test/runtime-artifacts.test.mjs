import test from 'node:test';
import assert from 'node:assert/strict';
import { assertRuntimeArtifacts } from '../lib/artifacts.mjs';

test('production readiness checks the pinned verifier artifacts', async () => {
  await assert.doesNotReject(() => assertRuntimeArtifacts({ production: true, role: 'relying' }));
  await assert.doesNotReject(() => assertRuntimeArtifacts({ production: true, role: 'gateway' }));
  await assert.doesNotReject(() => assertRuntimeArtifacts({ production: false, role: 'gateway' }));
});

test('production readiness fails closed when the artifact directory is unavailable', async () => {
  const previous = process.env.ZK_TELE_AUTH_ARTIFACTS_DIR;
  process.env.ZK_TELE_AUTH_ARTIFACTS_DIR = '/path/that/does/not/exist';
  try {
    await assert.rejects(() => assertRuntimeArtifacts({ production: true, role: 'gateway' }));
  } finally {
    if (previous === undefined) delete process.env.ZK_TELE_AUTH_ARTIFACTS_DIR;
    else process.env.ZK_TELE_AUTH_ARTIFACTS_DIR = previous;
  }
});
