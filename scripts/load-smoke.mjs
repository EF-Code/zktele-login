import assert from 'node:assert/strict';
import { loadConfig } from '../lib/config.mjs';
import { MemoryClaimStore } from '../lib/claim-store.mjs';
import { createApplication } from '../server.mjs';

function positiveInteger(name, fallback, max) {
  const value = process.env[name] === undefined ? fallback : Number(process.env[name]);
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new Error(`${name} must be an integer between 1 and ${max}`);
  return value;
}

const requests = positiveInteger('LOAD_REQUESTS', 250, 900);
const concurrency = Math.min(positiveInteger('LOAD_CONCURRENCY', 25, 500), requests);
const targetP95Ms = Number(process.env.LOAD_TARGET_P95_MS || 500);
if (!Number.isFinite(targetP95Ms) || targetP95Ms <= 0) throw new Error('LOAD_TARGET_P95_MS must be positive');

const config = loadConfig({
  NODE_ENV: 'test',
  ALLOW_DEV_INIT: 'true',
  METRICS_ENABLED: 'true',
  RATE_LIMIT_PER_MINUTE: String(Math.max(100, requests + 10)),
});
const app = await createApplication({
  config,
  authService: {
    publicKey: 'PUBLIC KEY',
    publicKeyFingerprint: 'fingerprint',
    authenticate: async () => ({ signed: true }),
    verify: async () => ({ isValid: false }),
  },
  claimStore: new MemoryClaimStore(),
});

await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
const baseUrl = `http://127.0.0.1:${app.server.address().port}`;
const durations = [];
let next = 0;
let failures = 0;
const startedHeap = process.memoryUsage().heapUsed;

async function worker() {
  while (true) {
    const index = next;
    next += 1;
    if (index >= requests) return;
    const started = process.hrtime.bigint();
    try {
      const response = await fetch(`${baseUrl}/api/challenge`, { signal: AbortSignal.timeout(10_000) });
      await response.arrayBuffer();
      if (!response.ok) failures += 1;
    } catch {
      failures += 1;
    } finally {
      durations[index] = Number(process.hrtime.bigint() - started) / 1e6;
    }
  }
}

try {
  await Promise.all(Array.from({ length: concurrency }, worker));
  const sorted = durations.filter(Number.isFinite).sort((a, b) => a - b);
  assert.equal(sorted.length, requests, 'every load request must complete');
  const p95 = sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)];
  const metrics = app.metrics.snapshot();
  const summary = {
    requests,
    concurrency,
    failures,
    p95Ms: Number(p95.toFixed(2)),
    heapDeltaBytes: process.memoryUsage().heapUsed - startedHeap,
    proofActive: metrics.gauges.proof_active,
  };
  console.log(JSON.stringify(summary));
  assert.equal(failures, 0, 'load requests must succeed');
  assert.equal(metrics.gauges.proof_active, 0, 'proof gate must not retain work');
  assert.ok(p95 <= targetP95Ms, `p95 ${p95.toFixed(2)}ms exceeds target ${targetP95Ms}ms`);
} finally {
  await app.close();
}
