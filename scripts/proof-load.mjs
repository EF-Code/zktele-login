import assert from 'node:assert/strict';
import { loadConfig } from '../lib/config.mjs';
import { createApplication } from '../server.mjs';
import { signTelegramInitData } from '../lib/telegram.mjs';

// This is a local capacity smoke, not a Telegram-client test. The fixture bot
// token produces HMAC-valid synthetic initData while the gateway still runs
// the real Groth16 generator and the relying service runs the real verifier.
const requests = Number(process.env.PROOF_LOAD_REQUESTS || 4);
const concurrency = Number(process.env.PROOF_LOAD_CONCURRENCY || 2);
const targetP95Ms = Number(process.env.PROOF_LOAD_TARGET_P95_MS || 120_000);
if (!Number.isSafeInteger(requests) || requests < 1 || requests > 32) throw new Error('PROOF_LOAD_REQUESTS must be an integer between 1 and 32');
if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 16) throw new Error('PROOF_LOAD_CONCURRENCY must be an integer between 1 and 16');
if (!Number.isFinite(targetP95Ms) || targetP95Ms <= 0) throw new Error('PROOF_LOAD_TARGET_P95_MS must be positive');

const fixtureBotToken = '123456:proof-load-fixture';
const shared = {
  NODE_ENV: 'test',
  APP_DOMAIN: 'proof-load.example',
  ACTION_ID: 'claim-v1',
  GATEWAY_ISSUER: 'proof-load-gateway',
  GATEWAY_KEY_ID: 'proof-load-key',
  ATTESTATION_AUDIENCE: 'proof-load.example',
  CIRCUIT_ID: 'telegram-auth',
  CIRCUIT_VERSION: '2',
  ARTIFACT_SET_ID: 'proof-load-artifacts',
  APP_ORIGIN: 'http://localhost:3000',
  ALLOWED_ORIGINS: 'http://localhost:3000',
  PROOF_CONCURRENCY: String(Math.min(concurrency, 16)),
  RATE_LIMIT_PER_MINUTE: String(requests * 4),
};

const gatewayConfig = loadConfig({
  ...shared,
  SERVICE_ROLE: 'gateway',
  TELEGRAM_BOT_TOKEN: fixtureBotToken,
  NULLIFIER_SECRET: Buffer.alloc(32, 41).toString('base64'),
});
const gateway = await createApplication({ config: gatewayConfig });
const issuerKeyHash = await gateway.authService.issuerKeyHash;
const relyingConfig = loadConfig({
  ...shared,
  SERVICE_ROLE: 'relying',
  GATEWAY_PUBLIC_KEY_BASE64: Buffer.from(gateway.authService.publicKey, 'utf8').toString('base64'),
  ISSUER_KEY_HASH: issuerKeyHash,
  GATEWAY_ORIGIN: 'http://localhost:3001',
  SESSION_SECRET: Buffer.alloc(32, 42).toString('base64'),
});
const relying = await createApplication({ config: relyingConfig });

async function listen(app) {
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${app.server.address().port}`;
}

const gatewayUrl = await listen(gateway);
const relyingUrl = await listen(relying);

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(120_000) });
  let body;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { response, body };
}

const durations = [];
const outcomes = [];
let next = 0;

async function worker() {
  while (true) {
    const index = next;
    next += 1;
    if (index >= requests) return;
    const started = process.hrtime.bigint();
    let outcome = 'failed';
    try {
      const challengeResult = await jsonRequest(`${relyingUrl}/api/challenge`);
      assert.equal(challengeResult.response.status, 200);
      const challenge = challengeResult.body?.challenge;
      assert.equal(typeof challenge, 'string');
      const now = Math.floor(Date.now() / 1000);
      const initData = signTelegramInitData({
        auth_date: String(now),
        query_id: `proof-load-${index}`,
        user: JSON.stringify({ id: 10_000_000 + index, first_name: 'Proof load' }),
      }, fixtureBotToken);
      const attestResult = await jsonRequest(`${gatewayUrl}/v1/attest`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          initData,
          challenge,
          audience: shared.ATTESTATION_AUDIENCE,
          appDomain: shared.APP_DOMAIN,
          actionId: shared.ACTION_ID,
        }),
      });
      assert.equal(attestResult.response.status, 200);
      assert.equal(typeof attestResult.body?.attestation?.signature, 'string');
      const verifyResult = await jsonRequest(`${relyingUrl}/api/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ attestation: attestResult.body.attestation }),
      });
      assert.equal(verifyResult.response.status, 200);
      assert.equal(verifyResult.body?.isValid, true);
      outcome = 'verified';
    } catch {
      // The summary contains only counts and timings; never print request data
      // or dependency error messages that could contain sensitive inputs.
    } finally {
      durations[index] = Number(process.hrtime.bigint() - started) / 1e6;
      outcomes[index] = outcome;
    }
  }
}

let failed = false;
try {
  await Promise.all(Array.from({ length: Math.min(concurrency, requests) }, worker));
  const sorted = durations.filter(Number.isFinite).sort((a, b) => a - b);
  assert.equal(sorted.length, requests, 'every proof load request must finish');
  const p95 = sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)];
  const summary = {
    requests,
    concurrency: Math.min(concurrency, requests),
    verified: outcomes.filter((value) => value === 'verified').length,
    failures: outcomes.filter((value) => value !== 'verified').length,
    p95Ms: Number(p95.toFixed(2)),
    gatewayProofActive: gateway.metrics.snapshot().gauges.proof_active,
    relyingProofActive: relying.metrics.snapshot().gauges.proof_active,
  };
  console.log(JSON.stringify(summary));
  assert.equal(summary.verified, requests, 'every synthetic Telegram proof must verify');
  assert.equal(summary.gatewayProofActive, 0, 'gateway proof gate must drain');
  assert.equal(summary.relyingProofActive, 0, 'relying proof gate must drain');
  assert.ok(p95 <= targetP95Ms, `p95 ${p95.toFixed(2)}ms exceeds target ${targetP95Ms}ms`);
} catch {
  // Do not print assertion/dependency details that could contain request data.
  failed = true;
} finally {
  await Promise.all([gateway.close(), relying.close()]);
}

// The upstream prover can leave worker-pool handles alive after the app closes.
// Exit only after cleanup so this standalone load command cannot hang forever.
process.exit(failed ? 1 : 0);
