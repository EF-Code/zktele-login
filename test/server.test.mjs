import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryClaimStore } from '../lib/claim-store.mjs';
import { loadConfig } from '../lib/config.mjs';
import { createApplication } from '../server.mjs';
import { createGatewayKeys, publicKeyPem } from '../lib/attestation.mjs';

async function withServer(operation) {
  const config = loadConfig({
    NODE_ENV: 'test',
    ALLOW_DEV_INIT: 'true',
    PORT: '3210',
    BODY_LIMIT_BYTES: '1024',
    RATE_LIMIT_PER_MINUTE: '100',
  });
  const validAttestation = { signed: true };
  const authService = {
    publicKey: 'PUBLIC KEY',
    publicKeyFingerprint: 'fingerprint',
    authenticate: async () => validAttestation,
    verify: async (attestation, domain) => attestation?.signed && domain === config.appDomain
      ? { isValid: true, nullifierHash: 'nullifier', issuer: config.issuer, actionId: config.actionId, challenge: attestation.challenge }
      : { isValid: false, error: 'invalid attestation' },
  };
  const app = await createApplication({ config, authService, claimStore: new MemoryClaimStore() });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const address = app.server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  try {
    await operation(baseUrl, validAttestation);
  } finally {
    await app.close();
  }
}

test('HTTP boundary gates development signing and atomically rejects duplicate claims', async () => {
  await withServer(async (baseUrl) => {
    const dev = await fetch(`${baseUrl}/api/dev/init`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 42, isPremium: false }),
    });
    assert.equal(dev.status, 200);

    const firstChallenge = await (await fetch(`${baseUrl}/api/challenge`)).json();
    const first = await fetch(`${baseUrl}/api/claim`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ attestation: { signed: true, challenge: firstChallenge.challenge } }),
    });
    const secondChallenge = await (await fetch(`${baseUrl}/api/challenge`)).json();
    const second = await fetch(`${baseUrl}/api/claim`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ attestation: { signed: true, challenge: secondChallenge.challenge } }),
    });
    assert.equal(first.status, 200);
    assert.equal(second.status, 409);
  });
});

test('completion rejects unavailable challenges before invoking the verifier', async () => {
  const config = loadConfig({ NODE_ENV: 'test', ALLOW_DEV_INIT: 'true' });
  let verifierCalls = 0;
  const app = await createApplication({
    config,
    authService: {
      publicKey: 'PUBLIC KEY',
      publicKeyFingerprint: 'fingerprint',
      verify: async () => { verifierCalls += 1; return { isValid: true }; },
      authenticate: async () => ({ signed: true }),
    },
    claimStore: new MemoryClaimStore(),
  });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${app.server.address().port}`;
  try {
    const response = await fetch(`${baseUrl}/api/auth/complete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: JSON.stringify({ operation: 'login', attestation: { challenge: 'not-issued' } }),
    });
    assert.equal(response.status, 409);
    assert.equal(verifierCalls, 0);
  } finally {
    await app.close();
  }
});

test('HTTP boundary enforces content type, body size and security headers', async () => {
  await withServer(async (baseUrl) => {
    const wrongType = await fetch(`${baseUrl}/api/verify`, { method: 'POST', body: '{}' });
    assert.equal(wrongType.status, 415);

    const tooLarge = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ value: 'x'.repeat(2_000) }),
    });
    assert.equal(tooLarge.status, 413);

    const page = await fetch(baseUrl);
    assert.match(page.headers.get('content-security-policy'), /script-src 'self' https:\/\/telegram\.org/);
    assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
  });
});

test('completion issues an opaque session and logout revokes it', async () => {
  await withServer(async (baseUrl) => {
    const challenge = await (await fetch(`${baseUrl}/api/challenge`)).json();
    const complete = await fetch(`${baseUrl}/api/auth/complete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: JSON.stringify({
        operation: 'login',
        attestation: { signed: true, challenge: challenge.challenge },
      }),
    });
    assert.equal(complete.status, 200);
    const cookie = complete.headers.get('set-cookie');
    assert.match(cookie, /zktele_session=/);
    assert.match(cookie, /HttpOnly/);
    const session = await fetch(`${baseUrl}/api/session`, { headers: { cookie } });
    const sessionPayload = await session.json();
    assert.equal(sessionPayload.authenticated, true);
    assert.equal(Number.isSafeInteger(sessionPayload.expiresAt), true);
    const logout = await fetch(`${baseUrl}/api/logout`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', cookie },
      body: '{}',
    });
    assert.equal(logout.status, 200);
    const after = await fetch(`${baseUrl}/api/session`, { headers: { cookie } });
    assert.deepEqual(await after.json(), { authenticated: false, expiresAt: null });
  });
});

test('gateway and relying roles expose only their intended HTTP boundaries', async () => {
  const gatewayConfig = loadConfig({
    NODE_ENV: 'test', SERVICE_ROLE: 'gateway', TELEGRAM_BOT_TOKEN: '123456:test',
    NULLIFIER_SECRET: Buffer.alloc(32, 2).toString('base64'), ALLOWED_ORIGINS: 'http://localhost:3000',
  });
  const gatewayAuth = {
    publicKey: 'PUBLIC KEY', publicKeyFingerprint: 'fingerprint',
    authenticate: async () => ({ signed: true }),
  };
  const gateway = await createApplication({ config: gatewayConfig, authService: gatewayAuth, claimStore: new MemoryClaimStore() });
  await new Promise((resolve) => gateway.server.listen(0, '127.0.0.1', resolve));
  const gatewayUrl = `http://127.0.0.1:${gateway.server.address().port}`;
  try {
    assert.equal((await fetch(`${gatewayUrl}/api/config`)).status, 404);
    assert.equal((await fetch(`${gatewayUrl}/api/authenticate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404);
    const attest = await fetch(`${gatewayUrl}/v1/attest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: JSON.stringify({ initData: 'fixture', challenge: 'challenge' }),
    });
    assert.equal(attest.status, 200);
  } finally {
    await gateway.close();
  }

  const keys = createGatewayKeys();
  const relyingConfig = loadConfig({
    NODE_ENV: 'test', SERVICE_ROLE: 'relying', DATABASE_URL: '', ISSUER_KEY_HASH: '12345',
    GATEWAY_PUBLIC_KEY_BASE64: Buffer.from(publicKeyPem(keys.publicKey)).toString('base64'),
    SESSION_SECRET: Buffer.alloc(32, 3).toString('base64'), ALLOWED_ORIGINS: 'http://localhost:3000',
  });
  const relying = await createApplication({
    config: relyingConfig,
    relyingService: { publicKey: publicKeyPem(keys.publicKey), publicKeyFingerprint: 'fingerprint', verify: async () => ({ isValid: false }) },
  });
  await new Promise((resolve) => relying.server.listen(0, '127.0.0.1', resolve));
  const relyingUrl = `http://127.0.0.1:${relying.server.address().port}`;
  try {
    assert.equal((await fetch(`${relyingUrl}/v1/attest`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404);
    assert.equal((await fetch(`${relyingUrl}/api/dev/init`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404);
    assert.equal((await fetch(`${relyingUrl}/api/challenge`)).status, 200);
  } finally {
    await relying.close();
  }
});

test('unexpected dependency failures are generic 500 responses', async () => {
  const config = loadConfig({ NODE_ENV: 'test', ALLOW_DEV_INIT: 'true', ALLOWED_ORIGINS: 'http://localhost:3000' });
  const app = await createApplication({
    config,
    authService: {
      publicKey: 'PUBLIC KEY',
      publicKeyFingerprint: 'fingerprint',
      verify: async () => { throw new Error('database password leaked'); },
    },
    claimStore: new MemoryClaimStore(),
  });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${app.server.address().port}`;
  try {
    const response = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ attestation: {} }),
    });
    const payload = await response.json();
    assert.equal(response.status, 500);
    assert.equal(payload.error, 'internal server error');
    assert.equal(JSON.stringify(payload).includes('database password'), false);
  } finally {
    await app.close();
  }
});

test('metrics endpoint is opt-in and contains only coarse service measurements', async () => {
  const config = loadConfig({
    NODE_ENV: 'test', ALLOW_DEV_INIT: 'true', METRICS_ENABLED: 'true', RATE_LIMIT_PER_MINUTE: '100',
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
  try {
    const challenge = await fetch(`${baseUrl}/api/challenge`);
    assert.equal(challenge.status, 200);
    const challengePayload = await challenge.json();
    const response = await fetch(`${baseUrl}/health/metrics`);
    assert.equal(response.status, 200);
    const text = await response.text();
    assert.match(text, /http_responses_2xx_total/);
    assert.match(text, /challenges_created_total 1/);
    assert.equal(text.includes(challengePayload.challenge), false, 'metrics must not contain challenge values');
  } finally {
    await app.close();
  }
});

test('metrics endpoint requires the configured bearer token', async () => {
  const token = Buffer.alloc(32, 6).toString('base64');
  const config = loadConfig({ NODE_ENV: 'test', ALLOW_DEV_INIT: 'true', METRICS_ENABLED: 'true', METRICS_TOKEN: token });
  const app = await createApplication({
    config,
    authService: { publicKey: 'PUBLIC KEY', publicKeyFingerprint: 'fingerprint', authenticate: async () => ({ signed: true }), verify: async () => ({ isValid: false }) },
    claimStore: new MemoryClaimStore(),
  });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${app.server.address().port}`;
  try {
    assert.equal((await fetch(`${baseUrl}/health/metrics`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/health/metrics`, { headers: { authorization: `Bearer ${token}` } })).status, 200);
  } finally {
    await app.close();
  }
});
