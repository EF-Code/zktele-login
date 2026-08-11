import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../lib/config.mjs';

test('production configuration fails closed without required secrets', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'production' }), /SERVICE_ROLE/);
  const base = {
    NODE_ENV: 'production',
    SERVICE_ROLE: 'gateway',
    ENVIRONMENT_ID: 'production',
    APP_ORIGIN: 'https://login.acme',
    ALLOWED_ORIGINS: 'https://login.acme',
    APP_DOMAIN: 'login.acme',
    ACTION_ID: 'claim-v1',
    GATEWAY_ISSUER: 'gateway-prod',
    GATEWAY_KEY_ID: 'key-prod-1',
    ATTESTATION_AUDIENCE: 'login.acme',
    CIRCUIT_ID: 'telegram-auth',
    CIRCUIT_VERSION: '2',
    ARTIFACT_SET_ID: 'artifact-prod-1',
  };
  assert.throws(() => loadConfig({
    ...base,
    TELEGRAM_BOT_TOKEN: '123:real-token',
    NULLIFIER_SECRET: Buffer.alloc(32, 1).toString('base64'),
  }), /GATEWAY_PRIVATE_KEY/);
  assert.throws(() => loadConfig({
    ...base,
    TELEGRAM_BOT_TOKEN: '123:real-token',
  }), /NULLIFIER_SECRET/);
});

test('development simulation is impossible in production', () => {
  assert.throws(() => loadConfig({
    NODE_ENV: 'production',
    SERVICE_ROLE: 'gateway',
    ENVIRONMENT_ID: 'production',
    ALLOW_DEV_INIT: 'true',
    TELEGRAM_BOT_TOKEN: '123456:DEV-TOKEN-DO-NOT-USE-IN-PRODUCTION',
    APP_DOMAIN: 'login.acme',
    ACTION_ID: 'claim-v1',
    GATEWAY_ISSUER: 'gateway-prod',
    GATEWAY_KEY_ID: 'key-prod-1',
    ATTESTATION_AUDIENCE: 'login.acme',
    CIRCUIT_ID: 'telegram-auth',
    CIRCUIT_VERSION: '2',
    ARTIFACT_SET_ID: 'artifact-prod-1',
    APP_ORIGIN: 'https://login.acme',
    ALLOWED_ORIGINS: 'https://login.acme',
  }), /development bot token is forbidden/);
});

test('development configuration exposes simulation only when explicitly enabled', () => {
  const config = loadConfig({ NODE_ENV: 'development', ALLOW_DEV_INIT: 'true' });
  assert.equal(config.allowDevInit, true);
  assert.equal(config.production, false);
  assert.equal(config.nullifierSecret.length, 32);
});

test('relying configuration does not accept gateway secrets and pins public policy', () => {
  const publicKey = Buffer.from('-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n', 'utf8').toString('base64');
  const secret = Buffer.alloc(32, 4).toString('base64');
  const config = loadConfig({
    NODE_ENV: 'test', SERVICE_ROLE: 'relying', ENVIRONMENT_ID: 'test', APP_ORIGIN: 'http://localhost:3000',
    ALLOWED_ORIGINS: 'http://localhost:3000', DATABASE_URL: 'postgresql://database/app',
    GATEWAY_PUBLIC_KEY_BASE64: publicKey, ISSUER_KEY_HASH: '12345', SESSION_SECRET: secret,
  });
  assert.equal(config.role, 'relying');
  assert.equal(config.botToken, '');
  assert.equal(config.nullifierSecret, null);
  assert.equal(config.gatewayPublicKeys[config.keyId], Buffer.from(publicKey, 'base64').toString('utf8'));
  assert.throws(() => loadConfig({
    NODE_ENV: 'test', SERVICE_ROLE: 'relying', APP_ORIGIN: 'http://localhost:3000', ALLOWED_ORIGINS: 'http://localhost:3000',
    DATABASE_URL: 'postgresql://database/app', GATEWAY_PUBLIC_KEY_BASE64: publicKey, ISSUER_KEY_HASH: '12345', SESSION_SECRET: secret,
    TELEGRAM_BOT_TOKEN: 'should-not-be-here',
  }), /must not receive gateway private secrets/);
});

test('metrics are disabled by default and require a strong production token when enabled', () => {
  const development = loadConfig({ NODE_ENV: 'development', ALLOW_DEV_INIT: 'true' });
  assert.equal(development.metricsEnabled, false);
  assert.equal(development.metricsToken, null);

  const base = {
    NODE_ENV: 'production',
    SERVICE_ROLE: 'gateway',
    ENVIRONMENT_ID: 'production',
    APP_ORIGIN: 'https://login.acme',
    ALLOWED_ORIGINS: 'https://login.acme',
    APP_DOMAIN: 'login.acme',
    ACTION_ID: 'claim-v1',
    GATEWAY_ISSUER: 'gateway-prod',
    GATEWAY_KEY_ID: 'key-prod-1',
    ATTESTATION_AUDIENCE: 'login.acme',
    CIRCUIT_ID: 'telegram-auth',
    CIRCUIT_VERSION: '2',
    ARTIFACT_SET_ID: 'artifact-prod-1',
    TELEGRAM_BOT_TOKEN: '123:real-token',
    NULLIFIER_SECRET: Buffer.alloc(32, 1).toString('base64'),
    GATEWAY_PRIVATE_KEY_BASE64: Buffer.from('fixture-private-key').toString('base64'),
  };
  assert.throws(() => loadConfig({ ...base, METRICS_ENABLED: 'true' }), /METRICS_TOKEN/);
  const token = Buffer.alloc(32, 8).toString('base64');
  assert.equal(loadConfig({ ...base, METRICS_ENABLED: 'true', METRICS_TOKEN: token }).metricsToken.length, 32);
});
