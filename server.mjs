import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { fileURLToPath } from 'url';
import { createAuthService } from './lib/auth-service.mjs';
import { createClaimStore } from './lib/claim-store.mjs';
import { createChallengeStore } from './lib/challenge-store.mjs';
import { createRelyingService } from './lib/relying-service.mjs';
import { createSessionStore } from './lib/session-store.mjs';
import { loadConfig } from './lib/config.mjs';
import { signTelegramInitData } from './lib/telegram.mjs';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(MODULE_DIR, 'public');
const SESSION_COOKIE = '__Host-zktele_session';

class HttpError extends Error {
  constructor(status, message, { expose = true } = {}) {
    super(message);
    this.status = status;
    this.expose = expose;
  }
}

class ProofGate {
  #active = 0;

  constructor(limit) {
    this.limit = limit;
  }

  get active() {
    return this.#active;
  }

  async run(operation) {
    if (this.#active >= this.limit) throw new HttpError(503, 'proof service is busy; retry later');
    this.#active += 1;
    try {
      return await operation();
    } finally {
      this.#active -= 1;
    }
  }
}

function createRateLimiter(limit) {
  const clients = new Map();
  return (key, now = Date.now()) => {
    const windowStart = now - (now % 60_000);
    const current = clients.get(key);
    if (!current || current.windowStart !== windowStart) {
      clients.set(key, { windowStart, count: 1 });
      if (clients.size > 10_000) {
        for (const [client, entry] of clients) {
          if (entry.windowStart < windowStart) clients.delete(client);
        }
      }
      return true;
    }
    current.count += 1;
    return current.count <= limit;
  };
}

function setSecurityHeaders(res, config) {
  const connectSources = ["'self'", config.gatewayOrigin].filter(Boolean).join(' ');
  res.setHeader('Content-Security-Policy', [
    "default-src 'none'",
    "script-src 'self' https://telegram.org",
    "style-src 'self'",
    `connect-src ${connectSources}`,
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; '));
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (config.production) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

async function readJsonBody(req, limit) {
  if (!(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
    throw new HttpError(415, 'content-type must be application/json');
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, 'request body is too large');
    chunks.push(chunk);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch {
    throw new HttpError(400, 'invalid JSON object body');
  }
}

function sendJson(res, status, value) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(value));
}

function serveStatic(res, pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname === '/' ? '/index.html' : pathname);
  } catch {
    throw new HttpError(400, 'invalid URL encoding');
  }
  const fullPath = path.resolve(PUBLIC_DIR, `.${decoded}`);
  if (fullPath !== PUBLIC_DIR && !fullPath.startsWith(`${PUBLIC_DIR}${path.sep}`)) {
    throw new HttpError(403, 'forbidden');
  }
  let contents;
  try {
    contents = fs.readFileSync(fullPath);
  } catch {
    throw new HttpError(404, 'not found');
  }
  const types = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
  };
  res.writeHead(200, {
    'Content-Type': types[path.extname(fullPath)] || 'application/octet-stream',
    'Cache-Control': pathname === '/' || pathname.endsWith('.html') ? 'no-cache' : 'public, max-age=3600',
  });
  res.end(contents);
}

function clientKey(req) {
  // X-Forwarded-For is deliberately ignored until a trusted proxy is configured.
  return req.socket.remoteAddress || 'unknown';
}

function assertFields(body, { required = [], optional = [] } = {}) {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) throw new HttpError(400, `unexpected field: ${key}`);
  }
  for (const key of required) {
    if (!(key in body)) throw new HttpError(400, `${key} required`);
  }
}

function stringField(body, name, { max = 16 * 1024, required = true } = {}) {
  if (!required && body[name] === undefined) return undefined;
  if (typeof body[name] !== 'string' || body[name].length === 0 || body[name].length > max) {
    throw new HttpError(400, `${name} must be a non-empty string`);
  }
  return body[name];
}

function parseCookies(header = '') {
  const result = new Map();
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    result.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return result;
}

function originAllowed(req, config) {
  const origin = req.headers.origin;
  if (config.production && !origin) return false;
  return !origin || config.allowedOrigins.includes(origin);
}

function applyCors(req, res, config) {
  const origin = req.headers.origin;
  if (!origin) return;
  if (!config.allowedOrigins.includes(origin)) throw new HttpError(403, 'origin is not allowed');
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
}

function setSessionCookie(res, token, config) {
  const cookieName = config.production ? SESSION_COOKIE : 'zktele_session';
  const attributes = [
    `${cookieName}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (config.production) attributes.push('Secure');
  res.setHeader('Set-Cookie', attributes.join('; '));
}

function clearSessionCookie(res, config) {
  const cookieName = config.production ? SESSION_COOKIE : 'zktele_session';
  const attributes = [`${cookieName}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (config.production) attributes.push('Secure');
  res.setHeader('Set-Cookie', attributes.join('; '));
}

function publicServiceMetadata(config, verifier) {
  return {
    appDomain: config.appDomain,
    actionId: config.actionId,
    issuer: config.issuer,
    keyId: config.keyId,
    audience: config.audience,
    circuitId: config.circuitId,
    circuitVersion: config.circuitVersion,
    artifactSetId: config.artifactSetId,
    proofTtlSec: config.proofTtlSec,
    challengeTtlSec: config.challengeTtlSec,
    requirePremium: config.requirePremium,
    devSimulationEnabled: config.allowDevInit,
    gatewayOrigin: config.gatewayOrigin,
    gatewayPublicKey: verifier.publicKey,
    gatewayPublicKeyFingerprint: verifier.publicKeyFingerprint,
  };
}

export async function createApplication(options = {}) {
  const config = options.config || loadConfig();
  const gatewayService = options.authService || (
    config.role === 'gateway' || config.role === 'combined' ? createAuthService(config) : null
  );
  const verifierService = options.relyingService || (
    config.role === 'relying' ? createRelyingService(config) : gatewayService
  );
  if (!verifierService) throw new Error('a relying verifier is required');
  const claimStore = options.claimStore || createClaimStore(config);
  const challengeStore = options.challengeStore || createChallengeStore(config);
  const sessionStore = options.sessionStore || createSessionStore(config);
  await claimStore.initialize();
  await challengeStore.initialize();
  await sessionStore.initialize();
  const proofGate = new ProofGate(config.proofConcurrency);
  const allowRequest = createRateLimiter(config.rateLimitPerMinute);
  let accepting = true;

  const server = http.createServer({ maxHeaderSize: 16 * 1024 }, async (req, res) => {
    setSecurityHeaders(res, config);
    const requestId = crypto.randomBytes(8).toString('hex');
    res.setHeader('X-Request-Id', requestId);

    try {
      const requestUrl = new URL(req.url || '/', 'http://localhost');
      const pathname = requestUrl.pathname;
      if (!accepting && pathname !== '/health/live') throw new HttpError(503, 'service is shutting down');

      if (req.method === 'OPTIONS') {
        if (pathname === '/v1/attest' && (config.role === 'gateway' || config.role === 'combined')) {
          applyCors(req, res, config);
          res.writeHead(204);
          res.end();
          return;
        }
        throw new HttpError(404, 'not found');
      }
      if (pathname.startsWith('/api/') || pathname.startsWith('/v1/')) {
        if (!allowRequest(clientKey(req))) throw new HttpError(429, 'rate limit exceeded');
      }

      if (req.method === 'GET' && pathname === '/health/live') {
        sendJson(res, 200, { status: 'ok' });
        return;
      }
      if (req.method === 'GET' && pathname === '/health/ready') {
        await Promise.all([claimStore.ping?.(), challengeStore.ping?.(), sessionStore.ping?.()]);
        sendJson(res, 200, { status: 'ready' });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/config') {
        if (config.role === 'gateway') throw new HttpError(404, 'not found');
        sendJson(res, 200, publicServiceMetadata(config, verifierService));
        return;
      }
      if (req.method === 'GET' && pathname === '/api/challenge') {
        if (config.role === 'gateway') throw new HttpError(404, 'not found');
        const challenge = await challengeStore.create({
          audience: config.audience,
          appDomain: config.appDomain,
          actionId: config.actionId,
          ttlSec: config.challengeTtlSec,
        });
        sendJson(res, 200, { challenge: challenge.challenge, expiresAt: challenge.expiresAt, audience: config.audience, appDomain: config.appDomain, actionId: config.actionId });
        return;
      }
      if (req.method === 'GET' && pathname === '/api/session') {
        if (config.role === 'gateway') throw new HttpError(404, 'not found');
        const token = parseCookies(req.headers.cookie).get(config.production ? SESSION_COOKIE : 'zktele_session');
        const session = token ? await sessionStore.get(token) : null;
        sendJson(res, 200, { authenticated: Boolean(session), expiresAt: session?.absoluteExpiresAt || null });
        return;
      }
      if (req.method === 'GET' && pathname === '/api/claims') {
        if (config.production || config.role === 'gateway') throw new HttpError(404, 'not found');
        sendJson(res, 200, { claims: await claimStore.count() });
        return;
      }
      if (req.method === 'GET') {
        if (config.role === 'gateway') throw new HttpError(404, 'not found');
        serveStatic(res, pathname);
        return;
      }
      if (req.method !== 'POST') throw new HttpError(405, 'method not allowed');

      if (pathname === '/v1/attest') {
        if (config.role === 'relying') throw new HttpError(404, 'not found');
        applyCors(req, res, config);
      }
      const body = await readJsonBody(req, config.bodyLimitBytes);

      if (pathname === '/v1/attest' || pathname === '/api/authenticate') {
        if (pathname === '/api/authenticate' && config.role === 'gateway') throw new HttpError(404, 'not found');
        assertFields(body, { required: ['initData', 'challenge'], optional: ['audience', 'appDomain', 'actionId'] });
        const initData = stringField(body, 'initData', { max: 16 * 1024 });
        const challenge = stringField(body, 'challenge', { max: 512 });
        const audience = body.audience === undefined ? config.audience : stringField(body, 'audience', { max: 255 });
        const appDomain = body.appDomain === undefined ? config.appDomain : stringField(body, 'appDomain', { max: 255 });
        const actionId = body.actionId === undefined ? config.actionId : stringField(body, 'actionId', { max: 128 });
        let attestation;
        if (typeof gatewayService.validateInitData === 'function' && typeof gatewayService.authenticateValidated === 'function') {
          let telegram;
          try {
            telegram = gatewayService.validateInitData(initData);
          } catch {
            throw new HttpError(401, 'Telegram authentication is invalid');
          }
          try {
            attestation = await proofGate.run(() => gatewayService.authenticateValidated(telegram, { challenge, audience, appDomain, actionId }));
          } catch (error) {
            if (error instanceof HttpError) throw error;
            throw new HttpError(503, 'proof service unavailable');
          }
        } else {
          try {
            attestation = await proofGate.run(() => gatewayService.authenticate(initData, { challenge, audience, appDomain, actionId }));
          } catch (error) {
            if (error instanceof HttpError) throw error;
            throw new HttpError(401, 'Telegram authentication is invalid');
          }
        }
        sendJson(res, 200, { attestation });
        return;
      }

      if (pathname === '/api/dev/init') {
        if (!config.allowDevInit || config.role !== 'combined') throw new HttpError(404, 'not found');
        assertFields(body, { required: ['userId'], optional: ['isPremium'] });
        const userId = Number(body.userId);
        if (!Number.isSafeInteger(userId) || userId <= 0) throw new HttpError(400, 'valid userId required');
        const params = {
          auth_date: Math.floor(Date.now() / 1000).toString(),
          query_id: crypto.randomBytes(8).toString('hex'),
          user: JSON.stringify({ id: userId, first_name: 'Development User', is_premium: body.isPremium === true }),
        };
        sendJson(res, 200, { initData: signTelegramInitData(params, config.botToken) });
        return;
      }

      if (pathname === '/api/verify') {
        if (config.role === 'gateway') throw new HttpError(404, 'not found');
        assertFields(body, { required: ['attestation'], optional: ['appDomain'] });
        const expectedDomain = body.appDomain === undefined ? config.appDomain : stringField(body, 'appDomain', { max: 255 });
        const verification = await proofGate.run(() => verifierService.verify(body.attestation, expectedDomain));
        sendJson(res, 200, config.production && !verification.isValid
          ? { isValid: false, nullifierHash: '', error: 'attestation invalid' }
          : verification);
        return;
      }

      if (pathname === '/api/auth/complete' || pathname === '/api/claim') {
        if (config.role === 'gateway') throw new HttpError(404, 'not found');
        assertFields(body, { required: ['attestation'], optional: ['operation'] });
        const operation = body.operation === undefined ? 'claim' : body.operation;
        if (operation !== 'claim' && operation !== 'login') throw new HttpError(400, 'operation must be claim or login');
        if (!originAllowed(req, config)) throw new HttpError(403, 'origin is not allowed');
        const verification = await proofGate.run(() => verifierService.verify(body.attestation, config.appDomain));
        if (!verification.isValid) throw new HttpError(401, 'attestation invalid');
        const expected = { audience: config.audience, appDomain: config.appDomain, actionId: config.actionId };
        if (operation === 'claim') {
          const result = typeof claimStore.completeClaim === 'function'
            ? await claimStore.completeClaim(verification.nullifierHash, { issuer: verification.issuer, appDomain: config.appDomain, actionId: verification.actionId }, { challengeStore, challenge: verification.challenge, expected })
            : await (async () => {
              const consumed = await challengeStore.consume(verification.challenge, expected);
              if (!consumed.consumed) return { claimed: false, claims: await claimStore.count(), challengeConsumed: false, challengeReason: consumed.reason };
              return { ...(await claimStore.claim(verification.nullifierHash, { issuer: verification.issuer, appDomain: config.appDomain, actionId: verification.actionId })), challengeConsumed: true };
            })();
          if (!result.challengeConsumed) throw new HttpError(409, result.challengeReason || 'challenge already used');
          if (!result.claimed) {
            sendJson(res, 409, { claimed: false, claims: result.claims, error: 'this account already completed this action' });
            return;
          }
          sendJson(res, 200, { claimed: true, claims: result.claims });
          return;
        }
        const consumed = await challengeStore.consume(verification.challenge, expected);
        if (!consumed.consumed) throw new HttpError(409, consumed.reason || 'challenge already used');
        const session = await sessionStore.create({
          nullifierHash: verification.nullifierHash,
          issuer: verification.issuer,
          appDomain: config.appDomain,
          actionId: verification.actionId,
          idleTtlSec: config.sessionIdleTtlSec,
          absoluteTtlSec: config.sessionAbsoluteTtlSec,
        });
        setSessionCookie(res, session.token, config);
        sendJson(res, 200, { authenticated: true, expiresAt: session.expiresAt });
        return;
      }

      if (pathname === '/api/logout') {
        if (config.role === 'gateway') throw new HttpError(404, 'not found');
        if (!originAllowed(req, config)) throw new HttpError(403, 'origin is not allowed');
        const token = parseCookies(req.headers.cookie).get(config.production ? SESSION_COOKIE : 'zktele_session');
        if (token) await sessionStore.revoke(token);
        clearSessionCookie(res, config);
        sendJson(res, 200, { loggedOut: true });
        return;
      }

      throw new HttpError(404, 'not found');
    } catch (error) {
      const isHttp = error instanceof HttpError;
      const status = isHttp ? error.status : 500;
      const message = isHttp && error.expose ? error.message : 'internal server error';
      if (!isHttp || status >= 500) {
        console.error(JSON.stringify({ requestId, errorClass: error?.name || 'Error' }));
      }
      if (!res.headersSent) sendJson(res, status, { error: message, requestId });
      else res.destroy();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;

  async function close() {
    accepting = false;
    if (server.listening) {
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('server shutdown timed out')), 10_000);
        server.close((error) => { clearTimeout(timeout); error ? reject(error) : resolve(); });
      });
    }
    await Promise.all([claimStore.close(), challengeStore.close(), sessionStore.close()]);
  }

  return { server, close, config, authService: gatewayService, relyingService: verifierService, claimStore, challengeStore, sessionStore, proofGate };
}

async function main() {
  const app = await createApplication();
  app.server.listen(app.config.port, () => {
    console.log(`zktele-login ${app.config.role} listening on port ${app.config.port}`);
    console.log(`  environment: ${app.config.environmentId}`);
    console.log(`  app/action:  ${app.config.appDomain} / ${app.config.actionId}`);
    console.log(`  gateway key: ${app.relyingService.publicKeyFingerprint}`);
    console.log(`  dev signing: ${app.config.allowDevInit ? 'enabled' : 'disabled'}`);
  });

  const shutdown = async () => {
    await app.close();
    process.exit(0);
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : 'startup failed');
    process.exitCode = 1;
  });
}
