import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { fileURLToPath } from 'url';
import { ZkTeleAuthGateway } from 'zk-tele-auth/dist/gateway/server.js';
import { ZkAuthProofVerifier } from 'zk-tele-auth/dist/sdk/index.js';
import {
  ROOT as ALLOWLIST_ROOT,
  MEMBER_COUNT,
  MEMBER_IDS,
  generateMembershipProof,
  verifyMembershipProof,
} from './lib/membership.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '123456:DEV-TOKEN-DO-NOT-USE-IN-PRODUCTION';
const APP_DOMAIN = process.env.APP_DOMAIN || 'zktele-login.demo';
const PORT = Number(process.env.PORT || 3000);

const gateway = new ZkTeleAuthGateway(BOT_TOKEN, APP_DOMAIN);

const claims = new Map();

/**
 * Replicates Telegram's MiniApp initData signing (WebAppData HMAC scheme) so
 * the flow can be exercised locally. In production Telegram signs initData —
 * this endpoint exists purely so the demo needs no real bot.
 */
function signInitData(params) {
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const checkString = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join('\n');
  const hash = crypto.createHmac('sha256', secret).update(checkString).digest('hex');
  return { ...params, hash };
}

async function readBody(req) {
  let body = '';
  for await (const chunk of req) body += chunk;
  try {
    return JSON.parse(body || '{}');
  } catch {
    throw new Error('invalid JSON body');
  }
}

function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function serveStatic(res, url) {
  const file = url === '/' ? '/index.html' : url;
  const full = path.join(PUBLIC_DIR, path.normalize(file));
  if (!full.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('forbidden');
    return;
  }
  fs.readFile(full, (err, buf) => {
    if (err) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
    res.writeHead(200, { 'Content-Type': types[path.extname(full)] || 'application/octet-stream' });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  const url = (req.url || '').split('?')[0];

  if (req.method === 'GET') {
    if (url === '/api/config') {
      send(res, 200, { appDomain: APP_DOMAIN, botTokenIsDev: BOT_TOKEN === '123456:DEV-TOKEN-DO-NOT-USE-IN-PRODUCTION' });
      return;
    }
    if (url === '/api/membership') {
      send(res, 200, {
        root: ALLOWLIST_ROOT,
        depth: 12,
        memberCount: MEMBER_COUNT,
        members: MEMBER_IDS,
      });
      return;
    }
    serveStatic(res, url);
    return;
  }

  if (req.method !== 'POST') {
    send(res, 405, { error: 'method not allowed' });
    return;
  }

  try {
    const body = await readBody(req);
    switch (url) {
      case '/api/init': {
        // DEV ONLY: sign an initData as Telegram would, for the given user.
        const userId = Number(body.userId) || 0;
        if (!userId) throw new Error('userId required');
        const user = JSON.stringify({
          id: userId,
          first_name: 'User',
          is_premium: Boolean(body.isPremium),
        });
        const params = {
          auth_date: Math.floor(Date.now() / 1000).toString(),
          query_id: crypto.randomBytes(8).toString('hex'),
          user,
        };
        const initData = new URLSearchParams(signInitData(params)).toString();
        send(res, 200, { initData });
        return;
      }
      case '/api/authenticate': {
        if (typeof body.initData !== 'string') throw new Error('initData required');
        const result = await gateway.handleAuthenticate(body.initData);
        send(res, 200, result);
        return;
      }
      case '/api/verify': {
        const appDomain = typeof body.appDomain === 'string' ? body.appDomain : APP_DOMAIN;
        const verification = await ZkAuthProofVerifier.verifyProof(body.proofPayload, appDomain);
        send(res, 200, verification);
        return;
      }
      case '/api/claim': {
        const verification = await ZkAuthProofVerifier.verifyProof(body.proofPayload, APP_DOMAIN);
        if (!verification.isValid) {
          send(res, 400, { claimed: false, error: verification.error || 'proof invalid' });
          return;
        }
        const nullifier = verification.nullifierHash;
        if (claims.has(nullifier)) {
          send(res, 409, {
            claimed: false,
            nullifierHash: nullifier,
            claims: claims.size,
            error: 'nullifier already claimed — replay rejected',
          });
          return;
        }
        claims.set(nullifier, Date.now());
        send(res, 200, { claimed: true, nullifierHash: nullifier, claims: claims.size });
        return;
      }
      case '/api/claims': {
        send(res, 200, { claims: claims.size });
        return;
      }
      case '/api/membership': {
        send(res, 200, {
          root: ALLOWLIST_ROOT,
          depth: 12,
          memberCount: MEMBER_COUNT,
          members: MEMBER_IDS,
        });
        return;
      }
      case '/api/membership/prove': {
        const memberId = Number(body.memberId);
        if (!memberId) throw new Error('memberId required');
        const result = await generateMembershipProof(memberId);
        send(res, 200, result);
        return;
      }
      case '/api/membership/verify': {
        const verification = await verifyMembershipProof(body.proofPayload);
        send(res, 200, verification);
        return;
      }
      default:
        send(res, 404, { error: 'not found' });
    }
  } catch (err) {
    send(res, 400, { error: err instanceof Error ? err.message : String(err) });
  }
});

server.listen(PORT, () => {
  const isDevToken = BOT_TOKEN === '123456:DEV-TOKEN-DO-NOT-USE-IN-PRODUCTION';
  console.log(`zktele-login demo listening on http://localhost:${PORT}`);
  console.log(`  appDomain:      ${APP_DOMAIN}`);
  console.log(`  bot token:      ${isDevToken ? 'DEV placeholder (initData is simulated)' : 'provided via env'}`);
});
