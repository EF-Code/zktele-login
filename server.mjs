import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '123456:DEV-TOKEN-DO-NOT-USE-IN-PRODUCTION';
const PORT = Number(process.env.PORT || 3000);

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
    serveStatic(res, url);
    return;
  }

  if (req.method !== 'POST') {
    send(res, 405, { error: 'method not allowed' });
    return;
  }

  try {
    const body = await readBody(req);
    if (url !== '/api/init') {
      send(res, 404, { error: 'not found' });
      return;
    }
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
  } catch (err) {
    send(res, 400, { error: err instanceof Error ? err.message : String(err) });
  }
});

server.listen(PORT, () => {
  const isDevToken = BOT_TOKEN === '123456:DEV-TOKEN-DO-NOT-USE-IN-PRODUCTION';
  console.log(`zktele-login demo listening on http://localhost:${PORT}`);
  console.log(`  bot token:      ${isDevToken ? 'DEV placeholder (initData is simulated)' : 'provided via env'}`);
});
