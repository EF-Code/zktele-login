import * as crypto from 'crypto';

function safeEqualHex(actual, expected) {
  if (!/^[0-9a-f]{64}$/i.test(actual)) return false;
  const actualBytes = Buffer.from(actual, 'hex');
  const expectedBytes = Buffer.from(expected, 'hex');
  return actualBytes.length === expectedBytes.length && crypto.timingSafeEqual(actualBytes, expectedBytes);
}

export function signTelegramInitData(params, botToken) {
  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const checkString = Object.keys(params)
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join('\n');
  const hash = crypto.createHmac('sha256', secret).update(checkString).digest('hex');
  return new URLSearchParams({ ...params, hash }).toString();
}

export function validateTelegramInitData(rawInitData, {
  botToken,
  now = Math.floor(Date.now() / 1000),
  maxAgeSec = 300,
  futureSkewSec = 30,
} = {}) {
  if (typeof rawInitData !== 'string' || rawInitData.length === 0 || rawInitData.length > 16 * 1024) {
    throw new Error('invalid Telegram initData length');
  }

  const params = new URLSearchParams(rawInitData);
  const seen = new Set();
  for (const [key] of params) {
    if (seen.has(key)) throw new Error(`duplicate Telegram initData field: ${key}`);
    seen.add(key);
  }

  const receivedHash = params.get('hash') || '';
  params.delete('hash');
  const dataCheckString = [...params.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const expectedHash = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');
  if (!safeEqualHex(receivedHash, expectedHash)) throw new Error('invalid Telegram initData signature');

  const authDate = Number(params.get('auth_date'));
  if (!Number.isSafeInteger(authDate) || authDate <= 0) throw new Error('invalid Telegram auth_date');
  if (authDate > now + futureSkewSec) throw new Error('Telegram initData is from the future');
  if (now - authDate > maxAgeSec) throw new Error('Telegram initData has expired');

  let user;
  try {
    user = JSON.parse(params.get('user') || '{}');
  } catch {
    throw new Error('invalid Telegram user payload');
  }
  if (!Number.isSafeInteger(user.id) || user.id <= 0) throw new Error('invalid Telegram user id');

  return Object.freeze({
    userId: user.id,
    authDate,
    isPremium: user.is_premium === true,
  });
}
