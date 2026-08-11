import test from 'node:test';
import assert from 'node:assert/strict';
import { signTelegramInitData, validateTelegramInitData } from '../lib/telegram.mjs';

const BOT_TOKEN = '123456:test-token';
const NOW = 1_800_000_000;

function validInitData(overrides = {}) {
  return signTelegramInitData({
    auth_date: String(NOW - 5),
    query_id: 'query-1',
    user: JSON.stringify({ id: 42, first_name: 'Test', is_premium: true }),
    ...overrides,
  }, BOT_TOKEN);
}

test('validates a fresh Telegram HMAC with constant policy inputs', () => {
  const result = validateTelegramInitData(validInitData(), {
    botToken: BOT_TOKEN,
    now: NOW,
    maxAgeSec: 300,
  });
  assert.deepEqual(result, { userId: 42, authDate: NOW - 5, isPremium: true });
});

test('rejects tampered, expired, future, duplicate and malformed Telegram data', () => {
  assert.throws(() => validateTelegramInitData(`${validInitData()}x`, {
    botToken: BOT_TOKEN,
    now: NOW,
    maxAgeSec: 300,
  }), /signature/);

  assert.throws(() => validateTelegramInitData(validInitData({ auth_date: String(NOW - 301) }), {
    botToken: BOT_TOKEN,
    now: NOW,
    maxAgeSec: 300,
  }), /expired/);

  assert.throws(() => validateTelegramInitData(validInitData({ auth_date: String(NOW + 31) }), {
    botToken: BOT_TOKEN,
    now: NOW,
    maxAgeSec: 300,
  }), /future/);

  assert.throws(() => validateTelegramInitData(`${validInitData()}&user=%7B%22id%22%3A7%7D`, {
    botToken: BOT_TOKEN,
    now: NOW,
    maxAgeSec: 300,
  }), /duplicate/);

  const malformedUser = validInitData({ user: '{' });
  assert.throws(() => validateTelegramInitData(malformedUser, {
    botToken: BOT_TOKEN,
    now: NOW,
    maxAgeSec: 300,
  }), /user payload/);
});
