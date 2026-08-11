import * as crypto from 'crypto';
import pg from 'pg';

export function hashChallenge(challenge) {
  if (typeof challenge !== 'string' || challenge.length === 0 || challenge.length > 512) {
    throw new Error('invalid challenge');
  }
  return crypto.createHash('sha256').update(challenge, 'utf8').digest('hex');
}

function challengeBytes() {
  return crypto.randomBytes(32).toString('base64url');
}

export class MemoryChallengeStore {
  #challenges = new Map();

  async initialize() {}

  async create({ audience, appDomain, actionId, ttlSec, now = Math.floor(Date.now() / 1000) }) {
    const challenge = challengeBytes();
    const expiresAt = now + ttlSec;
    this.#challenges.set(hashChallenge(challenge), {
      audience,
      appDomain,
      actionId,
      createdAt: now,
      expiresAt,
    });
    return { challenge, expiresAt };
  }

  async consume(challenge, expected, now = Math.floor(Date.now() / 1000)) {
    const key = hashChallenge(challenge);
    const record = this.#challenges.get(key);
    if (!record) return { consumed: false, reason: 'challenge not found or already consumed' };
    if (record.expiresAt <= now) {
      this.#challenges.delete(key);
      return { consumed: false, reason: 'challenge expired' };
    }
    if (record.audience !== expected.audience || record.appDomain !== expected.appDomain || record.actionId !== expected.actionId) {
      return { consumed: false, reason: 'challenge context mismatch' };
    }
    this.#challenges.delete(key);
    return { consumed: true, ...record };
  }

  async close() {}

  async ping() {}
}

export class PostgresChallengeStore {
  #pool;

  constructor(databaseUrl, { ssl = false, ca = undefined } = {}) {
    this.#pool = new pg.Pool({
      connectionString: databaseUrl,
      ssl: ssl ? { rejectUnauthorized: true, ca } : false,
      max: 10,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 10_000,
      query_timeout: 10_000,
      idle_in_transaction_session_timeout: 10_000,
    });
  }

  async initialize() {
    // Schema ownership belongs to the migration role, not the runtime role.
  }

  async create({ audience, appDomain, actionId, ttlSec, now = Math.floor(Date.now() / 1000) }) {
    const challenge = challengeBytes();
    const expiresAt = now + ttlSec;
    await this.#pool.query(
      `INSERT INTO zktele_challenges
       (challenge_hash, audience, app_domain, action_id, created_at, expires_at)
       VALUES ($1, $2, $3, $4, to_timestamp($5), to_timestamp($6))`,
      [hashChallenge(challenge), audience, appDomain, actionId, now, expiresAt],
    );
    return { challenge, expiresAt };
  }

  async consume(challenge, expected, now = Math.floor(Date.now() / 1000)) {
    const result = await this.#pool.query(
      `DELETE FROM zktele_challenges
       WHERE challenge_hash = $1
         AND audience = $2
         AND app_domain = $3
         AND action_id = $4
         AND expires_at > to_timestamp($5)
       RETURNING audience, app_domain, action_id,
                 EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
                 EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at`,
      [hashChallenge(challenge), expected.audience, expected.appDomain, expected.actionId, now],
    );
    if (result.rowCount !== 1) return { consumed: false, reason: 'challenge not found, expired, or already consumed' };
    const row = result.rows[0];
    return {
      consumed: true,
      audience: row.audience,
      appDomain: row.app_domain,
      actionId: row.action_id,
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
    };
  }

  async close() {
    await this.#pool.end();
  }

  async ping() {
    await this.#pool.query('SELECT 1');
  }
}

export function createChallengeStore(config) {
  return config.databaseUrl
    ? new PostgresChallengeStore(config.databaseUrl, { ssl: config.databaseSsl, ca: config.databaseCa })
    : new MemoryChallengeStore();
}
