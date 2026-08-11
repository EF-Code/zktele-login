import * as crypto from 'crypto';
import pg from 'pg';

export function hashSessionToken(token, secret = undefined) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 512) throw new Error('invalid session token');
  const digest = secret
    ? crypto.createHmac('sha256', secret).update(token, 'utf8').digest('hex')
    : crypto.createHash('sha256').update(token, 'utf8').digest('hex');
  return digest;
}

function newToken() {
  return crypto.randomBytes(32).toString('base64url');
}

export class MemorySessionStore {
  #sessions = new Map();
  #secret;

  constructor({ secret = undefined } = {}) {
    this.#secret = secret;
  }

  async initialize() {}

  async create({ nullifierHash, issuer, appDomain, actionId, idleTtlSec, absoluteTtlSec, now = Math.floor(Date.now() / 1000) }) {
    const token = newToken();
    const tokenHash = hashSessionToken(token, this.#secret);
    this.#sessions.set(tokenHash, {
      tokenHash,
      nullifierHash,
      issuer,
      appDomain,
      actionId,
      createdAt: now,
      lastSeenAt: now,
      idleExpiresAt: now + idleTtlSec,
      absoluteExpiresAt: now + absoluteTtlSec,
    });
    return { token, expiresAt: now + absoluteTtlSec };
  }

  async get(token, now = Math.floor(Date.now() / 1000)) {
    let tokenHash;
    try { tokenHash = hashSessionToken(token, this.#secret); } catch { return null; }
    const session = this.#sessions.get(tokenHash);
    if (!session || session.idleExpiresAt <= now || session.absoluteExpiresAt <= now) {
      if (session) this.#sessions.delete(tokenHash);
      return null;
    }
    session.lastSeenAt = now;
    return { ...session };
  }

  async revoke(token) {
    let tokenHash;
    try { tokenHash = hashSessionToken(token, this.#secret); } catch { return false; }
    return this.#sessions.delete(tokenHash);
  }

  async ping() {}

  async close() {}
}

export class PostgresSessionStore {
  #pool;
  #secret;

  constructor(databaseUrl, { ssl = false, ca = undefined, secret = undefined } = {}) {
    this.#secret = secret;
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

  async initialize() {}

  async create({ nullifierHash, issuer, appDomain, actionId, idleTtlSec, absoluteTtlSec, now = Math.floor(Date.now() / 1000) }) {
    const token = newToken();
    await this.#pool.query(
      `INSERT INTO zktele_sessions
       (token_hash, nullifier_hash, issuer, app_domain, action_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
       VALUES ($1, $2, $3, $4, $5, to_timestamp($6), to_timestamp($6), to_timestamp($7), to_timestamp($8))`,
      [hashSessionToken(token, this.#secret), nullifierHash, issuer, appDomain, actionId, now, now + idleTtlSec, now + absoluteTtlSec],
    );
    return { token, expiresAt: now + absoluteTtlSec };
  }

  async get(token, now = Math.floor(Date.now() / 1000)) {
    let tokenHash;
    try { tokenHash = hashSessionToken(token, this.#secret); } catch { return null; }
    const result = await this.#pool.query(
      `UPDATE zktele_sessions
       SET last_seen_at = to_timestamp($2)
       WHERE token_hash = $1
         AND revoked_at IS NULL
         AND idle_expires_at > to_timestamp($2)
         AND absolute_expires_at > to_timestamp($2)
       RETURNING token_hash, nullifier_hash, issuer, app_domain, action_id,
                 EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
                 EXTRACT(EPOCH FROM last_seen_at)::bigint AS last_seen_at,
                 EXTRACT(EPOCH FROM idle_expires_at)::bigint AS idle_expires_at,
                 EXTRACT(EPOCH FROM absolute_expires_at)::bigint AS absolute_expires_at`,
      [tokenHash, now],
    );
    if (result.rowCount !== 1) return null;
    const row = result.rows[0];
    return {
      tokenHash: row.token_hash,
      nullifierHash: row.nullifier_hash,
      issuer: row.issuer,
      appDomain: row.app_domain,
      actionId: row.action_id,
      createdAt: Number(row.created_at),
      lastSeenAt: Number(row.last_seen_at),
      idleExpiresAt: Number(row.idle_expires_at),
      absoluteExpiresAt: Number(row.absolute_expires_at),
    };
  }

  async revoke(token) {
    let tokenHash;
    try { tokenHash = hashSessionToken(token, this.#secret); } catch { return false; }
    const result = await this.#pool.query(
      'UPDATE zktele_sessions SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL',
      [tokenHash],
    );
    return result.rowCount === 1;
  }

  async ping() {
    await this.#pool.query('SELECT 1');
  }

  async close() {
    await this.#pool.end();
  }
}

export function createSessionStore(config) {
  return config.databaseUrl
    ? new PostgresSessionStore(config.databaseUrl, { ssl: config.databaseSsl, ca: config.databaseCa, secret: config.sessionSecret })
    : new MemorySessionStore({ secret: config.sessionSecret });
}
