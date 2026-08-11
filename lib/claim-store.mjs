import * as crypto from 'crypto';
import pg from 'pg';

export class MemoryClaimStore {
  #claims = new Map();

  async initialize() {}

  async claim(nullifierHash, metadata) {
    const scope = `${metadata.issuer}\0${metadata.appDomain}\0${metadata.actionId}\0${nullifierHash}`;
    if (this.#claims.has(scope)) return { claimed: false, claims: this.#claims.size };
    this.#claims.set(scope, { claimedAt: new Date(), ...metadata, nullifierHash });
    return { claimed: true, claims: this.#claims.size };
  }

  async completeClaim(nullifierHash, metadata, { challengeStore, challenge, expected } = {}) {
    const consumed = await challengeStore.consume(challenge, expected);
    if (!consumed.consumed) return { claimed: false, claims: this.#claims.size, challengeConsumed: false, challengeReason: consumed.reason };
    const result = await this.claim(nullifierHash, metadata);
    return { ...result, challengeConsumed: true };
  }

  async count() {
    return this.#claims.size;
  }

  async ping() {}

  async close() {}
}

export class PostgresClaimStore {
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

  async claim(nullifierHash, metadata) {
    const inserted = await this.#pool.query(
      `INSERT INTO zktele_claims (nullifier_hash, issuer, app_domain, action_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (issuer, app_domain, action_id, nullifier_hash) DO NOTHING
       RETURNING nullifier_hash`,
      [nullifierHash, metadata.issuer, metadata.appDomain, metadata.actionId]
    );
    const count = await this.count();
    return { claimed: inserted.rowCount === 1, claims: count };
  }

  async completeClaim(nullifierHash, metadata, { challenge, expected, now = Math.floor(Date.now() / 1000) } = {}) {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const challengeResult = await client.query(
        `DELETE FROM zktele_challenges
         WHERE challenge_hash = $1
           AND audience = $2
           AND app_domain = $3
           AND action_id = $4
           AND expires_at > to_timestamp($5)
         RETURNING challenge_hash`,
        [crypto.createHash('sha256').update(challenge, 'utf8').digest('hex'), expected.audience, expected.appDomain, expected.actionId, now],
      );
      if (challengeResult.rowCount !== 1) {
        await client.query('ROLLBACK');
        return { claimed: false, claims: await this.count(), challengeConsumed: false, challengeReason: 'challenge not found, expired, or already consumed' };
      }
      const inserted = await client.query(
        `INSERT INTO zktele_claims (nullifier_hash, issuer, app_domain, action_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (issuer, app_domain, action_id, nullifier_hash) DO NOTHING
         RETURNING nullifier_hash`,
        [nullifierHash, metadata.issuer, metadata.appDomain, metadata.actionId],
      );
      const count = await client.query('SELECT COUNT(*)::int AS count FROM zktele_claims');
      await client.query('COMMIT');
      return { claimed: inserted.rowCount === 1, claims: count.rows[0].count, challengeConsumed: true };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async count() {
    const result = await this.#pool.query('SELECT COUNT(*)::int AS count FROM zktele_claims');
    return result.rows[0].count;
  }

  async ping() {
    await this.#pool.query('SELECT 1');
  }

  async close() {
    await this.#pool.end();
  }
}

export function createClaimStore(config) {
  return config.databaseUrl
    ? new PostgresClaimStore(config.databaseUrl, { ssl: config.databaseSsl, ca: config.databaseCa })
    : new MemoryClaimStore();
}
