import test from 'node:test';
import assert from 'node:assert/strict';
import * as childProcess from 'child_process';
import * as fs from 'node:fs';
import pg from 'pg';
import { PostgresChallengeStore } from '../lib/challenge-store.mjs';
import { PostgresClaimStore } from '../lib/claim-store.mjs';
import { PostgresSessionStore } from '../lib/session-store.mjs';

const databaseUrl = process.env.DATABASE_URL;
const databaseSsl = process.env.DATABASE_SSL === 'true';
const databaseCa = process.env.DATABASE_CA_FILE ? fs.readFileSync(process.env.DATABASE_CA_FILE, 'utf8') : undefined;
const storeOptions = { ssl: databaseSsl, ca: databaseCa };

test('PostgreSQL migrations and concurrency preserve one-time semantics', { skip: !databaseUrl && 'DATABASE_URL is not configured' }, async () => {
  childProcess.execFileSync(process.execPath, ['scripts/migrate.mjs'], {
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'pipe',
  });
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    ssl: databaseSsl ? { rejectUnauthorized: true, ca: databaseCa } : false,
  });
  await pool.query('TRUNCATE zktele_challenges, zktele_claims, zktele_sessions RESTART IDENTITY');
  const challenges = new PostgresChallengeStore(databaseUrl, storeOptions);
  const claims = new PostgresClaimStore(databaseUrl, storeOptions);
  const sessions = new PostgresSessionStore(databaseUrl, { ...storeOptions, secret: Buffer.alloc(32, 17) });
  await Promise.all([challenges.initialize(), claims.initialize(), sessions.initialize()]);

  const challenge = await challenges.create({ audience: 'aud', appDomain: 'app', actionId: 'login', ttlSec: 300 });
  const consumed = await Promise.all(Array.from({ length: 20 }, () => challenges.consume(challenge.challenge, {
    audience: 'aud', appDomain: 'app', actionId: 'login',
  })));
  assert.equal(consumed.filter((result) => result.consumed).length, 1);

  const claimResults = await Promise.all(Array.from({ length: 20 }, () => claims.claim('nullifier', {
    issuer: 'issuer', appDomain: 'app', actionId: 'action',
  })));
  assert.equal(claimResults.filter((result) => result.claimed).length, 1);
  assert.equal((await claims.claim('nullifier', { issuer: 'issuer', appDomain: 'app', actionId: 'other-action' })).claimed, true);

  const session = await sessions.create({
    nullifierHash: 'nullifier', issuer: 'issuer', appDomain: 'app', actionId: 'login', idleTtlSec: 60, absoluteTtlSec: 300,
  });
  assert.equal((await sessions.get(session.token)).nullifierHash, 'nullifier');
  assert.equal(await sessions.revoke(session.token), true);
  assert.equal(await sessions.get(session.token), null);

  await Promise.all([challenges.close(), claims.close(), sessions.close()]);
  const afterRestart = new PostgresClaimStore(databaseUrl, storeOptions);
  assert.equal(await afterRestart.count(), 2);
  await afterRestart.close();
  await pool.end();
});
