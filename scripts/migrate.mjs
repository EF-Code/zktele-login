import * as fs from 'fs/promises';
import * as path from 'path';
import pg from 'pg';
import { fileURLToPath } from 'url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required for migrations');
if (process.env.NODE_ENV === 'production' && process.env.DATABASE_SSL !== 'true') {
  throw new Error('DATABASE_SSL=true is required for production migrations');
}

const files = (await fs.readdir(path.join(root, 'db', 'migrations')))
  .filter((name) => /^\d+_[a-z0-9_-]+\.sql$/.test(name))
  .sort();
if (files.length === 0) throw new Error('no migrations found');

const pool = new pg.Pool({
  connectionString: databaseUrl,
  ssl: process.env.DATABASE_SSL === 'true'
    ? { rejectUnauthorized: true, ca: process.env.DATABASE_CA_FILE ? await fs.readFile(process.env.DATABASE_CA_FILE, 'utf8') : undefined }
    : false,
  max: 2,
  connectionTimeoutMillis: 5_000,
  statement_timeout: 30_000,
  query_timeout: 30_000,
});
const client = await pool.connect();
try {
  await client.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', ['zktele-login-migrations']);
  await client.query(`
    CREATE TABLE IF NOT EXISTS zktele_schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  for (const file of files) {
    const already = await client.query('SELECT 1 FROM zktele_schema_migrations WHERE version = $1', [file]);
    if (already.rowCount) continue;
    const sql = await fs.readFile(path.join(root, 'db', 'migrations', file), 'utf8');
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('INSERT INTO zktele_schema_migrations (version) VALUES ($1)', [file]);
      await client.query('COMMIT');
      console.log(`applied ${file}`);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  }
} finally {
  await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', ['zktele-login-migrations']).catch(() => {});
  client.release();
  await pool.end();
}
