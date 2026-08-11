-- Apply this file as the database owner after migrations. It is a psql
-- template: pass -v runtime_user=... and -v app_database=...; never make the
-- runtime role the schema owner or grant it CREATE/ALTER/DROP privileges.
\set ON_ERROR_STOP on
\if :{?runtime_user}
\else
  \error 'runtime_user is required (use psql -v runtime_user=...)'
\endif
\if :{?app_database}
\else
  \error 'app_database is required (use psql -v app_database=...)'
\endif

GRANT CONNECT ON DATABASE :"app_database" TO :"runtime_user";
GRANT USAGE ON SCHEMA public TO :"runtime_user";
REVOKE CREATE ON SCHEMA public FROM :"runtime_user";

GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE zktele_challenges, zktele_claims, zktele_sessions
  TO :"runtime_user";

GRANT USAGE, SELECT
  ON SEQUENCE zktele_claims_claim_id_seq, zktele_sessions_session_id_seq
  TO :"runtime_user";

-- The migration ledger is intentionally not granted to the runtime role.
