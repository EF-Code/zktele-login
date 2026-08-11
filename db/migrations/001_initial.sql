CREATE TABLE IF NOT EXISTS zktele_challenges (
  challenge_hash TEXT PRIMARY KEY,
  audience TEXT NOT NULL,
  app_domain TEXT NOT NULL,
  action_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS zktele_challenges_expiry_idx
  ON zktele_challenges (expires_at);

CREATE TABLE IF NOT EXISTS zktele_claims (
  claim_id BIGSERIAL PRIMARY KEY,
  nullifier_hash TEXT NOT NULL,
  issuer TEXT NOT NULL,
  app_domain TEXT NOT NULL,
  action_id TEXT NOT NULL,
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (issuer, app_domain, action_id, nullifier_hash)
);

CREATE TABLE IF NOT EXISTS zktele_sessions (
  session_id BIGSERIAL PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  nullifier_hash TEXT NOT NULL,
  issuer TEXT NOT NULL,
  app_domain TEXT NOT NULL,
  action_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  idle_expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS zktele_sessions_expiry_idx
  ON zktele_sessions (absolute_expires_at);
