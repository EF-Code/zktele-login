-- Keep periodic expiry cleanup bounded and index-backed. Runtime users need
-- DELETE rights on these tables but never schema ownership.
CREATE INDEX IF NOT EXISTS zktele_sessions_idle_expiry_idx
  ON zktele_sessions (idle_expires_at);

CREATE INDEX IF NOT EXISTS zktele_sessions_revoked_idx
  ON zktele_sessions (revoked_at)
  WHERE revoked_at IS NOT NULL;
