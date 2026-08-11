# Operations checklist

Before launch, record the canonical production origin, app-domain namespace,
audience, action ID, issuer ID, policy/circuit version, artifact-set ID,
gateway key ID, issuer commitment, supported Telegram clients, rate/latency
objectives, provider, secret manager, database endpoint, backup policy, and
on-call owner.

The backend cannot be deployed on InfinityFree's free PHP/MySQL-only hosting:
keep the InfinityFree domain only as a DNS/static edge if desired, and run the
Docker/Node gateway and relying service plus PostgreSQL on a compatible
provider. Record the DNS provider, TLS termination point, trusted proxy hops,
backend origins, and the exact managed PostgreSQL TLS/CA configuration before
staging.

Monitor only coarse, non-identifying signals: HTTP status/latency, readiness,
proof queue depth and latency, coarse verification failures, challenge/claim
success and conflict counts, database pool saturation, process restarts, and
resource usage. Never use Telegram IDs, nullifiers, challenges, full IPs,
`initData`, attestations, or session tokens as metric labels.

The optional `/health/metrics` endpoint is disabled by default. When enabled,
protect it with the production metrics token and expose it only on the private
monitoring path. Alert on readiness failures, proof rejections/failures,
database errors, cleanup failures, and sustained proof queue saturation.

During incidents, remove the affected gateway key ID from relying allowlists,
pause claim traffic, preserve redacted request IDs, and redeploy from a
reviewed image. Keep the old key available only for the documented attestation
expiry overlap. Treat issuer/nullifier compromise as a continuity incident:
do not rotate it casually during an active one-per-account action.

## Backup, restore, and rollback drill record

Record each drill with UTC start/end times, source and target PostgreSQL major
versions, dump/backup identifiers, checksums where applicable, restore target,
row-count/invariant checks, RTO/RPO measurements, and the operator who
approved cleanup. A logical restore must re-run migrations/permission checks
and the one-time challenge/claim concurrency test. A release rollback must use
an immutable prior image digest, keep migrations backward-compatible, verify
readiness and session/claim continuity, and exercise key revocation if the
rollback was caused by a signing-key incident.

Never place bot tokens, database passwords, private keys, session tokens, raw
Telegram `initData`, or proof witnesses in the drill record.
