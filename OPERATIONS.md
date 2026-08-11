# Operations checklist

Before launch, record the canonical production origin, app-domain namespace,
audience, action ID, issuer ID, policy/circuit version, artifact-set ID,
gateway key ID, issuer commitment, supported Telegram clients, rate/latency
objectives, provider, secret manager, database endpoint, backup policy, and
on-call owner.

Monitor only coarse, non-identifying signals: HTTP status/latency, readiness,
proof queue depth and latency, coarse verification failures, challenge/claim
success and conflict counts, database pool saturation, process restarts, and
resource usage. Never use Telegram IDs, nullifiers, challenges, full IPs,
`initData`, attestations, or session tokens as metric labels.

During incidents, remove the affected gateway key ID from relying allowlists,
pause claim traffic, preserve redacted request IDs, and redeploy from a
reviewed image. Keep the old key available only for the documented attestation
expiry overlap. Treat issuer/nullifier compromise as a continuity incident:
do not rotate it casually during an active one-per-account action.
