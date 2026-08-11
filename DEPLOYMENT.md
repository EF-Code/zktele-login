# Provider-neutral deployment runbook

This document describes the release sequence without choosing a cloud
provider. Do not expose the gateway and relying roles through one process in a
production deployment.

## Hosting compatibility gate

This application requires a Docker- or Node-capable runtime for the gateway
and relying services, plus PostgreSQL with TLS. InfinityFree's free hosting
environment does not provide Node.js, Docker, or PostgreSQL, so it cannot host
these backend roles. An InfinityFree domain may still be used for DNS and a
static frontend/redirect if its terms and TLS setup meet the product needs;
the backend and database must run on a separate VPS, container platform, or
managed services. Do not upload the backend container or database credentials
to InfinityFree.

Before provider-specific work, record the backend provider, PostgreSQL
provider/major version, TLS CA/verification method, secret manager, trusted
proxy topology, and canonical HTTPS origins. No production launch gate is
green until those external values are verified in the deployed environment.

## Build and migration

1. Build from the reviewed commit with a clean checkout and `npm ci`.
2. Verify `npm run check`, `npm test`, `npm audit --omit=dev`, and the artifact
   hashes in `test/artifact-provenance.test.mjs`.
3. Build the multi-stage `Dockerfile` and scan the image. It must contain no
   `.env` files, keys, Git metadata, tests, or deployment handoff notes.
4. Run `npm run migrate` once with the separate migration credential. The
   runtime role must have DML access only to the application tables and must
   not be a schema owner. Apply [db/runtime-permissions.sql](/home/wellington/stuff/zktele-login/db/runtime-permissions.sql)
   as the database owner with `psql -v runtime_user=... -v app_database=...`.
5. Perform a restore drill against a disposable database and retain the
   timestamped evidence. Use `pg_dump`/`pg_restore` from the same PostgreSQL
   major version as the target server (or the provider's native backup tools);
   client/server major mismatches can make a dump fail during restore even
   when the database itself is healthy.

## Gateway

Set `SERVICE_ROLE=gateway`, an explicit production `ENVIRONMENT_ID`, HTTPS
`APP_ORIGIN`, exact `ALLOWED_ORIGINS`, and the configured issuer/action/circuit
identities. Inject only the Telegram bot token, issuer/nullifier secret, and
Ed25519 private key. Mount the private key read-only (`0400`) and record its
fingerprint out of band. The gateway exposes `/v1/attest` and health routes;
it does not serve the browser or a database.

## Relying service

Set `SERVICE_ROLE=relying` and inject only the pinned gateway public key map,
`ISSUER_KEY_HASH`, session secret, restricted PostgreSQL URL, database TLS CA,
and exact browser/gateway origins. It must not contain `TELEGRAM_BOT_TOKEN`,
`NULLIFIER_SECRET`, or `GATEWAY_PRIVATE_KEY_*`. Serve the browser, challenges,
completion, sessions, and claims from this role.

Terminate TLS at a controlled edge, configure the edge body/request limits and
distributed rate limiter, and document the exact proxy trust behavior before
enabling any forwarded-address logic. Preserve the application CSP and do not
use wildcard CORS with credentials.

If metrics are enabled, keep `/health/metrics` private to the monitoring
network and send `Authorization: Bearer <base64 METRICS_TOKEN>`. The endpoint
contains only coarse counters, gauges, and latency buckets; never add identity,
challenge, nullifier, IP, or token labels. The built-in cleanup pass is bounded
to 1,000 expired rows per interval, so schedule an operational database job or
increase capacity separately if backlog metrics show sustained growth.

## Staging and rollback

1. Deploy both roles to an isolated staging origin and run database migrations.
2. Pin the gateway public key and issuer commitment in the relying deployment.
3. Exercise challenge issuance, valid completion, replay, cross-origin,
   malformed-proof, logout, restart, and concurrent claim paths.
4. Verify that relying logs and database rows contain no raw Telegram ID,
   `initData`, profile JSON, proof witness, issuer secret, private key, or
   session token.
5. Test the supported Telegram Android, iOS, Desktop, and Web clients.
6. Promote gradually with liveness/readiness checks, latency/CPU/memory
   budgets, and an alert-backed rollback window.

Rollback means stopping new traffic, restoring the last reviewed container,
running only backward-compatible migrations, and retaining the active public
key until every old attestation expires. Revoke a compromised Ed25519 key by
removing its key ID from the relying allowlist and redeploying. Issuer/nullifier
secret rotation is a separate migration because it changes nullifier continuity.

### Local evidence versus provider evidence

The repository tests can prove protocol and persistence invariants locally,
but they do not prove provider networking, managed PostgreSQL TLS, DNS,
Telegram WebView behavior, or a real release rollback. Retain separate
staging evidence for those gates:

- container image digest, read-only/rootless smoke output, and health checks;
- HTTPS header, cookie, CORS, and exact-origin checks through the production
  proxy;
- provider-native backup/PITR restore and a rollback to a prior immutable image;
- the supported Telegram Android, iOS, Desktop, and Web client matrix;
- load results using genuine proof generation with the chosen CPU/memory
  limits and an explicit latency/error objective.
