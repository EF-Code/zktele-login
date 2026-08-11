# Local validation evidence

Recorded 2026-08-11 from the reviewed worktree. Values below are aggregate
or artifact metadata only; no bot token, private key, password, raw Telegram
`initData`, proof witness, session token, Telegram ID, or challenge value is
recorded.

## Passed locally

- `npm run check`: pass.
- `npm test`: 37 tests, 36 passed, 1 skipped because the first run had no
  `DATABASE_URL`; no failures.
- `npm audit --omit=dev`: 0 vulnerabilities.
- `npm ls --all --omit=dev`: resolved dependency tree; `zk-tele-auth` is pinned
  to `e50efa26ce54c940b138885a9aac40ee7ed00206` over HTTPS.
- PostgreSQL migrations, twenty-way challenge consumption, scoped claim
  uniqueness, session creation/revocation, and restart persistence passed
  against a disposable PostgreSQL 16 container on `127.0.0.1:55432`.
- Restricted runtime permissions passed: DML works for the runtime role,
  schema DDL and migration-ledger reads fail, and template variables are
  required by `db/runtime-permissions.sql`.
- A disposable TLS-enabled PostgreSQL 16 container passed migration, CA
  verification, twenty-way challenge consumption, runtime-role DML, and
  session round-trip using `DATABASE_SSL=true` and a supplied CA bundle.
- Four-process gateway/relying multi-instance exercise passed with shared
  PostgreSQL state: valid attestations verified on the other relying replica,
  concurrent completion produced exactly one success and fifteen rejections,
  sessions were readable on the other replica, and the service continued after
  one replica stopped.
- `npm run test:proof-load` passed with real Groth16 generation and verification
  over synthetic HMAC-valid Telegram fixtures:
  - 4 requests / concurrency 2: 4 verified, p95 2,109.92 ms.
  - repeat 4 requests / concurrency 2: 4 verified, p95 2,427.94 ms.
  - 8 requests / concurrency 4: 8 verified, p95 5,251.97 ms.
  Both runs drained gateway and relying proof gates to zero. These are local
  capacity smokes, not provider-scale SLO evidence.
- Production image build passed with host networking:
  `zktele-login:staging`, image ID
  `sha256:8433429a93db8db5a50edea8e874d9aa9bbe3ac5564d96cee51690614436712`.
  The image runs as `node`, excludes tests, Git metadata, local env files, and
  the handoff, and passed read-only/capability-dropped liveness, readiness, and
  Docker health checks.
- The provider-neutral Compose stack passed a fresh local build, PostgreSQL
  17.5 health, both migrations, and application readiness. Its development
  fixture flow completed verification, login/session, and claim in the
  containerized app. This stack intentionally uses combined development
  simulation and is not a production split deployment.
- Same-image restart drill against PostgreSQL preserved an authenticated
  server-side session after restart.
- The supplied staging bot token was read only from the local ignored secret
  file with mode `600`; Telegram `getMe` succeeded, and the gateway accepted a
  fixture HMAC made with that token before generating a real Groth16
  attestation. No bot identity or token value is recorded here.
- `npm run local:backend` started separate localhost gateway and relying
  processes with secret separation and the restricted PostgreSQL runtime role.
  The local HTTP flow passed challenge issuance, token-backed gateway
  attestation, relying verification, login completion, and session lookup;
  the production simulation route returned 404 on the gateway.
- Headless Chrome against the running localhost split backend passed the real
  page flow with an injected token-backed Telegram WebApp fixture: the page
  obtained an attestation, displayed the verified state, enabled the claim
  action, and received a successful claim response. No browser secrets or
  request values were recorded.
- A disposable production-mode rehearsal passed behind a local self-signed
  HTTPS edge and TLS-enabled PostgreSQL 16 with CA verification. Exact HTTPS
  origin/CORS policy, HSTS and security headers, real token-backed gateway
  attestation, `__Host-` Secure session cookies, session lookup, claim, and
  gateway development-route isolation all passed. The fixture used synthetic
  HMAC-valid Telegram data; it is not a real Telegram WebView test.
- Logical backup/restore passed with matching PostgreSQL 16 client/server
  tools. Restored challenge race, claim, session, and row-count invariants
  passed. The latest disposable dump was 11,970 bytes with recorded SHA-256
  `b0e87479c56005539e178c562c2270ada12d58989b4e16a4be2ad9fa4bca48ac` and the
  restored table counts were `0|2|1` (challenges|claims|sessions).

## Not a local green gate

- The host PostgreSQL service has no initialized cluster; local database
  evidence uses disposable containers. The production provider's exact major,
  connection budget, TLS mode, CA, backups/PITR, and restore RTO/RPO remain to
  be verified.
- InfinityFree cannot host the Node/Docker/PostgreSQL backend. It can only be
  considered for domain/DNS/static-edge use; a compatible backend provider is
  still required.
- The supplied staging bot token passes local `getMe`, HMAC, and gateway
  attestation checks. Real BotFather/Mini App configuration and Android, iOS,
  Desktop, and Web client tests remain pending until a public HTTPS origin is
  configured.
- DNS ownership, certificate issuance, proxy trust, exact production origins,
  secret-manager injection, distributed rate limiting, and deployed HTTP
  header/cookie/CORS checks remain external gates.
- A true rollback to a prior immutable release image and provider-native PITR
  drill require a staging provider and a retained previous release.
- The user explicitly waived independent cryptographic review for this solo
  project. That waiver is recorded as risk acceptance; it is not evidence of
  cryptographic or trusted-setup independence.

Do not call the service production-ready until the external gates above are
completed and the release checklist in `LUNA_MAX_DEPLOYMENT_HANDOFF.md` is
updated with evidence.
