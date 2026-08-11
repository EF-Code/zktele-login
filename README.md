# zktele-login

`zktele-login` is a reference implementation of gateway-attested Telegram
Mini App authentication. A trusted gateway validates Telegram's server-signed
`initData`, generates an issuer-bound Groth16 proof, and signs the complete
proof envelope with Ed25519. A separate relying service pins the gateway key
and issuer commitment, verifies the proof policy, consumes a one-time
challenge, and records a scoped claim or server-side session.

A valid Groth16 proof by itself is not Telegram authentication. The circuit
does not verify Telegram's HMAC; the relying service therefore requires both
the issuer-bound commitment and the pinned gateway signature.

## Trust boundary

The `gateway` role may read `TELEGRAM_BOT_TOKEN`, `NULLIFIER_SECRET`, and the
Ed25519 private key. It must not receive relying-service session or database
credentials. The `relying` role receives only the gateway public-key map, its
own session secret, and restricted PostgreSQL credentials. The browser receives
no secret and never uses `initDataUnsafe` for authentication.

For local UI work, `SERVICE_ROLE=combined` and `ALLOW_DEV_INIT=true` enable a
clearly non-production simulation route. Production rejects the combined role
unless an explicit exception is configured, and never exposes
`/api/dev/init`.

## Local development

```sh
npm ci
npm run dev
# http://localhost:3000
```

The local development process creates ephemeral keys and permits simulated
identities. For a database-backed local run, start PostgreSQL with
`docker compose up -d postgres`, set `DATABASE_URL`, run `npm run migrate`, and
then start the app. The migration user should be separate from the runtime
user outside local development.

## Production roles

Set `SERVICE_ROLE=gateway` for the Telegram proof service and
`SERVICE_ROLE=relying` for the browser/API service. The exact HTTPS origins,
audience, action, issuer, key ID, circuit version, and artifact set are
deployment identities—not defaults. The relying service requires
`ISSUER_KEY_HASH` and a pinned `GATEWAY_PUBLIC_KEY_FILE`,
`GATEWAY_PUBLIC_KEY_BASE64`, or `GATEWAY_PUBLIC_KEYS_JSON`.

The full variable list is in [.env.example](/home/wellington/stuff/zktele-login/.env.example). In production, also provide:

- a managed secret mount for the gateway private key and nullifier secret;
- a restricted PostgreSQL runtime credential and a separate migration
  credential;
- `DATABASE_SSL=true` plus a verified CA bundle when required by the provider;
- a session secret on the relying service;
- exact `ALLOWED_ORIGINS` and `GATEWAY_ORIGIN` values.

Run migrations before starting the runtime user:

```sh
DATABASE_URL='postgresql://migration-user@db/zktele' npm run migrate
NODE_ENV=production SERVICE_ROLE=relying npm start
```

The runtime does not create schema objects at startup. PostgreSQL uniqueness
is enforced on `(issuer, app_domain, action_id, nullifier_hash)`, and challenge
consumption plus claim insertion use a transaction when the PostgreSQL store is
active.

Expired challenges and sessions are removed by a bounded periodic cleanup pass;
the migration adds the supporting expiry indexes. Set `METRICS_ENABLED=true` to
enable the private `/health/metrics` Prometheus endpoint. In production it also
requires a base64-encoded `METRICS_TOKEN` (at least 32 decoded bytes), supplied
only to the service and scrape configuration.

## API surface

Relying service:

| Route | Purpose |
| --- | --- |
| `GET /health/live` | Process liveness |
| `GET /health/ready` | Readiness boundary (database and production artifacts) |
| `GET /health/metrics` | Opt-in, token-protected coarse metrics |
| `GET /api/config` | Public descriptive policy metadata |
| `GET /api/challenge` | Creates a verifier-owned one-time challenge |
| `POST /api/auth/complete` | Verifies an attestation and issues a session or claim result |
| `POST /api/claim` | Compatibility claim completion route |
| `GET /api/session` / `POST /api/logout` | Opaque server-side session lifecycle |

Gateway service:

| Route | Purpose |
| --- | --- |
| `GET /health/live` | Process liveness |
| `GET /health/ready` | Readiness boundary (database and production artifacts) |
| `POST /v1/attest` | Validates Telegram data and returns a signed attestation |
| `GET /health/metrics` | Opt-in, token-protected coarse metrics |

`/v1/attest` accepts `initData`, `challenge`, `audience`, `appDomain`, and
`actionId`. The gateway allowlists all authorization context values against its
configuration. The relying side treats the public key in `/api/config` as
diagnostic metadata, never as a trust root.

## Validation and supply chain

```sh
npm ci
npm run check
npm test
npm audit --omit=dev
docker build --tag zktele-login:local .
```

`npm run test:load` exercises the bounded challenge/control-plane path and
reports p95 latency, failures, heap delta, and proof-gate occupancy. It does
not claim a production proof-throughput result; valid-proof flooding still
requires a staging environment with real resource limits and telemetry.

The dependency is pinned to the issuer-bound upstream revision
`e50efa26ce54c940b138885a9aac40ee7ed00206` over credential-free HTTPS. Root
overrides select `bfj@9.1.3` and `underscore>=1.13.8`; the current audit is
clean. `.npmrc` permits only the root Git dependency, while CI and the build
stage rewrite any accidental GitHub SSH transport to HTTPS.
`test/artifact-provenance.test.mjs` verifies the exact Telegram-auth
WASM, R1CS, proving-key, and verification-key hashes copied from that pinned
revision. Review the trusted setup and circuit independently before any
production claim.

The container runs as the unprivileged `node` user. CI uses `npm ci`, the
issuer-bound proof integration suite, dependency audit, secret scanning, a
container build, a health smoke test, and a bounded control-plane load smoke
test. Provider-neutral deployment and
rollback procedures are in [DEPLOYMENT.md](/home/wellington/stuff/zktele-login/DEPLOYMENT.md)
and [SECURITY.md](/home/wellington/stuff/zktele-login/SECURITY.md).

Passing local tests is not a production declaration. Real PostgreSQL,
multi-instance, load, Telegram-client, deployment-edge, backup/restore,
trusted-setup, and independent security-review gates remain external until
performed and evidenced.
