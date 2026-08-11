# Security and disclosure notes

## Security properties

- Telegram HMAC and freshness are checked only by the trusted gateway.
- The v2 circuit binds the proof to an issuer commitment, application domain,
  freshness policy, Premium policy, and seven-signal public layout.
- Ed25519 signs a strict version-2 envelope containing the key ID, issuer,
  audience, domain, action, challenge, timestamps, circuit/artifact IDs, issuer
  commitment, and complete proof payload.
- Challenges are random 32-byte values; only SHA-256 hashes are persisted and
  successful completion consumes them once.
- Claims are atomically unique by issuer, domain, action, and nullifier.
- Login sessions are opaque random tokens; only their hashes are stored, with
  bounded idle/absolute expiry and server-side revocation.
- Unexpected HTTP failures return a generic 500 and a request ID. Request and
  proof inputs are never logged.

## Trusted components and limits

The gateway operator can see the Telegram user ID because Telegram HMAC
validation requires the raw `initData`. Telegram, the gateway host and its
secret store, the Ed25519 key, the issuer/nullifier secret, proving artifacts
and trusted setup, the relying verifier configuration, PostgreSQL, the
deployment edge, and operator access procedures are trusted components.

The proof does not independently establish that Telegram signed a user. A
compromised gateway can issue fraudulent attestations. A compromised relying
configuration can accept the wrong issuer. Database, edge, browser bridge,
client, and trusted-setup review remain necessary for a production launch.

## Reporting

Do not file public reports containing bot tokens, keys, raw Telegram
`initData`, profile JSON, proof witnesses, session tokens, or private URLs. Use
the repository owner's private security channel, include a minimal reproducible
description, and redact all identity-bearing values. Rotate a suspected key or
secret before sharing any log bundle.
