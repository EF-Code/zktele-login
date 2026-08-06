# zktele-login

Demo web app for **anonymous, Sybil-resistant Telegram login** powered by the [zk-tele-auth](https://github.com/EF-Code/zk-tele-auth) stack.

"Log in with Telegram, but nobody sees your ID": the gateway validates your
Telegram MiniApp `initData`, then emits a Groth16 proof over **BLS12-381**. The
only thing a dApp ever learns is a **nullifier** — a deterministic hash of
`userId + app domain`. No `userId`, name, or photo ever leaves the gateway.

## Run

```sh
npm install
npm start
# → http://localhost:3000
```

Options:

| env var | default | meaning |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `APP_DOMAIN` | `zktele-login.demo` | domain bound into the nullifier |
| `TELEGRAM_BOT_TOKEN` | dev placeholder | used to sign/verify initData |

## What it demonstrates

- **Anonymity** — the `/api/authenticate` response (shown on the page) contains
  no `userId`; only a proof and a nullifier. The `userId` never leaves the
  gateway.
- **Unlinkability** — a random salt is mixed into the nullifier, so every login
  mints a *fresh* nullifier. Log in twice as the same user and you get two
  different nullifiers — sessions cannot be correlated even by a server holding
  the full history.
- **Sybil-resistance** — a proof can only be minted for a real bot-signed
  Telegram session (the HMAC check happens inside the gateway), so identities
  cannot be forged for free. Note: because nullifiers are fresh per login,
  enforcing strict "one account = one vote" dedup requires the deterministic
  nullifier variant of the stack (omit the salt); this demo shows the
  unlinkable-session mode.
- **Freshness & tamper-resistance** — proofs carry a timestamp and are
  pairing-checked; the "replay" button shows a tampered proof being rejected.
- **Domain binding** — the app domain is hashed into the circuit, so a proof
  minted for this demo can't be replayed on another app (try the cross-domain
  button).
- **Session claims** — a nullifier registry lets the app hand out "one thing
  per account": a claim succeeds once, and replaying the same proof is
  rejected.
- **Allowlist membership** — prove you're on a private list without revealing
  who you are. The app commits to a Merkle `root` only; `leaf = Poseidon(userId,
  1)` hides the account even from the leaf, and outsiders get `isMember=0`.

## API

| route | request | response |
|---|---|---|
| `POST /api/init` | `{ userId, isPremium }` | `{ initData }` signed like Telegram would |
| `POST /api/authenticate` | `{ initData }` | `{ nullifierHash, proofPayload }` |
| `POST /api/verify` | `{ proofPayload, appDomain? }` | `{ isValid, nullifierHash, error? }` |
| `POST /api/claim` | `{ proofPayload }` | `{ claimed, claims }` — 409 on replay |
| `GET /api/claims` | — | `{ claims }` |
| `GET /api/config` | — | `{ appDomain }` |
| `GET /api/membership` | — | `{ root, memberCount, members }` |
| `POST /api/membership/prove` | `{ memberId }` | `{ proofPayload, leaf, isMember }` |
| `POST /api/membership/verify` | `{ proofPayload }` | `{ isValid, isMember, leaf, root, error? }` |

## Security notes

- `POST /api/init` **simulates Telegram's signing** so the flow can be tested
  with no real bot. In production, initData is signed by Telegram inside the
  MiniApp; do not expose a signing endpoint.
- The bot token is a **server secret** — set `TELEGRAM_BOT_TOKEN` in production.
- For a production deployment, re-run the setup ceremony with a public
  powers-of-tau (the committed artifacts use a fixed dev beacon).
