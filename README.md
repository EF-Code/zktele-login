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
