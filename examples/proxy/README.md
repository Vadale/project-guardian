# Network proxy example — read a private site, never change it

This shows Guardian's flagship use case over **real web traffic**: let an agent
*read* a site you authorize (your bank page, Agenzia delle Entrate, …) using a
token Guardian holds — the agent never sees the credential — while **blocking any
state-changing request** (transfers, payments, deletions), even under prompt
injection or a hallucinating model.

Guardian runs as a **user-space HTTP(S) forward proxy**: the agent points
`HTTP_PROXY` / `HTTPS_PROXY` at it. Egress is **default-deny** — only the hosts and
methods in the policy get through; everything else is blocked. Every decision is
written to the tamper-evident audit log.

## Run it

```sh
# 1) Prepare your secret (the agent never sees this value)
cp examples/proxy/secrets.example.toml examples/proxy/secrets.toml
chmod 600 examples/proxy/secrets.toml
$EDITOR examples/proxy/secrets.toml          # put the real token in

# 2) Start the proxy
guardian proxy \
  --listen 127.0.0.1:8080 \
  --policy  examples/proxy/web-policy.toml \
  --secrets examples/proxy/secrets.toml

# 3) For HTTPS, trust the local CA (one time). This warns you, prints the exact
#    commands, and on macOS runs the trust command (the OS asks you to authorize):
guardian proxy --install-ca
#    (or just print the cert path and install it yourself: guardian proxy --print-ca-path)

# 4) Point the agent at the proxy
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
```

Then review what happened:

```sh
guardian log            # recent decisions + integrity status
```

## What the policy enforces

`web-policy.toml` (edit the host names to your real ones):

- **Tunnel allowlist** — a TLS tunnel (`CONNECT`) opens only to the authorized
  hosts. An unlisted host gets *no tunnel at all*, so nothing can be smuggled to it.
- **Read-only** — `GET`/`HEAD` to those hosts are allowed; Guardian injects the
  brokered `Authorization` here.
- **Block writes** — `POST`/`PUT`/`PATCH`/`DELETE` are denied outright with a clear
  reason. "Go read the balance, never empty the account."

## Trusting the CA (HTTPS only)

Intercepting HTTPS means Guardian presents a certificate the client must trust, so
you install the local CA into your trust store. **This is security-sensitive**: that
CA can mint a certificate for any site, so its private key is generated locally and
stored owner-only (`ca.key`, mode `600`) and never leaves your machine. Install only
the certificate (`ca.crt`), and only for the client/agent you are guarding.

> Known limitation (tracked): once an allowed `CONNECT` is upgraded to a WebSocket,
> individual frames are not yet inspected — only the upgrade's host is policed.
