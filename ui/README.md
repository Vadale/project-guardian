# Guardian UI

Guardian has **two** human approval surfaces, both thin clients of the daemon
control socket (no policy logic in the UI):

- **Terminal cockpit (primary, available now):** `guardian ui` — a lightweight
  ASCII TUI (ratatui) meant to sit in a terminal pane next to the agent. Run the
  daemon, then `guardian ui --daemon <socket>`; pending `ask` actions show up with
  risk bars and `[A]llow`/`[D]eny` (keyboard or mouse), `p` = panic. This is the
  surface to use for the Claude Code test.
- **Desktop window (later):** the Tauri v2 app below, for non-terminal users.

---

## Guardian desktop UI (Tauri v2)

The human control surface: a small desktop app that shows the actions an agent is
waiting on (the **yellow** queue) with their plain-language explanation and risk,
and lets you **Allow** or **Deny** each one. It is a thin client of the running
`guardian-daemon` — all policy logic stays in the daemon (see `CLAUDE.md`).

```
ui/
├─ src/                 # static frontend (no Node build step)
│  ├─ index.html
│  └─ main.js           # polls `pending`, sends `respond`
└─ src-tauri/           # Tauri (Rust) backend — its own cargo workspace
   ├─ Cargo.toml
   ├─ build.rs
   ├─ tauri.conf.json
   ├─ capabilities/default.json
   └─ src/{lib.rs,main.rs}   # `pending` / `respond` commands → DaemonClient
```

## How it works
- `src-tauri/src/lib.rs` exposes two Tauri commands, `pending` and `respond`,
  which call [`guardian_daemon::DaemonClient`] over the daemon's Unix control
  socket (`GUARDIAN_SOCK`, default `<tempdir>/guardian.sock`).
- The frontend polls `pending` every 1.5 s, renders one card per pending action
  (tool, plain-language text, traffic-light risk badge), and calls `respond` on
  Allow/Deny.

## Prerequisites
- Rust toolchain (same as the rest of the repo).
- Tauri CLI: `cargo install tauri-cli` (no Node required — the frontend is static).
- A system webview: macOS ships WKWebView (install Xcode Command Line Tools);
  Linux needs `webkit2gtk`; Windows needs WebView2.

## Run it
1. Start the daemon (in the repo root):
   ```sh
   GUARDIAN_SOCK=/tmp/guardian.sock cargo run -p guardian-daemon
   ```
2. In another terminal, launch the UI:
   ```sh
   cd ui/src-tauri
   GUARDIAN_SOCK=/tmp/guardian.sock cargo tauri dev
   ```
3. Drive a tool call that needs review (e.g. an `exec`/payment) through the
   daemon socket or an MCP client; it appears in the window for Allow/Deny.

## Status / caveats
- **Not built in CI / headless environments.** Building and running this app
  needs the Tauri toolchain and a desktop (a display + a system webview), so it is
  not part of `cargo test --workspace` and has not been built here. The backend
  bridge it depends on (`DaemonClient`) **is** covered by tests in `guardian-daemon`.
- Icons: release bundling (`bundle.active`) is off. For a packaged build, generate
  icons with `cargo tauri icon <png>` and enable bundling.
- First `cargo tauri dev` generates `src-tauri/gen/` (schemas etc.); commit or
  ignore per preference.
