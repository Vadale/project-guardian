# Packaging & release (Phase 4 — §9.3)

How Guardian is distributed. **Code-signing is optional and intentionally NOT
enabled** — Guardian ships fine unsigned on GitHub; signing only removes the OS
"unverified developer" warning. There are no certificate secrets in the repo or the
release workflow, by design (see *Optional: signing* below).

## Platform support (v0.1.0)
- **macOS & Linux — supported.** Developed and tested here; the proxy, daemon
  control socket (Unix domain socket), sandbox backstop, keychain, and TUI are
  exercised on these platforms.
- **Windows — experimental / best-effort, NOT tested end-to-end.** The whole
  workspace **compiles** and the **unit-test suite passes** on the `windows-latest`
  CI runner (including the named-pipe IPC tests), but Guardian has **not** been run
  end-to-end on real Windows hardware. The OS sandbox backstop (`guardian-sandbox`)
  has **no Windows backend** (it reports "no sandbox available" and the policy keeps
  `Exec` at ask/deny — fail safe). Treat Windows as unverified until a real-world
  pass is done. Bug reports from Windows users are welcome.

## You do NOT need certificates to ship
The supported, zero-cost path for an open-source tool:

- **`cargo install`** (no signing involved — it's a local build from source):
  ```sh
  cargo install --git https://github.com/Vadale/project-guardian guardian-cli
  # or from a clone:  cargo install --path crates/guardian-cli
  ```
- **GitHub Releases** — push a `v*` tag; the release workflow builds the binaries and
  attaches them (see below). Users download and run them. They are **unsigned**, so
  the OS shows a one-time warning the user clicks through:
  - **macOS:** right-click the binary → **Open** (or System Settings → Privacy &
    Security → **Open Anyway**). Once, then it runs normally.
  - **Windows:** SmartScreen → **More info** → **Run anyway**.
  - **Linux:** no warning; `chmod +x guardian` and run.

Signing (below) is a later polish that removes those warnings — **not** a
prerequisite for releasing.

## The CLI (`guardian`)
```sh
cargo build --release -p guardian-cli            # → target/release/guardian
```
On a `v*` tag, `.github/workflows/release.yml` builds the CLI for **macOS**
(aarch64 + x86_64), **Linux** (x86_64), and **Windows** (x86_64) and attaches the
archives to the GitHub Release. These are **unsigned developer builds** today.

## The desktop cockpit (Tauri app, `ui/`)
The Tauri bundler is enabled in `ui/src-tauri/tauri.conf.json`
(`bundle.active = true`, `targets = "all"`). Build platform installers with:
```sh
cd ui && npm install && npm run tauri build      # → .dmg/.app (macOS), .msi (Windows), .deb/.AppImage (Linux)
```
(The `ui/` app is its own build, excluded from the Cargo workspace.)

## Optional: signing & notarization (removes the OS warning)
This is a **polish step, not a requirement**. It removes the "unidentified
developer" / SmartScreen warnings above. It needs paid certificates (Apple Developer
Program ~$99/yr; a Windows code-signing cert) provided as **repo secrets** — kept
intentionally **out** of the repo. Skip this until/unless you want the warnings gone.

- **macOS** — an Apple **Developer ID Application** certificate. Sign and notarize:
  ```sh
  codesign --deep --force --options runtime --sign "Developer ID Application: …" Guardian.app
  xcrun notarytool submit Guardian.dmg --apple-id … --team-id … --password … --wait
  xcrun stapler staple Guardian.dmg
  ```
  In CI: import the cert into the keychain from a base64 secret, then run the above
  with `notarytool` credentials from secrets.
- **Windows** — an Authenticode (ideally EV) code-signing certificate:
  ```powershell
  signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 guardian.exe
  ```
- **Linux** — distro packages (`.deb`/`.rpm`) are typically signed with the repo's
  GPG key; the AppImage can be GPG-signed.

### Status
**v0.1.0 ships unsigned, by design.** Unsigned cross-platform CLI builds (`v*` tag)
+ `cargo install` + the Tauri bundler config are all in place. Code signing /
notarization is **deliberately left disabled**: no certificate secrets exist in the
repo or the release workflow, and none are required to download and run Guardian
from GitHub. Signing is an optional, later polish that only removes the OS
"unverified developer" warning and needs paid certificates as CI secrets; the
commands above are ready to wire in if/when the maintainer obtains them.
