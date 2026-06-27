# Packaging & release (Phase 4 — §9.3)

How Guardian is built into distributable artifacts, and what **requires the
maintainer's signing certificates** (not in the repo).

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

## Signing & notarization — **requires the maintainer's certificates**
Distributing without these means users see "unidentified developer" / SmartScreen
warnings. Adding them needs credentials that must be provided as **repo secrets**;
they are intentionally **not** in the repo.

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
Unsigned cross-platform builds + the Tauri bundler config are in place. **Signed /
notarized release artifacts are blocked on the maintainer providing the Apple
Developer ID and Windows code-signing certificates** (as CI secrets); the signing
commands above are ready to wire in once they exist.
