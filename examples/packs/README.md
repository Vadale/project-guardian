# Signed community policy packs (§8.4)

A **pack** is a directory of policy `.toml` files plus a signed manifest
(`guardian-pack.json`). It lets you share policy you can prove came from a specific
publisher and hasn't been tampered with — and it can **never silently grant a
critical capability** (money movement, credential access, exfiltration, deletion).

## Publish a pack

```sh
# Sign the .toml files in a directory. The signing key (a 32-byte hex seed) is
# created in --key-file the first time (chmod 600); keep it secret.
guardian pack sign examples/packs/web-readonly \
  --name web-readonly --version 0.1.0 \
  --key-file ~/.guardian/pack-signing.key
# Prints your publisher public key — share THAT so others can pin you.
```

This writes `guardian-pack.json` (the manifest + your public key + signature) into
the directory.

## Verify before trusting

```sh
# Integrity only (any valid signature):
guardian pack verify examples/packs/web-readonly

# Provenance too — require a specific publisher (recommended):
guardian pack verify examples/packs/web-readonly --pubkey <publisher-hex>

# Record the verified pack's provenance into the audit log:
guardian pack verify examples/packs/web-readonly --pubkey <hex> --audit ~/.guardian/audit.db
```

Verification fails (non-zero exit) if the pack is unsigned, any file was altered, a
file was added/removed, or `--pubkey` doesn't match. It also reports any rule that
would **widen a critical category**; loading such a pack requires an explicit opt-in.

## The sample

`web-readonly/web.toml` is an unsigned sample policy (read a site, block writes).
Sign it yourself with the command above — packs are not shipped pre-signed because
the signature is bound to *your* publisher key.
