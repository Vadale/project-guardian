#!/usr/bin/env bash
# Project Guardian — README hero demo.
#
# A narrated, fully real walkthrough: every verdict comes from the deterministic
# `guardian decide` engine, and the data-vault round-trip runs against a live
# daemon. Designed to be recorded with VHS (scripts/demo/guardian-demo.tape) but
# it is just a script — run it directly to watch the demo in your own terminal.
#
#   GUARDIAN_BIN=target/release/guardian ./scripts/demo/play.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
GBIN="${GUARDIAN_BIN:-$ROOT/target/release/guardian}"
DBIN="${GUARDIAN_DAEMON_BIN:-$ROOT/target/release/guardian-daemon}"

# ---- palette --------------------------------------------------------------
G=$'\033[38;5;48m'     # bright green
R=$'\033[38;5;203m'    # red
Y=$'\033[38;5;221m'    # yellow
C=$'\033[38;5;81m'     # cyan accent
M=$'\033[38;5;213m'    # magenta (tokens)
DIM=$'\033[2m'
B=$'\033[1m'
RST=$'\033[0m'

WORK="$(mktemp -d)"
SOCK="/tmp/guardian-demo.sock"        # short path: avoids the sun_path limit
DPID=""
cleanup() { [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true; rm -rf "$WORK"; rm -f "$SOCK"; }
trap cleanup EXIT

p()  { sleep "${1:-0.9}"; }
rule() { printf "${DIM}  ────────────────────────────────────────────────────────────────${RST}\n"; }

# Plain-language statement of what the agent is trying to do.
agent() { printf "\n  ${C}🤖 the agent wants to${RST}  ${B}%s${RST}\n" "$1"; p 0.8; }

# Run a real policy decision and render it as a traffic-light badge.
decide() { printf '%s' "$1" | "$GBIN" decide --policy "$DIR/policy.toml" | python3 "$DIR/fmt_badge.py"; p 1.1; }

# Talk to the live daemon's control socket.
gcall() { python3 "$DIR/gcall.py" "$SOCK" "$1"; }
jget()  { python3 -c 'import sys,json;print(json.load(sys.stdin)'"$1"')'; }

clear
# ===========================================================================
# Title
# ===========================================================================
printf "\n"
printf "   ${G}${B}🛡  Project Guardian${RST}\n"
printf "   ${DIM}   an AI guardian firewall for autonomous agents${RST}\n"
printf "   ${DIM}   local${RST} ${G}·${RST} ${DIM}deterministic${RST} ${G}·${RST} ${DIM}tamper-evident${RST}\n"
p 1.6

# ===========================================================================
# Act 1 — the traffic light
# ===========================================================================
printf "\n  ${B}${C}1 · THE TRAFFIC LIGHT${RST}  ${DIM}every action is checked against a deterministic policy${RST}\n"
p 0.8

agent "read the project's README"
decide '{"tool":"read_file","args":{"path":"README.md"},"kind":"FileRead"}'

agent "run a shell command:  rm -rf / --no-preserve-root"
decide '{"tool":"run_shell","args":{"cmd":"rm -rf / --no-preserve-root"},"kind":"Exec"}'

agent "wire money to a brand-new payee"
decide '{"tool":"pay","args":{"amount":4800},"capability":"Payment"}'
printf "            ${DIM}critical categories can never be auto-allowed — invariant #4${RST}\n"
p 1.4

# ===========================================================================
# Act 2 — the data vault
# ===========================================================================
printf "\n  ${B}${C}2 · THE DATA VAULT${RST}  ${DIM}the agent works with your data — but never sees it${RST}\n"
p 0.6

cat > "$WORK/customer.txt" <<EOF
Customer: Mario Rossi
IBAN: IT60X0542811101000000123456
Status: VIP onboarding
EOF

# Start the daemon (vault seeded from scripts/demo/config.toml).
GUARDIAN_CONFIG="$DIR/config.toml" GUARDIAN_POLICY="$DIR/policy.toml" \
GUARDIAN_SOCK="$SOCK" GUARDIAN_AUDIT="$WORK/audit.db" RUST_LOG=error \
  "$DBIN" >/dev/null 2>&1 &
DPID=$!
disown "$DPID" 2>/dev/null || true   # no "Terminated" job message on cleanup
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done

n=$(gcall '{"cmd":"vault_status"}' | jget '["protected"]')
printf "\n  ${DIM}vault seeded — ${RST}${B}%s${RST}${DIM} sensitive values protected${RST}\n" "$n"
p 0.8

agent "read the customer record  ${DIM}(policy: allow)${RST}"
view=$(gcall '{"cmd":"call","tool":"read_file","args":{"path":"'"$WORK"'/customer.txt"},"kind":"FileRead"}' | jget '["detail"]["content"]')
printf "     ${G}● ALLOW${RST}  ${DIM}but this is all the agent ever receives:${RST}\n"
printf '%s\n' "$view" | sed -E "s/\[\[GDN-[0-9a-f]+\]\]/${M}&${RST}/g" | sed "s/^/       ${DIM}│${RST} /"
p 1.6

t1=$(printf '%s' "$view" | grep -oE '\[\[GDN-[0-9a-f]+\]\]' | sed -n 1p)
t2=$(printf '%s' "$view" | grep -oE '\[\[GDN-[0-9a-f]+\]\]' | sed -n 2p)

agent "write a report using the tokens it holds  ${DIM}(policy: allow — authorized egress)${RST}"
gcall '{"cmd":"call","tool":"write_file","args":{"path":"'"$WORK"'/report.txt","content":"Report\nName: '"$t1"'\nIBAN: '"$t2"'\n"},"kind":"FileWrite"}' >/dev/null
printf "     ${G}● ALLOW${RST}  ${DIM}Guardian restores the real values only at the authorized boundary:${RST}\n"
sed -E "s/(Mario Rossi|IT60X0542811101000000123456)/${G}${B}&${RST}/g" "$WORK/report.txt" | sed "s/^/       ${DIM}│${RST} /"
p 1.6

agent "send that same report to an untrusted site  ${DIM}(exfil)${RST}"
out=$(gcall '{"cmd":"call","tool":"write_file","args":{"path":"'"$WORK"'/exfil-evil.txt","content":"'"$t1"'"},"kind":"FileWrite"}')
reason=$(printf '%s' "$out" | jget '["detail"].get("reason","")')
printf "     ${R}● DENY${RST}   ${DIM}%s${RST}\n" "$reason"
printf "            ${DIM}the token is useless off-boundary — your data never left${RST}\n"
p 1.8

# ===========================================================================
# Close
# ===========================================================================
rule
printf "  ${G}${B}No LLM on the allow/deny path.${RST}  ${DIM}The policy decides; a model only explains.${RST}\n"
printf "  ${DIM}every decision above is appended to a hash-chained, tamper-evident log${RST}\n\n"
printf "  ${C}${B}github.com/Vadale/project-guardian${RST}\n"
p 2.2
