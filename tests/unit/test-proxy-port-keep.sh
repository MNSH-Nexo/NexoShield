#!/bin/bash
# Port-keeper suite (v3.16.3): an update on a RUNNING proxy must
# keep its port. The old picker treated any listener as foreign,
# so every update silently moved the proxy to port+1 and broke
# every client configured for the old port.
# The install.info path is hardcoded in the product, so the
# fixture goes to the real location behind a guard + full restore.
set -u

# Root-only fixture path: re-exec once via passwordless sudo,
# else skip (same pattern as the delete suite).
if [ "$(id -u)" -ne 0 ]; then
    if [ -z "${NX_SUDOED:-}" ] && sudo -n true 2>/dev/null; then
        NX_SUDOED=1 exec sudo -n bash "$0" "$@"
    fi
    echo "  SKIP: requires root (no passwordless sudo available)"
    exit 0
fi
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

MOD=$(mktemp -d)
python3 "$ROOT/tools/build.py" --emit-modules "$MOD" >/dev/null 2>&1 || { echo "  FAIL: emit"; exit 1; }
extract_fn() {
    awk -v n="$1" 'BEGIN{p=0} $0 ~ "^" n "\\(\\) \\{" {p=1} p{print} p && /^\}/{exit}' "$2"
}
extract_fn _port_held_by_other "$MOD/3proxy-socks5.sh" > "$MOD/fn.sh"
extract_fn pick_proxy_port "$MOD/3proxy-socks5.sh" >> "$MOD/fn.sh"
grep -q 'pick_proxy_port' "$MOD/fn.sh" || { echo "  FAIL: picker not found in assembled 3proxy-socks5.sh"; exit 1; }

# Static pin: the old raw loop is gone (only the helper bumps).
[ "$(grep -c 'PORT=$((PORT + 1))' "$MOD/3proxy-socks5.sh")" = "1" ] && ok || bad "old port-bump loop still present"

INFO=/etc/3proxy/install.info
BK=""
if [ -e "$INFO" ]; then
    BK=$(mktemp); cp -a "$INFO" "$BK"
    grep -q '^NX_TEST_FIXTURE=1' "$INFO" || { echo "  SKIP: a real /etc/3proxy/install.info exists - refusing to touch it"; rm -rf "$MOD" "$BK"; exit 0; }
fi
restore() {
    if [ -n "$BK" ]; then cp -a "$BK" "$INFO"; rm -f "$BK"; else rm -f "$INFO"; fi
    rm -rf "$MOD"
}
trap restore EXIT
mkdir -p /etc/3proxy

YELLOW=""; RED=""; CYAN=""; NC=""
SS_TLNP=""; SS_TULN=""
ss() {
    case "$*" in
        *tlnp*) printf '%s\n' "$SS_TLNP" ;;
        *)      printf '%s\n' "$SS_TULN" ;;
    esac
}
read() { return 1; }  # non-interactive: the prompt falls back to the default
# shellcheck disable=SC1091
. "$MOD/fn.sh"

# (a) Own 3proxy listener on the installed port: KEEP it.
printf 'PORT=1080\nUSER=x\nPASS=y\nNX_TEST_FIXTURE=1\n' > "$INFO"
SS_TLNP='LISTEN 0 4096 0.0.0.0:1080 0.0.0.0:* users:(("3proxy",pid=123,fd=3))'
SS_TULN='LISTEN 0 4096 0.0.0.0:1080 0.0.0.0:*'
pick_proxy_port >/dev/null 2>&1; RC=$?
[ "$RC" -eq 0 ] && [ "$PORT" = "1080" ] && ok || bad "own listener moved the port (rc=$RC PORT=$PORT)"

# (b) Foreign listener on 1080: bump exactly once to the free port.
SS_TLNP='LISTEN 0 4096 0.0.0.0:1080 0.0.0.0:* users:(("nginx",pid=456,fd=6))'
SS_TULN='LISTEN 0 4096 0.0.0.0:1080 0.0.0.0:*'
pick_proxy_port >/dev/null 2>&1; RC=$?
[ "$RC" -eq 0 ] && [ "$PORT" = "1081" ] && ok || bad "foreign listener did not bump (rc=$RC PORT=$PORT)"

# (c) Free port: keep it.
SS_TLNP=""; SS_TULN=""
pick_proxy_port >/dev/null 2>&1; RC=$?
[ "$RC" -eq 0 ] && [ "$PORT" = "1080" ] && ok || bad "free port moved (rc=$RC PORT=$PORT)"

# (d) Installed on a non-default port with its own listener: keep it.
printf 'PORT=3128\nUSER=x\nPASS=y\nNX_TEST_FIXTURE=1\n' > "$INFO"
SS_TLNP='LISTEN 0 4096 0.0.0.0:3128 0.0.0.0:* users:(("3proxy",pid=123,fd=3))'
SS_TULN='LISTEN 0 4096 0.0.0.0:3128 0.0.0.0:*'
pick_proxy_port >/dev/null 2>&1; RC=$?
[ "$RC" -eq 0 ] && [ "$PORT" = "3128" ] && ok || bad "non-default installed port not kept (rc=$RC PORT=$PORT)"

# (e) No install.info at all: default 1080.
rm -f "$INFO"
SS_TLNP=""; SS_TULN=""
pick_proxy_port >/dev/null 2>&1; RC=$?
[ "$RC" -eq 0 ] && [ "$PORT" = "1080" ] && ok || bad "fresh install did not default to 1080 (rc=$RC PORT=$PORT)"

echo "proxy port keep: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
