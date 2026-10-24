#!/bin/bash
# Binary install suite (v3.16.1): replacing a RUNNING executable
# with cp fails with ETXTBSY ("Text file busy") - the field bug
# that made every 3proxy Install/Update abort on a live server.
# All binary installs must go through nx_install_binary
# (stage in the same directory + rename over the target).
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

# ── Static pins: no direct writes onto live binary paths ────
grep -q 'cp bin/3proxy "$PROXY_BIN"' "$ROOT/src/modules/3proxy/40-install.sh" \
    && bad "3proxy still cp's onto the live binary" || ok
grep -q 'cc -O2 -o /usr/local/bin/nxcountd' "$ROOT/src/modules/antiddos/40-autoban-setup.sh" \
    && bad "nxcountd still compiles onto the live binary" || ok
grep -q 'nx_install_binary bin/3proxy' "$ROOT/src/modules/3proxy/40-install.sh" && ok \
    || bad "3proxy install does not use nx_install_binary"
[ "$(grep -c 'nx_install_binary' "$ROOT/src/modules/antiddos/40-autoban-setup.sh")" -ge 3 ] && ok \
    || bad "countd/xdp installs do not all use nx_install_binary"

# ── Functional: reproduce ETXTBSY, then prove the fix ───────
# shellcheck disable=SC1091
. "$ROOT/src/lib/install-binary.sh"
W=$(mktemp -d)
cp /bin/sleep "$W/fakebin" && cp /bin/true "$W/other" || { echo "setup failed"; exit 1; }
"$W/fakebin" 60 & PID=$!
sleep 0.3
# Positive control: the old way MUST fail on this kernel,
# otherwise the rest of the test proves nothing.
if cp "$W/other" "$W/fakebin" 2>/dev/null; then
    bad "control: plain cp unexpectedly succeeded (ETXTBSY not enforced here)"
else
    ok
fi
if nx_install_binary "$W/other" "$W/fakebin" 755; then ok; else bad "nx_install_binary failed on a running target"; fi
kill -0 "$PID" 2>/dev/null && ok || bad "running process was disturbed by the replace"
[ "$(sha256sum < "$W/fakebin")" = "$(sha256sum < "$W/other")" ] && ok || bad "target does not hold the new binary"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
# And the replaced path must execute as the NEW program.
"$W/fakebin" && ok || bad "replaced binary does not execute"
ls "$W" | grep -q 'new\.' && bad "staging file left behind" || ok
rm -rf "$W"

echo "binary-install: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
