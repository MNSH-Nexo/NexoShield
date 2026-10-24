#!/bin/bash
# Delete-user suite: delete_proxy_user empties the users file,
# switches the live config to auth none + allow *, clears
# install.info and restarts the proxy; a second run is a no-op.
# Round-trip: set_proxy_password must then CREATE fresh
# credentials and switch auth back on (the old --change-pass read
# the user from "allow *", wrote a literal "*" user and left
# auth none - credentials could never be set again), and a
# further run must ROTATE the same user's password.
# The install.info path is hardcoded in the product, so the fixture
# goes to the real location behind a guard + full restore.
set -u

# This suite exercises root-only paths (the menu refuses non-root;
# the delete fixture lives in /etc). CI runners are unprivileged
# but carry passwordless sudo: re-exec once as root, else skip.
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
extract_fn delete_proxy_user "$MOD/3proxy-socks5.sh" > "$MOD/fn.sh"
extract_fn set_proxy_password "$MOD/3proxy-socks5.sh" >> "$MOD/fn.sh"
grep -q 'delete_proxy_user' "$MOD/fn.sh" || { echo "  FAIL: function not found in assembled 3proxy-socks5.sh"; exit 1; }
grep -q 'set_proxy_password' "$MOD/fn.sh" || { echo "  FAIL: set_proxy_password not found in assembled 3proxy-socks5.sh"; exit 1; }

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

mkdir -p /etc/3proxy "$MOD/fix"
printf 'PORT=1080\nUSER=alice\nPASS=secret1\nNX_TEST_FIXTURE=1\n' > "$INFO"
printf 'users alice:CL:secret1\n' > "$MOD/fix/users.cfg"
cat > "$MOD/fix/3proxy.cfg" <<'EOF'
include /x/users.cfg
auth strong
allow alice
socks -p1080 -i0.0.0.0 -e0.0.0.0
EOF
STUB_LOG="$MOD/stub.log"; : > "$STUB_LOG"
GREEN=""; YELLOW=""; RED=""; NC=""
PROXY_USERS="$MOD/fix/users.cfg"
PROXY_CONF="$MOD/fix/3proxy.cfg"
systemctl() { echo "$*" >> "$STUB_LOG"; return 0; }
# shellcheck disable=SC1091
. "$MOD/fn.sh"

delete_proxy_user >/dev/null 2>&1; RC=$?
[ "$RC" -eq 0 ] && ok || bad "delete run rc=$RC"
[ ! -s "$PROXY_USERS" ] && ok || bad "users file not emptied"
grep -qx 'auth none' "$PROXY_CONF" && ok || bad "config auth not switched to none"
grep -qx 'allow \*' "$PROXY_CONF" && ok || bad "config allow not opened"
grep -q '^USER=$' "$INFO" && grep -q '^PASS=$' "$INFO" && ok || bad "install.info creds not cleared"
grep -q 'restart 3proxy' "$STUB_LOG" && ok || bad "proxy not restarted"

# Second run: nothing to delete -> rc 0, no restart, no damage.
: > "$STUB_LOG"
delete_proxy_user >/dev/null 2>&1; RC=$?
[ "$RC" -eq 0 ] && ok || bad "second run rc=$RC"
grep -q 'restart' "$STUB_LOG" && bad "second run restarted the proxy" || ok
grep -qx 'auth none' "$PROXY_CONF" && ok || bad "config damaged by second run"

# ── Round-trip: set credentials again from the auth-OFF state ──
: > "$STUB_LOG"
OUT=$(set_proxy_password 2>&1); RC=$?
[ "$RC" -eq 0 ] && ok || bad "set-after-delete rc=$RC"
NU=$(grep -oP '(?<=^users )\S+(?=:CL:)' "$PROXY_USERS" 2>/dev/null | head -1 || true)
NP=$(grep -oP '(?<=:CL:)\S+' "$PROXY_USERS" 2>/dev/null | head -1 || true)
[ -n "$NU" ] && [ "$NU" != "*" ] && ok || bad "no real user created (got '$NU')"
[ -n "$NP" ] && ok || bad "no password created"
grep -qx 'auth strong' "$PROXY_CONF" && ok || bad "auth not switched back on"
grep -qx "allow $NU" "$PROXY_CONF" && ok || bad "allow not pointed at the new user"
grep -q "^USER=$NU\$" "$INFO" && grep -q "^PASS=$NP\$" "$INFO" && ok || bad "install.info not synced with new creds"
grep -q 'restart 3proxy' "$STUB_LOG" && ok || bad "proxy not restarted after set"
case "$OUT" in *"$NP"*) ok ;; *) bad "new password not shown to the admin" ;; esac

# ── Rotate: same user, new password, auth stays on ────────────
OUT=$(set_proxy_password 2>&1); RC=$?
[ "$RC" -eq 0 ] && ok || bad "rotate rc=$RC"
NU2=$(grep -oP '(?<=^users )\S+(?=:CL:)' "$PROXY_USERS" 2>/dev/null | head -1 || true)
NP2=$(grep -oP '(?<=:CL:)\S+' "$PROXY_USERS" 2>/dev/null | head -1 || true)
[ "$NU2" = "$NU" ] && ok || bad "rotate changed the username ($NU -> $NU2)"
[ -n "$NP2" ] && [ "$NP2" != "$NP" ] && ok || bad "rotate did not change the password"
grep -qx 'auth strong' "$PROXY_CONF" && ok || bad "auth lost during rotate"

echo "proxy user delete: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
