#!/usr/bin/env bash
# Phase 3b: daemon shield control. A recording nx-xdp stub stands in
# for the loader; the tick state machine must attach on kernel
# distress, sync the real ban/exempt state, re-sync on ban changes,
# and detach after a sustained calm — and stay silent when the
# shield was never built.
set -uo pipefail
cd "$(dirname "$0")/../.."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
extract_fn() {
    local start end
    start=$(grep -n "^$2() {" "$1" | head -1 | cut -d: -f1)
    [ -n "$start" ] || return 1
    end=$(tail -n +"$start" "$1" | grep -n '^}' | head -1 | cut -d: -f1)
    sed -n "${start},$((start + end - 1))p" "$1" >> "$3"
}
: > "$TMP/fns.sh"
for fn in nx_xdp_init nx_xdp_build_files nx_xdp_attach nx_xdp_detach nx_xdp_tick; do
    extract_fn src/modules/autoban/26-xdp.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done

CALLS="$TMP/calls.log"; : > "$CALLS"
mkdir -p "$TMP/bin"
cat > "$TMP/bin/nx-xdp" <<EOF
#!/usr/bin/env bash
echo "nx-xdp \$*" >> "$CALLS"
exit 0
EOF
chmod +x "$TMP/bin/nx-xdp"
touch "$TMP/nx_xdp.o"
ip() { echo "default via 10.0.0.1 dev eth9 proto dhcp"; }
log() { :; }

BANNED_LIST="$TMP/banned.list"; WHITELIST_FILE="$TMP/whitelist.list"
LOG_FILE="$TMP/daemon.log"
BAN_HOURS=4
SELF_IPS=("10.0.0.5"); SELF6_IPS=("fe80::1")
CF_RANGES=("173.245.48.0/20"); CF6_RANGES=("2606:4700::/32")
printf '%s\n' "198.51.100.7" > "$WHITELIST_FILE"
NOW=$(date +%s)
printf '%s\n' "5.5.5.5 $NOW 3600" "6.6.6.6 $((NOW - 7200)) 3600" > "$BANNED_LIST"
XDP_SYNCOOKIE_RATE=500; XDP_OVERFLOW_RATE=1000; XDP_SYN_RATE=3000; XDP_CALM_SECONDS=600
NX_OVF_DELTA=0; NX_SYNCOOK_DELTA=0; NX_EV_OK=0; NX_EV_TOT_DSYN=0; NX_EV_DT=2
NX_XDP_BIN="$TMP/bin/nx-xdp"; NX_XDP_OBJ="$TMP/nx_xdp.o"; NX_XDP_DIR="$TMP/run"
NX_XDP_BANS_FILE="$NX_XDP_DIR/xdp-bans.list"; NX_XDP_EXEMPT_FILE="$NX_XDP_DIR/xdp-exempt.list"
NX_XDP_AVAILABLE=0; NX_XDP_ATTACHED=""; NX_XDP_IFACE=""
_NX_XDP_HOT=0; _NX_XDP_CALM_SINCE=0; _NX_XDP_WIN_START=0; _NX_XDP_OVF_WIN=0; _NX_XDP_SCOOK_WIN=0; _NX_XDP_BANS_MT=0
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
has() { grep -qF "$1" "$CALLS" && ok || bad "missing call: $1"; }

nx_xdp_init
[ "$NX_XDP_AVAILABLE" = "1" ] && [ "$NX_XDP_IFACE" = "eth9" ] && ok || bad "init should detect shield + iface (avail=$NX_XDP_AVAILABLE iface=$NX_XDP_IFACE)"

# sync files: live ban with remaining TTL; expired ban excluded
nx_xdp_build_files
grep -qE '^5\.5\.5\.5 3[0-9]{3}$' "$NX_XDP_BANS_FILE" && ok || bad "bans file should carry the live ban with ~3600s TTL: $(cat "$NX_XDP_BANS_FILE")"
grep -q '6.6.6.6' "$NX_XDP_BANS_FILE" && bad "expired ban must not be synced" || ok
for want in 10.0.0.5 fe80::1 173.245.48.0/20 2606:4700::/32 198.51.100.7; do
    grep -qx "$want" "$NX_XDP_EXEMPT_FILE" && ok || bad "exempt file missing $want"
done

# trigger: syncookies 600/min > 500 across a closed window
_NX_XDP_WIN_START=$((NOW - 61)); NX_SYNCOOK_DELTA=600
nx_xdp_tick
has "nx-xdp load eth9 $TMP/nx_xdp.o"
has "nx-xdp sync-bans $NX_XDP_BANS_FILE"
has "nx-xdp sync-exempt $NX_XDP_EXEMPT_FILE"
[ "$NX_XDP_ATTACHED" = "eth9" ] && ok || bad "shield should be attached after distress tick"

# re-sync when the ban state changes while attached
sleep 1.1
printf '%s\n' "7.7.7.7 $(date +%s) 3600" >> "$BANNED_LIST"
: > "$CALLS"
nx_xdp_tick
has "nx-xdp sync-bans $NX_XDP_BANS_FILE"

# calm: no deltas, low rate, calm clock pre-aged past the window
NX_SYNCOOK_DELTA=0; NX_OVF_DELTA=0
XDP_CALM_SECONDS=5
_NX_XDP_CALM_SINCE=$(( $(date +%s) - 10 ))
: > "$CALLS"
nx_xdp_tick
has "nx-xdp unload eth9"
[ -z "$NX_XDP_ATTACHED" ] && ok || bad "shield should detach after sustained calm"

# unavailable shield: total silence
NX_XDP_BIN="/nonexistent/nx-xdp"; NX_XDP_AVAILABLE=0; NX_XDP_ATTACHED=""
nx_xdp_init
[ "$NX_XDP_AVAILABLE" = "0" ] && ok || bad "missing binary must keep the shield unavailable"
: > "$CALLS"
NX_SYNCOOK_DELTA=99999; _NX_XDP_WIN_START=1
nx_xdp_tick
[ -s "$CALLS" ] && bad "unavailable shield must never invoke the loader" || ok

echo "xdp daemon (Phase 3b): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
