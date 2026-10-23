#!/usr/bin/env bash
# Phase 1b: nftables timed-set ban backend. A recording nft stub
# stands in for the kernel; the iptables path must remain reachable
# (explicit selection AND nft-failure fallback), and the exempt-set
# projection must carry self/whitelist/CF entries.
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
for fn in state_has_ip state_get_field state_del_ip; do
    extract_fn src/modules/autoban/10-ip-utils.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
for fn in nx_nft_ensure nx_resolve_ban_backend nx_nft_sync_exempt nx_ban_apply nx_ban_remove_fw ban_ip; do
    extract_fn src/modules/autoban/20-enforce.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
extract_fn src/modules/autoban/30-reputation.sh rep_ban_duration_secs "$TMP/fns.sh" || { echo "FAIL extract rep_ban_duration_secs"; exit 1; }

BANNED_LIST="$TMP/banned.list"; THROTTLE_LIST="$TMP/throttled.list"
WHITELIST_FILE="$TMP/whitelist.list"; SCORE_FILE="$TMP/reputation.dat"
BAN_BASE_MINUTES=30; BAN_MAX_MINUTES=10080; BAN_HOURS=4; IF="eth0"
SELF_IPS=("10.0.0.5"); SELF6_IPS=("fe80::1")
CF_RANGES=("173.245.48.0/20"); CF6_RANGES=("2606:4700::/32")
: > "$BANNED_LIST"; : > "$THROTTLE_LIST"; : > "$SCORE_FILE"
printf '%s\n' "198.51.100.7" "2001:db8::99" > "$WHITELIST_FILE"
CALLS="$TMP/calls.log"; : > "$CALLS"
log() { :; }
is_self_ip() { return 1; }
is_exempt() { return 1; }
tc() { return 0; }
iptables()  { echo "iptables $*" >> "$CALLS"; [ "$1" = "-C" ] && return 1; return 0; }
ip6tables() { echo "ip6tables $*" >> "$CALLS"; [ "$1" = "-C" ] && return 1; return 0; }
nft() {
    echo "nft $*" >> "$CALLS"
    case "$*" in
        "list table inet nexoshield") [ -f "$TMP/nft.exists" ] ;;
        -f*) touch "$TMP/nft.exists"; return 0 ;;
        "add element"*) [ -n "${NFT_FAIL:-}" ] && return 1; return 0 ;;
        *) return 0 ;;
    esac
}
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
has() { grep -qF "$1" "$CALLS" && ok || bad "missing call: $1"; }
hasnt() { grep -qF "$1" "$CALLS" && bad "unexpected call: $1" || ok; }

# resolve -> nft (stub creates the table on ensure)
nx_resolve_ban_backend
[ "$NX_BAN_BACKEND" = "nft" ] && ok || bad "backend should resolve to nft"
has "nft -f -"

# apply: families + CIDR + timeouts
: > "$CALLS"
nx_ban_apply 1.2.3.4 1800;        has "nft add element inet nexoshield ban4 { 1.2.3.4 timeout 1800s }"
nx_ban_apply 2001:db8::5 3600;    has "nft add element inet nexoshield ban6 { 2001:db8::5 timeout 3600s }"
nx_ban_apply 5.6.7.0/24 3600 subnet-ban; has "nft add element inet nexoshield ban4 { 5.6.7.0/24 timeout 3600s }"
hasnt "iptables -I"

# remove
: > "$CALLS"
nx_ban_remove_fw 1.2.3.4;         has "nft delete element inet nexoshield ban4 { 1.2.3.4 }"
nx_ban_remove_fw 2001:db8::5;     has "nft delete element inet nexoshield ban6 { 2001:db8::5 }"

# nft failure -> iptables fallback for THAT ban
: > "$CALLS"; NFT_FAIL=1
nx_ban_apply 9.9.9.9 1800
has "iptables -I INPUT -s 9.9.9.9 -m comment --comment auto-ban -j DROP"
unset NFT_FAIL

# explicit iptables backend: no nft traffic at all
NX_BAN_BACKEND=iptables; : > "$CALLS"
nx_ban_apply 8.8.8.8 1800
has "iptables -I INPUT -s 8.8.8.8"
hasnt "nft add element"

# exempt projection carries every source class
NX_BAN_BACKEND=nft; : > "$CALLS"
nx_nft_sync_exempt
grep -F "add element inet nexoshield exempt4" "$CALLS" | grep -q "10.0.0.5" && ok || bad "exempt4 missing self IP"
grep -F "add element inet nexoshield exempt4" "$CALLS" | grep -q "173.245.48.0/20" && ok || bad "exempt4 missing CF range"
grep -F "add element inet nexoshield exempt4" "$CALLS" | grep -q "198.51.100.7" && ok || bad "exempt4 missing whitelist entry"
grep -F "add element inet nexoshield exempt6" "$CALLS" | grep -q "fe80::1" && ok || bad "exempt6 missing self v6"
grep -F "add element inet nexoshield exempt6" "$CALLS" | grep -q "2001:db8::99" && ok || bad "exempt6 missing whitelist v6"

# ban_ip integration: progressive duration lands in state AND set
: > "$CALLS"; : > "$BANNED_LIST"
ban_ip 7.7.7.7
has "nft add element inet nexoshield ban4 { 7.7.7.7 timeout 1800s }"
grep -q "^7.7.7.7 [0-9]* 1800$" "$BANNED_LIST" && ok || bad "state line should carry the 1800s duration"

echo "ban backend (Phase 1b): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
