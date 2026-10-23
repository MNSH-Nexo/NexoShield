#!/usr/bin/env bash
# Functional guards for ban_subnet (R-15/R-17): a whitelisted CIDR of
# ANY prefix length must protect the /24s it covers (the old guard
# compared first-3-octets only and missed e.g. a whitelisted /16);
# state is recorded only when the rule actually lands.
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
for fn in ip_to_int ip_in_cidr subnet_overlaps_cf; do
    extract_fn src/modules/autoban/10-ip-utils.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
extract_fn src/modules/autoban/40-subnet.sh ban_subnet "$TMP/fns.sh" || { echo "FAIL extract ban_subnet"; exit 1; }
extract_fn src/modules/autoban/20-enforce.sh nx_ban_apply "$TMP/fns.sh" || { echo "FAIL extract nx_ban_apply"; exit 1; }
NX_BAN_BACKEND=iptables

CF_RANGES=()
SELF_IPS=("192.0.2.1")
BANNED_LIST="$TMP/banned.list"; : > "$BANNED_LIST"
WHITELIST_FILE="$TMP/whitelist.list"
printf '%s\n' "10.9.0.0/16" "203.0.113.7" > "$WHITELIST_FILE"
BAN_HOURS=4
IPT_MODE=ok
iptables() {
    case "$1" in
        -C) return 1 ;;                       # rule never pre-exists
        -I) if [ "$IPT_MODE" = ok ]; then echo "RULE $*" >> "$TMP/rules.log"; return 0; else return 1; fi ;;
    esac
}
log() { echo "$*" >> "$TMP/daemon.log"; }
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }

# /24 inside the whitelisted /16 -> must be skipped (R-15)
ban_subnet "10.9.3"
grep -q "10.9.3.0/24" "$BANNED_LIST" && bad "R-15: subnet inside whitelisted /16 was banned" || ok
# /24 containing the whitelisted host /32 -> skipped
ban_subnet "203.0.113"
grep -q "203.0.113.0/24" "$BANNED_LIST" && bad "R-15: subnet containing whitelisted IP was banned" || ok
# unrelated /24 -> banned and recorded
ban_subnet "8.8.8"
grep -q "8.8.8.0/24" "$BANNED_LIST" && ok || bad "clean subnet should be banned + recorded"
# iptables refusal -> NO state recorded (R-17)
IPT_MODE=fail
ban_subnet "9.9.9"
grep -q "9.9.9.0/24" "$BANNED_LIST" && bad "R-17: state recorded for a rule that never landed" || ok

echo "subnet guards: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
