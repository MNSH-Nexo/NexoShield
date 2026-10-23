#!/usr/bin/env bash
# THE exemption guarantee (FR-1/FR-2, re-audited 2026-10-24): the
# server's own IPs (v4 AND v6), Cloudflare (v4 AND v6) and the admin
# whitelist (hosts AND CIDRs, both families) must NEVER be banned,
# throttled or subnet-banned by the daemon - and a non-exempt control
# IP MUST be, so the test cannot pass vacuously.
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
extract_fn src/modules/autoban/00-header.sh ip_int "$TMP/fns.sh" || { echo "FAIL extract ip_int"; exit 1; }
for fn in ip_to_int ip_in_cidr ip6_in_cidr is_cf_ip is_cf6_ip is_self_ip is_user_whitelisted is_exempt is_exempt6 is_exempt_any subnet_overlaps_cf state_has_ip state_get_field state_del_ip nx_ban nx_throttle nx_hard_throttle refresh_self_ips; do
    extract_fn src/modules/autoban/10-ip-utils.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
for fn in next_tc_prio tc_class_exists throttle_ip hard_throttle_ip ban_ip _throttle6 throttle_ip6 hard_throttle_ip6 ban_ip6; do
    extract_fn src/modules/autoban/20-enforce.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
extract_fn src/modules/autoban/40-subnet.sh ban_subnet "$TMP/fns.sh" || { echo "FAIL extract ban_subnet"; exit 1; }

# ── fixtures ──
CF_RANGES=("173.245.48.0/20" "103.21.244.0/22")
CF6_RANGES=("2606:4700::/32")
SELF_IPS=("203.0.113.10" "10.0.0.5" "127.0.0.1")
SELF6_IPS=("2001:db8:aaaa::10" "fe80::1")
WHITELIST_FILE="$TMP/whitelist.list"
printf '%s\n' "198.51.100.7" "198.51.101.0/24" "2001:db8:beef::99" "2001:db8:cafe::/48" > "$WHITELIST_FILE"
BANNED_LIST="$TMP/banned.list"; THROTTLE_LIST="$TMP/throttled.list"; WATCH_LIST="$TMP/watch.list"
: > "$BANNED_LIST"; : > "$THROTTLE_LIST"; : > "$WATCH_LIST"
IF="eth0"; BAN_HOURS=4; OBSERVE_SECONDS=45
CALLS="$TMP/calls.log"; : > "$CALLS"
log() { :; }
iptables()  { echo "iptables $*" >> "$CALLS"; [ "$1" = "-C" ] && return 1; return 0; }
ip6tables() { echo "ip6tables $*" >> "$CALLS"; [ "$1" = "-C" ] && return 1; return 0; }
tc() { echo "tc $*" >> "$CALLS"; if [ "$1" = "class" ]; then echo "class htb 1:30 parent 1:1 leaf 30:"; echo "class htb 1:40 parent 1:1 leaf 40:"; fi; return 0; }
. "$TMP/fns.sh"

# CF integer precompute - byte-for-byte the autoban/00-header.sh
# block (ip_int + shifted-network comparison, BUG-020)
declare -a CF_NET_INT=() CF_SHIFT=()
for _cfr in "${CF_RANGES[@]}"; do
    ip_int "${_cfr%%/*}"
    CF_NET_INT+=("$IP_INT")
    CF_SHIFT+=("$(( 32 - ${_cfr#*/} ))")
done

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
no_enforcement() {  # $1 = ip, $2.. = description
    local ip="$1"
    : > "$CALLS"; : > "$BANNED_LIST"; : > "$THROTTLE_LIST"
    case "$ip" in
        *:*) ban_ip6 "$ip"; throttle_ip6 "$ip"; hard_throttle_ip6 "$ip" ;;
        *)   ban_ip "$ip"; throttle_ip "$ip"; hard_throttle_ip "$ip" ;;
    esac
    if [ -s "$CALLS" ] || [ -s "$BANNED_LIST" ] || [ -s "$THROTTLE_LIST" ]; then
        bad "EXEMPT $ip was enforced: $(cat "$CALLS" | head -1)"
    else ok; fi
    is_exempt_any "$ip" && ok || bad "is_exempt_any false for exempt $ip"
}
# exempt targets: self v4 public, self v4 private, loopback, CF v4,
# whitelist v4 host, whitelist v4 CIDR member
for ip in 203.0.113.10 10.0.0.5 127.0.0.1 173.245.48.55 198.51.100.7 198.51.101.77; do
    no_enforcement "$ip"
done
# exempt v6: self, link-local self, CF6, whitelist host, whitelist CIDR member
for ip in 2001:db8:aaaa::10 fe80::1 2606:4700::5 2001:db8:beef::99 2001:db8:cafe::1234; do
    no_enforcement "$ip"
done
# controls: MUST be enforced (positive control)
: > "$CALLS"; : > "$BANNED_LIST"
ban_ip 8.8.8.8
grep -q "8.8.8.8" "$BANNED_LIST" && grep -q "iptables" "$CALLS" && ok || bad "control v4 8.8.8.8 was NOT banned"
: > "$CALLS"; : > "$BANNED_LIST"
ban_ip6 2001:db8:dead::1
grep -q "2001:db8:dead::1" "$BANNED_LIST" && grep -q "ip6tables" "$CALLS" && ok || bad "control v6 was NOT banned (E-2 regression: bare v6 whitelist entry must not exempt the world)"
is_exempt_any 2001:db8:dead::1 && bad "control v6 reported exempt" || ok
is_exempt_any 8.8.8.8 && bad "control v4 reported exempt" || ok
# subnet level: whitelist/self/CF /24s skipped, control banned
ban_subnet "198.51.101"   # contains whitelisted /24 members + host .7 is in 198.51.100 - use the CIDR subnet
grep -q "198.51.101.0/24" "$BANNED_LIST" && bad "subnet of whitelisted CIDR was banned" || ok
ban_subnet "203.0.113"    # the server's own /24
grep -q "203.0.113.0/24" "$BANNED_LIST" && bad "server's own /24 was subnet-banned" || ok
ban_subnet "173.245.48"   # inside CF 173.245.48.0/20
grep -q "173.245.48.0/24" "$BANNED_LIST" && bad "CF /24 was subnet-banned" || ok
ban_subnet "8.8.8"
grep -q "8.8.8.0/24" "$BANNED_LIST" && ok || bad "control subnet NOT banned"

echo "exemption guarantee (daemon): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
