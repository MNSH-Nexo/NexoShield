#!/usr/bin/env bash
# Exemption surfaces beyond the daemon (audit 2026-10-24):
#  - the fail2ban ignoreip builder must carry the FULL exempt set,
#    including the server's own IPv6 addresses (E-1)
#  - the admin whitelist accepts IPv6 and --exempt-check verifies
#    IPv6 targets (E-5): validators + per-layer classification
#  - the daemon picks up newly assigned own IPs without a restart (E-3)
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
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }

# ── shared fixtures ──
WHITELIST_FILE="$TMP/whitelist.list"
printf '%s\n' "198.51.100.7" "2001:db8:beef::99" "2001:db8:cafe::/48" > "$WHITELIST_FILE"
CF_RANGES=("173.245.48.0/20")
CF6_RANGES=("2606:4700::/32")
list_self_ips()  { printf '%s\n' "203.0.113.10" "10.0.0.5"; }
list_self_ips_all() { list_self_ips; }
list_self_ips6() { printf '%s\n' "2001:db8:aaaa::10" "fe80::1"; }
log() { :; }

# ── Part B: the real ignoreip builder block from apply_fail2ban ──
awk '/_F2B_IGNORE="127/{f=1} /# Field finding T-1/{f=0} f' \
    src/modules/antiddos/30-fail2ban.sh > "$TMP/ignoreip.sh"
grep -q "list_self_ips6" "$TMP/ignoreip.sh" || { echo "FAIL: builder block extraction (E-1 loop missing)"; exit 1; }
. "$TMP/ignoreip.sh"
_IGN_FLAT=$(echo $_F2B_IGNORE)   # collapse the chunked newlines
for want in "203.0.113.10/32" "10.0.0.5/32" "2001:db8:aaaa::10" "2606:4700::/32" "173.245.48.0/20" "2001:db8:beef::99" "2001:db8:cafe::/48"; do
    case " $_IGN_FLAT " in *" $want "*) ok ;; *) bad "ignoreip missing $want" ;; esac
done

# ── Part C: v6 validator + exempt-check classification ──
: > "$TMP/fns.sh"
for fn in valid_ip_or_cidr valid_ip6_or_cidr nx_ip6_in_cidr nx_ip_in_cidr exempt_check; do
    extract_fn src/modules/antiddos/70-whitelist-main.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
F2B_JAIL_DIR="$TMP/none"
iptables() { return 1; }
. "$TMP/fns.sh"
for good in "2001:db8::1" "2001:db8::1:2:3:4" "2001:db8:cafe::/48" "::1" "fe80::1" "2001:0db8:0000:0000:0000:ff00:0042:8329" "2606:4700::/32"; do
    valid_ip6_or_cidr "$good" && ok || bad "validator rejected $good"
done
for bad6 in "2001:db8:::1" "2001:db8::1::2" "12345::1" "hello" "1.2.3.4" "2001:db8::/129" "" "2001:db8::1/xx"; do
    valid_ip6_or_cidr "$bad6" && bad "validator accepted '$bad6'" || ok
done
exempt_check "2001:db8:aaaa::10" >/dev/null 2>&1 && ok || bad "exempt-check: own v6 not exempt"
exempt_check "2001:db8:beef::99" >/dev/null 2>&1 && ok || bad "exempt-check: whitelisted v6 host not exempt"
exempt_check "2001:db8:cafe::77" >/dev/null 2>&1 && ok || bad "exempt-check: whitelisted v6 CIDR member not exempt"
exempt_check "2606:4700::9"     >/dev/null 2>&1 && ok || bad "exempt-check: CF6 not exempt"
exempt_check "2001:db8:dead::1" >/dev/null 2>&1 && bad "exempt-check: control v6 marked exempt" || ok
OUT=$(exempt_check "2001:db8:aaaa::10" 2>/dev/null)
echo "$OUT" | grep -q "server own IP     : yes" && ok || bad "exempt-check: self line wrong"

# ── E-3: refresh picks up a newly assigned address ──
: > "$TMP/fns2.sh"
extract_fn src/modules/autoban/10-ip-utils.sh refresh_self_ips "$TMP/fns2.sh" || { echo "FAIL extract refresh"; exit 1; }
extract_fn src/modules/autoban/10-ip-utils.sh is_self_ip "$TMP/fns2.sh" || { echo "FAIL extract is_self_ip"; exit 1; }
SELF_IPS=("203.0.113.10"); SELF6_IPS=("2001:db8:aaaa::10")
NX_PUBLIC_IPS_FILE="$TMP/no-cloud-cache"   # no cache file: metadata branch off
. "$TMP/fns2.sh"
list_self_ips()  { printf '%s\n' "203.0.113.10" "192.0.2.55"; }
list_self_ips6() { printf '%s\n' "2001:db8:aaaa::10" "2001:db8:aaaa::20"; }
refresh_self_ips
is_self_ip "192.0.2.55" && ok || bad "E-3: refreshed v4 self IP not immune"

echo "exemption surfaces: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
