#!/usr/bin/env bash
# IPv6 membership tests (Wave 9): ip6_in_cidr / is_cf6_ip extracted
# verbatim from the daemon's ip-utils.
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
for fn in ip6_in_cidr is_cf6_ip; do
    extract_fn src/modules/autoban/10-ip-utils.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
CF6_RANGES=(2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f8b0::/32)
# shellcheck disable=SC1091
. "$TMP/fns.sh"

pass=0; fail=0
in6()  { ip6_in_cidr "$1" "$2" && pass=$((pass+1)) || { echo "  FAIL in: $1 $2"; fail=$((fail+1)); }; }
out6() { ip6_in_cidr "$1" "$2" && { echo "  FAIL out: $1 $2"; fail=$((fail+1)); } || pass=$((pass+1)); }

in6  2606:4700:4700::1111 2606:4700::/32
out6 2606:4701::1         2606:4700::/32
in6  2606:4700:0000:0000:0000:0000:0000:1111 2606:4700::/32
in6  2400:CB00:1234::1    2400:cb00::/32
in6  2a06:98c5::1         2a06:98c0::/29
out6 2a06:98c8::1         2a06:98c0::/29
in6  ::1                  ::1/128
out6 ::2                  ::1/128
in6  2001:db8::dead:beef  2001:db8::/32
out6 2001:db9::1          2001:db8::/32

is_cf6_ip 2606:4700::1 && pass=$((pass+1)) || { echo "  FAIL is_cf6_ip hit"; fail=$((fail+1)); }
is_cf6_ip 2001:db8::1 && { echo "  FAIL is_cf6_ip miss"; fail=$((fail+1)); } || pass=$((pass+1))

# data file sanity: 7 well-formed ranges ship
[ "$(grep -c . src/data/cloudflare-ipv6.list)" = "7" ] && pass=$((pass+1)) || { echo "  FAIL data count"; fail=$((fail+1)); }

echo "ip6 cidr: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
