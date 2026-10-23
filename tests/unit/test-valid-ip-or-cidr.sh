#!/usr/bin/env bash
# Unit tests for valid_ip_or_cidr() (src/modules/antiddos/70-whitelist-main.sh).
# The function is extracted verbatim from the source part, so the tests
# always exercise the shipped implementation, never a copy.
set -uo pipefail
cd "$(dirname "$0")/../.."

SRC="src/modules/antiddos/70-whitelist-main.sh"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Extract the function (from its definition line to the closing brace).
awk '/^valid_ip_or_cidr\(\) \{/,/^\}/' "$SRC" > "$TMP"
grep -q 'valid_ip_or_cidr' "$TMP" || { echo "FAIL: function not found in $SRC"; exit 1; }
# shellcheck disable=SC1090
. "$TMP"

pass=0; fail=0
expect_valid() {
    if valid_ip_or_cidr "$1"; then pass=$((pass+1)); else echo "  FAIL (want valid):   '$1'"; fail=$((fail+1)); fi
}
expect_invalid() {
    if valid_ip_or_cidr "$1"; then echo "  FAIL (want invalid): '$1'"; fail=$((fail+1)); else pass=$((pass+1)); fi
}

# Valid: plain IPs
for v in 1.2.3.4 0.0.0.0 255.255.255.255 192.168.0.1 8.8.8.8 01.2.3.4; do expect_valid "$v"; done
# Valid: CIDRs
for v in 1.2.3.0/24 0.0.0.0/0 1.2.3.4/32 10.0.0.0/8 172.16.0.0/12; do expect_valid "$v"; done
# Invalid: structure
for v in "" "1.2.3" "1.2.3.4.5" "1..2.3" ".1.2.3" "1.2.3." "1.2.3.4/" "/24" "abc" "1.2.3.x"; do expect_invalid "$v"; done
# Invalid: ranges
for v in "1.2.3.256" "256.1.1.1" "1.2.3.4/33" "1.2.3.4/-1" "1.2.3.4/24x" "999.999.999.999"; do expect_invalid "$v"; done
# Invalid: injection-ish / whitespace (manager strips spaces first; the
# function itself must still reject anything non-numeric)
for v in "1.2.3.4; rm -rf /" "1.2.3.4\$(id)" "1.2.3.4/ 24"; do expect_invalid "$v"; done

echo "valid_ip_or_cidr: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
