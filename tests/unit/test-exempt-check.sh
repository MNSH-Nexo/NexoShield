#!/usr/bin/env bash
# Unit tests for exempt_check() + helpers (FR-1/FR-2, Wave 1).
# Functions are extracted verbatim from the shipped source part.
set -uo pipefail
cd "$(dirname "$0")/../.."

SRC="src/modules/antiddos/70-whitelist-main.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

extract_fn() { # src fn out
    local start end
    start=$(grep -n "^$2() {" "$1" | head -1 | cut -d: -f1)
    [ -n "$start" ] || return 1
    end=$(tail -n +"$start" "$1" | grep -n '^}' | head -1 | cut -d: -f1)
    sed -n "${start},$((start + end - 1))p" "$1" >> "$3"
}
: > "$TMP/fns.sh"
for fn in valid_ip_or_cidr nx_ip_to_int nx_ip_in_cidr exempt_check; do
    extract_fn "$SRC" "$fn" "$TMP/fns.sh" || { echo "FAIL: cannot extract $fn"; exit 1; }
done

# Fixture environment
CF_RANGES=("1.2.3.0/24" "104.16.0.0/13")
WHITELIST_FILE="$TMP/whitelist.list"
F2B_JAIL_DIR="$TMP/no-fail2ban"
printf '%s\n' "5.5.5.5" "6.6.6.0/24" "# comment" "" > "$WHITELIST_FILE"
list_self_ips() { printf '%s\n' "9.9.9.9" "127.0.0.1"; }
list_self_ips_all() { list_self_ips; }

# shellcheck disable=SC1091
. "$TMP/fns.sh"

pass=0; fail=0
check() { # ip expected_rc label
    exempt_check "$1" >/dev/null 2>&1; local rc=$?
    if [ "$rc" -eq "$2" ]; then pass=$((pass+1)); else echo "  FAIL: $3 ($1 -> rc=$rc, want $2)"; fail=$((fail+1)); fi
}

check 1.2.3.9    0 "CF range member"
check 104.20.1.1 0 "CF /13 member"
check 104.24.0.1 1 "just outside CF /13"
check 9.9.9.9    0 "self IP"
check 5.5.5.5    0 "whitelist exact"
check 6.6.6.200  0 "whitelist CIDR member"
check 6.6.7.1    1 "outside whitelist CIDR"
check 8.8.8.8    1 "ordinary IP not exempt"
check "garbage"  2 "invalid input"
check "1.2.3.4/33" 2 "invalid mask input"

echo "exempt_check: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
