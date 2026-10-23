#!/usr/bin/env bash
# Unit tests for the auto-ban daemon's is_user_whitelisted() hardening
# (BUG-029 daemon half, Wave 1): malformed whitelist entries must never
# widen a match. Functions extracted verbatim from the shipped source.
set -uo pipefail
cd "$(dirname "$0")/../.."

SRC="src/modules/autoban/10-ip-utils.sh"
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
for fn in ip_to_int ip_in_cidr is_user_whitelisted; do
    extract_fn "$SRC" "$fn" "$TMP/fns.sh" || { echo "FAIL: cannot extract $fn"; exit 1; }
done

WHITELIST_FILE="$TMP/whitelist.list"
printf '%s\n' "5.6.7.0/abc" "7.7.7.0/33" "9.9.9.9" "6.6.6.0/24" > "$WHITELIST_FILE"

# shellcheck disable=SC1091
. "$TMP/fns.sh"

pass=0; fail=0
wl() { # ip expected_rc label
    if is_user_whitelisted "$1"; then rc=0; else rc=1; fi
    if [ "$rc" -eq "$2" ]; then pass=$((pass+1)); else echo "  FAIL: $3 ($1 -> rc=$rc, want $2)"; fail=$((fail+1)); fi
}

wl 5.6.7.8   1 "garbage mask /abc must NOT exempt"
wl 7.7.7.7   1 "mask /33 must NOT exempt"
wl 9.9.9.9   0 "exact entry exempts"
wl 6.6.6.42  0 "valid CIDR entry exempts"
wl 6.6.7.42  1 "outside valid CIDR"

echo "autoban is_user_whitelisted: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
