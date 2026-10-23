#!/usr/bin/env bash
# U-11: the daemon's throttle state lives in /tmp (volatile) while the
# reboot restore path (generated tc-setup.sh) reads the persistent
# /etc/antiddos/throttled.list - which nothing wrote before this fix,
# so every reboot silently dropped all recorded throttles.
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
for fn in mirror_throttle_state restore_throttle_state; do
    extract_fn src/modules/autoban/20-enforce.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
THROTTLE_LIST="$TMP/live"; THROTTLE_MIRROR="$TMP/mirror"
log() { :; }
. "$TMP/fns.sh"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }

printf '%s\n' "1.2.3.4 20001 1700000000 soft" > "$THROTTLE_LIST"
mirror_throttle_state
grep -q "1.2.3.4" "$THROTTLE_MIRROR" 2>/dev/null && ok || bad "mirror not written"
printf '%s\n' "5.6.7.8 20002 1700000000 hard" >> "$THROTTLE_LIST"
mirror_throttle_state
[ "$(wc -l < "$THROTTLE_MIRROR")" = "2" ] && ok || bad "mirror did not track changes"
rm "$THROTTLE_LIST"
restore_throttle_state
[ -f "$THROTTLE_LIST" ] && [ "$(wc -l < "$THROTTLE_LIST")" = "2" ] && ok || bad "restore did not recreate the live file"
# restore is a no-op when the live file already exists
printf '%s\n' "9.9.9.9 20003 1700000000 soft" > "$THROTTLE_LIST"
restore_throttle_state
grep -q "9.9.9.9" "$THROTTLE_LIST" && [ "$(wc -l < "$THROTTLE_LIST")" = "1" ] && ok || bad "restore overwrote live state"

echo "throttle mirror (U-11): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
