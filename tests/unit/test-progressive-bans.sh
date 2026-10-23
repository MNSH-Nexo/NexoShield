#!/usr/bin/env bash
# Phase 1c: progressive ban durations from the strike record
# (reputation fields 8/9), rep_on_ban strike bookkeeping with the
# REAL ban duration, and sweep carry-through of the new fields.
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
for fn in state_has_ip state_get_field state_del_ip is_exempt_any; do
    extract_fn src/modules/autoban/10-ip-utils.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
for fn in load_reputation save_reputation rep_on_ban rep_ban_duration_secs reputation_sweep; do
    extract_fn src/modules/autoban/30-reputation.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done

SCORE_DIR="$TMP/scores"; SCORE_FILE="$SCORE_DIR/reputation.dat"
BANNED_LIST="$TMP/banned.list"; WATCH_LIST="$TMP/watch.list"; THROTTLE_LIST="$TMP/throttled.list"
BAN_BASE_MINUTES=30; BAN_MAX_MINUTES=10080; BAN_HOURS=4
PROBATION_SCORE=50; PROBATION_SECONDS=1800; PROBATION_RECOVER_PER_MIN=10
SCORE_RECOVER_PER_MIN=6; CONN_THRESHOLD=120
declare -A CONN_COUNT=()
mkdir -p "$SCORE_DIR"; : > "$SCORE_FILE"; : > "$BANNED_LIST"; : > "$WATCH_LIST"; : > "$THROTTLE_LIST"
log() { :; }
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
eq()  { [ "$1" = "$2" ] && ok || bad "$3 (got '$1', want '$2')"; }
NOW=$(date +%s)
seed9() { printf '%s\n' "$1 $2 0 $NOW 0 0 0 $3 $4" > "$SCORE_FILE"; }  # ip score strikes lastban

# duration schedule: 30m, 1h, 2h, 4h ... capped at 7d
seed9 1.1.1.1 50 0 0;            eq "$(rep_ban_duration_secs 1.1.1.1)" "1800"   "first ban = 30min"
seed9 1.1.1.1 50 1 $NOW;         eq "$(rep_ban_duration_secs 1.1.1.1)" "3600"   "second ban = 1h"
seed9 1.1.1.1 50 2 $NOW;         eq "$(rep_ban_duration_secs 1.1.1.1)" "7200"   "third ban = 2h"
seed9 1.1.1.1 50 3 $NOW;         eq "$(rep_ban_duration_secs 1.1.1.1)" "14400"  "fourth ban = 4h"
seed9 1.1.1.1 50 9 $NOW;         eq "$(rep_ban_duration_secs 1.1.1.1)" "604800" "cap = 7 days"
seed9 1.1.1.1 50 3 $((NOW - 8*86400)); eq "$(rep_ban_duration_secs 1.1.1.1)" "1800" "strikes expire after 7 clean days"
: > "$SCORE_FILE";               eq "$(rep_ban_duration_secs 2.2.2.2)" "1800"   "unknown IP = first ban"

# legacy 7-field lines read strikes as 0
printf '%s\n' "3.3.3.3 80 0 $NOW 0 0 0" > "$SCORE_FILE"
eq "$(rep_ban_duration_secs 3.3.3.3)" "1800" "legacy record = first ban"

# rep_on_ban: probation anchored to the REAL duration + strike recorded
: > "$SCORE_FILE"
printf '%s\n' "4.4.4.4 $NOW 1800" > "$BANNED_LIST"
rep_on_ban 4.4.4.4
read -r _ip _sc _pc _ts _pu _fr _rt _st _lb <<< "$(cat "$SCORE_FILE")"
eq "$_sc" "50" "post-ban score is probation score"
eq "$_st" "1" "strike recorded"
[ "$_lb" -ge $((NOW - 2)) ] && [ "$_lb" -le $(( $(date +%s) + 2 )) ] && ok || bad "last_ban stamped (got $_lb)"
[ "$_pu" -ge $((NOW + 1800 + 1800 - 2)) ] && [ "$_pu" -le $((NOW + 1800 + 1800 + 5)) ] && ok || bad "probation ends after real ban + window (got $_pu, now $NOW)"
# second ban: strike 2, longer real duration
printf '%s\n' "4.4.4.4 $(date +%s) 3600" > "$BANNED_LIST"
rep_on_ban 4.4.4.4
_st=$(awk '{print $8}' "$SCORE_FILE")
eq "$_st" "2" "second ban increments strikes"

# sweep carries fields 8/9 untouched for quiet IPs
printf '%s\n' "5.5.5.5 90 0 $((NOW - 100)) 0 0 0 2 $((NOW - 1000))" > "$SCORE_FILE"
: > "$BANNED_LIST"
reputation_sweep
read -r _ip _sc _pc _ts _pu _fr _rt _st _lb <<< "$(cat "$SCORE_FILE")"
eq "$_st" "2" "sweep preserves strikes"
eq "$_lb" "$((NOW - 1000))" "sweep preserves last_ban"

echo "progressive bans (Phase 1c): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
