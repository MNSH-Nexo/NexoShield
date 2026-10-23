#!/usr/bin/env bash
# Phase 1d: the stress gate in update_score's ban branch.
# Calm host + first offence + shallow ban band (10..19) -> hard
# throttle, NO ban. Deep score (<10), repeat offender, stressed
# host, or gate disabled -> ban as before.
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
for fn in state_has_ip state_get_field state_del_ip is_exempt_any nx_ban nx_throttle nx_hard_throttle; do
    extract_fn src/modules/autoban/10-ip-utils.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
for fn in load_reputation save_reputation rep_on_ban rep_on_unban update_score; do
    extract_fn src/modules/autoban/30-reputation.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done

SCORE_DIR="$TMP/scores"; SCORE_FILE="$SCORE_DIR/reputation.dat"
BANNED_LIST="$TMP/banned.list"; WATCH_LIST="$TMP/watch.list"; THROTTLE_LIST="$TMP/throttled.list"
SCORE_BAN=20; SCORE_HARD=40; SCORE_THROTTLE=60; SCORE_SUSPECT=80
SCORE_RECOVER_PER_MIN=6; SCORE_DROP_CAP_PER_MIN=45
PROBATION_SCORE=50; PROBATION_SECONDS=1800; PROBATION_RECOVER_PER_MIN=10
CONN_THRESHOLD=120; BAN_HOURS=4; STRESS_GATE=1
CHURN_ALLOW=2; CHURN_WEIGHT=1.2; CHURN_CAP=30; SUST_DIV=40; SUST_CAP=20
SYN_MIN=20; SYN_RATIO=0.5; SYN_WEIGHT=40; SYN_CAP=15
mkdir -p "$SCORE_DIR"; : > "$SCORE_FILE"; : > "$BANNED_LIST"; : > "$WATCH_LIST"; : > "$THROTTLE_LIST"
CALLS="$TMP/calls.log"; : > "$CALLS"
log() { :; }
is_exempt() { return 1; }
throttle_ip() { echo "throttle $1" >> "$CALLS"; }
hard_throttle_ip() { echo "hard $1" >> "$CALLS"; }
ban_ip() { echo "ban $1" >> "$CALLS"; echo "$1 $(date +%s) 1800" >> "$BANNED_LIST"; }
. "$TMP/fns.sh"
# Deterministic stress oracle (redefinition wins over any extraction).
nx_host_stressed() { return 1; }

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
NOW=$(date +%s)
# Seed: score S, prev 200, ts 60s ago, EWMA rate 30/s (field 7 = 3000),
# strikes K. One update at cur=200 syn=200 dt=60 drops exactly 32
# (churn 15.6 + sust 2 + syn 15 = 32.6/min x 60s, frac aside).
seedg() { printf '%s\n' "$1 $2 200 $((NOW - 60)) 0 0 3000 $3 $NOW" > "$SCORE_FILE"; : > "$CALLS"; : > "$BANNED_LIST"; }
banned() { grep -q "^ban $1" "$CALLS"; }
harded() { grep -q "^hard $1" "$CALLS"; }

# 1) calm + first offence + lands at 18 -> deferred to hard throttle
seedg 1.2.3.4 50 0; update_score 1.2.3.4 200 200 60
harded 1.2.3.4 && ok || bad "deferred ban should hard-throttle"
banned 1.2.3.4 && bad "calm first offence at score ~18 must NOT ban" || ok

# 2) calm but lands at 8 (< 10) -> bans anyway
seedg 1.2.3.5 40 0; update_score 1.2.3.5 200 200 60
banned 1.2.3.5 && ok || bad "score <10 must ban even when calm"

# 3) repeat offender (strikes=1) at 18 -> bans
seedg 1.2.3.6 50 1; update_score 1.2.3.6 200 200 60
banned 1.2.3.6 && ok || bad "repeat offender must ban even when calm"

# 4) stressed host at 18 -> bans
nx_host_stressed() { return 0; }
seedg 1.2.3.7 50 0; update_score 1.2.3.7 200 200 60
banned 1.2.3.7 && ok || bad "stressed host must ban at 18"
nx_host_stressed() { return 1; }

# 5) gate disabled -> classic behaviour
STRESS_GATE=0
seedg 1.2.3.8 50 0; update_score 1.2.3.8 200 200 60
banned 1.2.3.8 && ok || bad "STRESS_GATE=0 must restore classic bans"

echo "stress gate (Phase 1d): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
