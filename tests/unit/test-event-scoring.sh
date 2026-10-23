#!/usr/bin/env bash
# Phase 2b/2c/2e: event-driven score terms. The real snapshot loader
# reads fixture counters files; update_score must (a) price the
# handshake-completion deficit, (b) accumulate CUSUM from exact
# arrival deltas, (c) price slow-attack behaviour (age x bytes),
# and (d) fall back to legacy behaviour when data is stale.
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
extract_fn src/modules/autoban/25-events.sh nx_load_event_counters "$TMP/fns.sh" || { echo "FAIL extract loader"; exit 1; }
for fn in load_reputation save_reputation rep_on_ban update_score; do
    extract_fn src/modules/autoban/30-reputation.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done

SCORE_DIR="$TMP/scores"; SCORE_FILE="$SCORE_DIR/reputation.dat"
BANNED_LIST="$TMP/banned.list"; WATCH_LIST="$TMP/watch.list"; THROTTLE_LIST="$TMP/throttled.list"
NX_COUNTERS_FILE="$TMP/counters.dat"
SCORE_BAN=20; SCORE_HARD=40; SCORE_THROTTLE=60; SCORE_SUSPECT=80
SCORE_RECOVER_PER_MIN=6; SCORE_DROP_CAP_PER_MIN=45
PROBATION_SCORE=50; PROBATION_SECONDS=1800; PROBATION_RECOVER_PER_MIN=10
CONN_THRESHOLD=120; BAN_HOURS=4; STRESS_GATE=0
CHURN_ALLOW=2; CHURN_WEIGHT=1.2; CHURN_CAP=30; SUST_DIV=40; SUST_CAP=20
SYN_MIN=20; SYN_RATIO=0.5; SYN_WEIGHT=40; SYN_CAP=15
BAN_BASE_MINUTES=30; BAN_MAX_MINUTES=10080
declare -A EV_SYN60 EV_EST60 EV_CLOSED EV_BYTES EV_AGE EV_DSYN EV_DEST EV_PSYN EV_PEST
NX_EV_OK=0; NX_EV_BASE=""; NX_EV_TOT_DSYN=0; NX_EV_TOT_DEST=0; NX_EV_DT=2
_NX_EV_PREV_TOTSYN=""; _NX_EV_PREV_TOTEST=""; _NX_EV_PREV_TS=""
mkdir -p "$SCORE_DIR"; : > "$SCORE_FILE"; : > "$BANNED_LIST"; : > "$WATCH_LIST"; : > "$THROTTLE_LIST"
log() { :; }
is_exempt() { return 1; }
throttle_ip() { :; }; hard_throttle_ip() { :; }; ban_ip() { :; }
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
eq()  { [ "$1" = "$2" ] && ok || bad "$3 (got '$1', want '$2')"; }
NOW=$(date +%s)
snap() { # ts base totsyn totest, then rows on stdin
    { printf '# nxcountd 1 ts=%s base=%s dropped=0 flows_dropped=0 totalsyn=%s totalest=%s\n' "$1" "$2" "$3" "$4"; cat; } > "$NX_COUNTERS_FILE"
}
seed() { printf '%s\n' "$1 $2 $3 $((NOW - 60)) 0 0 0 0 0 0 0" > "$SCORE_FILE"; }  # ip score prev
score_of() { awk -v x="$1" '$1==x{print $2}' "$SCORE_FILE"; }
field_of() { awk -v x="$1" -v f="$2" '$1==x{print $f}' "$SCORE_FILE"; }

# ── loader: fresh arms, stale disarms ──
printf '' | snap "$NOW" 7 0 0
nx_load_event_counters; eq "$NX_EV_OK" "1" "fresh snapshot arms event terms"
printf '' | snap "$((NOW - 30))" 7 0 0
nx_load_event_counters; eq "$NX_EV_OK" "0" "stale snapshot disarms event terms"

# ── completion ratio: flooder (r=0) vs busy NAT (r=0.9) ──
# cur=200 prev=200 syn(ss)=0: legacy terms give sust=2/min only.
{ printf '%s\n' "1.2.3.4 100 90 100 90 0 0 0 0 0"; printf '%s\n' "1.2.3.5 100 90 100 90 0 0 0 0 0"; } | snap "$NOW" 7 190 180
nx_load_event_counters
# rewrite windows: flooder syn60=100 est60=0; NAT syn60=100 est60=90
{ printf '%s\n' "1.2.3.4 100 0 100 0 0 0 0 0 0"; printf '%s\n' "1.2.3.5 100 90 100 90 0 0 0 0 0"; } | snap "$NOW" 7 200 90
nx_load_event_counters
seed 1.2.3.4 100 200; update_score 1.2.3.4 200 0 60; SF=$(score_of 1.2.3.4)
seed 1.2.3.5 100 200; update_score 1.2.3.5 200 0 60; SN=$(score_of 1.2.3.5)
eq "$SF" "83" "flooder: sust 2 + completion 15 over 60s -> 83"
eq "$SN" "98" "NAT r=0.9: sust only -> 98"

# ── stale data: same flooder seed scores like the NAT (legacy) ──
printf '' | snap "$((NOW - 30))" 7 0 0
nx_load_event_counters
seed 1.2.3.4 100 200; update_score 1.2.3.4 200 0 60
eq "$(score_of 1.2.3.4)" "98" "stale snapshot -> legacy behaviour only"

# ── CUSUM: 30 arrivals/cycle, 0 completions; allowance 2/s x 2s ──
: > "$SCORE_FILE"
printf '%s\n' "9.9.9.9 100 200 $NOW 0 0 0 0 0 0 0" > "$SCORE_FILE"
cum=0
for i in 1 2 3 4 5 6; do
    cum=$((cum + 30))
    printf '%s\n' "9.9.9.9 $cum 0 30 0 0 0 0 0 0" | snap "$NOW" 7 "$cum" 0
    nx_load_event_counters
    update_score 9.9.9.9 200 0 2
done
# (first cycle re-bases: delta 0 by design — the daemon cannot count
# arrivals from before it started watching. 5 effective cycles.)
eq "$(field_of 9.9.9.9 10)" "13000" "CUSUM arrivals accumulate 2600/cycle x5 after re-base"
[ "$(field_of 9.9.9.9 11)" -ge 6000 ] && ok || bad "CUSUM incomplete-handshake accumulator should pass 6000"

# ── slow attack: old, tiny connections cost points; fat ones don't ──
{ printf '%s\n' "5.5.5.5 0 0 0 0 0 0 20 20000 6000000"; printf '%s\n' "5.5.5.6 0 0 0 0 0 0 20 1000000 6000000"; } | snap "$NOW" 7 0 0
nx_load_event_counters
seed 5.5.5.5 100 100; update_score 5.5.5.5 100 0 60; SLOWA=$(score_of 5.5.5.5)
seed 5.5.5.6 100 100; update_score 5.5.5.6 100 0 60
eq "$SLOWA" "93" "slow (age 300s, 1000 B/conn, 100 conns) -> slow term 7"
eq "$(score_of 5.5.5.6)" "100" "same age but 50 KB/conn -> no slow term"

echo "event scoring (Phase 2b/2c/2e): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
