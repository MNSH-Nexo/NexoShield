#!/usr/bin/env bash
# Scenario-level audit of scoring v2 (Pass 4 of the 2026-10-23 deep
# review): whole behaviour trajectories, not single calls. Time is
# simulated by seeding the persisted timestamp (update_score/sweep
# measure real elapsed time from it). Design references: the classic
# pipeline bans any IP holding >=120 conns for ~90s regardless of
# score; scoring governs the grey zone and all post-ban behaviour.
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
for fn in score_init load_reputation save_reputation clear_reputation rep_on_ban rep_on_unban update_score reputation_sweep; do
    extract_fn src/modules/autoban/30-reputation.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
SCORE_DIR="$TMP/scores"; SCORE_FILE="$SCORE_DIR/reputation.dat"
BANNED_LIST="$TMP/banned.list"; WATCH_LIST="$TMP/watch.list"; THROTTLE_LIST="$TMP/throttled.list"
SCORE_BAN=20; SCORE_HARD=40; SCORE_THROTTLE=60; SCORE_SUSPECT=80
SCORE_RECOVER_PER_MIN=6; SCORE_DROP_CAP_PER_MIN=45
PROBATION_SCORE=50; PROBATION_SECONDS=1800; PROBATION_RECOVER_PER_MIN=10
CONN_THRESHOLD=120; BAN_HOURS=4
declare -A CONN_COUNT=()
mkdir -p "$SCORE_DIR"; : > "$SCORE_FILE"; : > "$BANNED_LIST"; : > "$WATCH_LIST"; : > "$THROTTLE_LIST"
CALLS="$TMP/calls.log"; : > "$CALLS"
log() { :; }
is_exempt() { return 1; }
throttle_ip() { :; }; hard_throttle_ip() { :; }; ban_ip() { echo "ban $1" >> "$CALLS"; }
. "$TMP/fns.sh"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
score_of() { awk -v x="$1" '$1==x{print $2}' "$SCORE_FILE"; }
# seed ip score prev ago [prob_until] - ts = now-ago
seed() { printf '%s\n' "$1 $2 $3 $(($(date +%s) - $4)) ${5:-0} 0 0" > "$SCORE_FILE"; }
# minute ip cur syn - one simulated minute at steady concurrency $cur:
# prev is set to $cur (no net growth) except the EWMA warm-up call.
minute() { update_score "$1" "$2" "$3" 60; }

# ── S1: net-growth churn (the real churn signature) ──
# +10 conn/s net growth for one minute from 130: churn must dominate.
seed 1.1.1.1 100 130 60
update_score 1.1.1.1 730 0 60   # prev 130 -> 730 in 60s = +10/s
S=$(score_of 1.1.1.1)
# EWMA warm-up halves the first sample by design (anti-spike):
# rs=5 -> churn 3.6 + sust 15.25 = ~-19 -> 82. Second minute rs=7.5.
[ "${S:-100}" -le 85 ] && [ "${S:-0}" -ge 75 ] && ok || bad "S1 minute 1 (EWMA warm-up) expected ~82 (score $S)"
seed_ts_fix() { awk -v ip="$1" -v t="$(($(date +%s) - 60))" 'BEGIN{OFS=" "} $1==ip{$4=t} {print}' "$SCORE_FILE" > "$SCORE_FILE.t" && mv "$SCORE_FILE.t" "$SCORE_FILE"; }
seed_ts_fix 1.1.1.1
update_score 1.1.1.1 1330 0 60  # another +10/s minute
S=$(score_of 1.1.1.1)
[ "${S:-100}" -le 65 ] && ok || bad "S1 minute 2 should deepen the drop (score $S)"

# ── S2: burst then quiet - sweep recovers, no permanent stain ──
seed 2.2.2.2 70 0 3600          # an hour quiet since score 70
reputation_sweep
S=$(score_of 2.2.2.2)
[ "${S:-0}" -eq 100 ] && ok || bad "S2 quiet hour at 6/min must fully recover 70->100 (got $S)"

# ── S3: SYN-heavy minute-by-minute to the ban band ──
seed 3.3.3.3 100 200 60
update_score 3.3.3.3 200 190 60  # dt=60: syn term 15 + sust 2 = 17/min
seed_ts_fix() { awk -v ip="$1" -v t="$(($(date +%s) - 60))" 'BEGIN{OFS=" "} $1==ip{$4=t} {print}' "$SCORE_FILE" > "$SCORE_FILE.t" && mv "$SCORE_FILE.t" "$SCORE_FILE"; }
for i in 2 3 4 5; do seed_ts_fix 3.3.3.3; update_score 3.3.3.3 200 190 60; done
S=$(score_of 3.3.3.3)
grep -q "ban 3.3.3.3" "$CALLS" && ok || bad "S3 SYN-heavy 5min should reach ban band (score $S)"

# ── S4: probation relapse vs probation quiet ──
NOW=$(date +%s)
seed 4.4.4.4 50 150 $((NOW * 0)) 0  # placeholder, fixed below
printf '%s\n' "4.4.4.4 50 150 $(($(date +%s) - 60)) $(($(date +%s) + 1740)) 0 0" > "$SCORE_FILE"
update_score 4.4.4.4 510 0 60   # probation, +6/s growth: drops x2
S=$(score_of 4.4.4.4)
[ "${S:-50}" -lt 50 ] && [ "${S:-0}" -ge 25 ] && ok || bad "S4 probation relapse should cost double, bounded (score $S)"
printf '%s\n' "4.4.4.5 50 0 $(($(date +%s) - 360)) $(($(date +%s) + 1740)) 0 0" > "$SCORE_FILE"
reputation_sweep                 # 6 quiet minutes in probation at 10/min
S=$(score_of 4.4.4.5)
[ "${S:-0}" -eq 100 ] && ok || bad "S4 probation quiet 6min at 10/min should reach 100 (got $S)"

# ── S5: single-sample spike is gradual, not a cliff ──
seed 5.5.5.5 100 0 2
update_score 5.5.5.5 290 0 2    # appears at 290 conns in one sample
S=$(score_of 5.5.5.5)
[ "${S:-0}" -ge 95 ] && ok || bad "S5 one spike sample must cost only ~1-5 (score $S)"

# ── S6: steady high concurrency bleeds slowly (design: classic path
#        owns >=120 sustained; scoring adds ~2-4/min pressure) ──
seed 6.6.6.6 100 250 60
update_score 6.6.6.6 250 0 60
for i in 2 3 4 5; do seed_ts_fix 6.6.6.6; update_score 6.6.6.6 250 0 60; done
S=$(score_of 6.6.6.6)
[ "${S:-100}" -le 92 ] && [ "${S:-0}" -ge 70 ] && ok || bad "S6 steady 250 conns 5min: slow bleed expected (score $S)"

echo "scoring scenarios: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
