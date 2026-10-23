#!/usr/bin/env bash
# Scoring model v2 properties (docs/SCORING.md): continuity (no step
# cliffs), time-normalization (points per minute scaled by real dt),
# fractional accumulation, the SYN-share term, time-based recovery.
# Shipped functions are extracted verbatim; enforcers are recorders.
set -uo pipefail
cd "$(dirname "$0")/../.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

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
throttle_ip() { echo "throttle $1" >> "$CALLS"; }
hard_throttle_ip() { echo "hard $1" >> "$CALLS"; }
ban_ip() { echo "ban $1" >> "$CALLS"; }
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
score_of() { awk -v x="$1" '$1==x{print $2}' "$SCORE_FILE"; }
frac_of()  { awk -v x="$1" '$1==x{print $6}' "$SCORE_FILE"; }
seed() { # ip score prev ago [prob]
    printf '%s\n' "$1 $2 $3 $(($(date +%s) - $4)) ${5:-0} 0 0" > "$SCORE_FILE"
}
bump() { # ip newprev - rewind ts by 2s and set prev, keep score/frac/rate
    awk -v ip="$1" -v p="$2" -v t="$(($(date +%s) - 2))" 'BEGIN{OFS=" "} $1==ip{$3=p;$4=t} {print}' \
        "$SCORE_FILE" > "$SCORE_FILE.t" && mv "$SCORE_FILE.t" "$SCORE_FILE"
}

# ── 1) continuity at the old v1 cliff (24 vs 25 conn/s; v1 jumped +6) ──
run_rate() { # ip rate  -> runs 20 cycles of dt=2 at the given new-rate
    local ip="$1" rate="$2" i
    seed "$ip" 100 5000 2
    for i in $(seq 1 20); do
        update_score "$ip" $((5000 + rate * 2)) 0 2
        bump "$ip" 5000
    done
    score_of "$ip"
}
SA=$(run_rate 5.5.5.5 24)
SB=$(run_rate 6.6.6.6 25)
D=$(( SA > SB ? SA - SB : SB - SA ))
[ "$SA" -lt 85 ] && [ "$SB" -lt 85 ] && ok || bad "sustained 24-25/s should cost real points (got $SA/$SB)"
[ "$D" -le 3 ] && ok || bad "cliff: 24/s vs 25/s differ by $D points (v1: ~6/cycle)"

# ── 2) time normalization: same rate, dt=30 vs dt=2 ──
seed 7.7.7.7 100 1000 30; update_score 7.7.7.7 1450 0 30
SC=$(score_of 7.7.7.7)
seed 8.8.8.8 100 1000 2;  update_score 8.8.8.8 1030 0 2
SD=$(score_of 8.8.8.8); FD=$(frac_of 8.8.8.8)
[ "${SC:-100}" -le 90 ] && ok || bad "dt=30 at 15/s should drop >=10 (got $SC)"
[ "${SD:-0}" -eq 100 ] && [ "${FD:-0}" -le -50 ] && ok || bad "dt=2 same rate: sub-point drop must sit in frac (score $SD frac $FD)"

# ── 3) fractional accumulation: 4/s is below every v1 step (drop 0) ──
seed 9.9.9.9 100 100 2
for i in $(seq 1 20); do update_score 9.9.9.9 108 0 2; bump 9.9.9.9 100; done
S9=$(score_of 9.9.9.9); F9=$(frac_of 9.9.9.9)
# Total hundredths lost: ~160 at dt=2 (4/s), ~70 at dt=3 (the same 8
# conns spread over a longer measured window honestly reads as
# 2.7/s). Assert the accumulation is real but sub-cliff either way.
LOST9=$(( (100 - ${S9:-100}) * 100 - ${F9:-0} ))
[ "$LOST9" -ge 70 ] && [ "$LOST9" -le 250 ] && ok || bad "4/s for 40s should cost ~0.7-1.7 pts total (lost $LOST9 hundredths, score $S9 frac $F9)"

# ── 4) SYN-share term: same totals, syn-heavy drops faster ──
seed 1.2.3.4 100 200 10; update_score 1.2.3.4 200 0 10
SE=$(score_of 1.2.3.4)
seed 1.2.3.5 100 200 10; update_score 1.2.3.5 200 190 10
SF=$(score_of 1.2.3.5)
[ "${SF:-100}" -lt "${SE:-100}" ] && [ "${SF:-100}" -le 98 ] && ok || bad "syn-heavy should drop more (est $SE vs syn $SF)"

# ── 5) recovery in update_score is time-based too ──
seed 2.3.4.5 60 100 30; update_score 2.3.4.5 100 0 30
SR=$(score_of 2.3.4.5)
seed 2.3.4.6 60 100 2;  update_score 2.3.4.6 100 0 2
SR2=$(score_of 2.3.4.6); FR2=$(frac_of 2.3.4.6)
[ "${SR:-0}" -eq 63 ] && ok || bad "30s quiet at 6/min -> +3 (got $SR)"
# dt is wall-clock: under load the 2s seed elapses as 3s (frac 30).
# The load-bearing facts are: no whole point, recovery in frac only.
[ "${SR2:-0}" -eq 60 ] && [ "${FR2:-0}" -ge 20 ] && [ "${FR2:-0}" -le 30 ] && ok || bad "2s quiet -> +0.2 in frac only (score $SR2 frac $FR2)"

echo "scoring v2: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
