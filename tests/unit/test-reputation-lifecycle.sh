#!/usr/bin/env bash
# Lifecycle tests for the D3 reputation state machine (FR-3, Wave 4) and
# exact state matching (BUG-003). Shipped functions are extracted
# verbatim; iptables/tc-facing enforcers are replaced by call recorders.
set -uo pipefail
cd "$(dirname "$0")/../.."

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
for fn in state_has_ip state_get_field state_del_ip; do
    extract_fn src/modules/autoban/10-ip-utils.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
for fn in score_init load_reputation save_reputation clear_reputation rep_on_ban rep_on_unban update_score reputation_sweep; do
    extract_fn src/modules/autoban/30-reputation.sh "$fn" "$TMP/fns.sh" || { echo "FAIL extract $fn"; exit 1; }
done
extract_fn src/modules/autoban/50-main-loop.sh unban_expired "$TMP/fns.sh" || { echo "FAIL extract unban_expired"; exit 1; }

# ── environment ──
SCORE_DIR="$TMP/scores"; SCORE_FILE="$SCORE_DIR/reputation.dat"
BANNED_LIST="$TMP/banned.list"; WATCH_LIST="$TMP/watch.list"; THROTTLE_LIST="$TMP/throttled.list"
SUBNET_WATCH_LIST="$TMP/subnet-watch.list"
SCORE_BAN=20; SCORE_HARD=40; SCORE_THROTTLE=60; SCORE_SUSPECT=80; SCORE_RECOVER=3
PROBATION_SCORE=50; PROBATION_SECONDS=1800; PROBATION_RECOVER=5
CONN_THRESHOLD=120; BAN_HOURS=4
declare -A CONN_COUNT=()
mkdir -p "$SCORE_DIR"; : > "$SCORE_FILE"; : > "$BANNED_LIST"; : > "$WATCH_LIST"; : > "$THROTTLE_LIST"
CALLS="$TMP/calls.log"; : > "$CALLS"
log() { :; }
is_exempt() { return 1; }
throttle_ip() { echo "throttle $1" >> "$CALLS"; }
hard_throttle_ip() { echo "hard $1" >> "$CALLS"; }
ban_ip() { echo "ban $1" >> "$CALLS"; echo "$1 $(date +%s) 14400" >> "$BANNED_LIST"; }
iptables() { return 0; }

# shellcheck disable=SC1091
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }
NOW=$(date +%s)
score_of() { awk -v x="$1" '$1==x{print $2}' "$SCORE_FILE"; }
prob_of()  { awk -v x="$1" '$1==x{print $5}' "$SCORE_FILE"; }

# ── 1) BUG-003: exact matching ──
printf '%s\n' "11.2.3.4 111" "1.2.3.45 222" > "$WATCH_LIST"
state_has_ip "$WATCH_LIST" 1.2.3.4 && bad "1.2.3.4 must not match 11.2.3.4/1.2.3.45" || ok
state_has_ip "$WATCH_LIST" 11.2.3.4 && ok || bad "11.2.3.4 exact should match"
state_del_ip "$WATCH_LIST" 11.2.3.4
state_has_ip "$WATCH_LIST" 1.2.3.45 && ok || bad "state_del_ip removed the wrong entry"
[ "$(wc -l < "$WATCH_LIST")" -eq 1 ] && ok || bad "state_del_ip line count"

# ── 2) FR-3 core: stale post-ban score is normalized, no instant re-ban ──
printf '%s\n' "7.7.7.7 5 300 $((NOW - 100)) 0" > "$SCORE_FILE"
: > "$BANNED_LIST"; : > "$CALLS"
update_score 7.7.7.7 130 2
grep -q "ban 7.7.7.7" "$CALLS" && bad "stale-score IP was instantly re-banned (FR-3!)" || ok
S=$(score_of 7.7.7.7)
[ "${S:-0}" -ge 40 ] && [ "${S:-999}" -le 50 ] && ok || bad "normalized score should be ~46-50, got ${S:-none}"
[ "$(prob_of 7.7.7.7)" -gt "$NOW" ] && ok || bad "probation window not set"

# ── 3) reputation ban sets up its own probation release ──
printf '%s\n' "8.8.8.8 25 0 $((NOW - 10)) 0" > "$SCORE_FILE"
: > "$CALLS"
update_score 8.8.8.8 900 2
grep -q "ban 8.8.8.8" "$CALLS" && ok || bad "score 25 with 900 conns should be banned"
[ "$(score_of 8.8.8.8)" = "50" ] && ok || bad "post-ban score should be PROBATION_SCORE=50, got $(score_of 8.8.8.8)"
[ "$(prob_of 8.8.8.8)" -ge $((NOW + 14400)) ] && ok || bad "probation should extend past the ban"

# ── 4) ban expiry is a probation release (unban_expired transition) ──
printf '%s\n' "9.9.9.9 10 0 $((NOW - 20000)) 0" > "$SCORE_FILE"
printf '%s\n' "9.9.9.9 $((NOW - 20000)) 14400" > "$BANNED_LIST"
unban_expired
state_has_ip "$BANNED_LIST" 9.9.9.9 && bad "expired ban still listed" || ok
[ "$(score_of 9.9.9.9)" = "50" ] && ok || bad "expired ban should land at score 50, got $(score_of 9.9.9.9)"
[ "$(prob_of 9.9.9.9)" -gt "$NOW" ] && ok || bad "expiry should open a probation window"

# ── 5) quiet recovery in the sweep (+3 normal, +5 probation, prune) ──
printf '%s\n' "1.1.1.1 40 0 $((NOW - 50)) 0" "2.2.2.2 40 0 $((NOW - 50)) $((NOW + 600))" "3.3.3.3 100 0 $((NOW - 90000)) 0" > "$SCORE_FILE"
: > "$BANNED_LIST"
reputation_sweep
[ "$(score_of 1.1.1.1)" = "43" ] && ok || bad "quiet recovery +3 (got $(score_of 1.1.1.1))"
[ "$(score_of 2.2.2.2)" = "45" ] && ok || bad "probation recovery +5 (got $(score_of 2.2.2.2))"
state_has_ip "$SCORE_FILE" 3.3.3.3 && bad "stale full-score entry should be pruned" || ok

# ── 6) banned IPs are frozen in the sweep ──
printf '%s\n' "4.4.4.4 30 0 $((NOW - 50)) 0" > "$SCORE_FILE"
printf '%s\n' "4.4.4.4 $NOW 14400" > "$BANNED_LIST"
reputation_sweep
[ "$(score_of 4.4.4.4)" = "30" ] && ok || bad "banned IP score must stay frozen (got $(score_of 4.4.4.4))"

echo "reputation lifecycle: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
