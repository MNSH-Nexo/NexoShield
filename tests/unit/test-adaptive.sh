#!/usr/bin/env bash
# Phase 2d: adaptive global thresholds. Calm baseline learning,
# attack entry after 3 high-z cycles, baseline FREEZE during the
# attack, tightened effective gates, hysteretic exit after 30
# calm cycles, persistence of the learned baseline.
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
extract_fn src/modules/autoban/25-events.sh nx_update_adaptive "$TMP/fns.sh" || { echo "FAIL extract"; exit 1; }

CONN_THRESHOLD=120; OBSERVE_SECONDS=45; ADAPTIVE_ENABLED=1
NX_EV_OK=1; NX_EV_TOT_DSYN=0
NX_ADAPT_FILE="$TMP/adaptive.dat"
NX_MU=""; NX_SIG=""; NX_ATTACK=0; _NX_AD_HI=0; _NX_AD_LO=0; _NX_AD_INIT=0; _NX_AD_CYC=0; _NX_AD_PREV=0
EFF_CONN_THRESHOLD=120; EFF_OBSERVE=45
log() { :; }
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
eq()  { [ "$1" = "$2" ] && ok || bad "$3 (got '$1', want '$2')"; }
drive() { local i; for i in $(seq 1 "$2"); do NX_EV_TOT_DSYN="$1"; nx_update_adaptive; done; }

# calm baseline: 10 arrivals/cycle
drive 10 40
eq "$NX_ATTACK" "0" "calm traffic never enters attack state"
eq "$EFF_CONN_THRESHOLD" "120" "calm gates stay at configured values"
awk -v m="$NX_MU" 'BEGIN{ exit !(m > 8 && m < 12) }' && ok || bad "baseline mu should settle near 10 (got $NX_MU)"
[ -f "$NX_ADAPT_FILE" ] && ok || bad "baseline persisted to adaptive.dat"

# attack: 500/cycle — needs 3 consecutive high-z cycles to flip
drive 500 2
eq "$NX_ATTACK" "0" "two anomalous cycles do not flip the state (hysteresis-in)"
drive 500 1
eq "$NX_ATTACK" "1" "third anomalous cycle enters ATTACK"
eq "$EFF_CONN_THRESHOLD" "72" "attack tightens conn gate 120 -> 72"
eq "$EFF_OBSERVE" "22" "attack halves the observe window 45 -> 22"
MU_AT_ATTACK="$NX_MU"
drive 500 10
eq "$NX_MU" "$MU_AT_ATTACK" "baseline is FROZEN during the attack"
eq "$NX_ATTACK" "1" "sustained anomaly keeps the state"

# calm again: 30 low cycles to exit (hysteresis-out)
drive 5 29
eq "$NX_ATTACK" "1" "29 calm cycles do not yet exit"
drive 5 1
eq "$NX_ATTACK" "0" "30th calm cycle exits ATTACK"
eq "$EFF_CONN_THRESHOLD" "120" "gates relax after the attack"

# disabled layer never moves
ADAPTIVE_ENABLED=0; NX_ATTACK=0
drive 500 5
eq "$EFF_CONN_THRESHOLD" "120" "adaptive_enabled=0 keeps configured gates"

echo "adaptive thresholds (Phase 2d): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
