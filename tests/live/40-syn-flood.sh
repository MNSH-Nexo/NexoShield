#!/bin/bash
# 40-syn-flood.sh — short, count-capped SYN burst from 10.99.0.14.
# Verifies the SYN_COUNT sampler sees half-open floods (the syn= term in
# scoring v2). 3000 SYNs at 1ms spacing ≈ 3 s — loud enough to sample,
# far below anything that could hurt the host.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire
command -v hping3 >/dev/null || { log "SKIP: hping3 not installed"; exit 0; }
guard_target "$LAB_V4_HOST"
log "== 40 SYN burst: 3000 SYNs from $IP_SYNFLOOD =="

MARK="$(ts)"
timeout 60 in_ns hping3 -S -a "$IP_SYNFLOOD" -p 18081 -c 3000 -i u1000 "$LAB_V4_HOST" \
    > "$RESULT_DIR/40-hping.out" 2>&1 || true
sleep 12  # daemon sample window
log "daemon SCORE lines for $IP_SYNFLOOD since $MARK:"
LINES="$(nx_scores_for "$IP_SYNFLOOD" 5 | tee -a "$RESULT_DIR/battery.log")"
if echo "$LINES" | grep -q "syn="; then
    SYN_N="$(echo "$LINES" | tail -1 | grep -o "syn_n=[0-9]*" || echo "syn_n=?")"
    pass "SYN sampler observed the burst ($SYN_N in latest SCORE line)"
else
    fail "no SCORE/syn component for the SYN burst — sampler may be blind to it"
fi
log "== 40 done =="
