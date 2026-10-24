#!/bin/bash
# Tier-scaling suite (v3.13): the RAM tiers in detect_env must keep
# the layering coherent - every connlimit tier above the daemon's
# 120 watch gate (the behavioural scorer engages before the kernel
# resets connections), tiers strictly increasing, and the per-IP
# bandwidth ceilings at the raised 100/250/500 Mbit values sized
# for shared-IP (CGNAT/NAT) headroom.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

SRC="$ROOT/src/modules/antiddos/10-sysctl.sh"
CONNS=$(grep -oP 'CONN_LIMIT_PER_IP="\K[0-9]+' "$SRC")
BWS=$(grep -oP 'BW_PER_IP_MBIT="\K[0-9]+' "$SRC")
NEWS=$(grep -oP 'NEW_CONN_RATE="\K[0-9]+' "$SRC")
# File order is high tier (>=4GB) first, then mid, then low.
set -- $CONNS; CHI=${1:-0}; CMID=${2:-0}; CLO=${3:-0}
set -- $BWS;   BHI=${1:-0}; BMID=${2:-0}; BLO=${3:-0}
set -- $NEWS;  NHI=${1:-0}; NMID=${2:-0}; NLO=${3:-0}

[ "$CLO" -eq 150 ] && [ "$CMID" -eq 300 ] && [ "$CHI" -eq 600 ] && ok || bad "conn tiers are $CLO/$CMID/$CHI (want 150/300/600)"
[ "$BLO" -eq 100 ] && [ "$BMID" -eq 250 ] && [ "$BHI" -eq 500 ] && ok || bad "bw tiers are $BLO/$BMID/$BHI (want 100/250/500)"
[ "$NLO" -eq 100 ] && [ "$NMID" -eq 200 ] && [ "$NHI" -eq 400 ] && ok || bad "new-conn tiers are $NLO/$NMID/$NHI (want 100/200/400)"
# Coherence: smallest connlimit tier must exceed the daemon watch gate (120)
[ "$CLO" -gt 120 ] && ok || bad "smallest conn tier $CLO does not exceed the 120 watch gate"
[ "$CLO" -lt "$CMID" ] && [ "$CMID" -lt "$CHI" ] && ok || bad "conn tiers not increasing"
[ "$BLO" -lt "$BMID" ] && [ "$BMID" -lt "$BHI" ] && ok || bad "bw tiers not increasing"
# The old-kernel connlimit fallback must use the tier, not a hardcoded 60
grep -q 'connlimit-above "$CONN_LIMIT_PER_IP"' "$ROOT/src/modules/antiddos/20-iptables.sh" && ok || bad "bw fallback still hardcodes its connlimit"
# Installer OS gate: ubuntu + debian pass, others stop
grep -q 'ubuntu|debian' "$ROOT/src/installer/preamble.sh" && ok || bad "installer OS gate missing debian"
grep -q 'Unsupported OS' "$ROOT/src/installer/preamble.sh" && ok || bad "installer OS gate has no stop message"

echo "tier scaling: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
