#!/usr/bin/env bash
# Regression guards for the 2026-10-23 deep static review
# (docs/REVIEW-2026-10-23.md) - the review that replaced the blocked
# live attack battery: code, logic and math audited in several passes.
set -uo pipefail
cd "$(dirname "$0")/../.."
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
has() { grep -qF "$2" "$1" && ok || bad "missing in $1: $2"; }
hasnt() { grep -qF "$2" "$1" && bad "should NOT be in $1: $2" || ok; }

ML=src/modules/autoban/50-main-loop.sh
EN=src/modules/autoban/20-enforce.sh
SN=src/modules/autoban/40-subnet.sh
TC=src/modules/antiddos/50-tc.sh

# R-2: auto-release is score-gated and never wipes reputation
has   "$ML" '_REL_SCORE'
hasnt "$ML" 'clear_reputation "$ip"'
# R-13: self_guard purges v4 self IPs from the ban list too
has   "$ML" 'state_del_ip "$BANNED_LIST" "$_sip"'
# R-7: band-aware throttle enforcement (no per-cycle filter churn,
# v6 soft->hard upgrades possible)
has   "$EN" 'state_get_field "$THROTTLE_LIST" "$ip" 4'
has   "$EN" 'state_get_field "$THROTTLE_LIST" "$ip" 4)" = "$band"'
# R-15/R-17: subnet bans honour CIDR whitelist entries (real overlap)
# and record state only for rules that landed
has   "$SN" 'ip_in_cidr "${subnet}.0" "$_ECIDR"'
has   "$SN" 'SUBNET BAN FAILED'
# R-18/R-21: generated tc-setup restores v6 throttles; HTB tree is
# scaled to the detected link speed
has   "$TC" 'match ip6 dst "$TIP"'
has   "$TC" 'LINK_MBPS'
has   "$TC" '/sys/class/net/$MAIN_IF/speed'

echo "review fixes (R-2/R-7/R-13/R-15/R-17/R-18/R-21): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
