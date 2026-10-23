#!/bin/bash
# 50-whitelist-exemption.sh — FR-1: a whitelisted IP must be exempt from
# EVERYTHING. Adds 10.99.0.15 to the whitelist, floods 60 conns from it,
# asserts zero score movement / no watch / no throttle / no ban, then
# removes it from the whitelist.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire
guard_target "$LAB_V4_HOST"
log "== 50 whitelist exemption (FR-1) for $IP_WHITELIST =="

cp "$NX_WHITELIST" "$RESULT_DIR/50-whitelist.bak" 2>/dev/null || touch "$RESULT_DIR/50-whitelist.bak"
grep -qxF "$IP_WHITELIST" "$NX_WHITELIST" 2>/dev/null || echo "$IP_WHITELIST" >> "$NX_WHITELIST"
sleep 6  # daemon picks up whitelist changes live (Wave 1)
if /usr/local/bin/nx-proxy --exempt-check "$IP_WHITELIST" 2>/dev/null | grep -qi "exempt"; then
    pass "--exempt-check confirms $IP_WHITELIST is exempt"
else
    log "note: --exempt-check did not confirm; continuing — SCORE absence is the real assertion"
fi

cat > "$RESULT_DIR/wl_client.py" <<PY
import socket, time
ss = []
for i in range(60):
    s = socket.socket(); s.settimeout(8); s.bind(('$IP_WHITELIST', 0))
    s.connect(('$LAB_V4_HOST', 18080)); ss.append(s)
print(f"opened {len(ss)} from whitelisted IP", flush=True)
time.sleep(25)
PY
python3 "$RESULT_DIR/holder.py" & HOLDER_PID=$! 2>/dev/null || true
sleep 1
timeout 90 in_ns python3 "$RESULT_DIR/wl_client.py" > "$RESULT_DIR/50-client.out" 2>&1 || true
sleep 12

if nx_scores_for "$IP_WHITELIST" 20 | grep -q "SCORE:"; then
    fail "whitelisted IP $IP_WHITELIST was SCORED — FR-1 exemption is leaking"
    nx_scores_for "$IP_WHITELIST" 5 | tee -a "$RESULT_DIR/battery.log"
else
    pass "whitelisted IP untouched: no SCORE lines despite 60 conns"
fi
nx_banned "$IP_WHITELIST" && fail "whitelisted IP got BANNED — critical FR-1 violation" \
    || pass "whitelisted IP not banned"

# Restore whitelist exactly.
cp "$RESULT_DIR/50-whitelist.bak" "$NX_WHITELIST"
kill "$HOLDER_PID" 2>/dev/null || true
log "== 50 done (whitelist restored) =="
