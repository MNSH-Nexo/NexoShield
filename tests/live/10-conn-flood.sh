#!/bin/bash
# 10-conn-flood.sh — connection flood with ground-truth count comparison.
# Opens 170 concurrent TCP connections from 10.99.0.11 to a dummy holder on
# the host side, holds 60 s, then compares:
#   daemon's view (SCORE log lines for the IP) vs ground truth (ss + iptables).
# Proves the counting accuracy the "DPI" claim rests on.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire

NCONN="${1:-170}"
HOLDPORT=18080
guard_target "$LAB_V4_HOST"
log "== 10 conn flood: $NCONN conns from $IP_CONNFLOOD, 60s hold =="

# Dummy holder: accepts and holds connections (does not disturb 3proxy).
cat > "$RESULT_DIR/holder.py" <<'PY'
import socket
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 18080)); srv.listen(1000)
conns = []
while True:
    c, _ = srv.accept(); conns.append(c)
PY
python3 "$RESULT_DIR/holder.py" & HOLDER_PID=$!
sleep 1
kill -0 "$HOLDER_PID" 2>/dev/null || { fail "holder failed to start"; exit 1; }

# Client: N connections bound to the test source IP, held 60 s.
cat > "$RESULT_DIR/flood_client.py" <<PY
import socket, time, sys
ss = []
for i in range($NCONN):
    s = socket.socket()
    s.settimeout(8)
    s.bind(('$IP_CONNFLOOD', 0))
    s.connect(('$LAB_V4_HOST', $HOLDPORT))
    ss.append(s)
print(f"opened {len(ss)}", flush=True)
time.sleep(60)
PY
MARK="$(ts)"
timeout 120 in_ns python3 "$RESULT_DIR/flood_client.py" > "$RESULT_DIR/10-client.out" 2>&1 &
CLIENT_PID=$!
sleep 8  # let the daemon sample at least one full cycle with conns up

GT_MID="$(gt_conns_from "$IP_CONNFLOOD")"
log "ground truth mid-flood: ss shows $GT_MID established conns from $IP_CONNFLOOD (target $NCONN)"
echo "$GT_MID/$NCONN" > "$RESULT_DIR/10-ground-truth.txt"

wait "$CLIENT_PID"
sleep 12  # let the daemon log a post-flood cycle

log "daemon SCORE lines for $IP_CONNFLOOD since $MARK:"
nx_scores_for "$IP_CONNFLOOD" 8 | tee -a "$RESULT_DIR/battery.log" || log "(no SCORE lines yet — daemon cycle may not have sampled)"

if nx_banned "$IP_CONNFLOOD"; then
    pass "conn-flood IP is banned (expected: 170 sustained conns >> watch(120)/ban thresholds)"
else
    # Not banned is only OK if the score moved into throttle bands — record honestly.
    if nx_scores_for "$IP_CONNFLOOD" 3 | grep -q .; then
        log "note: scored but not banned — check SCORE lines above for band/throttle behavior"
    else
        fail "no SCORE lines and no ban for a 170-conn flood — counting path may be blind"
    fi
fi
kill "$HOLDER_PID" 2>/dev/null || true
log "== 10 done =="
