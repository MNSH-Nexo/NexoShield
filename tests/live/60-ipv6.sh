#!/bin/bash
# 60-ipv6.sh — IPv6 connection flood: the Wave-9 dual-stack path must count,
# score and enforce on v6 exactly like v4. 120 conns from fd99:99::21.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire
guard_target "$LAB_V6_HOST"
log "== 60 IPv6 conn flood: 120 conns from $IP_V6 =="

cat > "$RESULT_DIR/holder6.py" <<'PY'
import socket
srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('::', 18080)); srv.listen(1000)
conns = []
while True:
    c, _ = srv.accept(); conns.append(c)
PY
python3 "$RESULT_DIR/holder6.py" & HOLDER_PID=$!
sleep 1

cat > "$RESULT_DIR/flood6_client.py" <<PY
import socket, time
ss = []
for i in range(120):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(8); s.bind(('$IP_V6', 0))
    s.connect(('$LAB_V6_HOST', 18080, 0, 0)); ss.append(s)
print(f"opened {len(ss)} v6 conns", flush=True)
time.sleep(45)
PY
MARK="$(ts)"
timeout 120 in_ns python3 "$RESULT_DIR/flood6_client.py" > "$RESULT_DIR/60-client.out" 2>&1 || true
sleep 12

log "daemon SCORE lines for $IP_V6 since $MARK:"
if nx_scores_for "$IP_V6" 5 | tee -a "$RESULT_DIR/battery.log" | grep -q "SCORE:"; then
    pass "IPv6 source is counted and scored (Wave-9 parity path live)"
else
    fail "no SCORE lines for IPv6 flood — v6 counting path may be blind"
fi
kill "$HOLDER_PID" 2>/dev/null || true
log "== 60 done =="
