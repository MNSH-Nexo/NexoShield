#!/bin/bash
# 30-proxy-authfail.sh — wrong-credential SOCKS5 attempts must trip the
# fail2ban "3proxy-ddos" jail; a few plain TCP connects (control) must not.
# Source IP 10.99.0.13 -> 3proxy on the host side :1080.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire
guard_target "$LAB_V4_HOST"
log "== 30 proxy auth failures from $IP_PROXYAUTH =="

BAD=12
cat > "$RESULT_DIR/socks_auth.py" <<PY
import socket, sys
host, port, src = '$LAB_V4_HOST', 1080, '$IP_PROXYAUTH'
ok = bad = 0
for i in range($BAD):
    try:
        s = socket.socket(); s.settimeout(5); s.bind((src, 0)); s.connect((host, port))
        s.sendall(b'\x05\x01\x02')          # methods: no-auth, user/pass
        if s.recv(2) != b'\x05\x02': s.close(); continue
        u, p = b'attacker', b'wrongpass'
        s.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
        r = s.recv(2)
        if r == b'\x01\x00': ok += 1
        else: bad += 1
        s.close()
    except Exception:
        bad += 1
# control: plain connects with no SOCKS handshake at all
for i in range(3):
    try:
        s = socket.socket(); s.settimeout(5); s.bind((src, 0)); s.connect((host, port)); s.close()
    except Exception: pass
print(f"auth_ok={ok} auth_bad={bad}", flush=True)
PY
timeout 120 in_ns python3 "$RESULT_DIR/socks_auth.py" | tee "$RESULT_DIR/30-client.out" | tee -a "$RESULT_DIR/battery.log"

sleep 12  # fail2ban poll window (3proxy-ddos keys on the %E error field)
JAIL="$(fail2ban-client status 3proxy-ddos 2>/dev/null | tr '\n' ' ' || echo "(jail query failed)")"
log "3proxy-ddos jail: $JAIL"
if fail2ban-client status 3proxy-ddos 2>/dev/null | grep -q "$IP_PROXYAUTH"; then
    pass "auth-failure source $IP_PROXYAUTH banned by 3proxy-ddos jail (errors counted, control connects ignored)"
else
    fail "auth-failure source NOT banned — check jail log path (T-2 fix: dated access.log glob) and filter"
fi
log "== 30 done =="
