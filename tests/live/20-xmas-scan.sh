#!/bin/bash
# 20-xmas-scan.sh — XMAS port scan must trip the [NX-SCAN] LOG rule and the
# fail2ban "portscan" jail. Source IP 10.99.0.12, target host-side lab IP.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire
command -v nmap >/dev/null || { log "SKIP: nmap not installed"; exit 0; }
guard_target "$LAB_V4_HOST"
log "== 20 XMAS scan from $IP_XMAS =="

MARK="$(date +%s)"
timeout 120 in_ns nmap -sX -S "$IP_XMAS" -e nxl0 --max-retries 1 -T4 \
    -p 81,82,83,1080 "$LAB_V4_HOST" > "$RESULT_DIR/20-nmap.out" 2>&1 || true
log "nmap done (XMAS against closed+open ports)"

sleep 10  # fail2ban poll window
SCAN_HITS="$(journalctl -k --since "@$MARK" 2>/dev/null | grep -c "NX-SCAN" || true)"
if [ -z "$SCAN_HITS" ] || [ "$SCAN_HITS" = "0" ]; then
    SCAN_HITS="$(dmesg 2>/dev/null | grep -c "NX-SCAN" || echo 0)"
fi
log "[NX-SCAN] log hits since scan start: $SCAN_HITS"

JAIL="$(fail2ban-client status portscan 2>/dev/null | grep -A2 "Banned IP" || echo "(jail query failed)")"
log "portscan jail: $JAIL"
if fail2ban-client status portscan 2>/dev/null | grep -q "$IP_XMAS"; then
    pass "XMAS source $IP_XMAS banned by portscan jail"
else
    fail "XMAS source $IP_XMAS NOT banned by portscan jail (hits=$SCAN_HITS) — investigate jail filter/log path"
fi
log "== 20 done =="
