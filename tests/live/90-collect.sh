#!/bin/bash
# 90-collect.sh — gather all evidence into a timestamped tarball and tear
# down the lab namespace. Run last; safe to run standalone too.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire
log "== 90 evidence collection =="

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVDIR="$RESULT_DIR/evidence-$STAMP"
mkdir -p "$EVDIR"

cp "$NX_LOG" "$EVDIR/auto-ban.log" 2>/dev/null || echo "(no daemon log)" > "$EVDIR/auto-ban.log"
cp "$NX_SCORES" "$EVDIR/reputation.dat" 2>/dev/null || echo "(absent)" > "$EVDIR/reputation.dat"
cp "$NX_BANNED" "$EVDIR/banned.list" 2>/dev/null || echo "(absent)" > "$EVDIR/banned.list"
cp "$NX_WHITELIST" "$EVDIR/whitelist.list" 2>/dev/null || true
for j in sshd-aggressive portscan 3proxy-ddos conn-flood http-flood xray-proxy; do
    fail2ban-client status "$j" > "$EVDIR/fail2ban-$j.txt" 2>&1 || echo "(jail $j unavailable)" > "$EVDIR/fail2ban-$j.txt"
done
iptables -S > "$EVDIR/iptables-S.txt" 2>&1
ip6tables -S > "$EVDIR/ip6tables-S.txt" 2>&1
iptables -L -v -n --line-numbers > "$EVDIR/iptables-L.txt" 2>&1
tc -s class show dev eth0 > "$EVDIR/tc-classes.txt" 2>&1 || tc -s class show > "$EVDIR/tc-classes.txt" 2>&1 || true
ss -s > "$EVDIR/ss-summary.txt" 2>&1
dmesg 2>/dev/null | grep -E "NX-SCAN|NX-" | tail -50 > "$EVDIR/kernel-nx.txt" 2>&1 || true
cp "$RESULT_DIR/battery.log" "$EVDIR/" 2>/dev/null || true
cp "$RESULT_DIR"/[0-9]*-*.txt "$RESULT_DIR"/[0-9]*-*.out "$EVDIR/" 2>/dev/null || true

tar -czf "$RESULT_DIR/nx-livefire-$STAMP.tar.gz" -C "$RESULT_DIR" "evidence-$STAMP" 2>/dev/null
log "evidence tarball: $RESULT_DIR/nx-livefire-$STAMP.tar.gz"

# Teardown: remove the lab namespace and host veth.
ip netns del "$NS" 2>/dev/null || true
ip link del nxh0 2>/dev/null || true
pass "lab torn down; evidence preserved"
log "== 90 done =="
