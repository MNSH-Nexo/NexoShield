#!/bin/bash
# 00-lab-setup.sh — build the isolated lab namespace and snapshot baselines.
# Creates netns "nxlab" with veth pair:
#   host side: nxh0 = 10.99.0.1/24, fd99:99::1/64
#   ns side:   nxl0 = 10.99.0.10/24 (+ aliases .11-.15), fd99:99::10/64 (+ ::21)
# Per-test source IPs (.11-.15, ::21) let the daemon attribute each attack
# to its own address while everything stays inside the lab.
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire

log "== 00 lab setup =="

for cmd in ip ss python3; do
    command -v "$cmd" >/dev/null || { fail "missing required tool: $cmd"; exit 1; }
done
for cmd in nmap hping3; do
    command -v "$cmd" >/dev/null || log "note: optional tool missing: $cmd (its test will skip)"
done

# Clean any stale lab from a previous run.
ip netns del "$NS" 2>/dev/null || true
ip link del nxh0 2>/dev/null || true

ip netns add "$NS"
ip link add nxh0 type veth peer name nxl0
ip link set nxl0 netns "$NS"
ip addr add "$LAB_V4_HOST/24" dev nxh0
ip addr add "$LAB_V6_HOST/64" dev nxh0
ip link set nxh0 up
in_ns ip addr add 10.99.0.10/24 dev nxl0
in_ns ip addr add fd99:99::10/64 dev nxl0
for ip4 in "$IP_CONNFLOOD" "$IP_XMAS" "$IP_PROXYAUTH" "$IP_SYNFLOOD" "$IP_WHITELIST"; do
    in_ns ip addr add "$ip4/32" dev nxl0
done
in_ns ip addr add "$IP_V6/128" dev nxl0
in_ns ip link set nxl0 up
in_ns ip link set lo up
in_ns ip route add default via "$LAB_V4_HOST" dev nxl0

# Sanity: ns can reach the host side on both families.
in_ns ping -c1 -W2 "$LAB_V4_HOST" >/dev/null || { fail "v4 lab ping failed"; exit 1; }
in_ns ping -c1 -W2 "$LAB_V6_HOST" >/dev/null || { fail "v6 lab ping failed"; exit 1; }
pass "lab namespace up: v4+v6 host reachable from ns"

# NexoShield presence checks.
[ -x /usr/local/bin/3proxy ] || [ -x /usr/bin/3proxy ] || log "note: 3proxy binary not found at expected paths"
[ -f "$NX_LOG" ] || log "note: daemon log $NX_LOG not present yet"
systemctl is-active --quiet antiddos 2>/dev/null && log "antiddos service: active" || log "note: antiddos service not active (daemon may run standalone)"

# Baseline snapshot.
{
    echo "--- baseline $(ts) ---"
    echo "reputation.dat:"; cat "$NX_SCORES" 2>/dev/null || echo "(absent)"
    echo "banned.list:"; cat "$NX_BANNED" 2>/dev/null || echo "(absent)"
    echo "fail2ban jails:"; fail2ban-client status 2>/dev/null | head -5 || echo "(fail2ban not running)"
    echo "ss summary:"; ss -s 2>/dev/null | head -8
} > "$RESULT_DIR/00-baseline.txt"
pass "baseline snapshot saved to $RESULT_DIR/00-baseline.txt"
log "lab ready. Per-test source IPs: $IP_CONNFLOOD $IP_XMAS $IP_PROXYAUTH $IP_SYNFLOOD $IP_WHITELIST $IP_V6"
