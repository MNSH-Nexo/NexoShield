#!/usr/bin/env bash
# Unit tests for nx_static_rules_filter() (BUG-012, Wave 3): boot
# persistence snapshots must contain ONLY the static ruleset - never
# transient auto-ban/subnet-ban DROPs or fail2ban chains.
set -uo pipefail
cd "$(dirname "$0")/../.."

SRC="src/modules/antiddos/20-iptables.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

start=$(grep -n '^nx_static_rules_filter() {' "$SRC" | head -1 | cut -d: -f1)
[ -n "$start" ] || { echo "FAIL: filter not found"; exit 1; }
end=$(tail -n +"$start" "$SRC" | grep -n '^}' | head -1 | cut -d: -f1)
sed -n "${start},$((start + end - 1))p" "$SRC" > "$TMP/fn.sh"
# shellcheck disable=SC1091
. "$TMP/fn.sh"

cat > "$TMP/save.txt" << 'EOF'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:f2b-3proxy-ddos - [0:0]
:f2b-sshd - [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -s 104.16.0.0/13 -m comment --comment "cf_whitelist" -j ACCEPT
-A INPUT -s 5.6.7.8 -m comment --comment "auto-ban" -j DROP
-A INPUT -s 9.10.11.0/24 -m comment --comment "subnet-ban" -j DROP
-A INPUT -j f2b-3proxy-ddos
-A INPUT -j f2b-sshd
-A f2b-sshd -s 1.2.3.4 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m hashlimit --hashlimit-name syn_flood -j DROP
COMMIT
EOF

nx_static_rules_filter < "$TMP/save.txt" > "$TMP/out.txt"

pass=0; fail=0
kept()    { if grep -qF -- "$1" "$TMP/out.txt"; then pass=$((pass+1)); else echo "  FAIL (should be KEPT): $1"; fail=$((fail+1)); fi; }
dropped() { if grep -qF -- "$1" "$TMP/out.txt"; then echo "  FAIL (should be DROPPED): $1"; fail=$((fail+1)); else pass=$((pass+1)); fi; }

kept    'cf_whitelist'
kept    'syn_flood'
kept    '-i lo'
kept    'COMMIT'
kept    '*filter'
dropped 'auto-ban'
dropped 'subnet-ban'
dropped 'f2b-3proxy-ddos'
dropped 'f2b-sshd'
dropped '1.2.3.4'

echo "static rules filter: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
