#!/usr/bin/env bash
# Wave 8 regression guards: menu/UI truth (BUG-008/038/041/043/044/
# 051/052/053). Source-level assertions on the menu + antiddos parts.
set -uo pipefail
cd "$(dirname "$0")/../.."
pass=0; fail=0
has()   { grep -qF -- "$2" "$1" && pass=$((pass+1)) || { echo "  FAIL has: $1 :: $2"; fail=$((fail+1)); }; }
hasnt() { grep -qF -- "$2" "$1" && { echo "  FAIL hasnt: $1 :: $2"; fail=$((fail+1)); } || pass=$((pass+1)); }

M=src/modules/menu
A=src/modules/antiddos/70-whitelist-main.sh

# BUG-008: flush delegates to the engine; engine deletes by -S numbers
has "$M/60-autoban-main.sh" '--flush-autobans'
has "$A" 'flush_autobans()'
has "$A" "nx_delete_matching INPUT '--comment \"auto-ban\"'"
hasnt "$M/60-autoban-main.sh" 'grep -q \x27"auto-ban"\x27'
# BUG-038: exact unban deletes + exact state edit, both programs.
# Since v3.7 the menu side lives in the shared nx_unban_ip (U-2);
# the guard follows it there and checks both screens delegate.
has "$A" 'awk -v x="$UIP"'
has "$M/05-ui.sh" 'awk -v x="$_ip"'
has "$M/05-ui.sh" 'nx_unban_ip()'
has "$M/50-antiddos-menu.sh" 'nx_unban_ip "$UIP"'
has "$M/40-security-services-system.sh" 'nx_unban_ip "$UIP"'
hasnt "$A" 'sed -i "/${UIP}/d"'
hasnt "$M/50-antiddos-menu.sh" 'sed -i "/$UIP/d"'
# BUG-041: cnt() helper exists and the double-zero pattern is gone
has "$M/00-header.sh" 'cnt()'
grep -rn 'grep -c .*|| echo 0' "$M" | grep -v '00-header.sh' >/dev/null && { echo "  FAIL: grep -c || echo 0 remains in menu"; fail=$((fail+1)); } || pass=$((pass+1))
# BUG-043: get_ip memoized
has "$M/00-header.sh" '_NX_IP_CACHE'
# BUG-044: no apt->yum fallthrough chain
hasnt "$M/40-security-services-system.sh" 'apt-get upgrade -y || yum'
# BUG-052: backup verified + credentials warning
has "$M/40-security-services-system.sh" 'tar -tzf "$BACKUP"'
has "$M/40-security-services-system.sh" 'includes proxy credentials'
# BUG-053: DDoS status probes the service, not just the state file
has "$M/60-autoban-main.sh" 'systemctl is-active auto-ban'
has "$M/60-autoban-main.sh" 'Installed (stopped)'
# BUG-051: banned list comes from the state file, not -L scraping
hasnt "$M/60-autoban-main.sh" 'iptables -L INPUT -n 2>/dev/null | grep DROP'

echo "wave8 regressions: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
