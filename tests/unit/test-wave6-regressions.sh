#!/usr/bin/env bash
# Wave 6 regression guards: 3proxy lifecycle & hardening (BUG-015/016/
# 018/025/026/035/037/044/059/060/061). These assert properties of the
# built installer and sources that must never regress.
set -uo pipefail
cd "$(dirname "$0")/../.."
pass=0; fail=0
has()     { grep -qF "$2" "$1" && pass=$((pass+1)) || { echo "  FAIL has: $1 :: $2"; fail=$((fail+1)); }; }
hasnt()   { grep -qF "$2" "$1" && { echo "  FAIL hasnt: $1 :: $2"; fail=$((fail+1)); } || pass=$((pass+1)); }

I=install.sh
U=src/modules/3proxy/50-uninstall.sh
N=src/modules/3proxy/40-install.sh
M=src/modules/3proxy/30-apt-mirror.sh

# BUG-018: dedicated user + sandbox
has "$I" 'User=nexoproxy'
has "$I" 'NoNewPrivileges=true'
has "$I" 'AmbientCapabilities=CAP_NET_BIND_SERVICE'
grep -qE '^User=root$' "$I" && { echo "  FAIL: a unit still runs as root"; fail=$((fail+1)); } || pass=$((pass+1))
# BUG-026: credentials preserved across reinstall
has "$N" 'Existing proxy credentials preserved'
# BUG-035: SSRF deny list includes 0.0.0.0/8
has "$N" 'deny * * 0.0.0.0/8'
# BUG-061: fail fast when no free port
has "$N" 'No free port found after 20 attempts'
# BUG-016: mirror opt-in + HTTPS candidates + uninstall restore
has "$N" 'NX_APT_MIRROR'
hasnt "$M" '"http://'
has "$U" 'sources.list.bak'
# BUG-037/015: uninstall never touches the Anti-DDoS daemon or its state
hasnt "$U" 'pkill -f "auto-ban.sh"'
hasnt "$U" 'rm -rf /etc/antiddos'
hasnt "$U" 'auto-ban.service'
# BUG-060: no global unban
hasnt "$I" 'fail2ban-client unban --all'
grep -vE '^\s*#' "$U" | grep -q -- 'unban --all' && { echo "  FAIL: unban --all in uninstall code"; fail=$((fail+1)); } || pass=$((pass+1))
# BUG-044: dnf preferred
has "$N" 'command -v dnf'
# BUG-025: staged writes + activation
has tools/build.py '.nxnew'
has src/installer/outro.sh 'previous install left untouched'
# BUG-059: no IPv6 socks URL
hasnt src/modules/3proxy/60-cli-menu.sh 'SERVER_IPV6'

echo "wave6 regressions: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
