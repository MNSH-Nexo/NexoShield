#!/usr/bin/env bash
# Source-level regression guards for Wave 3 (iptables correctness).
set -uo pipefail
cd "$(dirname "$0")/../.."

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

# BUG-019: the -w wrapper must exist in every assembled program that
# calls iptables (antiddos, autoban, 3proxy, menu) in install.sh.
N=$(grep -c 'iptables() { command iptables -w 5' install.sh || true)
[ "$N" -eq 4 ] && ok || bad "iptables -w wrapper count in install.sh = $N (want 4)"

# BUG-013/014: no stale asymmetric delete specs may remain.
grep -rn 'MAX_CONN \* 2' src/modules/3proxy/ >/dev/null && bad "legacy *2 hitcount delete remains" || ok
grep -n 'hitcount 60' src/modules/3proxy/50-uninstall.sh >/dev/null && bad "hardcoded hitcount 60 delete remains" || ok
grep -q '3proxy_cf_allow' src/modules/3proxy/20-iptables.sh && \
  [ "$(grep -c '3proxy_cf_allow' src/modules/3proxy/20-iptables.sh)" -ge 2 ] && ok || bad "setup CF delete lacks the comment match"
[ "$(grep -c '3proxy_cf_allow' src/modules/3proxy/50-uninstall.sh)" -ge 1 ] && ok || bad "uninstall CF delete lacks the comment match"

# BUG-002: inside apply_iptables, insert order in code must be
# ESTABLISHED accept, then bw_per_ip, then http_req_rate, and all three
# BEFORE the first cf_whitelist insert (inserts stack: later = higher).
APP=$(awk '/^apply_iptables\(\) \{/,/^\}/' install.sh)
L_EST=$(printf '%s\n' "$APP" | grep -n 'ipt_ins INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' | head -1 | cut -d: -f1)
L_BW=$(printf '%s\n' "$APP" | grep -n 'hashlimit-name bw_per_ip \\' | head -1 | cut -d: -f1)
L_HTTP=$(printf '%s\n' "$APP" | grep -n 'hashlimit-name http_req_rate' | head -1 | cut -d: -f1)
L_CF=$(printf '%s\n' "$APP" | grep -n 'cf_whitelist' | head -1 | cut -d: -f1)
if [ -n "$L_EST" ] && [ -n "$L_BW" ] && [ -n "$L_HTTP" ] && [ -n "$L_CF" ] && \
   [ "$L_EST" -lt "$L_BW" ] && [ "$L_BW" -lt "$L_HTTP" ] && [ "$L_HTTP" -lt "$L_CF" ]; then
    ok
else
    bad "BUG-002 insert order wrong (EST=$L_EST BW=$L_BW HTTP=$L_HTTP CF=$L_CF)"
fi

# http_req_rate / bw_per_ip must be inserts now, not appends.
printf '%s\n' "$APP" | grep -B6 'hashlimit-name http_req_rate' | grep -q 'ipt_ins' && ok || bad "http_req_rate is not inserted"
printf '%s\n' "$APP" | grep -B6 'hashlimit-name bw_per_ip \\' | grep -q 'ipt_ins' && ok || bad "bw_per_ip is not inserted"

# BUG-012: both persistence save sites use the static filter.
grep -q 'save_static_rules "$IPTABLES_SAVE_FILE"' src/modules/antiddos/20-iptables.sh && ok || bad "apply snapshot not filtered"
grep -q 'save_static_rules /etc/iptables/rules.v4' src/modules/antiddos/50-tc.sh && ok || bad "rules.v4 snapshot not filtered"

echo "wave3 regressions: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
