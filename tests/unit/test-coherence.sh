#!/bin/bash
# Coherence suite (v3.14): pins the cross-layer invariants that
# silently drifted before - one value, one source of truth.
#  1. sysctl keys written by BOTH the optimizer and the Anti-DDoS
#     hardening must carry identical values (install order and
#     reboots must not change the machine's behaviour).
#  2. No user-facing string may claim the pre-v3.8 flat "4h" ban;
#     bans are progressive (30 min doubling to 7 days).
#  3. The SOCKS service has no per-service connection cap; the
#     per-IP port burst guard is a fixed 300 hits/60s.
#  4. Every nx_cfg key is read with ONE consistent fallback.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

AD="$ROOT/src/modules/antiddos/10-sysctl.sh"
OP="$ROOT/src/modules/sysctl/20-snapshot-config.sh"
val() { grep -oP "^$1 = \K.*" "$2" | head -1; }
for key in net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl \
           net.ipv4.tcp_keepalive_probes net.ipv4.tcp_fin_timeout \
           net.ipv4.tcp_syncookies net.ipv4.tcp_syn_retries \
           net.ipv4.tcp_synack_retries net.ipv4.tcp_tw_reuse \
           net.ipv4.tcp_max_tw_buckets net.ipv4.tcp_max_orphans; do
    A=$(val "$key" "$AD"); O=$(val "$key" "$OP")
    [ -n "$A" ] && [ "$A" = "$O" ] && ok || bad "sysctl $key: antiddos=$A optimizer=$O"
done
# syn backlog: optimizer is RAM-scaled with a 16384 floor; the
# hardening file must pin exactly that floor.
[ "$(val net.ipv4.tcp_max_syn_backlog "$AD")" = "16384" ] && ok || bad "antiddos syn_backlog != 16384 floor"
grep -q 'SYN_BACKLOG=16384' "$ROOT/src/modules/sysctl/10-detect.sh" && ok || bad "optimizer syn_backlog floor moved"

if grep -rn 'ban(4h)\|duration:4h\|"4 hours"' "$ROOT/src/modules" "$ROOT/src/installer" >/dev/null 2>&1; then
    bad "stale flat-4h ban claim in sources"
else
    ok
fi
grep -q 'progressive 30m-7d' "$ROOT/src/modules/antiddos/60-status-remove.sh" && ok || bad "status text not progressive"

# No per-service connection cap on the SOCKS proxy (operator
# decision: it may serve thousands of users; abuse is stopped
# per-IP by NexoShield's layers). The socks line carries no -n,
# no MAX_CONN variable exists outside MAX_TOTAL_CONN, and the
# per-IP port burst guard stays a fixed 300 hits/60s.
grep -q '^socks -p\$PORT -i0.0.0.0 -e0.0.0.0$' "$ROOT/src/modules/3proxy/40-install.sh" && ok || bad "socks line regained a connection cap"
[ "$(grep -o '\bMAX_CONN\b' "$ROOT/src/modules/3proxy/40-install.sh" | wc -l)" = "0" ] && ok || bad "a MAX_CONN cap variable is back"
grep -q -- '--hitcount 300 -j DROP' "$ROOT/src/modules/3proxy/20-iptables.sh" && ok || bad "per-IP port guard is not the fixed 300"

INCONS=$(grep -rhoP 'nx_cfg\s+\K[a-z_0-9]+\s+[^ )]+' "$ROOT/src" | sort | \
    awk '{d[$1]=d[$1]" "$2} END{c=0; for(k in d){n=split(d[k],a," "); for(i=2;i<=n;i++) if(a[i]!=a[1]) c++} print c}')
[ "$INCONS" = "0" ] && ok || bad "nx_cfg keys with inconsistent fallbacks: $INCONS"

# README version surfaces must match the VERSION file (this
# exact drift shipped silently in v3.13: badge/mock/credit
# stayed a release behind while every edit script reported OK).
RV=$(cat "$ROOT/VERSION")
grep -q "badge/Version-$RV-" "$ROOT/README.md" && ok || bad "README badge != VERSION ($RV)"
grep -q "NexoShield v$RV — Server Security Toolkit" "$ROOT/README.md" && ok || bad "README menu mock != VERSION ($RV)"
SHORT=$(echo "$RV" | cut -d. -f1,2)
grep -q "v3.5 → v$SHORT rebuild" "$ROOT/README.md" && ok || bad "README credit range != v$SHORT"

echo "coherence: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
