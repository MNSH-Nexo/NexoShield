#!/usr/bin/env bash
# Regression guards for the 2026-10-23 live field test findings
# (docs/FIELD-TEST-2026-10-23.md):
#   T-1: fail2ban died silently on journal-only images (missing log
#        files) while the installer reported success.
#   T-2: the 3proxy-ddos jail pointed at access.log, but 3proxy writes
#        a daily-rotated access.log.YYYY.MM.DD - the jail was blind.
set -uo pipefail
cd "$(dirname "$0")/../.."
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
has() { grep -qF "$2" "$1" && ok || bad "missing in $1: $2"; }
hasnt() { grep -qF "$2" "$1" && bad "should NOT be in $1: $2" || ok; }

F=src/modules/antiddos/30-fail2ban.sh
C=src/modules/3proxy/60-cli-menu.sh

# T-2: jail follows the dated log via glob; no reader uses the bare name
has   "$F" 'logpath   = /var/log/3proxy/access.log.*'
grep -qE '^logpath   = /var/log/3proxy/access\.log$' "$F" \
    && bad "jail still points at the bare access.log" || ok
hasnt "$C" '"$PROXY_LOG_DIR/access.log"'

# T-1: log files ensured, journal fallback, conditional http-flood
has "$F" 'touch "$_lf"'
has "$F" 'journalmatch = _TRANSPORT=kernel'
has "$F" 'enabled   = ${HTTP_ENABLED}'
# T-1: verification, not assumption - config test + real service state
has "$F" 'fail2ban-client -t'
has "$F" 'systemctl is-active --quiet fail2ban'
has "$F" 'service is NOT running after apply'

# T-3: legacy-C retry for GCC >= 14 (3proxy 0.9.4 is pre-C23)
I=src/modules/3proxy/40-install.sh
has "$I" 'Wno-error=implicit-function-declaration'
has "$I" 'legacy-C compatibility flags'

echo "field fixes (T-1/T-2/T-3): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
