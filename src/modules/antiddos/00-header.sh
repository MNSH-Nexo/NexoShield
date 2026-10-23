# @part modules/antiddos/00-header.sh - Config, helpers, Cloudflare + server-IP includes
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
#!/bin/bash
# ============================================================
#  Anti-DDoS Protection Manager v@@VERSION@@
#
#  Layers:
#    1. Kernel (sysctl hardening + tight conntrack timeouts)
#    2. iptables (SYNPROXY / hashlimit / connlimit / scans)
#       *** CF IPs ALWAYS whitelisted — NO limits ***
#    3. fail2ban (3proxy-ddos / portscan / sshd / xray)
#    4. Smart throttle+ban (watch → throttle → ban pipeline)
#    5. tc bandwidth control (CF=unlimited, others=500Mbps)
#
#  Key lessons from production:
#    - CF IPs must be whitelisted BEFORE any rate-limit rule
#    - rp_filter=0 for servers with multiple public IPs
#    - SYN hashlimit must NOT apply to CF IPs
#    - tc must work on SRC IP (not DST), else tunnel breaks
#    - keepalive_time=30s detects dead connections fast (Slowloris)
#    - conntrack established=120s cleans dead conns quickly
#    - auto-ban: 120 active conns = watch, 300 conns = instant ban (4h)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_VERSION="@@VERSION@@"
LOG_FILE="/var/log/antiddos.log"
STATE_FILE="/etc/antiddos/state.conf"
BANNED_LIST="/etc/antiddos/banned.list"
F2B_FILTER_DIR="/etc/fail2ban/filter.d"
F2B_JAIL_DIR="/etc/fail2ban/jail.d"
SYSCTL_FILE="/etc/sysctl.d/98-antiddos-hardening.conf"
IPTABLES_SAVE_FILE="/etc/antiddos/iptables-antiddos.rules"
AUTOBAN_SCRIPT="/opt/proxy-manager/auto-ban.sh"
AUTOBAN_SERVICE="/etc/systemd/system/auto-ban.service"
WHITELIST_FILE="/etc/antiddos/whitelist.list"
SELF_IPS_FILE="/etc/antiddos/self-ips.list"
EXEMPT_FILE="/etc/antiddos/exempt.list"

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1


# BUG-019: every iptables call in this script takes the xtables lock with
# a 5s wait. The daemon, fail2ban and the menus mutate rules concurrently;
# without -w a contended call fails with "Resource temporarily
# unavailable" and the failure is usually swallowed by || true - rules
# silently never landed. (iptables-save/-restore are separate binaries
# and are not affected by this wrapper.)
iptables() { command iptables -w 5 "$@"; }

mkdir -p /etc/antiddos
touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
touch "$BANNED_LIST" && chmod 600 "$BANNED_LIST"

log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
info()    { echo -e "  ${CYAN}->${NC}  $*"; log "INFO: $*"; }
success() { echo -e "  ${GREEN}✓${NC}  $*"; log "OK: $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; log "WARN: $*"; }
err()     { echo -e "  ${RED}✗${NC}  $*"; log "ERR: $*"; }
sep()     { echo -e "${CYAN}════════════════════════════════════════════════${NC}"; }

# ── Cloudflare IP ranges (NEVER rate-limited) ─────────────
# @include lib/cloudflare-loader.sh

# Get all server's own public IPs (auto-whitelist)
# @include lib/server-ips.sh
# @include lib/self-ips.sh

# Detect environment
