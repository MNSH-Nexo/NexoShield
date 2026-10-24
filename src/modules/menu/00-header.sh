# @part modules/menu/00-header.sh - Config, helpers, service probes, draw_header
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
#!/bin/bash
# shellcheck disable=SC2015,SC2094
# Reviewed idioms (Wave 10): SC2015 - `cond && ok-print || err-print`
# chains whose middle command is a print helper that cannot fail;
# SC2094 - atomic state writes via tmp-file + rename, which the
# checker flags as same-file pipelines. Both classes were audited
# site-by-site during the fix waves (docs/FIX-PLAN.md).
VERSION="@@VERSION@@"
INSTALL_DIR="/opt/proxy-manager"
_BSRC="${BASH_SOURCE[0]:-}"
if [ -n "$_BSRC" ] && [ "$_BSRC" != "/dev/stdin" ] && [[ "$_BSRC" != /dev/fd/* ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$_BSRC")" && pwd 2>/dev/null)" || SCRIPT_DIR="$INSTALL_DIR"
else
    SCRIPT_DIR="$INSTALL_DIR"
fi
# Verify scripts exist at detected path, fallback to hardcoded path
[ -f "$SCRIPT_DIR/3proxy-socks5.sh" ] || SCRIPT_DIR="$INSTALL_DIR"
PROXY_SCRIPT="$SCRIPT_DIR/3proxy-socks5.sh"
SYSCTL_SCRIPT="$SCRIPT_DIR/optimize-sysctl.sh"
ANTIDDOS_SCRIPT="$SCRIPT_DIR/antiddos.sh"

# BUG-019: every iptables call in this script takes the xtables lock with
# a 5s wait. The daemon, fail2ban and the menus mutate rules concurrently;
# without -w a contended call fails with "Resource temporarily
# unavailable" and the failure is usually swallowed by || true - rules
# silently never landed. (iptables-save/-restore are separate binaries
# and are not affected by this wrapper.)
iptables() { command iptables -w 5 "$@"; }
LOG_FILE="/var/log/proxy-manager.log"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
W='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

[ "$EUID" -ne 0 ] && echo -e "${R}Root required: sudo shield${NC}" && exit 1
touch "$LOG_FILE" 2>/dev/null && chmod 600 "$LOG_FILE" 2>/dev/null || true
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }
sep()  { echo -e "${C}════════════════════════════════════════════════${NC}"; }
sep2() { echo -e "${DIM}────────────────────────────────────────────────${NC}"; }
ok()   { echo -e "  ${G}✓${NC}  $*"; }
err()  { echo -e "  ${R}✗${NC}  $*"; }
warn() { echo -e "  ${Y}⚠${NC}  $*"; }
press_enter() { echo ""; printf '%s\n' "  Press Enter to go back..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; }

# cnt <pattern> <file> — a grep -c that always prints exactly ONE
# number (BUG-041: `grep -c ... || echo 0` prints "0" twice when grep
# exits 1 on no-match, corrupting counters and their arithmetic).
cnt() { local _n; _n=$(grep -c -- "$1" "$2" 2>/dev/null || true); echo "${_n:-0}"; }

svc_status() {
    case "$(systemctl is-active "$1" 2>/dev/null)" in
        active)   echo -e "${G}● Running${NC}" ;;
        inactive) echo -e "${R}○ Stopped${NC}" ;;
        failed)   echo -e "${R}✗ Failed${NC}" ;;
        *)        echo -e "${DIM}─ Not installed${NC}" ;;
    esac
}
svc_enabled() {
    systemctl is-enabled "$1" 2>/dev/null | grep -q "enabled" && \
        echo -e "${G}auto${NC}" || echo -e "${DIM}manual${NC}"
}
get_proxy_port() {
    grep -oP '(?<=socks -p)\s*\K\d+' /etc/3proxy/3proxy.cfg 2>/dev/null | head -1 || \
    grep -oP '(?<=socks5 -p)\s*\K\d+' /etc/3proxy/3proxy.cfg 2>/dev/null | head -1 || true
}
get_ip() {
    # Memoized (BUG-043): draw_header runs on every screen and used to
    # pay a fresh external curl (up to 4s) each time.
    [ -n "${_NX_IP_CACHE:-}" ] && { echo "$_NX_IP_CACHE"; return 0; }
    _NX_IP_CACHE=$(curl -s -4 --max-time 4 https://api.ipify.org 2>/dev/null || \
    ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127\.' | \
        head -1 | awk '{print $2}' | cut -d/ -f1 || echo "?")
    echo "$_NX_IP_CACHE"
}

draw_header() {
    clear 2>/dev/null || true
    echo -e "  ${C}${BOLD}NexoShield${NC} ${DIM}v${VERSION} — Server Security Toolkit${NC}"
    local PROXY_ST PROXY_PORT SERVER_IP LOAD MEM_PCT DISK_PCT DDOS_ST
    PROXY_ST=$(svc_status "3proxy")
    PROXY_PORT=$(get_proxy_port)
    SERVER_IP=$(get_ip)
    LOAD=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo "?")
    local _MEM_RAW; _MEM_RAW=$(free 2>/dev/null | awk '/Mem:/{if($2>0) printf "%.0f", $3/$2*100; else print 0}')
    MEM_PCT="${_MEM_RAW//[^0-9]/}"; MEM_PCT="${MEM_PCT:-0}"
    local _DISK_RAW; _DISK_RAW=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5+0}')
    DISK_PCT="${_DISK_RAW//[^0-9]/}"; DISK_PCT="${DISK_PCT:-0}"
    DDOS_ST="$([ -f /etc/antiddos/state.conf ] && echo "${G}●${NC}" || echo "${DIM}○${NC}")"
    echo ""
    echo -e "  ${DIM}IP:${NC} ${W}${SERVER_IP:-?}${NC}   ${DIM}3proxy:${NC} ${PROXY_ST}${PROXY_PORT:+   ${DIM}:${NC}${C}${PROXY_PORT}${NC}}   ${DIM}DDoS:${NC} $DDOS_ST"
    echo -e "  ${DIM}Load:${NC} ${W}${LOAD:-?}${NC}   ${DIM}RAM:${NC} ${W}${MEM_PCT:-?}%${NC}   ${DIM}Disk:${NC} $([ "${DISK_PCT:-0}" -ge 85 ] 2>/dev/null && echo "${R}${DISK_PCT}%${NC}" || echo "${W}${DISK_PCT:-?}%${NC}")"
    echo ""; sep2
}

# ── SOCKS5 Menu ───────────────────────────────────────────
