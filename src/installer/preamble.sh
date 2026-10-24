#!/bin/sh
exec bash <(tr -d '\r' < "$0" | tail -n +3) "$@"
#!/bin/bash
# ============================================================
#  Proxy Manager - Auto Installer  v@@VERSION@@
#  One file, one command, everything ready
#
#  Install:
#    bash install.sh
#
#  After install:
#    proxy
#
#  Changelog v3.0:
#    + Smart throttle+ban (watch->throttle->ban pipeline)
#    + tc bandwidth control (CF=unlimited, others=500Mbps)
#    + Full Cloudflare IP whitelist at every layer (no limits)
#    + Auto-detect server IPs, add to whitelist automatically
#    + Persistent tc rules via systemd + if-up.d
#    + conntrack tight timeouts (SYN=8s, UDP=15s, ICMP=5s)
#    + rp_filter auto-detect (multi-IP servers set to 0)
#    + Keepalive Slowloris mitigation (30s detect dead conns)
#    + fail2ban xray-proxy jail added
#    + iptables rule idempotency (no duplicate rules)
#    + Graceful error handling everywhere
#    + Log rotation for all logs
# ============================================================
set -euo pipefail

VERSION="@@VERSION@@"
INSTALL_DIR="/opt/proxy-manager"
BIN_LINK="/usr/local/bin/shield"
LOG="/var/log/proxy-manager-install.log"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; W='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

sep()  { echo -e "${C}════════════════════════════════════════════════${NC}"; }
ok()   { echo -e "  ${G}✓${NC}  $*"; echo "[OK] $*" >> "$LOG" 2>/dev/null || true; }
info() { echo -e "  ${C}->${NC}  $*"; echo "[INFO] $*" >> "$LOG" 2>/dev/null || true; }
err()  { echo -e "  ${R}✗${NC}  $*"; echo "[ERR] $*" >> "$LOG" 2>/dev/null || true; }
warn() { echo -e "  ${Y}⚠${NC}  $*"; echo "[WARN] $*" >> "$LOG" 2>/dev/null || true; }

# ─────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${R}Must be run as root: sudo bash $0${NC}"; exit 1
fi

clear 2>/dev/null || true
sep
echo -e "  ${C}${BOLD}Proxy Manager Installer v${VERSION}${NC}"
sep
echo ""
info "Install path: $INSTALL_DIR"
info "Command after install: ${W}proxy${NC}"
echo ""

mkdir -p "$INSTALL_DIR"

# ── Cloudflare IP ranges (single source of truth: src/data/cloudflare-ipv4.list) ──
CF_RANGES=(
@@CF_ENTRIES@@
)
mkdir -p /etc/antiddos
printf "%s\n" "${CF_RANGES[@]}" > /etc/antiddos/cloudflare-ipv4.list
# Pristine copy: the menu restores the runtime list from here if it is
# ever deleted/emptied, instead of fabricating one (see BUG-005).
mkdir -p "$INSTALL_DIR/data"
printf "%s\n" "${CF_RANGES[@]}" > "$INSTALL_DIR/data/cloudflare-ipv4.list"

# ── Cloudflare IPv6 ranges (single source: src/data/cloudflare-ipv6.list) ──
CF6_RANGES=(
@@CF6_ENTRIES@@
)
printf "%s\n" "${CF6_RANGES[@]}" > /etc/antiddos/cloudflare-ipv6.list
printf "%s\n" "${CF6_RANGES[@]}" > "$INSTALL_DIR/data/cloudflare-ipv6.list"

touch "$LOG" && chmod 600 "$LOG"

# ─────────────────────────────────────────────────────────
# Create files
# ─────────────────────────────────────────────────────────

info "Creating files..."

# ══════════════════════════════════════════════════════════
# File 1: 3proxy-socks5.sh
# ══════════════════════════════════════════════════════════
