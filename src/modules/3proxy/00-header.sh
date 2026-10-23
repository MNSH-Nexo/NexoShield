# @part modules/3proxy/00-header.sh - Config, colours, Cloudflare + server-IP includes, small getters
# Assembled into 3proxy-socks5.sh by tools/build.py - not a standalone script.
#!/bin/bash
# ============================================================
#  3proxy SOCKS5 Manager
#  - Cloudflare IPs: ALWAYS unlimited (no connlimit, no rate)
#  - tc bandwidth: CF=unlimited, others=500Mbps
#  - Per-IP connlimit only for non-CF IPs
# ============================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
PROXY_BIN="/usr/local/bin/3proxy"
PROXY_CONF="/etc/3proxy/3proxy.cfg"
PROXY_USERS="/etc/3proxy/users.cfg"
PROXY_LOG_DIR="/var/log/3proxy"
SERVICE_FILE="/etc/systemd/system/3proxy.service"

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1

# @include lib/cloudflare-loader.sh

# @include lib/server-ips.sh

get_server_ip() {
    curl -s -4 --max-time 5 https://api.ipify.org 2>/dev/null || \
    curl -s -4 --max-time 5 https://ifconfig.me 2>/dev/null || \
    hostname -I 2>/dev/null | awk '{print $1}'
}

get_server_ipv6() { curl -s -6 --max-time 5 https://api64.ipify.org 2>/dev/null || true; }
get_current_port() { grep -oP '(?<=socks -p)\s*\K\d+' "$PROXY_CONF" 2>/dev/null | head -1 || true; }
is_installed() { [ -f "$PROXY_BIN" ] && [ -f "$SERVICE_FILE" ]; }
sep() { echo -e "${CYAN}════════════════════════════════════════════════${NC}"; }

# ── tc bandwidth control ─────────────────────────────────
# CF IPs → class 1:10 (unlimited)
# non-CF normal → class 1:20 (500Mbps)
# throttled IPs → class 1:30 (100Mbps)
