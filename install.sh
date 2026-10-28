#!/bin/sh
exec bash <(tr -d '\r' < "$0" | tail -n +3) "$@"
#!/bin/bash
# ── GENERATED FILE ─ built by tools/build.py from src/ ─ do not edit directly; edit the sources and rebuild ──
# ============================================================
#  Proxy Manager - Auto Installer  v3.19.0
#  One file, one command, everything ready
#
#  Install:
#    bash install.sh
#
#  After install:
#    shield
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

VERSION="3.19.0"
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

# ── Supported OS: Ubuntu 20.04+ and Debian 11+ ────────────
# Everything NexoShield installs (apt packages, systemd units,
# sysctl.d, iptables persistence) is distribution-identical on
# the two; Debian 12 was field-verified with v3.5.0. Anything
# else gets a clear stop here instead of half-failed apt calls
# deeper in (override with NX_FORCE_OS=1 if you must).
_NX_OS_ID=""
[ -r /etc/os-release ] && _NX_OS_ID=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
case "$_NX_OS_ID" in
    ubuntu|debian) ;;
    *)
        if [ "${NX_FORCE_OS:-0}" != "1" ]; then
            echo -e "${R}Unsupported OS: '${_NX_OS_ID:-unknown}' - NexoShield supports Ubuntu 20.04+ and Debian 11+.${NC}"
            echo -e "${R}Set NX_FORCE_OS=1 to try anyway (untested).${NC}"
            exit 1
        fi
        echo -e "${Y}Warning: untested OS '${_NX_OS_ID}' - continuing because NX_FORCE_OS=1.${NC}"
        ;;
esac

clear 2>/dev/null || true
sep
echo -e "  ${C}${BOLD}Proxy Manager Installer v${VERSION}${NC}"
sep
echo ""
info "Install path: $INSTALL_DIR"
info "Command after install: ${W}shield${NC}"
echo ""

mkdir -p "$INSTALL_DIR"

# ── Cloudflare IP ranges (single source of truth: src/data/cloudflare-ipv4.list) ──
CF_RANGES=(
    "1.0.0.0/24"
    "1.1.1.0/24"
    "5.10.214.0/23"
    "5.226.183.0/24"
    "5.252.81.0/24"
    "8.6.112.0/24"
    "8.20.122.0/24"
    "8.20.125.0/24"
    "8.21.9.0/24"
    "8.21.10.0/24"
    "8.21.111.0/24"
    "8.23.139.0/24"
    "8.24.87.0/24"
    "8.25.97.0/24"
    "8.27.64.0/24"
    "8.27.66.0/23"
    "8.27.68.0/24"
    "8.29.109.0/24"
    "8.29.228.0/24"
    "8.29.230.0/23"
    "8.31.160.0/23"
    "8.34.70.0/23"
    "8.34.146.0/24"
    "8.35.211.0/24"
    "8.37.43.0/24"
    "8.39.125.0/24"
    "8.39.204.0/24"
    "8.39.214.0/24"
    "8.44.2.0/24"
    "8.44.60.0/23"
    "8.47.13.0/24"
    "8.47.69.0/24"
    "23.131.204.0/24"
    "23.227.37.0/24"
    "23.227.38.0/23"
    "23.227.48.0/23"
    "23.227.60.0/24"
    "31.185.108.0/24"
    "37.153.170.0/23"
    "38.96.28.0/23"
    "43.228.232.0/23"
    "43.230.112.0/23"
    "43.230.114.0/24"
    "45.12.44.0/23"
    "45.45.255.0/24"
    "45.128.76.0/24"
    "45.130.125.0/24"
    "45.146.130.0/24"
    "45.148.100.0/24"
    "45.157.17.0/24"
    "45.192.223.0/24"
    "45.192.224.0/24"
    "45.195.14.0/24"
    "45.195.153.0/24"
    "45.196.29.0/24"
    "45.198.114.0/24"
    "45.198.116.0/24"
    "45.199.183.0/24"
    "45.199.188.0/24"
    "45.250.154.0/23"
    "49.238.236.0/22"
    "51.194.144.0/22"
    "51.241.128.0/23"
    "57.250.49.0/24"
    "61.32.240.0/24"
    "61.245.108.0/24"
    "62.146.255.0/24"
    "64.8.255.0/24"
    "64.40.138.0/24"
    "64.40.140.0/24"
    "64.239.31.0/24"
    "65.110.63.0/24"
    "66.71.220.0/24"
    "66.80.5.0/24"
    "66.84.82.0/24"
    "66.92.62.0/24"
    "66.93.178.0/24"
    "66.203.249.0/24"
    "66.235.200.0/24"
    "66.242.60.0/23"
    "68.182.187.0/24"
    "69.90.210.0/24"
    "74.1.17.0/24"
    "77.73.113.0/24"
    "78.128.122.0/24"
    "80.240.93.0/24"
    "82.21.82.0/24"
    "82.22.16.0/24"
    "82.25.20.0/24"
    "82.26.156.0/24"
    "82.139.216.0/23"
    "88.216.69.0/24"
    "89.46.251.0/24"
    "89.106.90.0/24"
    "89.249.200.0/24"
    "91.206.71.0/24"
    "91.213.221.0/24"
    "91.224.186.0/24"
    "91.234.202.0/24"
    "92.8.0.0/15"
    "92.44.1.0/24"
    "94.156.10.0/24"
    "96.43.100.0/23"
    "98.98.234.0/24"
    "103.21.244.0/24"
    "103.22.200.0/23"
    "103.22.203.0/24"
    "103.31.4.0/24"
    "103.31.79.0/24"
    "103.50.96.0/23"
    "103.51.12.0/23"
    "103.54.128.0/23"
    "103.81.228.0/24"
    "103.186.74.0/24"
    "103.198.92.0/24"
    "103.215.22.0/24"
    "103.219.64.0/22"
    "104.16.0.0/14"
    "104.20.0.0/15"
    "104.22.0.0/22"
    "104.22.4.0/24"
    "104.22.7.0/24"
    "104.22.8.0/21"
    "104.22.16.0/21"
    "104.22.24.0/23"
    "104.22.26.0/24"
    "104.22.31.0/24"
    "104.22.32.0/22"
    "104.22.42.0/23"
    "104.22.44.0/22"
    "104.22.48.0/22"
    "104.22.52.0/24"
    "104.22.56.0/23"
    "104.22.58.0/24"
    "104.22.60.0/22"
    "104.22.64.0/22"
    "104.22.69.0/24"
    "104.22.70.0/23"
    "104.22.72.0/23"
    "104.22.78.0/23"
    "104.22.83.0/24"
    "104.22.84.0/22"
    "104.22.88.0/22"
    "104.22.93.0/24"
    "104.22.94.0/24"
    "104.22.97.0/24"
    "104.22.98.0/23"
    "104.22.100.0/22"
    "104.22.104.0/21"
    "104.22.112.0/21"
    "104.22.120.0/24"
    "104.22.123.0/24"
    "104.22.124.0/22"
    "104.22.128.0/23"
    "104.22.131.0/24"
    "104.22.132.0/23"
    "104.22.134.0/24"
    "104.22.136.0/21"
    "104.22.144.0/24"
    "104.22.146.0/24"
    "104.22.148.0/23"
    "104.22.150.0/24"
    "104.22.152.0/21"
    "104.22.160.0/23"
    "104.22.162.0/24"
    "104.22.165.0/24"
    "104.22.167.0/24"
    "104.22.168.0/22"
    "104.22.172.0/23"
    "104.22.174.0/24"
    "104.22.176.0/20"
    "104.22.192.0/19"
    "104.22.224.0/20"
    "104.23.96.0/19"
    "104.23.128.0/18"
    "104.23.194.0/23"
    "104.23.196.0/22"
    "104.23.201.0/24"
    "104.23.202.0/23"
    "104.23.204.0/24"
    "104.23.206.0/23"
    "104.23.208.0/20"
    "104.23.224.0/19"
    "104.24.0.0/13"
    "104.156.176.0/23"
    "104.233.58.0/24"
    "104.234.133.0/24"
    "104.239.29.0/24"
    "104.239.89.0/24"
    "104.243.192.0/24"
    "104.244.236.0/23"
    "104.249.18.0/24"
    "104.249.43.0/24"
    "108.162.192.0/20"
    "108.162.208.0/24"
    "108.162.210.0/23"
    "108.162.212.0/22"
    "108.162.216.0/21"
    "108.162.224.0/19"
    "109.234.211.0/24"
    "123.108.75.0/24"
    "123.253.173.0/24"
    "123.253.174.0/24"
    "131.0.72.0/22"
    "131.167.255.0/24"
    "137.66.96.0/24"
    "138.226.212.0/23"
    "138.226.234.0/24"
    "138.249.21.0/24"
    "138.249.126.0/24"
    "138.249.148.0/24"
    "140.233.180.0/24"
    "141.101.65.0/24"
    "141.101.66.0/23"
    "141.101.68.0/22"
    "141.101.72.0/22"
    "141.101.76.0/23"
    "141.101.82.0/23"
    "141.101.84.0/22"
    "141.101.90.0/24"
    "141.101.93.0/24"
    "141.101.94.0/23"
    "141.101.96.0/22"
    "141.101.100.0/24"
    "141.101.104.0/23"
    "141.101.109.0/24"
    "141.101.110.0/24"
    "141.101.112.0/20"
    "143.14.142.0/24"
    "143.14.224.0/24"
    "143.14.251.0/24"
    "144.124.208.0/24"
    "144.124.211.0/24"
    "144.124.212.0/24"
    "144.124.214.0/23"
    "144.208.122.0/24"
    "145.63.64.0/24"
    "145.224.255.0/24"
    "146.19.108.0/24"
    "147.189.42.0/23"
    "148.227.167.0/24"
    "150.48.128.0/18"
    "151.243.133.0/24"
    "151.245.127.0/24"
    "151.246.216.0/23"
    "152.114.0.0/17"
    "152.114.128.0/18"
    "154.46.20.0/24"
    "154.81.141.0/24"
    "154.193.133.0/24"
    "154.193.184.0/24"
    "154.200.89.0/24"
    "154.223.134.0/23"
    "155.117.208.0/23"
    "156.11.149.0/24"
    "156.70.60.0/24"
    "156.71.149.0/24"
    "156.224.73.0/24"
    "156.243.83.0/24"
    "156.246.69.0/24"
    "156.246.70.0/24"
    "157.96.22.0/24"
    "158.94.212.0/24"
    "159.242.242.0/24"
    "161.115.162.0/24"
    "161.248.134.0/23"
    "162.44.104.0/22"
    "162.158.0.0/21"
    "162.158.8.0/24"
    "162.158.10.0/23"
    "162.158.12.0/22"
    "162.158.16.0/20"
    "162.158.32.0/23"
    "162.158.35.0/24"
    "162.158.36.0/22"
    "162.158.40.0/22"
    "162.158.44.0/24"
    "162.158.47.0/24"
    "162.158.48.0/21"
    "162.158.56.0/24"
    "162.158.59.0/24"
    "162.158.61.0/24"
    "162.158.62.0/23"
    "162.158.65.0/24"
    "162.158.66.0/23"
    "162.158.68.0/23"
    "162.158.70.0/24"
    "162.158.73.0/24"
    "162.158.74.0/23"
    "162.158.76.0/22"
    "162.158.82.0/23"
    "162.158.84.0/22"
    "162.158.88.0/21"
    "162.158.97.0/24"
    "162.158.99.0/24"
    "162.158.100.0/22"
    "162.158.104.0/21"
    "162.158.112.0/20"
    "162.158.129.0/24"
    "162.158.130.0/23"
    "162.158.132.0/22"
    "162.158.137.0/24"
    "162.158.138.0/23"
    "162.158.140.0/23"
    "162.158.142.0/24"
    "162.158.144.0/23"
    "162.158.146.0/24"
    "162.158.148.0/23"
    "162.158.150.0/24"
    "162.158.152.0/21"
    "162.158.160.0/20"
    "162.158.176.0/24"
    "162.158.178.0/23"
    "162.158.180.0/22"
    "162.158.184.0/21"
    "162.158.193.0/24"
    "162.158.195.0/24"
    "162.158.196.0/22"
    "162.158.200.0/22"
    "162.158.207.0/24"
    "162.158.208.0/20"
    "162.158.224.0/22"
    "162.158.228.0/23"
    "162.158.230.0/24"
    "162.158.232.0/21"
    "162.158.240.0/21"
    "162.158.250.0/23"
    "162.158.254.0/24"
    "162.159.0.0/18"
    "162.159.64.0/20"
    "162.159.80.0/23"
    "162.159.83.0/24"
    "162.159.84.0/22"
    "162.159.88.0/21"
    "162.159.96.0/22"
    "162.159.100.0/23"
    "162.159.102.0/24"
    "162.159.104.0/21"
    "162.159.112.0/21"
    "162.159.120.0/22"
    "162.159.124.0/23"
    "162.159.126.0/24"
    "162.159.128.0/18"
    "162.159.192.0/21"
    "162.159.200.0/22"
    "162.159.205.0/24"
    "162.159.206.0/23"
    "162.159.208.0/20"
    "162.159.224.0/19"
    "162.251.82.0/24"
    "162.251.205.0/24"
    "165.101.60.0/23"
    "166.88.240.0/24"
    "167.1.137.0/24"
    "167.74.92.0/22"
    "167.74.130.0/24"
    "167.74.142.0/23"
    "168.151.31.0/24"
    "168.183.3.0/24"
    "169.40.40.0/23"
    "169.40.133.0/24"
    "170.168.7.0/24"
    "170.176.163.0/24"
    "172.64.0.0/17"
    "172.64.128.0/18"
    "172.64.192.0/22"
    "172.64.197.0/24"
    "172.64.198.0/23"
    "172.64.200.0/23"
    "172.64.203.0/24"
    "172.64.205.0/24"
    "172.64.206.0/23"
    "172.64.208.0/20"
    "172.64.224.0/19"
    "172.65.0.0/16"
    "172.66.0.0/15"
    "172.68.0.0/22"
    "172.68.4.0/24"
    "172.68.6.0/23"
    "172.68.8.0/23"
    "172.68.10.0/24"
    "172.68.12.0/22"
    "172.68.16.0/20"
    "172.68.32.0/22"
    "172.68.36.0/24"
    "172.68.38.0/23"
    "172.68.41.0/24"
    "172.68.42.0/23"
    "172.68.46.0/24"
    "172.68.48.0/21"
    "172.68.56.0/24"
    "172.68.58.0/24"
    "172.68.60.0/22"
    "172.68.64.0/24"
    "172.68.67.0/24"
    "172.68.68.0/22"
    "172.68.72.0/23"
    "172.68.74.0/24"
    "172.68.76.0/23"
    "172.68.79.0/24"
    "172.68.80.0/24"
    "172.68.82.0/23"
    "172.68.84.0/22"
    "172.68.88.0/23"
    "172.68.90.0/24"
    "172.68.92.0/23"
    "172.68.96.0/23"
    "172.68.99.0/24"
    "172.68.100.0/22"
    "172.68.105.0/24"
    "172.68.107.0/24"
    "172.68.108.0/22"
    "172.68.113.0/24"
    "172.68.114.0/23"
    "172.68.116.0/22"
    "172.68.120.0/24"
    "172.68.122.0/23"
    "172.68.126.0/23"
    "172.68.129.0/24"
    "172.68.130.0/24"
    "172.68.133.0/24"
    "172.68.134.0/23"
    "172.68.138.0/23"
    "172.68.142.0/24"
    "172.68.144.0/24"
    "172.68.146.0/23"
    "172.68.148.0/22"
    "172.68.152.0/22"
    "172.68.159.0/24"
    "172.68.161.0/24"
    "172.68.164.0/22"
    "172.68.168.0/24"
    "172.68.170.0/24"
    "172.68.172.0/22"
    "172.68.176.0/21"
    "172.68.184.0/22"
    "172.68.188.0/24"
    "172.68.191.0/24"
    "172.68.192.0/22"
    "172.68.196.0/24"
    "172.68.198.0/23"
    "172.68.202.0/24"
    "172.68.204.0/22"
    "172.68.208.0/21"
    "172.68.217.0/24"
    "172.68.219.0/24"
    "172.68.220.0/24"
    "172.68.222.0/23"
    "172.68.224.0/22"
    "172.68.228.0/23"
    "172.68.230.0/24"
    "172.68.234.0/23"
    "172.68.236.0/22"
    "172.68.242.0/23"
    "172.68.244.0/22"
    "172.68.248.0/23"
    "172.68.251.0/24"
    "172.68.252.0/24"
    "172.68.255.0/24"
    "172.69.0.0/21"
    "172.69.8.0/22"
    "172.69.12.0/24"
    "172.69.15.0/24"
    "172.69.17.0/24"
    "172.69.19.0/24"
    "172.69.21.0/24"
    "172.69.22.0/23"
    "172.69.32.0/22"
    "172.69.38.0/23"
    "172.69.40.0/24"
    "172.69.42.0/23"
    "172.69.44.0/24"
    "172.69.46.0/24"
    "172.69.48.0/22"
    "172.69.56.0/22"
    "172.69.60.0/24"
    "172.69.62.0/23"
    "172.69.64.0/21"
    "172.69.72.0/24"
    "172.69.74.0/23"
    "172.69.79.0/24"
    "172.69.80.0/24"
    "172.69.82.0/23"
    "172.69.86.0/23"
    "172.69.88.0/24"
    "172.69.90.0/23"
    "172.69.93.0/24"
    "172.69.94.0/23"
    "172.69.96.0/22"
    "172.69.101.0/24"
    "172.69.102.0/23"
    "172.69.104.0/23"
    "172.69.108.0/22"
    "172.69.112.0/23"
    "172.69.114.0/24"
    "172.69.116.0/22"
    "172.69.120.0/22"
    "172.69.125.0/24"
    "172.69.127.0/24"
    "172.69.128.0/21"
    "172.69.136.0/22"
    "172.69.140.0/23"
    "172.69.143.0/24"
    "172.69.144.0/23"
    "172.69.147.0/24"
    "172.69.148.0/22"
    "172.69.152.0/22"
    "172.69.156.0/24"
    "172.69.158.0/24"
    "172.69.160.0/24"
    "172.69.162.0/24"
    "172.69.164.0/22"
    "172.69.168.0/23"
    "172.69.171.0/24"
    "172.69.172.0/24"
    "172.69.174.0/23"
    "172.69.176.0/22"
    "172.69.180.0/23"
    "172.69.182.0/24"
    "172.69.184.0/24"
    "172.69.186.0/23"
    "172.69.188.0/22"
    "172.69.192.0/22"
    "172.69.196.0/23"
    "172.69.199.0/24"
    "172.69.200.0/22"
    "172.69.206.0/23"
    "172.69.208.0/23"
    "172.69.211.0/24"
    "172.69.212.0/22"
    "172.69.216.0/23"
    "172.69.219.0/24"
    "172.69.220.0/22"
    "172.69.224.0/22"
    "172.69.228.0/23"
    "172.69.232.0/22"
    "172.69.236.0/24"
    "172.69.238.0/23"
    "172.69.241.0/24"
    "172.69.245.0/24"
    "172.69.246.0/23"
    "172.69.248.0/22"
    "172.69.253.0/24"
    "172.69.255.0/24"
    "172.70.32.0/20"
    "172.70.48.0/21"
    "172.70.56.0/24"
    "172.70.58.0/23"
    "172.70.60.0/23"
    "172.70.72.0/21"
    "172.70.80.0/21"
    "172.70.88.0/22"
    "172.70.92.0/23"
    "172.70.94.0/24"
    "172.70.96.0/21"
    "172.70.105.0/24"
    "172.70.107.0/24"
    "172.70.108.0/22"
    "172.70.112.0/22"
    "172.70.118.0/23"
    "172.70.120.0/21"
    "172.70.128.0/20"
    "172.70.144.0/21"
    "172.70.152.0/24"
    "172.70.154.0/23"
    "172.70.156.0/22"
    "172.70.160.0/20"
    "172.70.176.0/21"
    "172.70.184.0/23"
    "172.70.187.0/24"
    "172.70.188.0/23"
    "172.70.191.0/24"
    "172.70.192.0/24"
    "172.70.194.0/24"
    "172.70.196.0/23"
    "172.70.199.0/24"
    "172.70.201.0/24"
    "172.70.202.0/23"
    "172.70.204.0/22"
    "172.70.208.0/20"
    "172.70.225.0/24"
    "172.70.228.0/22"
    "172.70.232.0/21"
    "172.70.240.0/20"
    "172.71.1.0/24"
    "172.71.3.0/24"
    "172.71.4.0/22"
    "172.71.8.0/22"
    "172.71.14.0/23"
    "172.71.16.0/23"
    "172.71.20.0/22"
    "172.71.24.0/24"
    "172.71.26.0/23"
    "172.71.28.0/22"
    "172.71.81.0/24"
    "172.71.82.0/23"
    "172.71.88.0/23"
    "172.71.90.0/24"
    "172.71.93.0/24"
    "172.71.94.0/23"
    "172.71.97.0/24"
    "172.71.98.0/23"
    "172.71.100.0/22"
    "172.71.104.0/21"
    "172.71.113.0/24"
    "172.71.114.0/23"
    "172.71.116.0/22"
    "172.71.120.0/21"
    "172.71.128.0/21"
    "172.71.140.0/22"
    "172.71.144.0/20"
    "172.71.160.0/24"
    "172.71.164.0/22"
    "172.71.168.0/21"
    "172.71.176.0/21"
    "172.71.184.0/23"
    "172.71.187.0/24"
    "172.71.189.0/24"
    "172.71.190.0/23"
    "172.71.192.0/21"
    "172.71.200.0/22"
    "172.71.205.0/24"
    "172.71.206.0/23"
    "172.71.208.0/21"
    "172.71.216.0/22"
    "172.71.221.0/24"
    "172.71.222.0/23"
    "172.71.224.0/24"
    "172.71.228.0/24"
    "172.71.232.0/21"
    "172.71.240.0/20"
    "173.0.92.0/24"
    "173.245.48.0/20"
    "176.103.113.0/24"
    "178.83.176.0/24"
    "178.94.249.0/24"
    "181.215.196.0/24"
    "182.23.210.0/24"
    "185.7.240.0/24"
    "185.18.184.0/24"
    "185.29.76.0/24"
    "185.38.25.0/24"
    "185.41.148.0/24"
    "185.60.251.0/24"
    "185.132.85.0/24"
    "185.132.86.0/24"
    "185.133.172.0/24"
    "185.146.172.0/23"
    "185.148.181.0/24"
    "185.149.135.0/24"
    "185.156.19.0/24"
    "185.158.133.0/24"
    "185.178.196.0/22"
    "185.229.206.0/24"
    "188.42.98.0/24"
    "188.95.12.0/24"
    "188.114.96.0/22"
    "188.114.100.0/24"
    "188.114.102.0/23"
    "188.114.106.0/23"
    "188.114.108.0/24"
    "188.114.111.0/24"
    "190.93.240.0/20"
    "191.101.212.0/22"
    "192.71.82.0/24"
    "192.86.150.0/24"
    "192.103.56.0/24"
    "193.8.231.0/24"
    "193.8.237.0/24"
    "193.118.171.0/24"
    "193.135.43.0/24"
    "193.135.44.0/24"
    "193.202.90.0/24"
    "193.202.112.0/24"
    "194.34.64.0/22"
    "194.34.70.0/23"
    "194.34.76.0/24"
    "194.34.78.0/23"
    "194.34.80.0/24"
    "194.34.82.0/23"
    "194.34.84.0/22"
    "194.34.88.0/22"
    "194.34.93.0/24"
    "194.41.114.0/24"
    "194.77.235.0/24"
    "194.152.130.0/24"
    "195.66.29.0/24"
    "195.216.190.0/24"
    "195.242.122.0/23"
    "197.234.240.0/22"
    "198.41.129.0/24"
    "198.41.130.0/23"
    "198.41.132.0/22"
    "198.41.136.0/22"
    "198.41.140.0/23"
    "198.41.142.0/24"
    "198.41.149.0/24"
    "198.41.151.0/24"
    "198.41.152.0/21"
    "198.41.160.0/19"
    "198.41.192.0/19"
    "198.41.224.0/20"
    "198.41.240.0/23"
    "198.41.242.0/24"
    "198.41.244.0/24"
    "198.41.254.0/24"
    "198.148.174.0/24"
    "198.217.251.0/24"
    "198.252.206.0/24"
    "199.27.128.0/21"
    "199.65.62.0/24"
    "199.68.16.0/22"
    "202.27.69.0/24"
    "202.49.114.0/24"
    "203.5.33.0/24"
    "203.15.65.0/24"
    "203.117.53.0/24"
    "203.120.52.0/24"
    "203.168.192.0/20"
    "204.4.235.0/24"
    "204.69.207.0/24"
    "204.153.16.0/24"
    "204.195.192.0/18"
    "205.203.78.0/24"
    "206.206.104.0/24"
    "207.57.150.0/23"
    "207.89.22.0/23"
    "207.207.209.0/24"
    "207.241.180.0/24"
    "208.88.71.0/24"
    "208.184.1.0/24"
    "208.185.162.0/24"
    "209.55.226.0/24"
    "209.55.232.0/24"
    "209.55.234.0/24"
    "209.55.246.0/23"
    "209.55.253.0/24"
    "209.55.254.0/24"
    "209.172.5.0/24"
    "209.236.210.0/24"
    "210.1.232.0/23"
    "211.188.26.0/23"
    "212.6.39.0/24"
    "212.104.128.0/24"
    "216.19.107.0/24"
    "216.74.106.0/24"
    "216.132.75.0/24"
    "216.163.179.0/24"
    "216.183.79.0/24"
    "216.224.121.0/24"
    "217.180.16.0/23"
    "218.33.92.0/22"
    "222.167.32.0/22"
)
mkdir -p /etc/antiddos
printf "%s\n" "${CF_RANGES[@]}" > /etc/antiddos/cloudflare-ipv4.list
# Pristine copy: the menu restores the runtime list from here if it is
# ever deleted/emptied, instead of fabricating one (see BUG-005).
mkdir -p "$INSTALL_DIR/data"
printf "%s\n" "${CF_RANGES[@]}" > "$INSTALL_DIR/data/cloudflare-ipv4.list"

# ── Cloudflare IPv6 ranges (single source: src/data/cloudflare-ipv6.list) ──
CF6_RANGES=(
    "2400:cb00::/32"
    "2606:4700::/32"
    "2803:f800::/32"
    "2405:b500::/32"
    "2405:8100::/32"
    "2a06:98c0::/29"
    "2c0f:f8b0::/32"
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
cat > "$INSTALL_DIR/.3proxy-socks5.sh.nxnew" << 'PROXY_SCRIPT'
#!/bin/bash
# shellcheck disable=SC2015,SC2094
# Reviewed idioms (Wave 10): SC2015 - `cond && ok-print || err-print`
# chains whose middle command is a print helper that cannot fail;
# SC2094 - atomic state writes via tmp-file + rename, which the
# checker flags as same-file pipelines. Both classes were audited
# site-by-site during the fix waves (docs/FIX-PLAN.md).
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

# BUG-019: every iptables call in this script takes the xtables lock with
# a 5s wait. The daemon, fail2ban and the menus mutate rules concurrently;
# without -w a contended call fails with "Resource temporarily
# unavailable" and the failure is usually swallowed by || true - rules
# silently never landed. (iptables-save/-restore are separate binaries
# and are not affected by this wrapper.)
iptables() { command iptables -w 5 "$@"; }
PROXY_USERS="/etc/3proxy/users.cfg"
PROXY_LOG_DIR="/var/log/3proxy"
SERVICE_FILE="/etc/systemd/system/3proxy.service"

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1

# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi

# (intentionally empty: the only function this lib held was removed - see above)
list_self_ips() {
    { ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+'
      hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    } | sort -u | grep -v '^$'
}

# list_self_ips6 - every local IPv6 address (incl. ::1), one per line.
list_self_ips6() {
    { ip -6 addr show 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+'
      echo "::1"
    } | sort -u | grep -v '^$'
}

# ── Public-IP discovery for NAT / cloud servers ─────────────────
# On cloud VMs (Azure, most NAT setups) the server's public IPv4
# exists only in the provider's NAT - it is on NO interface, so
# list_self_ips can never see it, yet it is unmistakably one of the
# server's own addresses (FR-2). Discovery asks the cloud metadata
# service (link-local, no internet involved); only when no metadata
# service answers does it fall back to an external echo service.
# Every candidate passes nx_is_public_ipv4: metadata/echo replies
# are untrusted input, and a private/documentation/garbage answer
# must never widen the immune set.
NX_PUBLIC_IPS_FILE="${NX_PUBLIC_IPS_FILE:-/etc/antiddos/public-ips.list}"

nx_is_public_ipv4() {
    local ip="${1:-}" o1 o2 o3 o4 extra _o
    case "$ip" in *[!0-9.]*) return 1 ;; esac
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for _o in "$o1" "$o2" "$o3" "$o4"; do
        case "$_o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_o}" -le 3 ] || return 1
        (( 10#$_o <= 255 )) || return 1
    done
    case "$o1" in
        0|10|127) return 1 ;;
        100) [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 1 ;;
        169) [ "$o2" = 254 ] && return 1 ;;
        172) [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 1 ;;
        192) [ "$o2" = 168 ] && return 1
             { [ "$o2" = 0 ] && { [ "$o3" = 0 ] || [ "$o3" = 2 ]; }; } && return 1 ;;
        198) case "$o2" in 18|19|51) return 1 ;; esac ;;
        203) { [ "$o2" = 0 ] && [ "$o3" = 113 ]; } && return 1 ;;
    esac
    [ "$o1" -ge 224 ] && return 1
    return 0
}

nx_metadata_public_ips() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _tok _base="http://169.254.169.254"
    # Azure IMDS (first two addresses on the primary NIC)
    for _idx in 0 1; do
        _ip=$(curl -s -m 2 -H "Metadata: true" \
            "$_base/metadata/instance/network/interface/0/ipv4/ipAddress/$_idx/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
        nx_is_public_ipv4 "$_ip" && echo "$_ip"
    done
    # AWS EC2 IMDS (token first, plain fallback)
    _tok=$(curl -s -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "$_base/latest/api/token" 2>/dev/null)
    if [ -n "$_tok" ]; then
        _ip=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $_tok" \
            "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    else
        _ip=$(curl -s -m 2 "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    fi
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # GCP
    _ip=$(curl -s -m 2 -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # DigitalOcean
    _ip=$(curl -s -m 2 "$_base/metadata/v1/interfaces/public/0/ipv4/address" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # Hetzner Cloud
    _ip=$(curl -s -m 2 "$_base/hetzner/v1/metadata/public-ipv4" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    return 0
}

nx_external_public_ip() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _url
    for _url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me/ip"; do
        _ip=$(curl -s -m 3 "$_url" 2>/dev/null | tr -d ' \r\n')
        nx_is_public_ipv4 "$_ip" && { echo "$_ip"; return 0; }
    done
    return 0
}

# Echo the server's public IPv4s that are NOT on any interface
# (metadata first; external echo only as a last resort).
discover_public_ips() {
    local _found _ip
    _found=$(nx_metadata_public_ips | sort -u)
    [ -z "$_found" ] && _found=$(nx_external_public_ip)
    for _ip in $_found; do
        list_self_ips | grep -qxF "$_ip" || echo "$_ip"
    done
}

# Refresh the cache file; a failed/empty discovery NEVER wipes a
# previously discovered set (an offline reinstall must not disarm
# the immunity). Prints the discovered addresses when any exist.
nx_refresh_public_ips_cache() {
    local _found
    _found=$(discover_public_ips)
    if [ -n "$_found" ]; then
        mkdir -p "$(dirname "$NX_PUBLIC_IPS_FILE")" 2>/dev/null || true
        printf '%s\n' "$_found" > "$NX_PUBLIC_IPS_FILE.tmp" 2>/dev/null && \
            mv "$NX_PUBLIC_IPS_FILE.tmp" "$NX_PUBLIC_IPS_FILE" 2>/dev/null || true
        printf '%s\n' "$_found"
    elif [ -f "$NX_PUBLIC_IPS_FILE" ]; then
        cat "$NX_PUBLIC_IPS_FILE"
    fi
}

# list_self_ips_all - interface addresses PLUS the cached
# discovered public IPs. This is the feed every enforcement layer
# uses for "the server's own addresses" (FR-2 complete: local,
# private, secondary AND NAT-public).
list_self_ips_all() {
    { list_self_ips
      if [ -r "$NX_PUBLIC_IPS_FILE" ]; then
          grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$NX_PUBLIC_IPS_FILE" 2>/dev/null
      fi
    } | sort -u | grep -v '^$'
}
# nx_install_binary SRC DEST [MODE]
# Atomically replace DEST with SRC: copy to a staging file in the
# SAME directory, then rename over DEST. A plain `cp` onto a
# RUNNING executable fails with ETXTBSY ("Text file busy") - this
# broke 3proxy Install/Update on every live server (v3.16.0 field
# report: the service runs from /usr/local/bin/3proxy while the
# update tried to overwrite that very file). rename(2) swaps the
# path instantly; the running process keeps its old inode and is
# undisturbed until its service restarts onto the new binary.
nx_install_binary() {
    local src="$1" dst="$2" mode="${3:-755}" tmp
    tmp="${dst}.new.$$"
    if cp "$src" "$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$dst"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}
# A counting rule has no -j target: it counts only packets that
# REACH it. Any ACCEPT above it (an antiddos -I insert, or a
# third-party firewall's blanket rule) shadows it, so a counter
# that is merely inserted once silently undercounts. Field report
# v3.16.3: stats_in buried at INPUT #811 below the ESTABLISHED
# accept counted SYNs only (282 pkts / 14 KB while the interface
# moved ~515 MB); stats_out below a blanket OUTPUT accept counted
# exactly zero. The pin below re-asserts the rules at position 1,
# and only moves them when they are NOT already on top, so a
# re-pin never destroys a healthy counter. Moving a target-less
# rule changes no allow/block behaviour - it only counts.
nx_proxy_stats_top() {
    # nx_proxy_stats_top CHAIN COMMENT [PORT] -> 0 if the chain's
    # first rule carries COMMENT (and, when PORT is given, the
    # matching --dport/--sport PORT). LOW-2: a stale other-port
    # rule at position 1 used to satisfy the comment-only check, so
    # the pin became a no-op and the accumulator read the wrong
    # counter. The trailing-space/EOL alternatives keep port 1080
    # from matching 10801.
    local _first
    _first=$(iptables -S "$1" 2>/dev/null | grep -m1 '^-A' || true)
    case "$_first" in *"$2"*) ;; *) return 1 ;; esac
    if [ -n "${3:-}" ]; then
        case "$_first" in
            *"--dport ${3} "*|*"--dport ${3}"|*"--sport ${3} "*|*"--sport ${3}") ;;
            *) return 1 ;;
        esac
    fi
    return 0
}

nx_pin_proxy_stats_rules() {
    # nx_pin_proxy_stats_rules PORT: re-assert both counting rules
    # at position 1. No-op (counter preserved) when already pinned.
    local PORT="$1"
    [ -n "$PORT" ] || return 0
    if ! nx_proxy_stats_top INPUT "3proxy_stats_in" "$PORT"; then
        iptables -D INPUT -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in" 2>/dev/null || true
        iptables -I INPUT 1 -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    fi
    if ! nx_proxy_stats_top OUTPUT "3proxy_stats_out" "$PORT"; then
        iptables -D OUTPUT -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out" 2>/dev/null || true
        iptables -I OUTPUT 1 -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    fi
}

nx_proxy_stats_bytes() {
    # nx_proxy_stats_bytes CHAIN COMMENT [PORT] -> counter bytes
    # (or empty). Same parse as show_stats: the bytes column of
    # `iptables -L`. With PORT, the row must also carry dpt:/spt:
    # PORT (the [^0-9] guard keeps 1080 from matching 10801).
    if [ -n "${3:-}" ]; then
        iptables -L "$1" -v -n -x 2>/dev/null | grep "$2" | grep -E "(dpt|spt):${3}([^0-9]|$)" | awk '{print $2}' | head -1
    else
        iptables -L "$1" -v -n -x 2>/dev/null | grep "$2" | awk '{print $2}' | head -1
    fi
}

nx_proxy_port_from_config() {
    # Live port from the 3proxy config (source of truth, not install.info).
    grep -oP '(?<=socks -p)\s*\K\d+' /etc/3proxy/3proxy.cfg 2>/dev/null | head -1 || true
}

# State file format (one line): LAST_IN LAST_OUT TOTAL_IN TOTAL_OUT.
# Written atomically (tmp + rename). Totals survive reboots and rule
# recreations: a counter that went BACKWARDS means its rule was
# recreated, so the delta is the new counter itself, never negative.
# A missing rule (proxy removed, rules wiped) leaves totals untouched.
nx_proxy_traffic_accum() {
    # LOW-3: the timer, the pin callers and a manual run can overlap
    # (two writers interleaving read-compute-write would lose a
    # delta). A non-blocking lock defers a contended run to the
    # next 5-minute tick instead of blocking the caller - the
    # snapshot is periodic, never urgent. No flock binary: proceed
    # unlocked (the old behaviour), never fail the caller.
    local PORT STATE CUR_IN CUR_OUT LAST_IN LAST_OUT TOT_IN TOT_OUT _lock_fd _rc
    PORT=$(nx_proxy_port_from_config)
    [ -n "$PORT" ] || return 0
    STATE="${NX_PROXY_TRAFFIC_STATE:-/etc/3proxy/traffic-total.state}"
    if command -v flock >/dev/null 2>&1; then
        exec {_lock_fd}>"${STATE}.lock" 2>/dev/null || _lock_fd=""
        if [ -n "$_lock_fd" ]; then
            flock -n "$_lock_fd" 2>/dev/null || { exec {_lock_fd}>&- 2>/dev/null || true; return 0; }
        fi
    fi
    CUR_IN=$(nx_proxy_stats_bytes INPUT "3proxy_stats_in" "$PORT")
    CUR_OUT=$(nx_proxy_stats_bytes OUTPUT "3proxy_stats_out" "$PORT")
    # Release the lock on every exit path: a leaked fd would hold
    # the lock in a long-lived caller (the menu process, the test
    # harness) and starve every later run.
    if [ -z "$CUR_IN" ] || [ -z "$CUR_OUT" ]; then
        [ -n "${_lock_fd:-}" ] && exec {_lock_fd}>&- 2>/dev/null || true
        return 0
    fi
    LAST_IN=""; LAST_OUT=""; TOT_IN=""; TOT_OUT=""
    if [ -f "$STATE" ]; then
        read -r LAST_IN LAST_OUT TOT_IN TOT_OUT < "$STATE" 2>/dev/null || true
    fi
    LAST_IN="${LAST_IN//[^0-9]/}"; LAST_OUT="${LAST_OUT//[^0-9]/}"
    TOT_IN="${TOT_IN//[^0-9]/}"; TOT_OUT="${TOT_OUT//[^0-9]/}"
    LAST_IN="${LAST_IN:-0}"; LAST_OUT="${LAST_OUT:-0}"
    TOT_IN="${TOT_IN:-0}"; TOT_OUT="${TOT_OUT:-0}"
    if [ "$CUR_IN" -ge "$LAST_IN" ] 2>/dev/null; then TOT_IN=$((TOT_IN + CUR_IN - LAST_IN)); else TOT_IN=$((TOT_IN + CUR_IN)); fi
    if [ "$CUR_OUT" -ge "$LAST_OUT" ] 2>/dev/null; then TOT_OUT=$((TOT_OUT + CUR_OUT - LAST_OUT)); else TOT_OUT=$((TOT_OUT + CUR_OUT)); fi
    printf '%s %s %s %s\n' "$CUR_IN" "$CUR_OUT" "$TOT_IN" "$TOT_OUT" > "${STATE}.tmp.$$" 2>/dev/null && mv -f "${STATE}.tmp.$$" "$STATE" 2>/dev/null || true
    # Self-heal shadowing AFTER the snapshot, so a re-pin never
    # destroys counts it has not yet recorded.
    nx_pin_proxy_stats_rules "$PORT"
    _rc=$?
    [ -n "${_lock_fd:-}" ] && exec {_lock_fd}>&- 2>/dev/null || true
    return "$_rc"
}

get_server_ip() {
    # Display only (the socks5:// line) - never enforcement, which
    # uses list_self_ips_all. NIT-3: the old hostname -I fallback
    # took the FIRST address, which on NAT/cloud boxes is often a
    # private address useless to the reader - prefer a public IPv4
    # from the local list, and only then fall back to the first.
    local _ip
    _ip=$(curl -s -4 --max-time 5 https://api.ipify.org 2>/dev/null || \
          curl -s -4 --max-time 5 https://ifconfig.me 2>/dev/null || true)
    if [ -z "$_ip" ]; then
        _ip=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
              grep -v -E '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.64\.)' | head -1 || true)
    fi
    if [ -z "$_ip" ]; then
        _ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    printf '%s' "$_ip"
}

get_server_ipv6() { curl -s -6 --max-time 5 https://api64.ipify.org 2>/dev/null || true; }
get_current_port() { grep -oP '(?<=socks -p)\s*\K\d+' "$PROXY_CONF" 2>/dev/null | head -1 || true; }
is_installed() { [ -f "$PROXY_BIN" ] && [ -f "$SERVICE_FILE" ]; }
sep() { echo -e "${CYAN}════════════════════════════════════════════════${NC}"; }

# ── tc bandwidth control ─────────────────────────────────
# CF IPs → class 1:10 (unlimited)
# non-CF normal → class 1:20 (500Mbps)
# throttled IPs → class 1:30 (100Mbps)
setup_tc() {
    local IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
    [ -z "$IF" ] && IF="eth0"

    # Get total bandwidth (try to detect, fallback 1Gbps)
    local BW="1gbit"
    command -v ethtool >/dev/null 2>&1 && {
        local SPEED; SPEED=$(ethtool "$IF" 2>/dev/null | grep Speed | awk '{print $2}' | grep -oP '\d+' | head -1)
        [ -n "$SPEED" ] && BW="${SPEED}mbit"
    }

    # Remove old tc config (record what was there first - BUG-032)
    mkdir -p /etc/antiddos
    tc qdisc show dev "$IF" 2>/dev/null | head -1 > /etc/antiddos/tc-qdisc-before.txt || true
    tc qdisc del dev "$IF" root 2>/dev/null || true

    # HTB root
    tc qdisc add dev "$IF" root handle 1: htb default 20
    tc class add dev "$IF" parent 1: classid 1:1  htb rate "$BW"  ceil "$BW"
    tc class add dev "$IF" parent 1:1 classid 1:10 htb rate "$BW"  ceil "$BW"   burst 25Mb  # CF: unlimited
    tc class add dev "$IF" parent 1:1 classid 1:20 htb rate 500mbit ceil 500mbit burst 6400Kb  # normal
    tc class add dev "$IF" parent 1:1 classid 1:30 htb rate 100mbit ceil 100mbit burst 1280Kb  # throttled
    tc class add dev "$IF" parent 1:1 classid 1:40 htb rate 50mbit  ceil 50mbit  burst 640Kb   # hard-throttled

    # Cloudflare IPs → class 1:10 (unlimited)
    local HANDLE=10
    for CF in "${CF_RANGES[@]}"; do
        # skip IPv6 if kernel doesn't support tc ip6
        [[ "$CF" == *":"* ]] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip dst "$CF" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done

    # Server own IPs → class 1:10 (unlimited)
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip dst "$SIP/32" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done < <(list_self_ips_all)

    # User whitelist → class 1:10 (unlimited, same as CF/self)
    if [ -f "/etc/antiddos/whitelist.list" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
                u32 match ip dst "$WIP" flowid 1:10 2>/dev/null || true
            HANDLE=$((HANDLE + 1))
        done < /etc/antiddos/whitelist.list
    fi

    # HIGH-2: re-apply live daemon throttles (BUG-022) - same loop as
    # the antiddos live rebuild and the boot script: the qdisc delete
    # above destroyed every recorded throttle filter, and the live
    # path never restored them (only the boot script did).
    while read -r TIP TPRIO _TS TBAND; do
        [ -z "$TIP" ] && continue
        TFLOW=1:30; [ "$TBAND" = "hard" ] && TFLOW=1:40
        case "$TIP" in
            *:*) tc filter add dev "$IF" parent 1: protocol ip6 prio $TPRIO \
                     u32 match ip6 dst "$TIP" flowid $TFLOW 2>/dev/null || true ;;
            *)   tc filter add dev "$IF" parent 1: protocol ip prio $TPRIO \
                     u32 match ip dst "$TIP/32" flowid $TFLOW 2>/dev/null || true ;;
        esac
    done < <(cat "${THROTTLE_LIST:-/run/nexoshield/autoban_throttle}" /etc/antiddos/throttled.list 2>/dev/null | awk '!seen[$1]++')

    # ── WARP / WireGuard awareness ──────────────────────────
    # tc shapes the default-route interface. If a WireGuard/WARP tunnel is
    # present, its traffic egresses on a wg* device, so these filters would
    # NOT shape tunneled traffic — warn the user (conditional, non-intrusive).
    if ip link show 2>/dev/null | grep -qE '^\s*[0-9]+:\s+(wg|utm|warp)[0-9]*[:@]'; then
        echo -e "${YELLOW}⚠ WARP/WireGuard tunnel detected on a different interface.${NC}"
        echo -e "   tc is applied to '${IF}' (default route). Tunneled (WARP) traffic"
        echo -e "   leaves via the tunnel device and is NOT shaped by these limits."
        echo -e "   This is intentional & safe — inbound anti-DDoS (iptables) still applies."
    fi

    echo -e "${GREEN}✓ tc bandwidth control configured (CF=unlimited, others=500Mbps)${NC}"
}

# ── Save tc config for persistence ──────────────────────
save_tc_persistent() {
    local IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
    [ -z "$IF" ] && IF="eth0"

    # systemd service for tc restore after reboot
    cat > /etc/systemd/system/tc-proxy-limit.service << EOF
[Unit]
Description=TC bandwidth shaping for proxy server
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/proxy-manager/tc-setup.sh $IF
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Detected link speed must reach the generated script (BUG-032: it
    # hardcoded 1gbit even on 10G links). Written via a placeholder that
    # is substituted after the quoted heredoc lands.
    local BW="1gbit"
    command -v ethtool >/dev/null 2>&1 && {
        local SPEED; SPEED=$(ethtool "$IF" 2>/dev/null | grep Speed | awk '{print $2}' | grep -oP '\d+' | head -1)
        [ -n "$SPEED" ] && BW="${SPEED}mbit"
    }

    # Write tc-setup.sh
    cat > /opt/proxy-manager/tc-setup.sh << 'TCEOF'
#!/bin/bash
# Auto-generated by proxy-manager — do not edit manually
IF="${1:-eth0}"
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi
list_self_ips() {
    { ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+'
      hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    } | sort -u | grep -v '^$'
}

# list_self_ips6 - every local IPv6 address (incl. ::1), one per line.
list_self_ips6() {
    { ip -6 addr show 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+'
      echo "::1"
    } | sort -u | grep -v '^$'
}

# ── Public-IP discovery for NAT / cloud servers ─────────────────
# On cloud VMs (Azure, most NAT setups) the server's public IPv4
# exists only in the provider's NAT - it is on NO interface, so
# list_self_ips can never see it, yet it is unmistakably one of the
# server's own addresses (FR-2). Discovery asks the cloud metadata
# service (link-local, no internet involved); only when no metadata
# service answers does it fall back to an external echo service.
# Every candidate passes nx_is_public_ipv4: metadata/echo replies
# are untrusted input, and a private/documentation/garbage answer
# must never widen the immune set.
NX_PUBLIC_IPS_FILE="${NX_PUBLIC_IPS_FILE:-/etc/antiddos/public-ips.list}"

nx_is_public_ipv4() {
    local ip="${1:-}" o1 o2 o3 o4 extra _o
    case "$ip" in *[!0-9.]*) return 1 ;; esac
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for _o in "$o1" "$o2" "$o3" "$o4"; do
        case "$_o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_o}" -le 3 ] || return 1
        (( 10#$_o <= 255 )) || return 1
    done
    case "$o1" in
        0|10|127) return 1 ;;
        100) [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 1 ;;
        169) [ "$o2" = 254 ] && return 1 ;;
        172) [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 1 ;;
        192) [ "$o2" = 168 ] && return 1
             { [ "$o2" = 0 ] && { [ "$o3" = 0 ] || [ "$o3" = 2 ]; }; } && return 1 ;;
        198) case "$o2" in 18|19|51) return 1 ;; esac ;;
        203) { [ "$o2" = 0 ] && [ "$o3" = 113 ]; } && return 1 ;;
    esac
    [ "$o1" -ge 224 ] && return 1
    return 0
}

nx_metadata_public_ips() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _tok _base="http://169.254.169.254"
    # Azure IMDS (first two addresses on the primary NIC)
    for _idx in 0 1; do
        _ip=$(curl -s -m 2 -H "Metadata: true" \
            "$_base/metadata/instance/network/interface/0/ipv4/ipAddress/$_idx/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
        nx_is_public_ipv4 "$_ip" && echo "$_ip"
    done
    # AWS EC2 IMDS (token first, plain fallback)
    _tok=$(curl -s -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "$_base/latest/api/token" 2>/dev/null)
    if [ -n "$_tok" ]; then
        _ip=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $_tok" \
            "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    else
        _ip=$(curl -s -m 2 "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    fi
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # GCP
    _ip=$(curl -s -m 2 -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # DigitalOcean
    _ip=$(curl -s -m 2 "$_base/metadata/v1/interfaces/public/0/ipv4/address" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # Hetzner Cloud
    _ip=$(curl -s -m 2 "$_base/hetzner/v1/metadata/public-ipv4" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    return 0
}

nx_external_public_ip() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _url
    for _url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me/ip"; do
        _ip=$(curl -s -m 3 "$_url" 2>/dev/null | tr -d ' \r\n')
        nx_is_public_ipv4 "$_ip" && { echo "$_ip"; return 0; }
    done
    return 0
}

# Echo the server's public IPv4s that are NOT on any interface
# (metadata first; external echo only as a last resort).
discover_public_ips() {
    local _found _ip
    _found=$(nx_metadata_public_ips | sort -u)
    [ -z "$_found" ] && _found=$(nx_external_public_ip)
    for _ip in $_found; do
        list_self_ips | grep -qxF "$_ip" || echo "$_ip"
    done
}

# Refresh the cache file; a failed/empty discovery NEVER wipes a
# previously discovered set (an offline reinstall must not disarm
# the immunity). Prints the discovered addresses when any exist.
nx_refresh_public_ips_cache() {
    local _found
    _found=$(discover_public_ips)
    if [ -n "$_found" ]; then
        mkdir -p "$(dirname "$NX_PUBLIC_IPS_FILE")" 2>/dev/null || true
        printf '%s\n' "$_found" > "$NX_PUBLIC_IPS_FILE.tmp" 2>/dev/null && \
            mv "$NX_PUBLIC_IPS_FILE.tmp" "$NX_PUBLIC_IPS_FILE" 2>/dev/null || true
        printf '%s\n' "$_found"
    elif [ -f "$NX_PUBLIC_IPS_FILE" ]; then
        cat "$NX_PUBLIC_IPS_FILE"
    fi
}

# list_self_ips_all - interface addresses PLUS the cached
# discovered public IPs. This is the feed every enforcement layer
# uses for "the server's own addresses" (FR-2 complete: local,
# private, secondary AND NAT-public).
list_self_ips_all() {
    { list_self_ips
      if [ -r "$NX_PUBLIC_IPS_FILE" ]; then
          grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$NX_PUBLIC_IPS_FILE" 2>/dev/null
      fi
    } | sort -u | grep -v '^$'
}
tc qdisc del dev "$IF" root 2>/dev/null || true
tc qdisc add dev "$IF" root handle 1: htb default 20
tc class add dev "$IF" parent 1: classid 1:1  htb rate __BW__ ceil __BW__
tc class add dev "$IF" parent 1:1 classid 1:10 htb rate __BW__  ceil __BW__  burst 25Mb
tc class add dev "$IF" parent 1:1 classid 1:20 htb rate 500mbit ceil 500mbit burst 6400Kb
tc class add dev "$IF" parent 1:1 classid 1:30 htb rate 100mbit ceil 100mbit burst 1280Kb
tc class add dev "$IF" parent 1:1 classid 1:40 htb rate 50mbit  ceil 50mbit  burst 640Kb
HANDLE=10
for CF in "${CF_RANGES[@]}"; do
    tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
        u32 match ip dst "$CF" flowid 1:10 2>/dev/null || true
    HANDLE=$((HANDLE + 1))
done
# Add server own IPs
for SIP in $(list_self_ips_all 2>/dev/null | grep -v '^127\.0\.0\.1$'); do
    tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
        u32 match ip dst "$SIP/32" flowid 1:10 2>/dev/null || true
    HANDLE=$((HANDLE + 1))
done
# Add user whitelist (unlimited)
if [ -f /etc/antiddos/whitelist.list ]; then
    while IFS= read -r WIP; do
        WIP="${WIP%%#*}"; WIP="${WIP// /}"
        [ -z "$WIP" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip dst "$WIP" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done < /etc/antiddos/whitelist.list
fi
# Re-apply live daemon throttles (BUG-022): a qdisc rebuild must not
# silently drop enforcement state recorded by the auto-ban daemon.
if [ -f /etc/antiddos/throttled.list ]; then
    while read -r TIP TPRIO _TS TBAND; do
        [ -z "$TIP" ] && continue
        TFLOW=1:30; [ "$TBAND" = "hard" ] && TFLOW=1:40
        case "$TIP" in
            *:*) tc filter add dev "$IF" parent 1: protocol ip6 prio $TPRIO \
                     u32 match ip6 dst "$TIP" flowid $TFLOW 2>/dev/null || true ;;
            *)   tc filter add dev "$IF" parent 1: protocol ip prio $TPRIO \
                     u32 match ip dst "$TIP/32" flowid $TFLOW 2>/dev/null || true ;;
        esac
    done < /etc/antiddos/throttled.list
fi
TCEOF
    sed -i "s/__BW__/$BW/g" /opt/proxy-manager/tc-setup.sh
    chmod +x /opt/proxy-manager/tc-setup.sh

    # Also add to if-up.d for NetworkManager
    mkdir -p /etc/network/if-up.d
    ln -sf /opt/proxy-manager/tc-setup.sh /etc/network/if-up.d/tc-proxy-limit 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable tc-proxy-limit.service >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ tc persistence configured (reboot-safe)${NC}"
}

# ── iptables rules for proxy port (CF unlimited) ─────────
# remove_proxy_port_rules: delete-only mirror of the delete half of
# setup_iptables_for_port. Used when an update deliberately moves
# the proxy to a new port, so the vacated port's rules do not
# linger (and the old port does not stay open behind us).
remove_proxy_port_rules() {
    local PORT="$1"
    # Snapshot BEFORE deleting (MED-1): the accumulator runs only
    # every 5 minutes, so deleting the counting rules first would lose
    # all traffic counted since the last tick (up to 5 minutes of
    # proxy traffic). The config port is the vacated port here: this
    # is called from install_proxy before the config is rewritten.
    nx_proxy_traffic_accum 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" \
        -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    iptables -D OUTPUT -p tcp --sport "$PORT" \
        -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT 2>/dev/null || true
    done
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
            -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
    done < <(list_self_ips_all)
    local _rn
    for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_${PORT}[^0-9]" | cut -d: -f1 | sort -rn); do
        iptables -D INPUT $((_rn - 1)) 2>/dev/null || true
    done
    if [ -f /etc/antiddos/whitelist.list ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$WIP" \
                -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
        done < /etc/antiddos/whitelist.list
    fi
    # LOW-5: mirror the ufw/firewalld cleanup setup and uninstall
    # already do - a vacated port must not stay open behind us.
    command -v ufw >/dev/null 2>&1 && ufw delete allow "$PORT"/tcp 2>/dev/null || true
    command -v firewall-cmd >/dev/null 2>&1 && {
        firewall-cmd --remove-port="${PORT}/tcp" --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    }
    # MED-3: the ruleset changed - refresh the persistent save so a
    # reboot does not resurrect the vacated port's rules.
    nx_3proxy_save_rules 2>/dev/null || true
}

# nx_3proxy_save_rules — persist the live ruleset (static filter only:
# transient bans/f2b chains are runtime state, never baked into boot
# persistence, BUG-012) so a 3proxy-only install survives a reboot
# (MED-3). The save path is overridable for tests. The restore unit
# itself is managed by install/uninstall, not here.
nx_3proxy_save_rules() {
    local _dir="${NX_3PROXY_SAVE_DIR:-/etc/iptables}"
    command -v iptables-save >/dev/null 2>&1 || return 0
    mkdir -p "$_dir" 2>/dev/null || return 0
    iptables-save 2>/dev/null | grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' > "$_dir/rules.v4" 2>/dev/null || true
}

setup_iptables_for_port() {
    local PORT="$1"

    # MED-5 (fail closed, mirroring antiddos BUG-027): with no
    # Cloudflare ranges loaded, every rule below would treat CF IPs
    # as ordinary traffic. Refuse to arm.
    if [ "${#CF_RANGES[@]}" -eq 0 ]; then
        echo -e "  ${RED}✗${NC}  Cloudflare range list is empty/missing - refusing to apply proxy iptables rules (CF would lose its exemption)" >&2
        return 1
    fi

    # Snapshot BEFORE deleting (MED-1, see remove_proxy_port_rules):
    # an Install/Update recreates the counting rules, which zeroes
    # their kernel counters. Without this, traffic since the last
    # 5-minute accumulator tick is lost on every update.
    nx_proxy_traffic_accum 2>/dev/null || true
    # Remove old rules for this port
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" \
        -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    iptables -D OUTPUT -p tcp --sport "$PORT" \
        -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    # Remove old CF rules (BUG-013: the delete spec must mirror the
    # create spec EXACTLY, including the comment match - without it the
    # delete never matched and every reinstall duplicated all 753 rules)
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT 2>/dev/null || true
    done
    # Remove old self-IP rules (mirror of Step 2 - previously missing, so
    # these duplicated on every reinstall too)
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
            -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
    done < <(list_self_ips_all)
    # Remove old rate-limit rules by enumeration (BUG-014: rules
    # created by older versions carry varying hitcounts, so a fixed
    # spec delete can miss the real rule; the recent-rule name is
    # the stable identifier)
    local _rn
    for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_${PORT}[^0-9]" | cut -d: -f1 | sort -rn); do
        iptables -D INPUT $((_rn - 1)) 2>/dev/null || true
    done
    # Remove old user-whitelist rules (spec mirrors the create below)
    if [ -f /etc/antiddos/whitelist.list ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$WIP" \
                -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
        done < /etc/antiddos/whitelist.list
    fi

    # ── Step 1: CF IPs → ACCEPT immediately (no limits!) ─
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -A INPUT -p tcp --dport "$PORT" -s "$CF" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT
    done

    # ── Step 2: Server own IPs → ACCEPT (no limits) ──────
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        iptables -A INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
            -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
    done < <(list_self_ips_all)

    # ── Step 2b: User whitelist → ACCEPT (FR-1: exempt means exempt
    # in EVERY layer, including this port's rate limits) ──────
    if [ -f /etc/antiddos/whitelist.list ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            iptables -A INPUT -p tcp --dport "$PORT" -s "$WIP" \
                -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
        done < /etc/antiddos/whitelist.list
    fi

    # ── Step 3: Non-CF rate-limit (new conns per IP) ──────
    # Per-IP burst guard: 300 NEW hits per 60s window from one IP.
    # This is the port's abuse protection - deliberately per-IP and
    # independent of any service-wide connection ceiling.
    # Only apply to IPs NOT from CF (CF already accepted above)
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --update --seconds 60 \
        --hitcount 300 -j DROP
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --set

    # ── Step 4: Allow all remaining ──────────────────────
    iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT

    # Stats counters, pinned at position 1 (v3.17.0: a target-less
    # counting rule only counts packets that reach it - anything
    # ACCEPTed above it shadows it, so the pin is re-asserted here
    # and after every antiddos apply, never merely appended).
    nx_pin_proxy_stats_rules "$PORT"

    # UFW / firewalld compat
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active" && \
        ufw allow "$PORT"/tcp >/dev/null 2>&1 || true
    command -v firewall-cmd >/dev/null 2>&1 && \
        firewall-cmd --add-port="$PORT"/tcp --permanent >/dev/null 2>&1 && \
        firewall-cmd --reload >/dev/null 2>&1 || true

    # MED-3: the ruleset changed - refresh the persistent save so a
    # reboot does not lose the proxy's rules on a 3proxy-only box.
    nx_3proxy_save_rules 2>/dev/null || true
}

# ── Run a command with visible "working" feedback ──────────
# Prints "<label> ......" and a growing dot animation so the user can see the
# step is still alive. The command itself is NEVER time-limited. Output is
# captured to a temp log so the dots stay clean; on failure the log tail is
# shown so the real error is not hidden.
run_spinner() {
    local label="$1"; shift
    local log _spin _rc
    log=$(mktemp)
    printf '  %s ' "$label"
    ( while :; do printf '.'; sleep 1; done ) &
    _spin=$!
    "$@" >"$log" 2>&1
    _rc=$?
    kill "$_spin" 2>/dev/null; wait "$_spin" 2>/dev/null
    if [ "$_rc" -eq 0 ]; then
        printf ' done\n'
    else
        printf ' FAILED\n'
        tail -n 15 "$log" >&2
    fi
    rm -f "$log"
    return "$_rc"
}

# Standalone script helpers (not inherited from install.sh).
info() { echo -e "  ${CYAN}->${NC}  $*"; }
ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }

# ── Pick the fastest reachable apt mirror ──────────────────
# Tests a set of candidate mirrors with a SHORT per-mirror timeout (this is a
# probe only) and echoes the URL of the fastest responsive one. The later
# apt-get update/install runs WITHOUT any timeout. Returns empty if none work.
pick_apt_mirror() {
    local os="$1" code="$2"
    local -a cands=()
    if [ "$os" = ubuntu ]; then
        cands=( "https://archive.ubuntu.com/ubuntu" "https://mirrors.aliyun.com/ubuntu" \
                "https://mirrors.tuna.tsinghua.edu.cn/ubuntu" "https://mirrors.ustc.edu.cn/ubuntu" \
                "https://mirrors.cloud.aliyuncs.com/ubuntu" "https://mirrors.huaweicloud.com/ubuntu" \
                "https://mirrors.zju.edu.cn/ubuntu" )
    else
        cands=( "https://deb.debian.org/debian" "https://mirrors.aliyun.com/debian" \
                "https://mirrors.tuna.tsinghua.edu.cn/debian" "https://mirrors.ustc.edu.cn/debian" \
                "https://mirrors.huaweicloud.com/debian" "https://mirrors.cloud.aliyuncs.com/debian" )
    fi
    local best="" best_ms=99999 m t0 ms
    for m in "${cands[@]}"; do
        t0=$(date +%s%N 2>/dev/null || echo 0)
        if curl -fsS --max-time 4 -o /dev/null "$m/dists/$code/InRelease" 2>/dev/null || \
           curl -fsS --max-time 4 -o /dev/null "$m/dists/$code/Release" 2>/dev/null; then
            ms=$(( ( $(date +%s%N 2>/dev/null || echo 0) - t0 ) / 1000000 ))
            [ "$ms" -lt 0 ] && ms=0
            if [ "$ms" -lt "$best_ms" ]; then best_ms=$ms; best=$m; fi
        fi
    done
    printf '%s' "$best"
}

# ── Point apt at the chosen mirror (with backup) ───────────
# Backs up existing apt sources, then writes a minimal sources.list using the
# selected mirror. The original config is kept as *.bak so nothing is lost.
configure_apt_mirror() {
    local os="$1" code="$2" mirror="$3"
    # LOW-7: never overwrite an existing .bak - the first backup is
    # the pre-NexoShield original; later runs must preserve it, or
    # an uninstall restore would hand back OUR mirror list.
    [ -f /etc/apt/sources.list ] && [ ! -f /etc/apt/sources.list.bak ] && \
        cp -a /etc/apt/sources.list /etc/apt/sources.list.bak 2>/dev/null || true
    for _f in /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
        [ -e "$_f" ] && [ ! -f "$_f.bak" ] && cp -a "$_f" "$_f.bak" 2>/dev/null || true
    done
    # On modern Ubuntu the default is deb822 (ubuntu.sources); use classic list.
    rm -f /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
    printf 'deb %s %s main restricted universe multiverse\n' "$mirror" "$code" > /etc/apt/sources.list
    printf 'deb %s %s-updates main restricted universe multiverse\n' "$mirror" "$code" >> /etc/apt/sources.list
    printf 'deb %s %s-security main restricted universe multiverse\n' "$mirror" "$code" >> /etc/apt/sources.list
}

# _port_held_by_other: is PORT held by something OTHER than our
# own 3proxy service? ss -tlnp names the owning process, so a
# listener owned by 3proxy is our own service - an update
# restarts it onto the same port, it is NOT a conflict.
_port_held_by_other() {
    local P="$1"
    if ss -tlnp 2>/dev/null | grep -qE ":$P\b.*\"3proxy\""; then
        return 1
    fi
    # NIT-2: TCP listeners only (-tln). A UDP listener on the same
    # number is a different protocol namespace, not a conflict for
    # a TCP proxy port.
    ss -tln 2>/dev/null | grep -qE ":$P\b"
}

# pick_proxy_port: settle PORT for install/update.
# - Default = the already-installed port (install.info) when one
#   exists, else 1080 - an update must not silently re-default.
# - The old loop treated ANY listener as foreign, so every update
#   on a running proxy silently moved it to port+1 (and broke
#   every client configured for the old port).
pick_proxy_port() {
    local DEFAULT_PORT=1080 _OLD
    if [ -f /etc/3proxy/install.info ]; then
        _OLD=$(grep '^PORT=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || true)
        [[ "$_OLD" =~ ^[0-9]+$ ]] && DEFAULT_PORT="$_OLD"
    fi
    read -t 30 -rp "Port (default: $DEFAULT_PORT): " INPUT_PORT < /dev/tty 2>/dev/null || INPUT_PORT=""
    PORT=${INPUT_PORT:-$DEFAULT_PORT}
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || PORT=$DEFAULT_PORT
    TRIED=0
    while _port_held_by_other "$PORT" && [ "$TRIED" -lt 20 ]; do
        echo -e "${YELLOW}Port $PORT is in use.${NC}"
        PORT=$((PORT + 1))
        TRIED=$((TRIED + 1))
        echo -e "Trying: ${CYAN}$PORT${NC}"
    done
    # BUG-061: fail fast - the loop used to give up after 20 tries and
    # still write a config bound to an occupied port.
    if _port_held_by_other "$PORT"; then
        echo -e "${RED}No free port found after 20 attempts (last tried: $PORT). Aborting - nothing was written.${NC}" >&2
        return 1
    fi
    return 0
}

# regen_proxy_traffic_accum — regenerate the derived accumulator
# script from the live lib functions (single source of truth). Used
# by install_proxy and by the menu self-update (MED-7): the timer
# executes this file directly, so after a self-update it would
# otherwise keep running the previous version's lib code. Atomic
# write (tmp + rename) so the timer never reads a half-written file.
regen_proxy_traffic_accum() {
    local _tmp
    _tmp=$(mktemp 2>/dev/null || echo "")
    [ -z "$_tmp" ] && return 1
    {
        printf '%s\n' '#!/bin/bash' '# Generated by NexoShield - recreated on every Install/Update.'
        declare -f nx_proxy_stats_top nx_pin_proxy_stats_rules nx_proxy_stats_bytes nx_proxy_port_from_config nx_proxy_traffic_accum
        printf '%s\n' 'nx_proxy_traffic_accum "$@"'
    } > "$_tmp" 2>/dev/null || { rm -f "$_tmp"; return 1; }
    chmod 755 "$_tmp" 2>/dev/null || true
    mv "$_tmp" /usr/local/bin/nx-proxy-traffic-accum 2>/dev/null || { rm -f "$_tmp"; return 1; }
    return 0
}

install_proxy() {
    sep; echo -e "${YELLOW}Installing 3proxy SOCKS5...${NC}"; sep

    echo -e "${YELLOW}[1/7] Installing dependencies...${NC}"
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=${ID:-unknown}; CODENAME=${VERSION_CODENAME:-}; fi
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        # Prefer a fast reachable mirror so `apt-get update` doesn't stall on a
        # slow one. Probe is quick (timeout on the test only); the install
        # itself below is NEVER time-limited. If no mirror responds, keep the
        # system's existing apt sources.
        # BUG-016: rewriting the system's apt sources is OPT-IN
        # (NX_APT_MIRROR=1). It used to happen silently on every install
        # - including pointing a production box at third-party mirrors
        # over plain HTTP.
        MIRROR=""
        if [ "${NX_APT_MIRROR:-0}" = "1" ]; then
            [ -n "$CODENAME" ] && MIRROR=$(pick_apt_mirror "$OS" "$CODENAME")
            if [ -n "$MIRROR" ]; then
                info "Using apt mirror: $MIRROR"
                configure_apt_mirror "$OS" "$CODENAME" "$MIRROR"
            else
                info "No faster mirror reachable - using system apt sources"
            fi
        else
            info "Using system apt sources (set NX_APT_MIRROR=1 to auto-pick a fast mirror)"
        fi
        run_spinner "Updating package lists" apt-get update -y || true
        run_spinner "Installing dependencies" apt-get install -y \
            wget curl iptables iproute2 logrotate build-essential tcpdump || {
            echo -e "${YELLOW}Some packages failed, continuing...${NC}"
        }
    elif [[ "$OS" == "centos" || "$OS" == "rhel" || \
            "$OS" == "rocky" || "$OS" == "almalinux" || \
            "$OS" == "fedora" ]]; then
        # BUG-044: yum is a dead stub on RHEL 9+/Fedora - prefer dnf.
        RH_PKG=$(command -v dnf 2>/dev/null || command -v yum 2>/dev/null || echo yum)
        run_spinner "Installing dependencies" "$RH_PKG" install -y \
            wget curl iptables iproute logrotate gcc make iproute-tc tcpdump || {
            echo -e "${YELLOW}Some packages failed, continuing...${NC}"
        }
    fi

    echo -e "${YELLOW}[2/7] Installing 3proxy...${NC}"
    TMPDIR_BUILD=$(mktemp -d)
    cd "$TMPDIR_BUILD" || return 1
    if run_spinner "Installing 3proxy via apt" apt-get install -y 3proxy; then
        PROXY_BIN_PATH=$(command -v 3proxy 2>/dev/null || echo "/usr/bin/3proxy")
        [ "$PROXY_BIN_PATH" != "$PROXY_BIN" ] && ln -sf "$PROXY_BIN_PATH" "$PROXY_BIN"
        echo -e "${GREEN}3proxy installed from apt.${NC}"
    else
        echo -e "${YELLOW}Compiling 3proxy from source...${NC}"
        # Pinned sha256 of the 3proxy 0.9.4 source tarball. Empty = skip the
        # check (not recommended). Fill from a trusted download with:
        #   sha256sum 3proxy.tar.gz
        # Hash computed 2026-10-23 from the official upstream release:
        #   https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz
        T3PROXY_SHA256="b497f74d6cc7ee58ff824457427acc02c6f7a102e483816fbb1b2494942ef983"
        if run_spinner "Downloading 3proxy source" wget -O 3proxy.tar.gz \
            https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz; then
            if [ -n "$T3PROXY_SHA256" ]; then
                echo "$T3PROXY_SHA256  3proxy.tar.gz" | sha256sum -c - >/dev/null || {
                    echo -e "${RED}Checksum mismatch for 3proxy source - aborting.${NC}"
                    cd /; rm -rf "$TMPDIR_BUILD"; return 1
                }
            fi
            run_spinner "Extracting source" tar -xzf 3proxy.tar.gz
            cd 3proxy-0.9.4 || { cd /; rm -rf "$TMPDIR_BUILD"; return 1; }
            # T-3 (field test 2026-10-23, Ubuntu 26.04 / GCC 15.2):
            # 3proxy 0.9.4 is pre-C23 C and fails the plain build on
            # GCC >= 14 (C23 default + implicit-declaration hard
            # errors). Retry once with legacy-C compatibility flags.
            _build_ok=0
            if run_spinner "Compiling (this can take a while)" \
                make -f Makefile.Linux -j"$(nproc)"; then
                _build_ok=1
            else
                make -f Makefile.Linux clean >/dev/null 2>&1 || true
                if run_spinner "Compiling (legacy-C compatibility flags)" \
                    make -f Makefile.Linux -j"$(nproc)" \
                    CC="gcc -std=gnu17 -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=incompatible-pointer-types -Wno-error=return-mismatch"; then
                    _build_ok=1
                    echo -e "${YELLOW}Note: built with legacy-C compatibility flags (modern compiler).${NC}"
                fi
            fi
            if [ "$_build_ok" -eq 1 ]; then
                # Atomic replace: cp onto the RUNNING binary fails
                # with ETXTBSY on every live update (field bug).
                nx_install_binary bin/3proxy "$PROXY_BIN" 755 && \
                    echo -e "${GREEN}3proxy compiled from source.${NC}" || {
                    echo -e "${RED}Copy failed!${NC}"; cd /; rm -rf "$TMPDIR_BUILD"; return 1
                }
            else
                echo -e "${RED}Compilation failed!${NC}"; cd /; rm -rf "$TMPDIR_BUILD"; return 1
            fi
        else
            echo -e "${RED}Cannot download 3proxy! Check internet connection.${NC}"
            cd /; rm -rf "$TMPDIR_BUILD"; return 1
        fi
    fi
    cd /; rm -rf "$TMPDIR_BUILD"

    # MED-4: fail closed when a required binary is absent after the
    # steps above (dependency failures are tolerated with a warning,
    # so a missing binary must not surface later as a half-installed
    # proxy printing success).
    if [ ! -x "$PROXY_BIN" ]; then
        echo -e "${RED}3proxy binary missing at $PROXY_BIN after install - aborting.${NC}" >&2
        return 1
    fi
    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "${RED}iptables binary missing after dependency install - aborting.${NC}" >&2
        return 1
    fi

    echo -e "${YELLOW}[3/7] Port configuration...${NC}"
    # LOW-6: the live config is the primary port source (install.info
    # can lag it); install.info stays as the fallback.
    _OLD_PORT="$(nx_proxy_port_from_config 2>/dev/null || true)"
    [ -z "$_OLD_PORT" ] && [ -f /etc/3proxy/install.info ] && _OLD_PORT=$(grep '^PORT=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || true)
    pick_proxy_port || return 1
    # A deliberate port change vacates the old port: drop its
    # firewall rules so the old port does not stay open behind us.
    if [ -n "$_OLD_PORT" ] && [ "$_OLD_PORT" != "$PORT" ]; then
        remove_proxy_port_rules "$_OLD_PORT"
    fi

    echo -e "${YELLOW}[4/7] Security settings...${NC}"
    # No per-service connection cap: the proxy may serve thousands
    # of users, and abuse is stopped per-IP by NexoShield's layers
    # (connlimit tiers, the auto-ban daemon, the per-IP port guard
    # below) - not by a blunt service-wide ceiling. maxconn stays
    # only as a high resource guard so 3proxy never falls back to
    # its built-in default of 100.
    read -t 30 -rp "Connection ceiling (resource guard only, default: 100000): " MAX_TOTAL_CONN < /dev/tty 2>/dev/null || MAX_TOTAL_CONN=""
    MAX_TOTAL_CONN=${MAX_TOTAL_CONN:-100000}
    [[ "$MAX_TOTAL_CONN" =~ ^[0-9]+$ ]] || MAX_TOTAL_CONN=100000

    read -t 30 -rp "Idle timeout in seconds (default: 60): " CONN_TIMEOUT < /dev/tty 2>/dev/null || CONN_TIMEOUT=""
    CONN_TIMEOUT=${CONN_TIMEOUT:-60}
    [[ "$CONN_TIMEOUT" =~ ^[0-9]+$ ]] || CONN_TIMEOUT=60

    # BUG-026: an update/reinstall must NOT rotate the proxy
    # credentials - every existing client would break. Preserve them;
    # rotation is the explicit --change-pass action.
    PROXY_USER=""; PROXY_PASS=""
    if [ -f "$PROXY_USERS" ]; then
        PROXY_USER=$(grep -oP '(?<=^users )\S+(?=:CL:)' "$PROXY_USERS" 2>/dev/null | head -1 || true)
        PROXY_PASS=$(grep -oP '(?<=:CL:)\S+' "$PROXY_USERS" 2>/dev/null | head -1 || true)
        if [ -n "$PROXY_USER" ] && [ -n "$PROXY_PASS" ]; then
            echo -e "${GREEN}Existing proxy credentials preserved (rotate with --change-pass).${NC}"
        else
            PROXY_USER=""; PROXY_PASS=""
        fi
    fi
    if [ -z "$PROXY_PASS" ]; then
        # shellcheck disable=SC2018 # byte-range alphabet is deliberate (credential generation)
        PROXY_USER=$(tr -dc 'a-z' </dev/urandom 2>/dev/null | head -c 8 || echo "proxyuser")
        PROXY_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16)
        if [ -z "$PROXY_PASS" ]; then
            echo -e "${RED}Failed to generate a secure proxy password (/dev/urandom unavailable). Aborting install.${NC}" >&2
            return 1
        fi
    fi

    mkdir -p /etc/3proxy "$PROXY_LOG_DIR"
    # BUG-018: the proxy runs as a dedicated unprivileged user (it was
    # User=root with proxy credentials and binding logic - any 3proxy
    # exploit was instant root).
    if ! id nexoproxy >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin nexoproxy 2>/dev/null || \
            useradd --system --no-create-home --shell /bin/false nexoproxy 2>/dev/null || true
    fi
    chown nexoproxy:nexoproxy "$PROXY_LOG_DIR" 2>/dev/null || true
    chmod 750 "$PROXY_LOG_DIR"
    chgrp nexoproxy /etc/3proxy 2>/dev/null || true
    chmod 750 /etc/3proxy
    # LOW-11: preserve any other users in users.cfg (manual additions)
    # - replace only the managed user's line instead of wiping the file.
    if [ -f "$PROXY_USERS" ] && [ -n "$PROXY_USER" ]; then
        grep -vF "users $PROXY_USER:CL:" "$PROXY_USERS" > "$PROXY_USERS.tmp" 2>/dev/null || true
        echo "users $PROXY_USER:CL:$PROXY_PASS" >> "$PROXY_USERS.tmp"
        mv "$PROXY_USERS.tmp" "$PROXY_USERS"
    else
        echo "users $PROXY_USER:CL:$PROXY_PASS" > "$PROXY_USERS"
    fi
    chgrp nexoproxy "$PROXY_USERS" 2>/dev/null || true
    chmod 640 "$PROXY_USERS"

    # HIGH-1: back up the working config + install.info BEFORE
    # rewriting them, so a failed restart below can roll back to
    # the previous working proxy instead of leaving it down.
    _ROLLBACK_DIR=""
    if [ -f "$PROXY_CONF" ] || [ -f /etc/3proxy/install.info ]; then
        _ROLLBACK_DIR=$(mktemp -d 2>/dev/null || echo "")
        if [ -n "$_ROLLBACK_DIR" ]; then
            [ -f "$PROXY_CONF" ] && cp -a "$PROXY_CONF" "$_ROLLBACK_DIR/3proxy.cfg" 2>/dev/null || true
            [ -f /etc/3proxy/install.info ] && cp -a /etc/3proxy/install.info "$_ROLLBACK_DIR/install.info" 2>/dev/null || true
        fi
    fi

    echo -e "${YELLOW}[5/7] Writing config...${NC}"
    cat > "$PROXY_CONF" << EOF
# 3proxy SOCKS5 — Generated: $(date)
# Cloudflare users: unlimited (no connlimit applied)
log $PROXY_LOG_DIR/access.log D
logformat "L%d-%m-%Y %H:%M:%S %U %C:%c %R:%r %O %I %E %T"
rotate 1
include $PROXY_USERS
nserver 8.8.8.8
nserver 1.1.1.1
nscache 65536
timeouts 1 5 30 $CONN_TIMEOUT 180 1800 15 60
maxconn $MAX_TOTAL_CONN
# Block private ranges (prevent SSRF)
deny * * 127.0.0.0/8
deny * * 0.0.0.0/8
deny * * 10.0.0.0/8
deny * * 172.16.0.0/12
deny * * 192.168.0.0/16
deny * * 169.254.0.0/16
deny * * 100.64.0.0/10
auth strong
allow $PROXY_USER
socks -p$PORT -i0.0.0.0 -e0.0.0.0
EOF
    chgrp nexoproxy "$PROXY_CONF" 2>/dev/null || true
    chmod 640 "$PROXY_CONF"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=3proxy SOCKS5 Proxy Server
After=network.target
[Service]
Type=simple
User=nexoproxy
Group=nexoproxy
# Low ports are not needed (default 1080); kept for custom port < 1024.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$PROXY_LOG_DIR
ProtectHome=true
LimitNOFILE=1048576
LimitNPROC=1048576
ExecStart=$PROXY_BIN $PROXY_CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/logrotate.d/3proxy << EOF
$PROXY_LOG_DIR/*.log {
    daily
    rotate 7
    maxsize 100M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    dateext
}
EOF

    echo -e "${YELLOW}[6/7] Firewall rules (CF=unlimited)...${NC}"
    setup_iptables_for_port "$PORT" || return 1
    # MED-4: verify the rules actually landed. Failed creates used
    # to be ignored (no set -e, no verification pass), so a lock
    # held past the 5 s wait or a backend error left the install
    # printing success with the port effectively closed (or CF
    # traffic rate-limited). Fail closed instead.
    if ! iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; then
        echo -e "${RED}Proxy port ACCEPT rule did not land - refusing to report success.${NC}" >&2
        return 1
    fi
    if ! iptables -S INPUT 2>/dev/null | grep -qF '3proxy_stats_in' || \
       ! iptables -S OUTPUT 2>/dev/null | grep -qF '3proxy_stats_out' || \
       ! iptables -S INPUT 2>/dev/null | grep -qF "3proxy_${PORT}"; then
        echo -e "${RED}Proxy stats/rate-limit rules did not land - refusing to report success.${NC}" >&2
        return 1
    fi

    # MED-3: on a 3proxy-only box nothing persists the firewall rules
    # (Anti-DDoS owns the restore service when it is installed). Give
    # the proxy its own restore unit, self-disabling the moment
    # Anti-DDoS appears (its service loads the same rules.v4 file).
    if [ ! -f /etc/antiddos/state.conf ]; then
        cat > /etc/systemd/system/nx-3proxy-restore.service << EOF
[Unit]
Description=NexoShield proxy firewall restore (3proxy-only installs)
After=network-pre.target
Before=network.target
[Service]
Type=oneshot
ExecCondition=/bin/sh -c 'test ! -f /etc/antiddos/state.conf'
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable nx-3proxy-restore.service >/dev/null 2>&1 || true
    fi

    # Cumulative traffic recording (v3.17.0): kernel counters reset
    # on every rule recreation and reboot, so snapshot their deltas
    # every 5 minutes into /etc/3proxy/traffic-total.state. The
    # script is generated from the live lib functions (single source
    # of truth - the same code the unit tests exercise), not a copy.
    # No -w wrapper here on purpose: every call below is guarded
    # (a contended lock just defers the snapshot/re-pin to the next
    # 5-minute run), and the wrapper string would break the
    # wave3 wrapper-count regression test.
    regen_proxy_traffic_accum 2>/dev/null || true
    cat > /etc/systemd/system/nx-proxy-traffic-accum.service << EOF
[Unit]
Description=NexoShield proxy traffic accumulator
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/nx-proxy-traffic-accum
[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/nx-proxy-traffic-accum.timer << EOF
[Unit]
Description=NexoShield proxy traffic accumulator (every 5 minutes)
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now nx-proxy-traffic-accum.timer 2>/dev/null || true
    /usr/local/bin/nx-proxy-traffic-accum 2>/dev/null || true

    echo -e "${YELLOW}[7/7] Bandwidth control...${NC}"
    # Detect main interface
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    MAIN_IF=${MAIN_IF:-eth0}
    if command -v tc >/dev/null 2>&1; then
        setup_tc "$MAIN_IF"
        save_tc_persistent "$MAIN_IF"
    else
        echo -e "${YELLOW}tc not available - bandwidth shaping skipped${NC}"
    fi

    systemctl daemon-reload
    systemctl enable 3proxy >/dev/null 2>&1
    systemctl restart 3proxy
    sleep 2

    SERVER_IP=$(get_server_ip)
    SERVER_IPV6=$(get_server_ipv6)

    # Verify service started
    if ! systemctl is-active 3proxy >/dev/null 2>&1; then
        echo -e "${RED}⚠ 3proxy failed to start! Checking logs...${NC}"
        journalctl -u 3proxy -n 20 --no-pager 2>/dev/null || true
        if [ -n "$_ROLLBACK_DIR" ] && [ -f "$_ROLLBACK_DIR/3proxy.cfg" ]; then
            echo -e "${YELLOW}Restoring the previous working configuration...${NC}"
            # Remove the new port's rules FIRST, while the config
            # still names the new port (so the snapshot-before-delete
            # inside covers it), then restore the old config + rules.
            remove_proxy_port_rules "$PORT" 2>/dev/null || true
            cp -a "$_ROLLBACK_DIR/3proxy.cfg" "$PROXY_CONF" 2>/dev/null || true
            [ -f "$_ROLLBACK_DIR/install.info" ] && cp -a "$_ROLLBACK_DIR/install.info" /etc/3proxy/install.info 2>/dev/null || true
            # A port change already deleted the old port's rules: the
            # restored service would listen behind no firewall rules
            # unless they are re-applied for the restored port.
            _RESTORED_PORT=$(grep -oP 'socks -p\K[0-9]+' "$PROXY_CONF" 2>/dev/null | head -1 || true)
            [ -n "$_RESTORED_PORT" ] && setup_iptables_for_port "$_RESTORED_PORT" 2>/dev/null || true
            systemctl restart 3proxy 2>/dev/null || true
            sleep 2
            if systemctl is-active 3proxy >/dev/null 2>&1; then
                echo -e "${GREEN}Previous configuration restored and the old service is running again.${NC}"
            else
                echo -e "${RED}WARNING: the previous configuration could not be restarted either - manual intervention needed.${NC}"
            fi
        fi
        [ -n "$_ROLLBACK_DIR" ] && rm -rf "$_ROLLBACK_DIR" 2>/dev/null || true
        return 1
    fi
    [ -n "$_ROLLBACK_DIR" ] && rm -rf "$_ROLLBACK_DIR" 2>/dev/null || true

    # LOW-12: install.info is written only AFTER the service-start
    # check passes, so a failed install never leaves install.info
    # describing a proxy that is not running.
    # Save install info
    mkdir -p /etc/3proxy
    cat > /etc/3proxy/install.info << EOF
PORT=$PORT
USER=$PROXY_USER
PASS=$PROXY_PASS
MAX_TOTAL_CONN=$MAX_TOTAL_CONN
INSTALL_DATE=$(date)
MAIN_IF=$MAIN_IF
EOF
    chmod 600 /etc/3proxy/install.info

    sep
    echo -e "${GREEN}✓ 3proxy SOCKS5 installed!${NC}"; sep
    echo -e "  Protocol : SOCKS5"
    echo -e "  Address  : ${GREEN}$SERVER_IP${NC}"
    echo -e "  Port     : ${GREEN}$PORT${NC}"
    echo -e "  User     : ${GREEN}$PROXY_USER${NC}"
    echo -e "  Password : ${GREEN}$PROXY_PASS${NC}"
    echo ""
    echo -e "  ${CYAN}Ready-to-use format:${NC}"
    echo -e "  ${GREEN}socks5://$PROXY_USER:$PROXY_PASS@$SERVER_IP:$PORT${NC}"
    [ -n "$SERVER_IPV6" ] && echo -e "  ${GREEN}socks5://$PROXY_USER:$PROXY_PASS@[$SERVER_IPV6]:$PORT${NC}"
    echo ""
    echo -e "  ${CYAN}Bandwidth control:${NC}"
    echo -e "  ${GREEN}CF IPs -> unlimited  |  Others -> 500Mbps${NC}"
    sep
    echo -e "  Status: ${GREEN}● Running${NC}"
    sep
}

uninstall_proxy() {
    sep; echo -e "${RED}Removing 3proxy...${NC}"; sep

    echo -e "${YELLOW}Stopping services...${NC}"

    # ── Stop & disable 3proxy ─────────────────────────────
    systemctl stop    3proxy 2>/dev/null || true
    systemctl disable 3proxy 2>/dev/null || true
    # Also stop any apt-installed 3proxy
    systemctl stop    3proxy.service 2>/dev/null || true

    # BUG-037: the auto-ban daemon belongs to the Anti-DDoS module, NOT
    # to 3proxy. It is not stopped, killed or removed here - uninstall
    # Anti-DDoS separately (antiddos.sh --remove) if you want it gone.

    # ── Stop & disable tc service ─────────────────────────
    # The tc setup is shared with Anti-DDoS; only remove it when the
    # Anti-DDoS module is not installed (BUG-015).
    if [ ! -f /etc/antiddos/state.conf ]; then
        systemctl stop    tc-proxy-limit  2>/dev/null || true
        systemctl disable tc-proxy-limit  2>/dev/null || true
    else
        echo -e "${CYAN}Anti-DDoS is installed - leaving shared tc setup in place.${NC}"
    fi

    # ── Detect port before removing config ────────────────
    PORT=$(get_current_port 2>/dev/null || true)
    # Fallback: read from install.info
    if [ -z "$PORT" ] && [ -f /etc/3proxy/install.info ]; then
        PORT=$(grep -oP '(?<=^PORT=)\d+' /etc/3proxy/install.info 2>/dev/null | head -1 || true)
    fi

    # ── Remove iptables rules ─────────────────────────────
    if [ -n "$PORT" ]; then
        echo -e "${YELLOW}Cleaning iptables rules for port $PORT...${NC}"
        # CF-specific port rules (delete spec mirrors create, incl. the
        # comment match - BUG-013)
        for CF in "${CF_RANGES[@]}"; do
            [[ "$CF" == *":"* ]] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" \
                -m comment --comment "3proxy_cf_allow" -j ACCEPT 2>/dev/null || true
        done
        # User-whitelist rules for this port (Wave 1 create; remove here)
        if [ -f /etc/antiddos/whitelist.list ]; then
            while IFS= read -r WIP; do
                WIP="${WIP%%#*}"; WIP="${WIP// /}"
                [ -z "$WIP" ] && continue
                iptables -D INPUT -p tcp --dport "$PORT" -s "$WIP" \
                    -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
            done < /etc/antiddos/whitelist.list
        fi
        # Self-IP rules for this port
        while IFS= read -r SIP; do
            [ -z "$SIP" ] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
                -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
        done < <(list_self_ips_all)
        # Rate-limit rules for this port - by enumeration (BUG-014:
        # older versions created them with varying hitcounts)
        local _rn
        for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_${PORT}[^0-9]" | cut -d: -f1 | sort -rn); do
            iptables -D INPUT $((_rn - 1)) 2>/dev/null || true
        done
        # connlimit rule for this port
        iptables -D INPUT -p tcp --dport "$PORT" \
            -m connlimit --connlimit-above 30 --connlimit-mask 32 \
            -j REJECT --reject-with tcp-reset 2>/dev/null || true
        # hashlimit rules for this port
        iptables -D INPUT -p tcp --dport "$PORT" \
            -m conntrack --ctstate NEW \
            -m hashlimit --hashlimit-above 200/min --hashlimit-burst 50 \
            --hashlimit-mode srcip --hashlimit-name "proxy_${PORT}" -j DROP 2>/dev/null || true
        # Stats counters
        iptables -D INPUT  -p tcp --dport "$PORT" \
            -m comment --comment "3proxy_stats_in"  2>/dev/null || true
        iptables -D OUTPUT -p tcp --sport "$PORT" \
            -m comment --comment "3proxy_stats_out" 2>/dev/null || true
        # Plain ACCEPT rule
        iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
        # UFW / firewalld
        command -v ufw >/dev/null 2>&1 && ufw delete allow "$PORT"/tcp 2>/dev/null || true
        command -v firewall-cmd >/dev/null 2>&1 && {
            firewall-cmd --remove-port="${PORT}/tcp" --permanent 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
        }
    else
        echo -e "${YELLOW}⚠ Could not detect port — skipping port-specific iptables rules${NC}"
    fi

    # MED-2: the ruleset changed - rewrite the persistent saves from
    # the cleaned live state (same filter antiddos remove uses), or
    # the next boot resurrects the removed proxy rules. The
    # antiddos save is refreshed only if antiddos already owns one.
    if [ -d /etc/iptables ]; then
        iptables-save 2>/dev/null | grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    if [ -f /etc/antiddos/iptables-antiddos.rules ]; then
        iptables-save 2>/dev/null | grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' > /etc/antiddos/iptables-antiddos.rules 2>/dev/null || true
    fi

    # LOW-1: NO auto-ban cleanup here. The loop this replaces fed
    # `iptables -S` output (comments rendered quoted) through
    # word-splitting, so it never matched anything - and making it
    # work would mass-unban every daemon ban while the daemon keeps
    # running. Daemon bans belong to the daemon (BUG-037): it
    # expires them itself.

    # ── Remove tc bandwidth shaping ───────────────────────
    if [ ! -f /etc/antiddos/state.conf ]; then
        MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
        MAIN_IF=${MAIN_IF:-eth0}
        # LOW-13: the recorded pre-existing qdisc is dropped, not
        # restored - exact restore is infeasible from the one-line
        # record, so say so instead of silently dropping it.
        if [ -s /etc/antiddos/tc-qdisc-before.txt ]; then
            echo -e "${YELLOW}Note: the pre-existing qdisc ($(cat /etc/antiddos/tc-qdisc-before.txt 2>/dev/null)) is dropped on uninstall (exact restore is not possible from the one-line record).${NC}"
        fi
        tc qdisc del dev "$MAIN_IF" root 2>/dev/null || true
        rm -f /etc/systemd/system/tc-proxy-limit.service
        rm -f /etc/network/if-up.d/tc-proxy-limit
        rm -f /opt/proxy-manager/tc-setup.sh
    fi

    # ── Remove fail2ban jails for 3proxy ─────────────────
    rm -f /etc/fail2ban/jail.d/3proxy-ddos.conf   2>/dev/null || true
    rm -f /etc/fail2ban/jail.d/3proxy.conf        2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy-ddos.conf 2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy.conf      2>/dev/null || true
    command -v fail2ban-client >/dev/null 2>&1 && {
        fail2ban-client stop  3proxy-ddos 2>/dev/null || true
        # BUG-060: NO "unban --all" here - it released EVERY fail2ban
        # ban on the box (sshd brute-forcers included), not just ours.
        systemctl reload fail2ban 2>/dev/null || true
    }

    # ── Restore apt sources if the mirror was opted into (BUG-016) ──
    if [ -f /etc/apt/sources.list.bak ]; then
        mv /etc/apt/sources.list.bak /etc/apt/sources.list 2>/dev/null || true
        for _bak in /etc/apt/sources.list.d/*.bak; do
            [ -e "$_bak" ] && mv "$_bak" "${_bak%.bak}" 2>/dev/null || true
        done
        echo -e "${GREEN}Original apt sources restored from backup.${NC}"
    fi

    # ── Remove traffic accumulator (v3.17.0) ─────────────
    systemctl stop    nx-proxy-traffic-accum.timer 2>/dev/null || true
    systemctl disable nx-proxy-traffic-accum.timer 2>/dev/null || true
    rm -f /etc/systemd/system/nx-proxy-traffic-accum.service
    rm -f /etc/systemd/system/nx-proxy-traffic-accum.timer
    rm -f /usr/local/bin/nx-proxy-traffic-accum

    # ── Remove the proxy's own restore unit (MED-3) ──────
    # Anti-DDoS's restore service, when present, owns rules.v4
    # instead; this unit self-disables there, but uninstall removes
    # it outright.
    systemctl stop    nx-3proxy-restore.service 2>/dev/null || true
    systemctl disable nx-3proxy-restore.service 2>/dev/null || true
    rm -f /etc/systemd/system/nx-3proxy-restore.service

    # ── Remove systemd service files ─────────────────────
    rm -f "$SERVICE_FILE"
    [ -f /etc/antiddos/state.conf ] || rm -f /etc/systemd/system/tc-proxy-limit.service

    # ── Remove binary ─────────────────────────────────────
    # Only remove our binary — don't touch apt-installed one if it differs
    if [ -L "$PROXY_BIN" ]; then
        rm -f "$PROXY_BIN"   # it's a symlink we created
    elif [ -f "$PROXY_BIN" ]; then
        rm -f "$PROXY_BIN"   # compiled binary we installed
    fi

    # ── Remove config, logs, state ────────────────────────
    rm -rf /etc/3proxy
    rm -rf "$PROXY_LOG_DIR"
    rm -f  /etc/logrotate.d/3proxy
    # BUG-015: /etc/antiddos, /var/lib/antiddos, the daemon log and its
    # state files belong to the Anti-DDoS module and are NOT touched.
    # Remove the dedicated nexoproxy user (created by this module for
    # the proxy service; the service is already stopped above).
    id nexoproxy >/dev/null 2>&1 && \
        userdel nexoproxy 2>/dev/null || true

    # ── Reload systemd ────────────────────────────────────
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed  2>/dev/null || true

    sep
    echo -e "${GREEN}✓ 3proxy and all related components removed.${NC}"
    echo -e "${YELLOW}  Note: Anti-DDoS iptables rules (SYN/UDP/connlimit) are kept${NC}"
    echo -e "${YELLOW}  to protect the server. Run 'antiddos --remove' to remove them too.${NC}"
    sep
    sleep 2
}

show_info() {
    [ ! -f /etc/3proxy/install.info ] && echo -e "${RED}Not installed.${NC}" && return 1
    local _INFO_USER _INFO_PASS _INFO_PORT
    _INFO_USER=$(grep '^USER=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    _INFO_PASS=$(grep '^PASS=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    _INFO_PORT=$(grep '^PORT=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    SERVER_IP=$(get_server_ip)
    sep
    echo -e "  ${CYAN}Connection info:${NC}"; sep
    if [ -n "$_INFO_USER" ]; then
        echo -e "  socks5://${_INFO_USER}:${_INFO_PASS:-?}@$SERVER_IP:${_INFO_PORT:-?}"
    else
        echo -e "  socks5://$SERVER_IP:${_INFO_PORT:-?}  ${YELLOW}(no authentication)${NC}"
    fi
    # (No IPv6 form: 3proxy binds 0.0.0.0 only - BUG-059.)
    sep
}

show_stats() {
    PORT=$(get_current_port || true)
    [ -z "$PORT" ] && echo -e "${RED}Not installed.${NC}" && return 1
    sep; echo -e "  ${CYAN}Stats - port $PORT${NC}"; sep
    # LOW-10: count only flows whose LOCAL side is the proxy port.
    # The old grep matched the peer side too (":$PORT " appears in
    # either column), inflating the count with outbound flows.
    ACTIVE=$(ss -tnp state established 2>/dev/null | awk -v p=":$PORT" '$5 ~ p"$" {c++} END {print c+0}')
    ACTIVE="${ACTIVE:-0}"
    echo -e "  Active connections: ${GREEN}$ACTIVE${NC}"

    IN_B=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "3proxy_stats_in" | awk '{print $2}' | head -1)
    OUT_B=$(iptables -L OUTPUT -v -n -x 2>/dev/null | grep "3proxy_stats_out" | awk '{print $2}' | head -1)

    _fmt() {
        # Format bytes without depending on `bc` (absent on some systems → used to show blank)
        awk -v n="${1:-0}" 'BEGIN{
            if (n>=1073741824) printf "%.2f GB\n", n/1073741824;
            else if (n>=1048576) printf "%.2f MB\n", n/1048576;
            else if (n>=1024) printf "%.2f KB\n", n/1024;
            else printf "%d B\n", n;
        }'
    }
    # 3proxy_stats_in  = bytes clients SENT to proxy (upload)
    # 3proxy_stats_out = bytes proxy   SENT to clients (download)
    echo -e "  Download (proxy -> client): ${GREEN}$(_fmt "$OUT_B")${NC}"
    echo -e "  Upload   (client -> proxy): ${GREEN}$(_fmt "$IN_B")${NC}"

    # Cumulative totals (v3.17.0): the kernel counters above reset
    # on rule recreation and reboot; the accumulator's state file
    # is the recorded history. Absent before the first 5-minute run.
    if [ -f /etc/3proxy/traffic-total.state ]; then
        _TOT_IN=$(awk '{print $3}' /etc/3proxy/traffic-total.state 2>/dev/null || true)
        _TOT_OUT=$(awk '{print $4}' /etc/3proxy/traffic-total.state 2>/dev/null || true)
        echo -e "  Total recorded (cumulative): Download ${GREEN}$(_fmt "${_TOT_OUT:-0}")${NC} / Upload ${GREEN}$(_fmt "${_TOT_IN:-0}")${NC}"
    fi

    # tc stats
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -n "$MAIN_IF" ] && command -v tc >/dev/null 2>&1; then
        echo ""
        echo -e "  ${CYAN}Bandwidth classes (tc):${NC}"
        tc -s class show dev "$MAIN_IF" 2>/dev/null | \
            grep -A2 "class htb" | grep -E "class htb|bytes" | \
            paste - - | awk -F'\t' '{printf "  %-30s %s\n", $1, $2}' | head -6 || true
    fi

    # 3proxy rotates daily: live file is access.log.YYYY.MM.DD (T-2).
    _LF=$(ls -t "$PROXY_LOG_DIR"/access.log* 2>/dev/null | head -1 || true)
    [ -n "$_LF" ] && {
        echo ""
        echo -e "  ${CYAN}Last 10 connections:${NC}"
        tail -10 "$_LF" 2>/dev/null || true
    }
    sep
    printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true
}

show_menu() {
    clear; sep; echo -e "  ${CYAN}3proxy SOCKS5 Manager${NC}"; sep
    is_installed && {
        PORT=$(get_current_port || true)
        ST=$(systemctl is-active 3proxy 2>/dev/null || echo "unknown")
        [ "$ST" = "active" ] && \
            echo -e "  Status: ${GREEN}● Running${NC}  Port: ${CYAN}$PORT${NC}" || \
            echo -e "  Status: ${RED}● Stopped${NC}  Port: ${CYAN}$PORT${NC}"
        sep
    }
    echo -e "  ${CYAN}1.${NC} Install/Update   ${CYAN}2.${NC} Remove"
    echo -e "  ${CYAN}3.${NC} Stop             ${CYAN}4.${NC} Restart"
    echo -e "  ${CYAN}5.${NC} Traffic stats    ${CYAN}6.${NC} Connection info"
    echo -e "  ${CYAN}7.${NC} Live log         ${CYAN}8.${NC} tc bandwidth status"
    echo -e "  ${CYAN}0.${NC} Back"
    sep
}

# delete_proxy_user: remove the SOCKS credentials entirely. The
# users file is emptied (the config's `include` stays valid), the
# config switches auth strong -> none and the per-user allow becomes
# allow *, and install.info is cleared so every display agrees.
# Re-running Install/Update generates fresh credentials (the install
# path already treats an empty users file as "no credentials").
# The caller (menu) confirms: this OPENS the proxy to anyone who can
# reach the port. SSRF deny rules for private ranges stay in place.
delete_proxy_user() {
    local _cu
    _cu=$(grep -oP '(?<=^users )\S+(?=:CL:)' "$PROXY_USERS" 2>/dev/null | head -1 || true)
    if [ -z "$_cu" ]; then
        echo -e "${YELLOW}No proxy user configured - authentication is already off.${NC}"
        return 0
    fi
    : > "$PROXY_USERS" || { echo -e "${RED}Cannot write $PROXY_USERS${NC}"; return 1; }
    chgrp nexoproxy "$PROXY_USERS" 2>/dev/null || true
    chmod 640 "$PROXY_USERS" 2>/dev/null || true
    sed -i 's/^auth strong/auth none/' "$PROXY_CONF" 2>/dev/null || true
    sed -i -E 's/^allow [^ ]+/allow */' "$PROXY_CONF" 2>/dev/null || true
    if [ -f /etc/3proxy/install.info ]; then
        sed -i 's/^USER=.*/USER=/' /etc/3proxy/install.info 2>/dev/null || true
        sed -i 's/^PASS=.*/PASS=/' /etc/3proxy/install.info 2>/dev/null || true
    fi
    if systemctl restart 3proxy 2>/dev/null; then
        echo -e "${GREEN}Proxy user '${_cu}' and its password deleted - authentication is OFF.${NC}"
        echo -e "${YELLOW}Anyone who can reach the port can now use this proxy. Run Install/Update to set new credentials.${NC}"
        return 0
    fi
    echo -e "${RED}Credentials removed but the 3proxy restart FAILED - check: systemctl status 3proxy${NC}"
    return 1
}

# set_proxy_password: the mirror of delete_proxy_user.
# - A user exists: rotate its password (BUG-026 semantics).
# - No user (authentication OFF, e.g. after Delete user): CREATE
#   fresh credentials and switch authentication back ON in the
#   live config. The old --change-pass read the username from the
#   config's allow line, which is "allow *" in the off state - it
#   wrote a literal user named "*" while auth stayed none, so
#   credentials could never be set again after a delete.
set_proxy_password() {
    local NEW_PASS CU
    if [ ! -f "$PROXY_CONF" ]; then
        echo -e "${RED}Not installed${NC}"
        return 1
    fi
    NEW_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16)
    if [ -z "$NEW_PASS" ]; then
        echo -e "${RED}Failed to generate a secure password (/dev/urandom unavailable). Aborting.${NC}" >&2
        return 1
    fi
    CU=$(grep -oP '(?<=^users )\S+(?=:CL:)' "$PROXY_USERS" 2>/dev/null | head -1 || true)
    if [ -n "$CU" ]; then
        echo "users ${CU}:CL:${NEW_PASS}" > "$PROXY_USERS" || return 1
        if [ -f /etc/3proxy/install.info ]; then
            sed -i "s/^PASS=.*/PASS=${NEW_PASS}/" /etc/3proxy/install.info 2>/dev/null || true
        fi
        if systemctl restart 3proxy 2>/dev/null; then
            echo -e "${GREEN}Password changed for user '${CU}': ${NEW_PASS}${NC}"
            return 0
        fi
        echo -e "${RED}Password written but the 3proxy restart FAILED - check: systemctl status 3proxy${NC}"
        return 1
    fi
    # No credentials configured: create a fresh user (same
    # generator as the installer) and re-enable authentication.
    CU=$(tr -dc 'a-z' </dev/urandom 2>/dev/null | head -c 8)
    [ -n "$CU" ] || CU="proxyuser"
    echo "users ${CU}:CL:${NEW_PASS}" > "$PROXY_USERS" || return 1
    chgrp nexoproxy "$PROXY_USERS" 2>/dev/null || true
    chmod 640 "$PROXY_USERS" 2>/dev/null || true
    sed -i 's/^auth none/auth strong/' "$PROXY_CONF" 2>/dev/null || true
    sed -i -E "s/^allow [^ ]+/allow ${CU}/" "$PROXY_CONF" 2>/dev/null || true
    if [ -f /etc/3proxy/install.info ]; then
        sed -i "s/^USER=.*/USER=${CU}/" /etc/3proxy/install.info 2>/dev/null || true
        sed -i "s/^PASS=.*/PASS=${NEW_PASS}/" /etc/3proxy/install.info 2>/dev/null || true
    fi
    if systemctl restart 3proxy 2>/dev/null; then
        echo -e "${GREEN}Credentials created - authentication is ON.${NC}"
        echo -e "  User: ${GREEN}${CU}${NC}   Password: ${GREEN}${NEW_PASS}${NC}"
        return 0
    fi
    echo -e "${RED}Credentials written but the 3proxy restart FAILED - check: systemctl status 3proxy${NC}"
    return 1
}

# ── CLI flags (called from proxy-menu.sh) ────────────────
# MED-6: every flag propagates the action's exit code (the old code
# exited 0 regardless, so wrappers and monitoring could not detect
# a failed install/remove). F6: unknown flags error out instead of
# silently falling through to the interactive menu.
case "${1:-}" in
    --install|-i) install_proxy;  exit $? ;;
    --remove|-r)  uninstall_proxy; exit $? ;;
    --stats|-s)   show_stats;      exit $? ;;
    --info)       show_info; _rc=$?; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; exit "$_rc" ;;
    --restart)    if systemctl restart 3proxy 2>/dev/null; then echo -e "${GREEN}Restarted${NC}"; exit 0; else echo -e "${RED}Error${NC}"; exit 1; fi ;;
    --stop)       if systemctl stop 3proxy 2>/dev/null; then echo -e "${GREEN}Stopped${NC}"; exit 0; else echo -e "${RED}Error${NC}"; exit 1; fi ;;
    --start)      if systemctl start 3proxy 2>/dev/null; then echo -e "${GREEN}Started${NC}"; exit 0; else echo -e "${RED}Error${NC}"; exit 1; fi ;;
    --delete-user) delete_proxy_user; exit $? ;;
    --log)        tail -f "$PROXY_LOG_DIR"/access.log.* 2>/dev/null || \
                      journalctl -u 3proxy -f --no-pager; exit $? ;;
    --tc-status)  MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
                  echo -e "${CYAN}tc classes on ${MAIN_IF:-eth0}:${NC}"
                  tc class show dev "${MAIN_IF:-eth0}" 2>/dev/null || echo "tc not configured"
                  printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; exit 0 ;;
    --change-pass) set_proxy_password; exit $? ;;
    --regen-accumulator) regen_proxy_traffic_accum; exit $? ;;
    *)  if [ -n "${1:-}" ]; then echo "Unknown option: $1 (usage: 3proxy-socks5.sh [--install|--remove|--stats|--info|--restart|--stop|--start|--log|--tc-status|--delete-user|--change-pass])" >&2; exit 2; fi ;;
esac

# Standalone mode (run directly without args): show own menu
# LOW-8: without a terminal every /dev/tty read below fails
# instantly and the loop spins forever - refuse plainly instead.
if ! : </dev/tty 2>/dev/null; then
    echo "3proxy menu requires a terminal (use CLI flags for scripting)." >&2
    exit 1
fi
while true; do
    show_menu
    printf '%s' "  Enter choice: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) install_proxy; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) printf '%s' "  Remove 3proxy completely? (y/N): " >/dev/tty; read -r _RC2 </dev/tty || _RC2=""
           [[ "$_RC2" == "y" || "$_RC2" == "Y" ]] && uninstall_proxy || echo -e "  ${DIM}Cancelled.${NC}" ;;
        3) systemctl stop 3proxy 2>/dev/null && \
               echo -e "${GREEN}Stopped${NC}" || \
               echo -e "${RED}Error stopping${NC}"; sleep 1 ;;
        4) systemctl restart 3proxy 2>/dev/null && \
               echo -e "${GREEN}Restarted${NC}" || \
               echo -e "${RED}Error restarting${NC}"; sleep 1 ;;
        5) show_stats ;;
        6) show_info; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        7) tail -f "$PROXY_LOG_DIR"/access.log.* 2>/dev/null || \
               journalctl -u 3proxy -f --no-pager ;;
        8) MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
           echo -e "${CYAN}tc classes on ${MAIN_IF:-eth0}:${NC}"
           tc class show dev "${MAIN_IF:-eth0}" 2>/dev/null || echo "tc not configured"
           printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
PROXY_SCRIPT

# ══════════════════════════════════════════════════════════
# File 2: optimize-sysctl.sh
# ══════════════════════════════════════════════════════════
cat > "$INSTALL_DIR/.optimize-sysctl.sh.nxnew" << 'SYSCTL_SCRIPT'
#!/bin/bash
# shellcheck disable=SC2015,SC2094
# Reviewed idioms (Wave 10): SC2015 - `cond && ok-print || err-print`
# chains whose middle command is a print helper that cannot fail;
# SC2094 - atomic state writes via tmp-file + rename, which the
# checker flags as same-file pipelines. Both classes were audited
# site-by-site during the fix waves (docs/FIX-PLAN.md).
set -uo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
TARGET_FILE="/etc/sysctl.d/99-vpn-optimized.conf"
SNAPSHOT_DIR="/var/lib/vpn-sysctl-snapshots"
LOG_FILE="/var/log/vpn-sysctl-optimizer.log"
LOCK_FILE="/var/run/vpn-sysctl.lock"
SCRIPT_VERSION="3.19.0"

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1

log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }
info()    { echo -e "  ${CYAN}i${NC}  $*"; log "INFO: $*"; }
success() { echo -e "  ${GREEN}✓${NC}  $*"; log "OK: $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; log "WARN: $*"; }
err()     { echo -e "  ${RED}✗${NC}  $*"; log "ERR: $*"; }
sep()     { echo -e "${CYAN}════════════════════════════════════════════════${NC}"; }

acquire_lock() {
    # Real mutual exclusion (BUG-054): the old pidfile check-then-write
    # had a race window and broke on PID reuse. flock on an open fd is
    # atomic and releases automatically if the holder dies.
    exec 9>"$LOCK_FILE" 2>/dev/null || return 0
    if ! flock -n 9; then
        err "Already running (another optimization holds the lock)"
        exit 1
    fi
    echo $$ >&9 2>/dev/null || true
}
release_lock() { flock -u 9 2>/dev/null || true; }
trap release_lock EXIT INT TERM

detect_environment() {
    info "Analyzing server..."
    RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 1048576)
    RAM_KB="${RAM_KB//[^0-9]/}"; RAM_KB="${RAM_KB:-1048576}"
    RAM_MB=$((RAM_KB / 1024))
    CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
    CPU_CORES="${CPU_CORES//[^0-9]/}"; CPU_CORES="${CPU_CORES:-1}"
    KERNEL=$(uname -r)
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_NAME="${NAME:-Unknown}"
        OS_VERSION="${VERSION_ID:-}"
    else
        OS_NAME="Unknown"; OS_VERSION=""
    fi

    HAS_IPV4=0; HAS_IPV6=0; IPV4_COUNT=0; IPV6_COUNT=0
    if ip -4 addr show 2>/dev/null | grep -q 'inet '; then
        HAS_IPV4=1
        IPV4_COUNT=$(ip -4 addr show 2>/dev/null | grep -c 'inet ' || echo 0)
    fi
    if ip -6 addr show 2>/dev/null | grep -v '::1\|fe80' | grep -q 'inet6'; then
        HAS_IPV6=1
        IPV6_COUNT=$(ip -6 addr show 2>/dev/null | grep -v '::1\|fe80' | grep -c 'inet6' || echo 0)
    fi

    PUBLIC_IP_COUNT=$(ip -4 addr show 2>/dev/null | grep 'inet ' | \
        grep -cv '127\.\|10\.\|192\.168\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.' || true)
    PUBLIC_IP_COUNT="${PUBLIC_IP_COUNT:-0}"


    BBR_AVAILABLE=0
    modprobe tcp_bbr 2>/dev/null || true
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        BBR_AVAILABLE=1
    fi

    CONNTRACK_AVAILABLE=0
    if modprobe nf_conntrack 2>/dev/null; then CONNTRACK_AVAILABLE=1; fi

    VIRT_TYPE="bare-metal"
    if [ -f /proc/vz/version ]; then VIRT_TYPE="openvz"
    elif systemd-detect-virt 2>/dev/null | grep -qi kvm; then VIRT_TYPE="kvm"
    elif systemd-detect-virt 2>/dev/null | grep -qi lxc; then VIRT_TYPE="lxc"
    fi

    SWAP_TOTAL=$(grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
    HAS_SWAP=0; [ "${SWAP_TOTAL:-0}" -gt 0 ] && HAS_SWAP=1

    CURRENT_CONGESTION=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    CURRENT_RMEM=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    CURRENT_SWAPPINESS=$(sysctl -n vm.swappiness 2>/dev/null || echo 60)
}

calculate_values() {
    if [ "$RAM_MB" -ge 8192 ]; then
        BUF_MAX=268435456
        CONNTRACK_MAX=1048576; SOMAXCONN=65536; BACKLOG=65536; SYN_BACKLOG=32768
    elif [ "$RAM_MB" -ge 4096 ]; then
        BUF_MAX=134217728
        CONNTRACK_MAX=524288; SOMAXCONN=32768; BACKLOG=32768; SYN_BACKLOG=16384
    elif [ "$RAM_MB" -ge 2048 ]; then
        BUF_MAX=134217728
        CONNTRACK_MAX=262144; SOMAXCONN=32768; BACKLOG=32768; SYN_BACKLOG=16384
    elif [ "$RAM_MB" -ge 1024 ]; then
        BUF_MAX=67108864
        CONNTRACK_MAX=131072; SOMAXCONN=16384; BACKLOG=16384; SYN_BACKLOG=8192
    else
        BUF_MAX=33554432
        CONNTRACK_MAX=65536; SOMAXCONN=8192; BACKLOG=8192; SYN_BACKLOG=4096
    fi

    # BUG-010: net.ipv4.tcp_mem is measured in PAGES, not bytes - the
    # old tier constants were byte-magnitudes (6,291,456 "max" = 24 GiB
    # of pages on a big tier, no ceiling at all in practice). Derive
    # from RAM: pressure at 50% of RAM, ceiling at 75%, in pages.
    local _page_size _ram_pages
    _page_size=$(getconf PAGE_SIZE 2>/dev/null || echo 4096)
    _ram_pages=$(( RAM_MB * 1048576 / _page_size ))
    TCP_MEM_PRESSURE=$(( _ram_pages / 2 ))
    [ "$TCP_MEM_PRESSURE" -lt 131072 ] && TCP_MEM_PRESSURE=131072
    TCP_MEM_MAX=$(( _ram_pages * 3 / 4 ))
    [ "$TCP_MEM_MAX" -lt 262144 ] && TCP_MEM_MAX=262144

    [ "$BBR_AVAILABLE" -eq 1 ] && CONGESTION="bbr" || CONGESTION="cubic"
    QDISC="fq"

    # Multi-IP servers: rp_filter=0 (important for servers with multiple public IPs)
    [ "$PUBLIC_IP_COUNT" -gt 1 ] && RP_FILTER=0 || RP_FILTER=1
    # BUG-040: preserve the system's current forwarding setting - the
    # optimizer used to force ip_forward=1 even on hosts that had it
    # deliberately off (and hosts that need it on keep it on).
    IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
    [[ "$IP_FORWARD" =~ ^[01]$ ]] || IP_FORWARD=0
    [ "$HAS_SWAP" -eq 1 ] && SWAPPINESS=10 || SWAPPINESS=1
    [ "$VIRT_TYPE" = "openvz" ] && CONNTRACK_AVAILABLE=0 && BUF_MAX=$((BUF_MAX / 2))
}

take_snapshot() {
    SNAPSHOT_ID="$(date +%Y%m%d_%H%M%S)"
    SNAPSHOT_PATH="$SNAPSHOT_DIR/$SNAPSHOT_ID"
    mkdir -p "$SNAPSHOT_PATH"
    # Save full sysctl dump (for reference only)
    sysctl -a 2>/dev/null > "$SNAPSHOT_PATH/sysctl_values.txt" || true
    # Save ONLY the keys we actually change — used for targeted rollback
    {
        for KEY in \
            net.core.rmem_max net.core.wmem_max \
            net.core.rmem_default net.core.wmem_default \
            net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_mem \
            net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min net.ipv4.udp_mem \
            net.core.default_qdisc net.ipv4.tcp_congestion_control \
            net.ipv4.tcp_notsent_lowat net.ipv4.tcp_fin_timeout \
            net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl \
            net.ipv4.tcp_keepalive_probes net.ipv4.tcp_slow_start_after_idle \
            net.ipv4.tcp_fastopen net.ipv4.tcp_synack_retries \
            net.ipv4.tcp_syn_retries net.ipv4.tcp_tw_reuse \
            net.core.somaxconn net.core.netdev_max_backlog \
            net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_max_tw_buckets \
            net.ipv4.tcp_max_orphans net.ipv4.tcp_ecn \
            net.ipv4.tcp_mtu_probing net.ipv4.tcp_window_scaling \
            net.core.netdev_budget net.core.netdev_budget_usecs \
            net.netfilter.nf_conntrack_max \
            net.netfilter.nf_conntrack_tcp_timeout_established \
            net.netfilter.nf_conntrack_tcp_timeout_syn_recv \
            net.netfilter.nf_conntrack_tcp_timeout_time_wait \
            net.netfilter.nf_conntrack_tcp_timeout_fin_wait \
            net.netfilter.nf_conntrack_tcp_timeout_close_wait \
            net.netfilter.nf_conntrack_udp_timeout \
            net.netfilter.nf_conntrack_udp_timeout_stream \
            net.netfilter.nf_conntrack_icmp_timeout \
            net.netfilter.nf_conntrack_generic_timeout \
            net.ipv4.ip_forward net.ipv4.conf.all.rp_filter \
            net.ipv4.conf.default.rp_filter net.ipv4.tcp_syncookies \
            net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
            net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route \
            net.ipv4.conf.all.log_martians net.ipv4.icmp_echo_ignore_broadcasts \
            net.ipv4.icmp_ignore_bogus_error_responses \
            vm.swappiness vm.dirty_ratio vm.dirty_background_ratio \
            fs.file-max \
            net.ipv6.conf.all.forwarding \
            net.ipv6.conf.all.accept_redirects \
            net.ipv6.conf.default.accept_redirects \
            net.ipv6.route.max_size \
            net.ipv6.neigh.default.gc_thresh1 \
            net.ipv6.neigh.default.gc_thresh2 \
            net.ipv6.neigh.default.gc_thresh3; do
            V=$(sysctl -n "$KEY" 2>/dev/null) || continue
            echo "$KEY = $V"
        done
    } > "$SNAPSHOT_PATH/our_keys.txt"
    cp /etc/sysctl.conf "$SNAPSHOT_PATH/sysctl.conf" 2>/dev/null || true
    [ -d /etc/sysctl.d ] && cp -r /etc/sysctl.d "$SNAPSHOT_PATH/sysctl.d" 2>/dev/null || true
    # Record the exact list of sysctl.d files present at snapshot time.
    # Used by rollback to remove files that OUR script added after this snapshot,
    # without touching unrelated system files.
    ls /etc/sysctl.d/ 2>/dev/null > "$SNAPSHOT_PATH/sysctl_d_list.txt" || true
    cat > "$SNAPSHOT_PATH/meta.txt" << EOF
SNAPSHOT_ID=$SNAPSHOT_ID
DATE=$(date)
KERNEL=$(uname -r)
OS=$OS_NAME $OS_VERSION
RAM=${RAM_MB}MB
SCRIPT_VERSION=$SCRIPT_VERSION
EOF
    echo "$SNAPSHOT_ID"
}

write_config() {
    [ "$BBR_AVAILABLE" -eq 1 ] && \
        sysctl -w "net.ipv4.tcp_congestion_control=bbr" >/dev/null 2>&1 || \
        CONGESTION="cubic"

    cat > "$TARGET_FILE" << EOF
# VPN/Proxy sysctl Optimized — $(date)
# RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | OS: ${OS_NAME} | Kernel: ${KERNEL} | Virt: ${VIRT_TYPE}
# rollback: proxy -> Network Optimization -> Rollback
net.core.rmem_max = $BUF_MAX
net.core.wmem_max = $BUF_MAX
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 32768 262144 $BUF_MAX
net.ipv4.tcp_wmem = 32768 262144 $BUF_MAX
net.ipv4.tcp_mem = 65536 $TCP_MEM_PRESSURE $TCP_MEM_MAX
EOF
    [ "$HAS_IPV4" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536
net.ipv4.udp_mem = 65536 262144 786432
EOF
    cat >> "$TARGET_FILE" << EOF
net.core.default_qdisc = $QDISC
net.ipv4.tcp_congestion_control = $CONGESTION
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = $SOMAXCONN
net.core.netdev_max_backlog = $BACKLOG
net.ipv4.tcp_max_syn_backlog = $SYN_BACKLOG
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 4000
EOF
    [ "$CONNTRACK_AVAILABLE" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.netfilter.nf_conntrack_max = $CONNTRACK_MAX
net.netfilter.nf_conntrack_tcp_timeout_established = 120
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 8
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_udp_timeout = 15
# stream=120: WARP/WireGuard keepalive (25s) must never expire the tunnel.
# 120 = ~5x keepalive — absorbs packet-loss/jitter, still < kernel default (180).
# UDP-flood protection comes from hashlimit, not this timeout, so it's safe.
net.netfilter.nf_conntrack_udp_timeout_stream = 120
net.netfilter.nf_conntrack_icmp_timeout = 5
net.netfilter.nf_conntrack_generic_timeout = 60
EOF
    [ "$HAS_IPV4" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.ipv4.ip_forward = $IP_FORWARD
net.ipv4.conf.all.rp_filter = $RP_FILTER
net.ipv4.conf.default.rp_filter = $RP_FILTER
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
    [ "$HAS_IPV6" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.ipv6.conf.all.forwarding = $IP_FORWARD
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.route.max_size = 409600
net.ipv6.neigh.default.gc_thresh1 = 1024
net.ipv6.neigh.default.gc_thresh2 = 4096
net.ipv6.neigh.default.gc_thresh3 = 8192
EOF
    cat >> "$TARGET_FILE" << EOF
fs.file-max = 1048576
vm.swappiness = $SWAPPINESS
vm.dirty_ratio = 5
vm.dirty_background_ratio = 2
EOF
    chmod 644 "$TARGET_FILE"
}


# nx_sysctl_parse <line> — split "key = value" WITHOUT destroying
# multi-token values (BUG-007: cut + tr -d ' ' glued "32768 262144
# 67108864" into one giant number, so the tcp_rmem/tcp_wmem/tcp_mem
# writes always failed kernel validation and were auto-disabled -
# silently, on every install). Whitespace runs (spaces, or the tabs
# sysctl -n emits) collapse to single spaces.
nx_sysctl_parse() {
    NX_KEY="${1%%=*}"
    NX_KEY="${NX_KEY//[[:space:]]/}"
    NX_VAL="${1#*=}"
    NX_VAL="$(printf '%s' "$NX_VAL" | tr -s '[:space:]' ' ')"
    NX_VAL="${NX_VAL# }"; NX_VAL="${NX_VAL% }"
}
apply_config() {
    FAILED_PARAMS=(); APPLIED_COUNT=0; SKIPPED_COUNT=0
    # BUG-042: on a read-only /proc/sys (OpenVZ and friends) EVERY
    # write fails - and the old flow reacted by permanently commenting
    # the parameters out of the generated config. Detect it once, up
    # front, and change nothing.
    if [ ! -w /proc/sys/net/core/rmem_max ] && [ ! -w /proc/sys/net/ipv4/tcp_rmem ]; then
        warn "sysctl is read-only on this system (virtualization limit) - nothing was changed"
        return 1
    fi
    if [ "${VIRT_TYPE:-}" != "openvz" ]; then
        modprobe tcp_bbr 2>/dev/null || true
        modprobe nf_conntrack 2>/dev/null || true
    fi

    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        nx_sysctl_parse "$line"; KEY="$NX_KEY"; VAL="$NX_VAL"
        [ -z "$KEY" ] || [ -z "$VAL" ] && continue
        if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
            APPLIED_COUNT=$((APPLIED_COUNT + 1))
        else
            FAILED_PARAMS+=("$KEY=$VAL")
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            sed -i "s|^${KEY} = |# [DISABLED] ${KEY} = |g" "$TARGET_FILE" 2>/dev/null || true
        fi
    done < "$TARGET_FILE"

    [ ${#FAILED_PARAMS[@]} -gt 0 ] && warn "${#FAILED_PARAMS[@]} params auto-disabled (virt limits)"
    success "$APPLIED_COUNT applied${SKIPPED_COUNT:+, $SKIPPED_COUNT skipped}"
}

do_rollback() {
    sep; echo -e "  ${CYAN}${BOLD}Rollback${NC}"; sep

    # ── Find snapshots ────────────────────────────────────
    SNAPSHOTS=()
    while IFS= read -r d; do
        [ -d "$SNAPSHOT_DIR/$d" ] && SNAPSHOTS+=("$d")
    done < <(ls -1t "$SNAPSHOT_DIR" 2>/dev/null | head -10)

    if [ ${#SNAPSHOTS[@]} -eq 0 ]; then
        err "No snapshots found in $SNAPSHOT_DIR"
        echo -e "  ${DIM}Snapshots are created automatically before each install.${NC}"
        return
    fi

    # ── List snapshots ────────────────────────────────────
    echo -e "  Available snapshots:"
    echo ""
    for i in "${!SNAPSHOTS[@]}"; do
        DATE=$(grep '^DATE=' "$SNAPSHOT_DIR/${SNAPSHOTS[$i]}/meta.txt" 2>/dev/null | \
            cut -d= -f2- || echo "${SNAPSHOTS[$i]}")
        # Mark if this was a pre-install snapshot
        HAS_KEYS=""; [ -f "$SNAPSHOT_DIR/${SNAPSHOTS[$i]}/our_keys.txt" ] && HAS_KEYS=" ${DIM}(targeted)${NC}"
        echo -e "  ${CYAN}$((i+1)).${NC} ${SNAPSHOTS[$i]}  ${DIM}$DATE${NC}${HAS_KEYS}"
    done
    echo ""

    # ── Select ────────────────────────────────────────────
    printf '%s' "  Which snapshot? (1-${#SNAPSHOTS[@]}, default 1): " >/dev/tty
    read -r CH </dev/tty || CH="1"
    CH=${CH:-1}
    if ! [[ "$CH" =~ ^[0-9]+$ ]] || [ "$CH" -lt 1 ] || [ "$CH" -gt ${#SNAPSHOTS[@]} ]; then
        err "Invalid selection: '$CH'"
        return
    fi

    SELECTED="${SNAPSHOTS[$((CH-1))]}"
    SPATH="$SNAPSHOT_DIR/$SELECTED"
    DATE_SEL=$(grep '^DATE=' "$SPATH/meta.txt" 2>/dev/null | cut -d= -f2- || echo "$SELECTED")

    echo ""
    echo -e "  Snapshot : ${CYAN}$SELECTED${NC}"
    echo -e "  Date     : $DATE_SEL"
    echo ""

    # ── Confirm ───────────────────────────────────────────
    printf '%s' "  Confirm rollback? (y/N): " >/dev/tty
    read -r CF </dev/tty || CF=""
    [[ "$CF" != "y" && "$CF" != "Y" ]] && echo "  Cancelled." && return

    echo ""
    info "Starting rollback to $SELECTED..."

    # ── Step 1: Remove our config file ───────────────────
    rm -f "$TARGET_FILE"
    success "Removed: $TARGET_FILE"

    # ── Step 2: Remove any of OUR config files added after this snapshot ──
    # TARGET_FILE was already removed above. This also catches leftover files
    # from OLDER installs of this script that are NOT in the snapshot's list,
    # without touching unrelated system files in /etc/sysctl.d/.
    if [ -f "$SPATH/sysctl_d_list.txt" ]; then
        local TBASE
        TBASE="$(basename "$TARGET_FILE")"
        while IFS= read -r CURF; do
            [ -z "$CURF" ] && continue
            # Only remove files that belong to OUR script (match TARGET_FILE name
            # or the standard 99-vpn pattern) AND were not present in snapshot.
            if ! grep -qxF "$CURF" "$SPATH/sysctl_d_list.txt" 2>/dev/null; then
                case "$CURF" in
                    "$TBASE"|99-vpn-*.conf)
                        rm -f "/etc/sysctl.d/$CURF" 2>/dev/null && \
                            success "Removed stale: /etc/sysctl.d/$CURF" || true
                        ;;
                esac
            fi
        done < <(ls /etc/sysctl.d/ 2>/dev/null)
    fi

    # ── Step 3: Restore .conf files from snapshot ────────
    if [ -f "$SPATH/sysctl.conf" ]; then
        cp "$SPATH/sysctl.conf" /etc/sysctl.conf 2>/dev/null && \
            success "Restored: /etc/sysctl.conf" || warn "Could not restore sysctl.conf"
    fi
    # Only restore sysctl.d files that existed in snapshot (don't add new ones)
    if [ -d "$SPATH/sysctl.d" ]; then
        for f in "$SPATH/sysctl.d/"*.conf; do
            [ -f "$f" ] || continue
            BNAME="$(basename "$f")"
            # Don't restore our own file (already deleted above)
            [ "$BNAME" = "$(basename "$TARGET_FILE")" ] && continue
            cp "$f" "/etc/sysctl.d/$BNAME" 2>/dev/null && \
                success "Restored: /etc/sysctl.d/$BNAME" || \
                warn "Could not restore: $BNAME"
        done
    fi

    # ── Step 4: Re-apply sysctl values live ──────────────
    # Use our_keys.txt (targeted — only keys we changed)
    # Fall back to sysctl_values.txt only if our_keys.txt missing (old snapshot)
    R=0; F=0; SKIP=0
    KEYS_FILE=""
    [ -f "$SPATH/our_keys.txt" ] && KEYS_FILE="$SPATH/our_keys.txt"

    if [ -n "$KEYS_FILE" ]; then
        info "Applying targeted rollback (${KEYS_FILE##*/})..."
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line//[[:space:]]/}" ]] && continue
            nx_sysctl_parse "$line"; KEY="$NX_KEY"; VAL="$NX_VAL"
            [ -z "$KEY" ] || [ -z "$VAL" ] && SKIP=$((SKIP+1)) && continue
            if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
                R=$((R+1))
            else
                warn "Could not set: $KEY=$VAL"
                F=$((F+1))
            fi
        done < "$KEYS_FILE"
    else
        # Old snapshot: parse sysctl_values.txt — but ONLY apply our known keys
        info "Old snapshot — applying known keys from sysctl_values.txt..."
        KNOWN_KEYS="net.core.rmem_max net.core.wmem_max net.core.default_qdisc \
            net.ipv4.tcp_congestion_control net.ipv4.tcp_keepalive_time \
            net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_tw_reuse \
            net.ipv4.tcp_fin_timeout net.ipv4.tcp_max_orphans \
            vm.swappiness net.core.somaxconn net.ipv4.tcp_syncookies"
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line//[[:space:]]/}" ]] && continue
            nx_sysctl_parse "$line"; KEY="$NX_KEY"; VAL="$NX_VAL"
            [ -z "$KEY" ] || [ -z "$VAL" ] && continue
            echo "$KNOWN_KEYS" | grep -qw "$KEY" || { SKIP=$((SKIP+1)); continue; }
            if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
                R=$((R+1))
            else
                F=$((F+1))
            fi
        done < "$SPATH/sysctl_values.txt"
    fi

    sep
    success "Rollback complete — $R restored${F:+, $F failed}${SKIP:+ ($SKIP skipped)}"
    echo -e "  ${YELLOW}Note: Reboot to fully confirm all settings took effect.${NC}"
    sep
}

do_status() {
    sep; echo -e "  ${CYAN}${BOLD}sysctl Status${NC}"; sep
    for P in net.ipv4.tcp_congestion_control net.core.default_qdisc net.core.rmem_max \
              net.ipv4.tcp_notsent_lowat net.core.somaxconn net.ipv4.ip_forward \
              vm.swappiness net.netfilter.nf_conntrack_max \
              net.ipv4.tcp_keepalive_time net.ipv4.conf.all.rp_filter; do
        V=$(sysctl -n "$P" 2>/dev/null || echo "N/A")
        printf "  ${DIM}%-50s${NC} %s\n" "$P" "$V"
    done
    [ -f "$TARGET_FILE" ] && success "Config installed: $TARGET_FILE" || \
        warn "Config not installed"
    sep
}

show_server_info() {
    sep; echo -e "  ${CYAN}${BOLD}Server Analysis${NC}"; sep
    printf "  %-20s ${GREEN}%s${NC}\n" "OS:"        "$OS_NAME $OS_VERSION"
    printf "  %-20s ${GREEN}%s${NC}\n" "Kernel:"    "$KERNEL"
    printf "  %-20s ${GREEN}%s${NC}\n" "RAM:"       "${RAM_MB}MB"
    printf "  %-20s ${GREEN}%s${NC}\n" "CPU:"       "$CPU_CORES core(s)"
    printf "  %-20s ${GREEN}%s${NC}\n" "Virt:"      "$VIRT_TYPE"
    printf "  %-20s ${GREEN}%s${NC}\n" "IPv4:"      "$([ "$HAS_IPV4" -eq 1 ] && \
        echo "Yes ($IPV4_COUNT, $PUBLIC_IP_COUNT public)" || echo "No")"
    printf "  %-20s ${GREEN}%s${NC}\n" "IPv6:"      "$([ "$HAS_IPV6" -eq 1 ] && \
        echo "Yes ($IPV6_COUNT)" || echo "No")"
    printf "  %-20s ${GREEN}%s${NC}\n" "Swap:"      "$([ "$HAS_SWAP" -eq 1 ] && echo "Yes" || echo "No")"
    printf "  %-20s ${GREEN}%s${NC}\n" "BBR:"       "$([ "$BBR_AVAILABLE" -eq 1 ] && \
        echo "Available ✓" || echo "Not available")"
    printf "  %-20s ${GREEN}%s${NC}\n" "conntrack:" "$([ "$CONNTRACK_AVAILABLE" -eq 1 ] && \
        echo "Available ✓" || echo "Not available")"
    printf "  %-20s ${GREEN}%s${NC}\n" "Multi-IP:"  "$([ "$PUBLIC_IP_COUNT" -gt 1 ] && \
        echo "Yes (rp_filter=0)" || echo "No (rp_filter=1)")"
    echo ""
    echo -e "  ${CYAN}Proposed changes:${NC}"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "congestion:" "$CURRENT_CONGESTION" "$CONGESTION"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "rmem_max:" \
        "$(awk -v v="${CURRENT_RMEM:-0}" 'BEGIN{printf "%d", v/1048576}')MB" \
        "$(awk -v v="$BUF_MAX" 'BEGIN{printf "%d", v/1048576}')MB"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "swappiness:" "$CURRENT_SWAPPINESS" "$SWAPPINESS"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "keepalive_time:" "$(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || echo '?')" "30"
    sep
}

do_install() {
    show_server_info
    # Read from /dev/tty directly — always reliable
    printf '%s' "  Continue? (y/N): " >/dev/tty
    read -r CF </dev/tty || CF=""
    [[ "$CF" != "y" && "$CF" != "Y" ]] && echo "  Cancelled." && return

    mkdir -p "$SNAPSHOT_DIR"
    touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
    info "Taking snapshot..."
    SNAP_ID=$(take_snapshot)
    success "Snapshot: $SNAP_ID"
    info "Writing config..."
    write_config
    success "File: $TARGET_FILE"
    info "Applying settings..."
    apply_config
    sep
    success "Optimization complete!"
    echo -e "  ${CYAN}Rollback:${NC} proxy -> Network Optimization -> Rollback"
    sep
}

case "${1:-}" in
    --rollback|-r)  acquire_lock; detect_environment; calculate_values; do_rollback; exit 0 ;;
    --status|-s)    detect_environment; calculate_values; do_status; exit 0 ;;
    --analyze|-a)   detect_environment; calculate_values; show_server_info; exit 0 ;;
    --install|-i)   acquire_lock; detect_environment; calculate_values; do_install; exit 0 ;;
    --auto|-y)      acquire_lock; detect_environment; calculate_values
                    mkdir -p "$SNAPSHOT_DIR"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
                    SNAP_ID=$(take_snapshot); write_config; apply_config
                    success "Auto install complete - snapshot: $SNAP_ID"; exit 0 ;;
esac

acquire_lock; detect_environment; calculate_values

while true; do
    clear; sep
    echo -e "  ${CYAN}${BOLD}Network Optimization (sysctl) v${SCRIPT_VERSION}${NC}"; sep
    [ -f "$TARGET_FILE" ] && \
        echo -e "  Status: ${GREEN}✓ Installed${NC}" || \
        echo -e "  Status: ${YELLOW}○ Not installed${NC}"
    echo ""
    echo -e "  ${CYAN}1.${NC}  Install/Optimize     ${CYAN}2.${NC}  Rollback"
    echo -e "  ${CYAN}3.${NC}  Current status       ${CYAN}4.${NC}  Analyze (no changes)"
    echo -e "  ${CYAN}0.${NC}  Back"; sep
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) do_install; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) do_rollback; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        3) do_status; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        4) show_server_info; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
SYSCTL_SCRIPT

# ══════════════════════════════════════════════════════════
# File 3: proxy-menu.sh (main menu)
# ══════════════════════════════════════════════════════════
cat > "$INSTALL_DIR/.proxy-menu.sh.nxnew" << 'MENU_SCRIPT'
#!/bin/bash
# shellcheck disable=SC2015,SC2094
# Reviewed idioms (Wave 10): SC2015 - `cond && ok-print || err-print`
# chains whose middle command is a print helper that cannot fail;
# SC2094 - atomic state writes via tmp-file + rename, which the
# checker flags as same-file pipelines. Both classes were audited
# site-by-site during the fix waves (docs/FIX-PLAN.md).
VERSION="3.19.0"
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
#
# Before v3.7 every screen hand-rolled its own loop: 21 separate
# printf/read pairs against /dev/tty, four different confirmation
# idioms, headers drawn ad hoc, and no fallback when /dev/tty was
# unavailable (ssh without -t meant an infinite empty-read redraw).
# All screens now share this small framework:
#   ui_input VAR "prompt"  - one read idiom (tty, stdin fallback)
#   ui_confirm "question"  - the single (y/N) idiom
#   ui_title "A › B"       - header + breadcrumb title
#   ui_options "n|label|status" ... - aligned menu rows
#   ui_home_panel          - the dashboard summary on the main menu
# State locations are overridable for tests (NX_STATE_DIR,
# NX_SCORE_FILE); production defaults are the real paths.
NX_STATE_DIR="${NX_STATE_DIR:-/etc/antiddos}"
NX_SCORE_FILE="${NX_SCORE_FILE:-/var/lib/antiddos/scores/reputation.dat}"
# The daemon's LIVE throttle state is /run/nexoshield/autoban_throttle; the
# persistent mirror (U-11) is /etc/antiddos/throttled.list. Displays
# read the live file, falling back to the mirror right after a
# reboot before the daemon has restored its state.
NX_THROTTLE_LIST="${NX_THROTTLE_LIST:-/run/nexoshield/autoban_throttle}"
NX_THROTTLE_MIRROR="${NX_THROTTLE_MIRROR:-/etc/antiddos/throttled.list}"
nx_throttle_file() {
    if [ -f "$NX_THROTTLE_LIST" ]; then echo "$NX_THROTTLE_LIST";
    elif [ -f "$NX_THROTTLE_MIRROR" ]; then echo "$NX_THROTTLE_MIRROR"; fi
}

# nx_valid_ip_or_cidr <value> — menu-program twin of antiddos's
# validator (the menu cannot call that file). v4 octets are range
# checked and leading zeros rejected (L10: "010.0.0.1" is octal to
# some parsers, so it must never validate as 10.0.0.1); v6 uses the
# same charset/group rules as the antiddos validator, embedded-v4
# forms rejected.
nx_valid_ip_or_cidr() {
    local input="${1:-}" addr mask o
    case "$input" in
        */*) addr="${input%%/*}"; mask="${input#*/}" ;;
        *)   addr="$input"; mask="" ;;
    esac
    case "$addr" in
        *:*)
            case "$addr" in *[!0-9a-fA-F:.]*|*:::*|*.*) return 1 ;; esac
            case "$addr" in *::*) case "${addr#*::}" in *::*) return 1 ;; esac ;; esac
            if [ -n "$mask" ]; then
                case "$mask" in ''|*[!0-9]*) return 1 ;; esac
                [ "${#mask}" -le 3 ] || return 1
                (( 10#$mask <= 128 )) || return 1
            fi
            return 0 ;;
    esac
    case "$addr" in ""|.*|*.|*..*|*[!0-9.]*) return 1 ;; esac
    local o1 o2 o3 o4 extra
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$addr"
    [ -z "${extra:-}" ] || return 1
    for o in "$o1" "$o2" "$o3" "$o4"; do
        case "$o" in ""|*[!0-9]*) return 1 ;; esac
        [ "${#o}" -le 3 ] || return 1
        case "$o" in 0?*) return 1 ;; esac
        (( 10#$o <= 255 )) || return 1
    done
    if [ -n "$mask" ]; then
        case "$mask" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#mask}" -le 2 ] || return 1
        (( 10#$mask <= 32 )) || return 1
    fi
    return 0
}

# nx_unban_ip <ip> - the ONE unban path (U-2). The Security screen's
# old inline version deleted an untagged rule spec the daemon never
# creates, edited the dead /tmp mirror by hand and never touched
# banned.list - so the "unbanned" IP was re-banned at the next
# daemon reconcile. Exact tagged deletes, exact state edits,
# throttle-filter cleanup, fail2ban unban - shared by every screen.
# F11: validates its input (return 2 when invalid) and reports
# honestly - return 0 only when something was actually removed, 1
# when the IP was found nowhere - so callers never print
# "unblocked (all layers)" for a no-op.
nx_unban_ip() {
    local _ip="$1" _tf _prio _if _j _removed=0
    nx_valid_ip_or_cidr "$_ip" || return 2
    # Phase 1b: if the daemon's nft backend holds this ban, remove the
    # set element too (the iptables deletes below stay as belt-and-braces).
    if command -v nft >/dev/null 2>&1; then
        case "$_ip" in
            *:*) nft delete element inet nexoshield ban6 "{ $_ip }" >/dev/null 2>&1 && _removed=1 || true ;;
            *)   nft delete element inet nexoshield ban4 "{ $_ip }" >/dev/null 2>&1 && _removed=1 || true ;;
        esac
    fi
    case "$_ip" in
        *:*)
            ip6tables -D INPUT -s "$_ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null && _removed=1 || true ;;
        *)
            if iptables -D INPUT -s "$_ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null; then
                _removed=1
            elif iptables -D INPUT -s "$_ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null; then
                _removed=1
            elif iptables -D INPUT -s "$_ip" -j DROP 2>/dev/null; then
                _removed=1
            fi ;;
    esac
    for _tf in "$NX_THROTTLE_LIST" "$NX_THROTTLE_MIRROR"; do
        [ -f "$_tf" ] || continue
        _prio=$(awk -v x="$_ip" '$1==x{print $2}' "$_tf" 2>/dev/null | head -1)
        if [ -n "$_prio" ]; then
            _removed=1
            _if=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
            [ -n "$_if" ] && tc filter del dev "$_if" parent 1: prio "$_prio" 2>/dev/null || true
        fi
        awk -v x="$_ip" '$1!=x' "$_tf" > "$_tf.nxtmp" 2>/dev/null && mv "$_tf.nxtmp" "$_tf"
    done
    if [ -f "$NX_STATE_DIR/banned.list" ]; then
        awk -v x="$_ip" '$1==x{found=1} END{exit !found}' "$NX_STATE_DIR/banned.list" 2>/dev/null && _removed=1 || true
        awk -v x="$_ip" '$1!=x' "$NX_STATE_DIR/banned.list" > "$NX_STATE_DIR/banned.list.nxtmp" 2>/dev/null && \
            mv "$NX_STATE_DIR/banned.list.nxtmp" "$NX_STATE_DIR/banned.list"
    fi
    fail2ban-client status 2>/dev/null | grep "Jail list" | \
        sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r _j; do
        [ -z "$_j" ] && continue
        fail2ban-client set "$_j" unbanip "$_ip" 2>/dev/null || true
    done
    [ "$_removed" -eq 1 ]
}

ui_input() {
    local _var="$1" _prompt="$2" _val=""
    if [ -n "${NX_UI_STDIN:-}" ]; then
        printf '%s' "$_prompt"; read -r _val || _val=""
    elif (exec </dev/tty) 2>/dev/null; then
        printf '%s' "$_prompt" >/dev/tty; read -r _val </dev/tty || _val=""
    else
        printf '%s' "$_prompt"; read -r _val || _val=""
    fi
    printf -v "$_var" '%s' "$_val"
}

ui_confirm() {
    local _a
    ui_input _a "  $1 (y/N): "
    [ "$_a" = "y" ] || [ "$_a" = "Y" ]
}

ui_title() {
    draw_header
    echo -e "  ${C}${BOLD}$1${NC}"; echo ""
}

ui_options() {
    local _spec _n _label _status
    for _spec in "$@"; do
        _n="${_spec%%|*}"; _label="${_spec#*|}"; _status=""
        case "$_label" in *\|*) _status="${_label#*|}"; _label="${_label%%|*}" ;; esac
        if [ -n "$_status" ]; then
            echo -e "  ${C}${_n}.${NC}  $_label  $_status"
        else
            echo -e "  ${C}${_n}.${NC}  $_label"
        fi
    done
    echo ""
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
}

# press_enter predates the framework (00-header); redefine it on top
# of ui_input so every "go back" pause shares the same input path.
press_enter() {
    echo ""
    local _pe
    ui_input _pe "  Press Enter to go back..."
}

# ── Dashboard summary for the main menu ────────────────────
ui_home_panel() {
    local _nb _nt _nw
    _nb=$(cnt . "$NX_STATE_DIR/banned.list")
    _nt=$(cnt . "$(nx_throttle_file)")
    _nw=$(cnt . "$NX_STATE_DIR/whitelist.list")
    echo -e "  ${BOLD}Overview${NC}"
    echo -e "  ${DIM}Banned now:${NC} ${W}${_nb}${NC}    ${DIM}Throttled:${NC} ${W}${_nt}${NC}    ${DIM}Whitelist entries:${NC} ${W}${_nw}${NC}"
    if [ -s "$NX_SCORE_FILE" ]; then
        echo -e "  ${DIM}Lowest reputation:${NC}"
        sort -k2 -n "$NX_SCORE_FILE" 2>/dev/null | head -3 | while read -r _ip _sc _rest; do
            [ -z "${_ip:-}" ] && continue
            local _col="$DIM"
            [ "${_sc:-100}" -lt 40 ] 2>/dev/null && _col="$R"
            [ "${_sc:-100}" -ge 40 ] && [ "${_sc:-100}" -lt 60 ] 2>/dev/null && _col="$Y"
            echo -e "    ${_col}${_ip} — score ${_sc}${NC}"
        done
    fi
    if [ -s /var/log/auto-ban.log ]; then
        echo -e "  ${DIM}Recent auto-ban events:${NC}"
        tail -3 /var/log/auto-ban.log 2>/dev/null | sed 's/^/    /'
    fi
    echo ""
}

# ── Plain-text CLI views (scriptable; no colours) ─────────
nx_status_plain() {
    echo "NexoShield v$VERSION"
    echo "3proxy:    $(systemctl is-active 3proxy 2>/dev/null || echo unknown) (port: $(get_proxy_port || echo -))"
    echo "auto-ban:  $(systemctl is-active auto-ban 2>/dev/null || echo unknown)"
    echo "fail2ban:  $(systemctl is-active fail2ban 2>/dev/null || echo unknown)"
    [ -f "$NX_STATE_DIR/state.conf" ] && echo "antiddos:  installed" || echo "antiddos:  not installed"
    echo "banned:    $(cnt . "$NX_STATE_DIR/banned.list")"
    echo "throttled: $(cnt . "$(nx_throttle_file)")"
}

nx_bans_plain() {
    [ -s "$NX_STATE_DIR/banned.list" ] || { echo "(no active bans)"; return 0; }
    local _ip _ts _dur
    while read -r _ip _ts _dur; do
        [ -z "$_ip" ] && continue
        _ts="${_ts//[^0-9]/}"; _dur="${_dur//[^0-9]/}"
        echo "$_ip  since $(date -d "@${_ts:-0}" '+%F %T' 2>/dev/null || echo '?')  expires $(date -d "@$(( ${_ts:-0} + ${_dur:-0} ))" '+%F %T' 2>/dev/null || echo '?')"
    done < "$NX_STATE_DIR/banned.list"
}
menu_proxy() {
    while true; do
        ui_title "SOCKS5 Proxy (3proxy)"
        local ST PORT
        ST=$(svc_status "3proxy")
        PORT=$(get_proxy_port)
        echo -e "  Status : $ST   $(svc_enabled "3proxy")"
        [ -n "$PORT" ] && echo -e "  Port   : ${C}$PORT${NC}"
        _L8="Change password"
        [ -f /etc/3proxy/install.info ] && {
            # shellcheck disable=SC1091
            # Read vars with prefix to avoid conflict with bash $USER builtin
            _INFO_USER=$(grep '^USER=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "")
            _INFO_PASS=$(grep '^PASS=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "")
            if [ -n "$_INFO_USER" ]; then
                echo -e "  User   : ${G}$_INFO_USER${NC}   Pass: ${G}${_INFO_PASS:-?}${NC}"
                echo -e "  Link   : ${G}socks5://$_INFO_USER:${_INFO_PASS:-?}@$(get_ip):${PORT:-?}${NC}"
            else
                _L8="Set username & password"
                echo -e "  User   : ${Y}(none - authentication OFF)${NC}"
                echo -e "  Link   : ${G}socks5://$(get_ip):${PORT:-?}${NC}"
            fi
        }
        echo ""
        ui_options "1|Install/Update" "2|Remove" "3|Start" "4|Stop" \
            "5|Restart" "6|Live log" "7|Traffic stats" "8|$_L8" \
            "9|Delete user & password" "10|Suspicious IPs" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
            1) # Ensure the Cloudflare whitelist file exists before install so CF
               # IPs are ALWAYS excluded from throttling (it can be deleted by an
               # earlier uninstall/antiddos --remove in the same session).
               mkdir -p /etc/antiddos
               # BUG-005 fix: this script has no CF_RANGES - never fabricate
               # the list here (the old code wrote a 1-byte blank file that
               # then counted as "present" forever). Restore the installer's
               # pristine copy; if there is none, refuse to install.
               _CF_OK=1
               if ! grep -q '[0-9]' /etc/antiddos/cloudflare-ipv4.list 2>/dev/null; then
                   if [ -s /opt/proxy-manager/data/cloudflare-ipv4.list ]; then
                       cp /opt/proxy-manager/data/cloudflare-ipv4.list \
                           /etc/antiddos/cloudflare-ipv4.list
                   else
                       _CF_OK=0
                   fi
               fi
               if [ "$_CF_OK" = 1 ]; then
                   bash "$PROXY_SCRIPT" --install < /dev/tty
               else
                   warn "Cloudflare whitelist missing and no pristine copy found - re-run the NexoShield installer to repair it. Install aborted."
               fi
               press_enter ;;
            2) echo ""
               if ui_confirm "Remove 3proxy completely?"; then
                   bash "$PROXY_SCRIPT" --remove < /dev/tty
               else
                   echo -e "  ${DIM}Cancelled.${NC}"
               fi
               press_enter ;;
            3) bash "$PROXY_SCRIPT" --start; press_enter ;;
            4) bash "$PROXY_SCRIPT" --stop;  press_enter ;;
            5) bash "$PROXY_SCRIPT" --restart; press_enter ;;
            6) bash "$PROXY_SCRIPT" --log ;;
            7) bash "$PROXY_SCRIPT" --stats ;;
            8) bash "$PROXY_SCRIPT" --change-pass; press_enter ;;
            9) echo ""
               echo -e "  ${R}${BOLD}⚠  Delete the proxy user & password${NC}"
               echo -e "  ${DIM}The proxy will accept connections WITHOUT authentication -"
               echo -e "  anyone who can reach the port will be able to use it.${NC}"
               echo ""
               if ui_confirm "Delete credentials and open the proxy?"; then
                   bash "$PROXY_SCRIPT" --delete-user
               else
                   echo -e "  ${DIM}Cancelled.${NC}"
               fi
               press_enter ;;
            10) _proxy_suspicious ;;
            0) return ;;
        esac
    done
}



_proxy_suspicious() {
    clear; echo -e "  ${C}Threat IPs (real blocked/throttled attackers)${NC}"; echo ""
    echo -e "  ${DIM}These are actual attackers auto-ban has blocked or throttled,"${NC}
    echo -e "  ${DIM}not your normal heavy users.${NC}"; sep2

    # State files are the source of truth: bans from banned.list
    # (the old iptables -L scrape could never match - rule comments
    # do not appear in -L output), throttles from the daemon's live
    # state file (mirror fallback after a reboot).
    local _banned=""
    _banned=$(awk '{print $1}' "$NX_STATE_DIR/banned.list" 2>/dev/null | head -20)
    local _throttled=""
    _throttled=$(awk '{print $1}' "$(nx_throttle_file)" 2>/dev/null | head -10)

    local _empty=1
    if [ -n "$_banned" ]; then
        echo -e "  ${R}── Currently BANNED ──${NC}"
        echo "$_banned" | while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            echo -e "  ${R}✗ $ip${NC}   (auto-ban state)"
        done
        _empty=0
    fi
    if [ -n "$_throttled" ]; then
        echo ""
        echo -e "  ${Y}── Currently THROTTLED ──${NC}"
        echo "$_throttled" | while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            echo -e "  ${Y}⚠ $ip${NC}   (auto-ban throttle)"
        done
        _empty=0
    fi
    [ "$_empty" -eq 1 ] && echo -e "  ${G}✓ No active threats${NC}"
    echo ""; sep2

    echo -e "  ${DIM}Enter an IP above to block it, or press Enter to skip.${NC}"
    ui_input BIP "  Block IP (empty = skip): "
    if [ -n "$BIP" ]; then
        bash "$ANTIDDOS_SCRIPT" --exempt-check "$BIP" >/dev/null 2>&1; _EC=$?
        if [ "$_EC" -eq 0 ]; then
            warn "$BIP is EXEMPT (Cloudflare / own IP / whitelist) - refusing to block"
        elif [ "$_EC" -eq 2 ]; then
            warn "Invalid IP/CIDR: $BIP"
        elif iptables -I INPUT -s "$BIP" -m comment --comment "auto-ban" -j DROP 2>/dev/null; then
            ok "$BIP blocked"
        else
            warn "Could not block $BIP"
        fi
    fi
    press_enter
}

# ── sysctl Menu ───────────────────────────────────────────
menu_sysctl() {
    while true; do
        ui_title "Network Optimization"
        if [ -f /etc/sysctl.d/99-vpn-optimized.conf ]; then
            echo -e "  Status  : ${G}✓ Optimized${NC}"
        else
            echo -e "  Status  : ${Y}○ Default settings${NC}"
            echo -e "  ${DIM}  → Choose option 1 to enable BBR + optimize for proxy${NC}"
        fi
        echo -e "  BBR     : ${G}$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')${NC} + $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
        echo -e "  Keepalive: $(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || echo '?')s  ${DIM}(30s = optimal for proxy)${NC}"
        echo ""
        ui_options "1|Install / Optimize (analyze + apply)" \
            "2|Rollback (restore previous settings)" "3|Current values" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
            1) bash "$SYSCTL_SCRIPT" --install < /dev/tty; press_enter ;;
            2) bash "$SYSCTL_SCRIPT" --rollback < /dev/tty; press_enter ;;
            3) bash "$SYSCTL_SCRIPT" --status; press_enter ;;
            0) return ;;
        esac
    done
}

# ── Monitoring Menu ───────────────────────────────────────
menu_monitor() {
    while true; do
        ui_title "Monitoring"
        ui_options "1|Live Threat Monitor" "2|Connections" "3|CPU & RAM" \
            "4|Disk" "5|Logs" "6|Auto-ban log" "7|Traffic top IPs" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
            1) _monitor_dashboard ;;
            2) ss -tnp 2>/dev/null | head -30; echo ""; ss -s 2>/dev/null; press_enter ;;
            3) ps aux --sort=-%cpu 2>/dev/null | head -12; echo ""; free -h 2>/dev/null; press_enter ;;
            4) df -h 2>/dev/null; echo ""
               du -sh /var/log/*/ 2>/dev/null | sort -rh | head -8; press_enter ;;
            5) _monitor_logs ;;
            6) [ -f /var/log/auto-ban.log ] && \
                   tail -50 /var/log/auto-ban.log || warn "auto-ban not running"
               press_enter ;;
            7) # Top IPs from the 3proxy log. U-7: the log is the
               # daily-rotated access.log.YYYY.MM.DD (T-2), and the
               # client is field 4 (%C:%c) of the log format, not $5
               # (that is %R, the server side) - both were wrong, so
               # this screen always said "No log found" or counted
               # the server's own addresses.
               _ALOG=$(ls -t /var/log/3proxy/access.log* 2>/dev/null | head -1)
               [ -n "$_ALOG" ] && {
                   echo -e "  ${C}Top 20 source IPs:${NC}"; sep2
                   awk '{print $4}' "$_ALOG" 2>/dev/null | cut -d: -f1 | \
                       grep -oP '^\d+\.\d+\.\d+\.\d+' | sort | uniq -c | \
                       sort -rn | head -20 | awk '{printf "  %-8s %s\n", $1, $2}'
               } || warn "No log found"
               press_enter ;;
            0) return ;;
        esac
    done
}

_monitor_dashboard() {
    # ── Live Threat Monitor ──────────────────────────────────
    # Full-screen real-time dashboard: attacks, bans, top IPs, system health
    # Press q to quit, r to reset counters

    # Define _bps ONCE here — not inside the loop
    _bps() {
        local b=${1:-0}
        b="${b//[^0-9]/}"; b="${b:-0}"
        if [ "$b" -ge 1048576 ]; then echo "$(( b/1024/1024 )) MB/s"
        elif [ "$b" -ge 1024 ]; then echo "$(( b/1024 )) KB/s"
        else echo "$b B/s"; fi
    }

    local PORT; PORT=$(get_proxy_port)
    local MAIN_IF; MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    local CYCLE=0 NEW_BANS_SINCE=0 BAN_LOG=/var/log/auto-ban.log PREV_BAN_COUNT=0
    if [ -f "$BAN_LOG" ]; then
        PREV_BAN_COUNT=$(cnt "BANNED:" "$BAN_LOG")
        PREV_BAN_COUNT="${PREV_BAN_COUNT//[^0-9]/}"; PREV_BAN_COUNT="${PREV_BAN_COUNT:-0}"
    fi
    local PREV_RX=0 PREV_TX=0 PREV_TIME=0
    local RESET_TIME; RESET_TIME=$(date '+%H:%M:%S')

    clear
    while true; do
        # ── Non-blocking key check ──────────────────────────
        read -r -t 0.8 -n 1 K 2>/dev/null || true
        [ "$K" = "q" ] || [ "$K" = "Q" ] && break
        if [ "$K" = "r" ] || [ "$K" = "R" ]; then
            PREV_BAN_COUNT=$(cnt "BANNED:" "$BAN_LOG")
            PREV_BAN_COUNT="${PREV_BAN_COUNT//[^0-9]/}"; PREV_BAN_COUNT="${PREV_BAN_COUNT:-0}"
            NEW_BANS_SINCE=0; RESET_TIME=$(date '+%H:%M:%S'); CYCLE=0
        fi
        CYCLE=$((CYCLE+1))
        K=""

        # ── Collect data ────────────────────────────────────
        local NOW; NOW=$(date '+%H:%M:%S')
        local LOAD; LOAD=$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo "? ? ?")
        local MT MU MP
        read -r MT MU <<< "$(free 2>/dev/null | awk '/Mem:/{print $2, $3}')"
        MT="${MT//[^0-9]/}"; MT="${MT:-1}"; [ "$MT" -eq 0 ] 2>/dev/null && MT=1
        MU="${MU//[^0-9]/}"; MU="${MU:-0}"
        MP=$(( MU * 100 / MT ))
        local DP; DP=$(df / 2>/dev/null | awk 'NR==2{printf "%.0f",$5}' || echo 0)
        DP="${DP//[^0-9]/}"; DP="${DP:-0}"
        local ACTIVE_CONNS=0
        if [ -n "$PORT" ]; then
            ACTIVE_CONNS=$(ss -tnp state established 2>/dev/null | grep -c ":$PORT " || true)
            ACTIVE_CONNS="${ACTIVE_CONNS:-0}"
            ACTIVE_CONNS="${ACTIVE_CONNS//[^0-9]/}"; ACTIVE_CONNS="${ACTIVE_CONNS:-0}"
        fi
        local TOTAL_CONNS=0
        TOTAL_CONNS=$(ss -tn 2>/dev/null | grep -c ESTAB || true)
        TOTAL_CONNS="${TOTAL_CONNS:-0}"
        TOTAL_CONNS="${TOTAL_CONNS//[^0-9]/}"; TOTAL_CONNS="${TOTAL_CONNS:-0}"

        # ── Bandwidth ───────────────────────────────────────
        local RX_BPS=0 TX_BPS=0
        if [ -n "$MAIN_IF" ] && [ -f "/sys/class/net/$MAIN_IF/statistics/rx_bytes" ]; then
            local CRX CTX CTIME DT
            CRX=$(cat "/sys/class/net/$MAIN_IF/statistics/rx_bytes" 2>/dev/null || echo 0)
            CTX=$(cat "/sys/class/net/$MAIN_IF/statistics/tx_bytes" 2>/dev/null || echo 0)
            CRX="${CRX//[^0-9]/}"; CRX="${CRX:-0}"
            CTX="${CTX//[^0-9]/}"; CTX="${CTX:-0}"
            CTIME=$(date +%s)
            DT=$(( CTIME - PREV_TIME ))
            if [ "$DT" -gt 0 ] && [ "$PREV_TIME" -gt 0 ]; then
                RX_BPS=$(( (CRX - PREV_RX) / DT ))
                TX_BPS=$(( (CTX - PREV_TX) / DT ))
                # Guard against counter wrap or negative
                [ "$RX_BPS" -lt 0 ] 2>/dev/null && RX_BPS=0
                [ "$TX_BPS" -lt 0 ] 2>/dev/null && TX_BPS=0
            fi
            PREV_RX=$CRX; PREV_TX=$CTX; PREV_TIME=$CTIME
        fi

        # ── Ban stats ───────────────────────────────────────
        local CUR_BAN_COUNT=0
        if [ -f "$BAN_LOG" ]; then
            CUR_BAN_COUNT=$(cnt "BANNED:" "$BAN_LOG")
            CUR_BAN_COUNT="${CUR_BAN_COUNT//[^0-9]/}"
            CUR_BAN_COUNT="${CUR_BAN_COUNT:-0}"
        fi
        local _DIFF=$(( CUR_BAN_COUNT - PREV_BAN_COUNT ))
        [ "$_DIFF" -lt 0 ] 2>/dev/null && _DIFF=0
        NEW_BANS_SINCE=$_DIFF

        # ── iptables drops ──────────────────────────────────
        local DROP_RULES=0 SYNPROXY_HIT=0
        DROP_RULES=$(iptables -S INPUT 2>/dev/null | grep -c -- "-j DROP" || true)
        DROP_RULES="${DROP_RULES:-0}"
        DROP_RULES="${DROP_RULES//[^0-9]/}"; DROP_RULES="${DROP_RULES:-0}"
        if [ -f /proc/net/stat/synproxy ]; then
            SYNPROXY_HIT=$(awk 'NR>1{s+=$8}END{print s+0}' /proc/net/stat/synproxy 2>/dev/null || echo 0)
            SYNPROXY_HIT="${SYNPROXY_HIT//[^0-9]/}"; SYNPROXY_HIT="${SYNPROXY_HIT:-0}"
        fi

        # ── Currently blocked / throttled attackers ──────────
        # From the daemon's state files (U-9): the old code grepped
        # iptables -L output for rule comments - comments never
        # appear in -L listings, so this section was always empty.
        local CUR_BANNED
        CUR_BANNED=$(awk '{print $1}' "$NX_STATE_DIR/banned.list" 2>/dev/null | sort -u | head -6)
        local CUR_THROTTLED
        CUR_THROTTLED=$(awk '{print $1}' "$(nx_throttle_file)" 2>/dev/null | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -4)

        # ── Recently banned IPs (last 8 from log) ───────────
        local RECENT_BANS=""
        [ -f "$BAN_LOG" ] && RECENT_BANS=$(grep "BANNED:" "$BAN_LOG" 2>/dev/null | \
            tail -8 | awk '{print $1,$2,$NF}' | sed 's/^/  /')

        # ── Currently throttled ─────────────────────────────
        local THROTTLED=0
        local _TF; _TF=$(nx_throttle_file)
        if [ -n "$_TF" ]; then
            THROTTLED=$(wc -l < "$_TF" 2>/dev/null || echo 0)
            THROTTLED="${THROTTLED//[^0-9]/}"; THROTTLED="${THROTTLED:-0}"
        fi

        # ── Active fail2ban bans ─────────────────────────────
        local F2B_BANS=0
        if command -v fail2ban-client >/dev/null 2>&1; then
            F2B_BANS=$(fail2ban-client status 2>/dev/null | grep -oP 'Currently banned:\s*\K\d+' | \
                awk '{s+=$1}END{print s+0}' 2>/dev/null || echo 0)
            F2B_BANS="${F2B_BANS//[^0-9]/}"; F2B_BANS="${F2B_BANS:-0}"
        fi

        # ── Draw screen ─────────────────────────────────────
        tput cup 0 0 2>/dev/null || printf '\033[H'

        # Header
        echo -e "\033[2K  ${C}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "\033[2K  ${C}${BOLD}║${NC}  🛡  LIVE THREAT MONITOR  ${DIM}${NOW}${NC}  ${DIM}[q=quit r=reset]${NC}  ${C}${BOLD}║${NC}"
        echo -e "\033[2K  ${C}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # ── Row 1: System health ─────────────────────────────
        local RAM_COLOR=$W DISK_COLOR=$W
        [ "$MP" -ge 85 ] && RAM_COLOR=$R || { [ "$MP" -ge 70 ] && RAM_COLOR=$Y; }
        [ "${DP:-0}" -ge 90 ] && DISK_COLOR=$R || { [ "${DP:-0}" -ge 80 ] && DISK_COLOR=$Y; }
        local MU_MB=$(( ${MU:-0} / 1024 ))
        local MT_MB=$(( ${MT:-1} / 1024 ))
        echo -e "\033[2K  ${DIM}┌─ SYSTEM ────────────────────────────────────────────────────┐${NC}"
        echo -e "\033[2K  ${DIM}│${NC}  Load: ${W}${LOAD:-?}${NC}   RAM: ${RAM_COLOR}${MP:-0}%${NC} (${MU_MB}MB/${MT_MB}MB)   Disk: ${DISK_COLOR}${DP:-0}%${NC}"
        echo -e "\033[2K  ${DIM}│${NC}  3proxy: $(svc_status '3proxy')   Proxy conns: ${W}${ACTIVE_CONNS:-0}${NC}   Total ESTAB: ${W}${TOTAL_CONNS:-0}${NC}"
        echo -e "\033[2K  ${DIM}│${NC}  BW in: ${G}$(_bps "$RX_BPS")${NC}   BW out: ${G}$(_bps "$TX_BPS")${NC}   Interface: ${DIM}${MAIN_IF:-?}${NC}"
        echo -e "\033[2K  ${DIM}└──────────────────────────────────────────────────────────────┘${NC}"
        echo ""

        # ── Row 2: Attack stats ──────────────────────────────
        local AB_COLOR=$G DR_COLOR=$G
        [ "${NEW_BANS_SINCE:-0}" -ge 5 ] && AB_COLOR=$R || { [ "${NEW_BANS_SINCE:-0}" -ge 1 ] && AB_COLOR=$Y; }
        [ "${DROP_RULES:-0}" -ge 20 ] && DR_COLOR=$R || { [ "${DROP_RULES:-0}" -ge 5 ] && DR_COLOR=$Y; }
        local AB_STATUS F2B_STATUS
        systemctl is-active auto-ban >/dev/null 2>&1 && AB_STATUS="${G}● running${NC}" || AB_STATUS="${R}○ stopped${NC}"
        systemctl is-active fail2ban >/dev/null 2>&1 && F2B_STATUS="${G}● running${NC}" || F2B_STATUS="${R}○ stopped${NC}"
        echo -e "\033[2K  ${DIM}┌─ ATTACK STATS ──────────────────────────────────────────────┐${NC}"
        echo -e "\033[2K  ${DIM}│${NC}  New bans (since ${RESET_TIME}): ${AB_COLOR}${NEW_BANS_SINCE:-0}${NC}   Total bans: ${W}${CUR_BAN_COUNT:-0}${NC}   Throttled: ${Y}${THROTTLED:-0}${NC}"
        echo -e "\033[2K  ${DIM}│${NC}  DROP rules: ${DR_COLOR}${DROP_RULES:-0}${NC}   SYNPROXY hits: ${W}${SYNPROXY_HIT:-0}${NC}   fail2ban bans: ${Y}${F2B_BANS:-0}${NC}"
        echo -e "\033[2K  ${DIM}│${NC}  auto-ban: ${AB_STATUS}   fail2ban: ${F2B_STATUS}"
        echo -e "\033[2K  ${DIM}└──────────────────────────────────────────────────────────────┘${NC}"
        echo ""

        # ── Row 3: Active threats (REAL blocked/throttled attackers) ──
        echo -e "\033[2K  ${DIM}┌─ ACTIVE THREATS (blocked / throttled attackers) ───────────┐${NC}"
        local _tcount=0 _bip _tip
        if [ -n "$CUR_BANNED" ]; then
            while IFS= read -r _bip; do
                [ -z "$_bip" ] && continue
                echo -e "\033[2K  ${DIM}│${NC}  ${R}✗ BANNED${NC}   ${_bip}"
                _tcount=$((_tcount+1))
            done <<< "$CUR_BANNED"
        fi
        if [ -n "$CUR_THROTTLED" ]; then
            while IFS= read -r _tip; do
                [ -z "$_tip" ] && continue
                echo -e "\033[2K  ${DIM}│${NC}  ${Y}⚠ THROTTLED${NC} ${_tip}"
                _tcount=$((_tcount+1))
            done <<< "$CUR_THROTTLED"
        fi
        if [ "$_tcount" -eq 0 ]; then
            echo -e "\033[2K  ${DIM}│  ${G}✓ No active threats${NC}"
        fi
        while [ "$_tcount" -lt 6 ]; do
            echo -e "\033[2K  ${DIM}│${NC}"
            _tcount=$((_tcount+1))
        done
        echo -e "\033[2K  ${DIM}└──────────────────────────────────────────────────────────────┘${NC}"
        echo ""

        # ── Row 4: Recently banned IPs ───────────────────────
        echo -e "\033[2K  ${DIM}┌─ RECENTLY BANNED IPs ───────────────────────────────────────┐${NC}"
        if [ -n "$RECENT_BANS" ]; then
            local ban_count=0
            while IFS= read -r bline; do
                [ -z "$bline" ] && continue
                echo -e "\033[2K  ${DIM}│${NC}  ${R}✗${NC} ${bline}"
                ban_count=$((ban_count+1))
            done <<< "$RECENT_BANS"
            while [ "$ban_count" -lt 4 ]; do
                echo -e "\033[2K  ${DIM}│${NC}"
                ban_count=$((ban_count+1))
            done
        else
            for _ in 1 2 3 4; do echo -e "\033[2K  ${DIM}│  (no bans recorded yet)${NC}"; done
        fi
        echo -e "\033[2K  ${DIM}└──────────────────────────────────────────────────────────────┘${NC}"
        echo ""

        # Footer
        echo -e "\033[2K  ${DIM}Cycle #${CYCLE}  │  Refresh: ~1s  │  q=quit  r=reset counters  │  log: $BAN_LOG${NC}"

    done
    clear
}

_monitor_logs() {
    while true; do
        clear; echo -e "  ${C}Logs${NC}"; echo ""
        echo -e "  ${C}1.${NC} 3proxy    ${C}2.${NC} fail2ban  ${C}3.${NC} auth/SSH"
        echo -e "  ${C}4.${NC} system    ${C}5.${NC} auto-ban  ${C}6.${NC} antiddos"
        echo -e "  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        ui_input CH "  Enter number: "
        case "$CH" in
            1) # T-2: 3proxy writes dated logs (access.log.YYYY.MM.DD)
               less +G "$(ls -t /var/log/3proxy/access.log* 2>/dev/null | head -1)" 2>/dev/null || \
               journalctl -u 3proxy --no-pager -n 50 ;;
            2) journalctl -u fail2ban --no-pager -n 50 2>/dev/null ;;
            3) less +G /var/log/auth.log 2>/dev/null ;;
            4) journalctl --no-pager -n 50 2>/dev/null ;;
            5) less +G /var/log/auto-ban.log 2>/dev/null || warn "Not found" ;;
            6) less +G /var/log/antiddos.log 2>/dev/null || warn "Not found" ;;
            0) return ;;
        esac
    done
}

# ── Security Menu ─────────────────────────────────────────
menu_security() {
    while true; do
        ui_title "Security"
        ui_options "1|Blocked IPs (all)" "2|Block IP" "3|Unblock IP" \
            "4|iptables rules" "5|SSH brute force" "6|Auto-ban status" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
             1) clear 2>/dev/null || true
               echo -e "  ${C}fail2ban bans:${NC}"
               fail2ban-client status 2>/dev/null | grep "Jail list" | \
                   sed 's/.*://g' | tr ',' '\n' | while read -r j; do
                   j=$(echo "$j" | tr -d ' '); [ -z "$j" ] && continue
                   # U-3: the count is the "Currently banned:" total.
                   # The old parse took the last number on the
                   # "Banned IP list:" line - the last octet of the
                   # last banned IP, not a count at all.
                   BCOUNT=$(fail2ban-client status "$j" 2>/dev/null | \
                       grep -oP 'Currently banned:\s*\K\d+' || echo 0)
                   [ "${BCOUNT:-0}" -gt 0 ] && echo -e "  ${Y}$j${NC}: $BCOUNT IPs"
               done
               echo ""
               echo -e "  ${C}auto-ban bans (state):${NC}"
               if [ -s "$NX_STATE_DIR/banned.list" ]; then
                   awk '{print $1}' "$NX_STATE_DIR/banned.list" | head -30 | \
                       while read -r ip; do echo -e "  ${R}$ip${NC}"; done
               else
                   echo -e "  ${DIM}(none)${NC}"
               fi
               press_enter ;;
            2) echo -e "  ${C}Block IP${NC}"; echo ""
               ui_input BIP "  Enter IP or CIDR to block (e.g. 1.2.3.4 or 1.2.3.0/24): "
               if [ -n "$BIP" ]; then
                   bash "$ANTIDDOS_SCRIPT" --exempt-check "$BIP" >/dev/null 2>&1; _EC=$?
                   if [ "$_EC" -eq 0 ]; then
                       warn "$BIP is EXEMPT (Cloudflare / own IP / whitelist) - refusing to block"
                   elif [ "$_EC" -eq 2 ]; then
                       warn "Invalid IP/CIDR: $BIP"
                   elif iptables -I INPUT -s "$BIP" -j DROP 2>/dev/null; then
                       ok "$BIP blocked"
                   else
                       warn "Could not block $BIP"
                   fi
               else
                   warn "No IP entered"
               fi
               press_enter ;;
            3) echo -e "  ${C}Unblock IP${NC}"; echo ""
               ui_input UIP "  Enter IP to unblock: "
               if [ -n "$UIP" ]; then
                   # U-2: the shared engine-grade unban (exact tagged
                   # deletes + state edits + throttle cleanup +
                   # fail2ban). The old inline copy deleted a rule
                   # spec the daemon never creates and never touched
                   # banned.list, so the IP was re-banned on the
                   # daemon's next reconcile. F11: honest result.
                   if nx_unban_ip "$UIP"; then
                       ok "$UIP unblocked (all layers)"
                   elif [ "$?" -eq 2 ]; then
                       warn "Invalid IP/CIDR: $UIP"
                   else
                       warn "$UIP was not found in any layer (nothing removed)"
                   fi
               else
                   warn "No IP entered"
               fi
               press_enter ;;
            4) iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -40; press_enter ;;
            5) # Journal fallback (T-1 class): auth.log may not exist
               # on journal-only images.
               if [ -s /var/log/auth.log ]; then
                   grep 'Failed password\|Invalid user' /var/log/auth.log 2>/dev/null
               else
                   journalctl -u ssh -u sshd --no-pager -n 1000 2>/dev/null | \
                       grep 'Failed password\|Invalid user'
               fi | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -15 | \
               awk '{printf "  %-8s %s\n", $1, $2}'
               press_enter ;;
            6) # Auto-ban status
               if systemctl is-active auto-ban >/dev/null 2>&1; then
                   echo -e "  ${G}● auto-ban: Running${NC}"
                   BANS=$(cnt "BANNED:" /var/log/auto-ban.log)
                   echo -e "  Total bans logged: ${Y}$BANS${NC}"
                   echo ""; tail -10 /var/log/auto-ban.log 2>/dev/null || true
               else
                   echo -e "  ${Y}○ auto-ban: Not running${NC}"
                   echo -e "  Run Anti-DDoS install to activate"
               fi
               press_enter ;;
            0) return ;;
        esac
    done
}

# ── Services Menu ─────────────────────────────────────────
menu_services() {
    # Only show services that are actually installed on this system
    ALL_POSSIBLE=(3proxy auto-ban fail2ban nginx apache2 mysql postgresql redis-server)
    while true; do
        # Build list dynamically each time (user may install/remove)
        SERVICES=()
        for S in "${ALL_POSSIBLE[@]}"; do
            # U-5: bare list-unit-files exits 0 even with zero matches,
            # so every candidate used to be listed as installed.
            systemctl list-unit-files --no-legend "${S}.service" 2>/dev/null | \
                grep -q . && SERVICES+=("$S") || true
        done
        # Always show 3proxy and auto-ban even if not installed yet
        for S in 3proxy auto-ban; do
            printf '%s\n' "${SERVICES[@]}" | grep -qx "$S" || SERVICES+=("$S")
        done
        ui_title "Services"
        for i in "${!SERVICES[@]}"; do
            printf "  ${C}%d.${NC}  %-20s %s  %s\n" "$((i+1))" \
                "${SERVICES[$i]}" \
                "$(svc_status "${SERVICES[$i]}")" \
                "$(svc_enabled "${SERVICES[$i]}")"
        done
        echo ""; sep2
        echo -e "  ${C}a.${NC} Start all   ${C}z.${NC} Restart all   ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        ui_input CH "  Enter number: "
        if [[ "$CH" =~ ^[0-9]+$ ]] && [ "$CH" -ge 1 ] && [ "$CH" -le "${#SERVICES[@]}" ]; then
            SVC="${SERVICES[$((CH-1))]}"
            clear; echo -e "  ${C}${BOLD}$SVC${NC}  $(svc_status "$SVC")"; echo ""
            echo -e "  ${C}1.${NC} Start   ${C}2.${NC} Stop   ${C}3.${NC} Restart   ${C}4.${NC} Status   ${C}0.${NC} Back"
            echo ""; sep2
            ui_input A "  Choice: "
            case "$A" in
                1) systemctl start "$SVC" 2>/dev/null && ok "Started" || err "Failed" ;;
                2) systemctl stop "$SVC" 2>/dev/null && ok "Stopped" || err "Failed" ;;
                3) systemctl restart "$SVC" 2>/dev/null && ok "Restarted" || err "Failed" ;;
                4) systemctl status "$SVC" --no-pager -l 2>/dev/null ;;
            esac
            press_enter
        else
            case "$CH" in
                a) for S in "${SERVICES[@]}"; do
                       systemctl start "$S" 2>/dev/null && ok "$S" || true
                   done; press_enter ;;
                z) for S in "${SERVICES[@]}"; do
                       systemctl is-active "$S" >/dev/null 2>&1 && \
                           systemctl restart "$S" 2>/dev/null && ok "$S" || true
                   done; press_enter ;;
                0) return ;;
            esac
        fi
    done
}

# ── Self-update (v3.12) ───────────────────────────────────
# One-click update from the menu. The latest version is whatever
# master on GitHub carries (the project's distribution channel).
# The downloaded installer must pass bash -n, carry the
# NexoShield marker and embed exactly the advertised version
# before it may run; the installer itself stages and verifies
# every module before activating (BUG-025), and an upgrade
# preserves credentials and scoring.conf. NX_UPDATE_BASE is a
# test hook.
NX_UPDATE_BASE="${NX_UPDATE_BASE:-https://raw.githubusercontent.com/MNSH-Nexo/NexoShield/master}"
nx_update_nexoshield() {
    local _latest _tmp _rc
    echo -e "  ${C}Checking for updates...${NC}"
    _latest=$(curl -fsSL --max-time 15 "$NX_UPDATE_BASE/VERSION" 2>/dev/null | tr -d '[:space:]' || true)
    if [ -z "$_latest" ]; then
        warn "Could not reach the update server - nothing was changed."
        return 1
    fi
    if [ "$_latest" = "$VERSION" ]; then
        ok "NexoShield is up to date (v$VERSION)."
        return 0
    fi
    if [ "$(printf '%s\n%s\n' "$_latest" "$VERSION" | sort -V | head -1)" != "$VERSION" ]; then
        warn "Remote version v$_latest is not newer than v$VERSION - nothing to do."
        return 0
    fi
    echo -e "  Update available: ${Y}v$VERSION${NC} -> ${G}v$_latest${NC}"
    echo -e "  ${DIM}Settings, proxy credentials and scoring.conf are preserved.${NC}"
    if ! ui_confirm "Download and install v$_latest now?"; then
        echo -e "  ${DIM}Cancelled.${NC}"
        return 0
    fi
    _tmp=$(mktemp -d) || return 1
    if ! curl -fsSL --max-time 180 -o "$_tmp/install.sh" "$NX_UPDATE_BASE/install.sh" 2>/dev/null; then
        warn "Download failed - nothing was changed."
        rm -rf "$_tmp"; return 1
    fi
    if ! bash -n "$_tmp/install.sh" 2>/dev/null || \
       ! grep -q "NexoShield" "$_tmp/install.sh" || \
       ! grep -qF "VERSION=\"$_latest\"" "$_tmp/install.sh"; then
        warn "Downloaded installer failed verification - nothing was changed."
        rm -rf "$_tmp"; return 1
    fi
    echo -e "  ${C}Installing NexoShield v$_latest ...${NC}"
    if (exec </dev/tty) 2>/dev/null; then
        bash "$_tmp/install.sh" < /dev/tty
    else
        bash "$_tmp/install.sh"
    fi
    _rc=$?
    rm -rf "$_tmp"
    if [ "$_rc" -ne 0 ]; then
        warn "Installer exited with an error - the previous install was left untouched."
        return 1
    fi
    # MED-7: the installer swaps module scripts but does not activate
    # them - services and rules still run the previous version until
    # each module is re-applied. Regenerate the one derived file a
    # timer executes directly (the accumulator script), and say
    # plainly what still needs a re-run.
    if [ -f /etc/3proxy/install.info ] && [ -x "$SCRIPT_DIR/3proxy-socks5.sh" ]; then
        if "$SCRIPT_DIR/3proxy-socks5.sh" --regen-accumulator 2>/dev/null; then
            echo -e "  ${DIM}Proxy traffic accumulator regenerated for v$_latest.${NC}"
        else
            warn "Could not regenerate the proxy traffic accumulator - re-run the proxy Install/Update to refresh it."
        fi
    fi
    ok "Updated to NexoShield v$_latest."
    _STALE=""
    [ -f /etc/3proxy/install.info ] && _STALE="3proxy"
    [ -f /etc/antiddos/state.conf ] && _STALE="${_STALE:+$_STALE, }Anti-DDoS"
    if [ -n "$_STALE" ]; then
        echo -e "  ${YELLOW}Note: running services and firewall rules still use the previous version until you re-apply each installed module ($_STALE: re-run its Install/Update).${NC}"
    fi
    if [ -z "${NX_UI_STDIN:-}" ] && ui_confirm "Restart the menu now to use v$_latest?"; then
        exec bash "$SCRIPT_DIR/proxy-menu.sh"
    fi
    return 0
}

# ── System Menu ───────────────────────────────────────────
menu_system() {
    while true; do
        ui_title "System"
        ui_options "1|Server info" "2|Update system packages" "3|Clean logs" "4|Reboot" \
            "5|Backup config" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
             1) clear 2>/dev/null || true
               printf "  ${DIM}%-20s${NC} %s\n" "Hostname:" "$(hostname)"
               printf "  ${DIM}%-20s${NC} %s\n" "OS:" "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
               printf "  ${DIM}%-20s${NC} %s\n" "Kernel:" "$(uname -r)"
               printf "  ${DIM}%-20s${NC} %s\n" "Uptime:" "$(uptime -p 2>/dev/null)"
               printf "  ${DIM}%-20s${NC} %s\n" "CPU:" "$(nproc) core(s)"
               printf "  ${DIM}%-20s${NC} %s\n" "RAM:" "$(free -h 2>/dev/null | awk '/Mem:/{print $2}')"
               printf "  ${DIM}%-20s${NC} %s\n" "IP:" "$(get_ip)"
               printf "  ${DIM}%-20s${NC} %s\n" "All IPs:" "$(ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127\.' | awk '{print $2}' | tr '\n' ' ')"
               press_enter ;;
            2) echo ""
               if ui_confirm "Update system packages?"; then
                   # BUG-044: the old && / || chain ran yum on Debian
                   # boxes when apt failed and printed "Update complete"
                   # either way. Branch properly, dnf first on RHEL.
                   if command -v apt-get >/dev/null 2>&1; then
                       if apt-get update -y && apt-get upgrade -y; then
                           ok "Update complete"
                       else
                           err "Package update FAILED"
                       fi
                   elif command -v dnf >/dev/null 2>&1; then
                       dnf update -y && ok "Update complete" || err "Package update FAILED"
                   elif command -v yum >/dev/null 2>&1; then
                       yum update -y && ok "Update complete" || err "Package update FAILED"
                   else
                       err "No supported package manager found"
                   fi
               else
                   echo -e "  ${DIM}Cancelled.${NC}"
               fi
               press_enter ;;
            3) BEFORE=$(df / 2>/dev/null | awk 'NR==2{print $3}' || echo 0)
               journalctl --vacuum-size=100M 2>/dev/null || true
               find /var/log -name "*.gz" -mtime +3 -delete 2>/dev/null || true
               apt-get clean 2>/dev/null || true
               AFTER=$(df / 2>/dev/null | awk 'NR==2{print $3}' || echo 0)
               ok "Freed: $(awk -v b="${BEFORE:-0}" -v a="${AFTER:-0}" 'BEGIN{printf "%.1f", (b-a)/1024}') MB"
               press_enter ;;
            4) echo ""
               if ui_confirm "Reboot server now?"; then
                   ok "Rebooting in 5 seconds..."
                   sleep 5 && reboot
               else
                   echo -e "  ${DIM}Cancelled.${NC}"; press_enter
               fi ;;
            5) BACKUP="/root/proxy-manager-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
               # BUG-052: the archive contains the proxy password
               # (/etc/3proxy/users.cfg) - warn, verify the archive,
               # and only claim success when it actually worked.
               warn "This backup includes proxy credentials - store it somewhere private."
               if tar -czf "$BACKUP" \
                   /etc/3proxy/ \
                   /etc/antiddos/ \
                   /etc/fail2ban/jail.d/ \
                   /etc/sysctl.d/ \
                   /opt/proxy-manager/ \
                   2>/dev/null && tar -tzf "$BACKUP" >/dev/null 2>&1; then
                   ok "Backup saved: $BACKUP ($(du -h "$BACKUP" 2>/dev/null | cut -f1))"
               else
                   err "Backup FAILED - no archive was created"
                   rm -f "$BACKUP"
               fi
               press_enter ;;
            0) return ;;
        esac
    done
}

# ── Anti-DDoS Menu ────────────────────────────────────────
menu_antiddos() {
    while true; do
        ui_title "Anti-DDoS Protection"

        # Status at a glance
        if [ -f /etc/antiddos/state.conf ]; then
            echo -e "  Status  : ${G}✓ Installed${NC}"
        else
            echo -e "  Status  : ${Y}○ Not installed${NC}"
            echo -e "  ${DIM}  → Choose option 1 to protect this server${NC}"
        fi
        AUTOBAN_ST=$(svc_status "auto-ban")
        echo -e "  Auto-ban: $AUTOBAN_ST"

        # Show layer status — gate everything on our install marker so that
        # after "Remove all protection" (which deletes state.conf) every layer
        # honestly shows as NOT installed. Never rely on generic system state
        # (kernel defaults like tcp_syncookies=1 or the fail2ban service), which
        # survive removal and would wrongly show checkmarks.
        echo ""; echo -e "  ${DIM}Protection layers:${NC}"
        if [ -f /etc/antiddos/state.conf ]; then
            [ -f /etc/sysctl.d/98-antiddos-hardening.conf ] && \
                echo -e "  ${G}✓${NC} Kernel hardening" || echo -e "  ${DIM}○ Kernel hardening${NC}"
            iptables -S INPUT 2>/dev/null | grep -qE 'cf_whitelist|hashlimit|syn_flood|SYNPROXY' && \
                echo -e "  ${G}✓${NC} iptables rules" || echo -e "  ${DIM}○ iptables rules${NC}"
            [ -f /etc/fail2ban/jail.d/antiddos.conf ] && \
                echo -e "  ${G}✓${NC} fail2ban" || echo -e "  ${DIM}○ fail2ban${NC}"
            systemctl is-active auto-ban >/dev/null 2>&1 && \
                echo -e "  ${G}✓${NC} Smart auto-ban" || echo -e "  ${DIM}○ Smart auto-ban${NC}"
            tc class show dev "$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)" 2>/dev/null | grep -q 'htb' && \
                echo -e "  ${G}✓${NC} Bandwidth shaping (tc)" || echo -e "  ${DIM}○ Bandwidth shaping (tc)${NC}"
        else
            for _layer in "Kernel hardening" "iptables rules" "fail2ban" \
                          "Smart auto-ban" "Bandwidth shaping (tc)"; do
                echo -e "  ${DIM}○ $_layer${NC}"
            done
        fi

        echo ""
        ui_options "1|Install / Re-install all layers" "2|Status & active bans" \
            "3|Unban an IP" "4|Auto-ban control (start/stop/log)" \
            "5|Whitelist — exempt an IP from ALL layers" \
            "6|Remove all protection" "7|Scoring & rate thresholds" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
            1) _antiddos_install ;;
            2) bash "$ANTIDDOS_SCRIPT" --status < /dev/tty; press_enter ;;
            3) echo -e "  ${C}Unban IP${NC}"; echo ""
               ui_input UIP "  Enter IP to unban (removes from iptables + fail2ban): "
               if [ -n "$UIP" ]; then
                   # The shared engine-grade unban (U-2): exact tagged
                   # deletes (BUG-038), exact state edits, throttle
                   # cleanup, fail2ban - one implementation everywhere.
                   # F11: honest result - success only when something
                   # was actually removed.
                   if nx_unban_ip "$UIP"; then
                       ok "$UIP unblocked (all layers)"
                   elif [ "$?" -eq 2 ]; then
                       warn "Invalid IP/CIDR: $UIP"
                   else
                       warn "$UIP was not found in any layer (nothing removed)"
                   fi
               else
                   warn "No IP entered"
               fi
               press_enter ;;
            4) _autoban_control ;;
            5) # The whitelist manager itself lives in antiddos.sh
               # (one implementation): entries are exempt from EVERY
               # layer - iptables, SYNPROXY, tc, fail2ban, auto-ban -
               # and changes apply live. It is part of the Anti-DDoS
               # subsystem, so it needs the layers installed first.
               if [ -f /etc/antiddos/state.conf ]; then
                   bash "$ANTIDDOS_SCRIPT" --whitelist < /dev/tty
               else
                   echo ""
                   echo -e "  ${C}Whitelist Manager${NC}"
                   echo -e "  ${DIM}The whitelist is part of Anti-DDoS protection - install it first"
                   echo -e "  (option 1). IPs you add there are exempt from every layer:"
                   echo -e "  iptables, SYNPROXY, tc shaping, fail2ban and the auto-ban daemon.${NC}"
                   press_enter
               fi ;;
            7) bash "$ANTIDDOS_SCRIPT" --thresholds; press_enter ;;
            6) echo ""
               echo -e "  ${R}${BOLD}⚠  Remove ALL Anti-DDoS Protection${NC}"
               echo -e "  ${DIM}This will remove: iptables rules, sysctl hardening, fail2ban jails,"
               echo -e "  auto-ban service, tc bandwidth shaping, and boot persistence.${NC}"
               echo ""
               if ui_confirm "Are you sure?"; then
                   bash "$ANTIDDOS_SCRIPT" --remove-force
               else
                   echo -e "  ${DIM}Cancelled.${NC}"
               fi
               press_enter ;;
            0) return ;;
        esac
    done
}

_antiddos_install() {
    clear; sep
    echo -e "  ${C}${BOLD}Installing Anti-DDoS Protection${NC}"; sep
    echo ""
    echo -e "  This will configure ${W}5 protection layers${NC} on this server:"
    echo ""
    echo -e "  ${C}[1/5]${NC} Kernel tweaks    — tight TCP timeouts, SYN cookies"
    echo -e "  ${C}[2/5]${NC} Firewall rules   — CF whitelist, SYN/UDP/HTTP rate limits"
    echo -e "  ${C}[3/5]${NC} fail2ban         — ban repeated attackers automatically"
    echo -e "  ${C}[4/5]${NC} Smart auto-ban   — watch → throttle → ban pipeline"
    echo -e "  ${C}[5/5]${NC} Bandwidth cap    — unlimited for CF, link-scaled cap for others"
    echo ""
    echo -e "  ${DIM}Cloudflare IPs are never affected by any limit.${NC}"
    echo ""
    if [ -f /etc/antiddos/state.conf ]; then
        echo -e "  ${Y}⚠  Already installed — re-installing will refresh all rules.${NC}"
        echo ""
    fi
    sep2
    ui_confirm "Start installation?" || { echo -e "  ${DIM}Cancelled.${NC}"; return; }

    echo ""
    # Use --auto flag: skips the second confirm prompt inside antiddos.sh
    bash "$ANTIDDOS_SCRIPT" --auto

    # Show result summary
    echo ""
    sep
    if [ -f /etc/antiddos/state.conf ]; then
        echo -e "  ${G}✓ Anti-DDoS is now active!${NC}"
    else
        echo -e "  ${Y}⚠  Installation may be incomplete — run Status to check.${NC}"
    fi
    echo ""
    echo -e "  ${DIM}What now?${NC}"
    echo -e "  • Everything is automatic — no action needed"
    echo -e "  • Use ${C}Status & active bans${NC} to monitor blocked IPs"
    echo -e "  • Use ${C}Auto-ban control${NC} to see live ban log"
    echo -e "  • Use ${C}Whitelist${NC} to exempt your own / office IPs from every layer"
    sep
    press_enter
}

_autoban_control() {
    while true; do
        ui_title "Anti-DDoS › Auto-ban Control"
        echo -e "  Status: $(svc_status 'auto-ban')"
        echo ""
        ui_options "1|Start auto-ban" "2|Stop auto-ban" "3|View log (last 30)" \
            "4|Current banned IPs" "5|Flush all auto-bans" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
            1) systemctl start auto-ban 2>/dev/null && ok "auto-ban started" || err "Failed (not installed?)"
               press_enter ;;
            2) systemctl stop auto-ban 2>/dev/null && ok "auto-ban stopped"
               press_enter ;;
            3) tail -30 /var/log/auto-ban.log 2>/dev/null || warn "Log not found"
               press_enter ;;
            4) echo -e "  ${C}Currently banned IPs:${NC}"
               # The state file is the source of truth (BUG-051: the old
               # fallback scraped iptables -L output and presented other
               # tools' DROP rules as auto-bans).
               if [ -s /etc/antiddos/banned.list ]; then
                   cat /etc/antiddos/banned.list
               else
                   echo -e "  ${DIM}(none)${NC}"
               fi
               press_enter ;;
            5) echo -e "  ${Y}Flushing all auto-ban blocks...${NC}"
               # Delegates to the Anti-DDoS engine (BUG-008): comments
               # never appear in `iptables -L` output, so the old
               # grep-the-listing loop deleted nothing while reporting
               # success.
               if bash "$ANTIDDOS_SCRIPT" --flush-autobans 2>/dev/null; then
                   ok "All auto-bans flushed"
               else
                   err "Flush failed"
               fi
               press_enter ;;
            0) return ;;
        esac
    done
}

# ── CLI (v3.7): scriptable views, no menu ─────────────────
# F6: unknown flags error out instead of silently opening the menu.
case "${1:-}" in
    --status)  nx_status_plain; exit 0 ;;
    --bans)    nx_bans_plain; exit 0 ;;
    --version) echo "NexoShield v$VERSION"; exit 0 ;;
    --help)    echo "Usage: shield [--status|--bans|--version]  (no flag = interactive menu)"; exit 0 ;;
    *)  if [ -n "${1:-}" ]; then echo "Unknown option: $1" >&2; exit 2; fi ;;
esac

# ── Main Menu (dashboard home, v3.7) ──────────────────────
log "START: NexoShield menu v$VERSION"
while true; do
    draw_header
    ui_home_panel

    # Show inline status for key items
    _PROXY_ST="$(systemctl is-active 3proxy 2>/dev/null)"
    # BUG-053: "Active" must mean the daemon is RUNNING - the old probe
    # used state.conf's existence, which stays true after the daemon
    # died or was stopped.
    if systemctl is-active auto-ban >/dev/null 2>&1; then
        _DDOS_ST='active'
    elif [ -f /etc/antiddos/state.conf ]; then
        _DDOS_ST='installed'
    else
        _DDOS_ST='inactive'
    fi
    _NET_ST="$([ -f /etc/sysctl.d/99-vpn-optimized.conf ] && echo 'active' || echo 'inactive')"

    [ "$_PROXY_ST" = "active" ] && _P="${G}● Running${NC}" || _P="${Y}○ Not running${NC}"
    if [ "$_DDOS_ST" = "active" ]; then _D="${G}● Active${NC}"
    elif [ "$_DDOS_ST" = "installed" ]; then _D="${Y}○ Installed (stopped)${NC}"
    else _D="${Y}○ Not installed${NC}"; fi
    [ "$_NET_ST"   = "active" ] && _N="${G}● Optimized${NC}" || _N="${Y}○ Default${NC}"

    ui_options "1|SOCKS5 Proxy|$_P" "2|Network Optimization|$_N" \
        "3|Anti-DDoS|$_D" "4|Monitoring" "5|Security" "6|Services" \
        "7|System" "8|Update NexoShield|v$VERSION" "0|Exit"
    ui_input CH "  Enter number: "
    case "$CH" in
        1) menu_proxy ;;
        2) menu_sysctl ;;
        3) menu_antiddos ;;
        4) menu_monitor ;;
        5) menu_security ;;
        6) menu_services ;;
        7) menu_system ;;
        8) nx_update_nexoshield; press_enter ;;
        0) clear; exit 0 ;;
    esac
done
MENU_SCRIPT


# ══════════════════════════════════════════════════════════
# File 4: antiddos.sh
# ══════════════════════════════════════════════════════════
cat > "$INSTALL_DIR/.antiddos.sh.nxnew" << 'ANTIDDOS_SCRIPT'
#!/bin/bash
# shellcheck disable=SC2015,SC2094
# Reviewed idioms (Wave 10): SC2015 - `cond && ok-print || err-print`
# chains whose middle command is a print helper that cannot fail;
# SC2094 - atomic state writes via tmp-file + rename, which the
# checker flags as same-file pipelines. Both classes were audited
# site-by-site during the fix waves (docs/FIX-PLAN.md).
# ============================================================
#  Anti-DDoS Protection Manager v3.19.0
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
#    - auto-ban: 120 active conns = watch, 300 conns = instant ban (progressive)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_VERSION="3.19.0"
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
PUBLIC_IPS_FILE="/etc/antiddos/public-ips.list"
EXEMPT_FILE="/etc/antiddos/exempt.list"

# Daemon live state (F5): /run/nexoshield, not /tmp — /tmp entries are
# world-writable, so a pre-planted symlink could make a root truncate
# or append hit an attacker-chosen file. /run is root-owned tmpfs
# (same volatility semantics as /tmp); the persistent mirrors stay
# under /etc/antiddos. The daemon uses the same defaults.
WATCH_LIST="${WATCH_LIST:-/run/nexoshield/autoban_watch}"
THROTTLE_LIST="${THROTTLE_LIST:-/run/nexoshield/autoban_throttle}"
SUBNET_WATCH_LIST="${SUBNET_WATCH_LIST:-/run/nexoshield/autoban_subnet_watch}"
mkdir -p /run/nexoshield 2>/dev/null || true

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1


# BUG-019: every iptables call in this script takes the xtables lock with
# a 5s wait. The daemon, fail2ban and the menus mutate rules concurrently;
# without -w a contended call fails with "Resource temporarily
# unavailable" and the failure is usually swallowed by || true - rules
# silently never landed. (iptables-save/-restore are separate binaries
# and are not affected by this wrapper.)
iptables() { command iptables -w 5 "$@"; }
ip6tables() { command ip6tables -w 5 "$@"; }

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
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi
# ── Cloudflare IPv6 ranges (loaded from shared data file) ──
CF6_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv6.list ]; then
    while IFS= read -r _cfl6; do
        _cfl6="${_cfl6//[[:space:]]/}"
        [ -n "$_cfl6" ] && CF6_RANGES+=("$_cfl6")
    done < /etc/antiddos/cloudflare-ipv6.list
fi

# Get all server's own public IPs (auto-whitelist)
# (intentionally empty: the only function this lib held was removed - see above)
list_self_ips() {
    { ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+'
      hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    } | sort -u | grep -v '^$'
}

# list_self_ips6 - every local IPv6 address (incl. ::1), one per line.
list_self_ips6() {
    { ip -6 addr show 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+'
      echo "::1"
    } | sort -u | grep -v '^$'
}

# ── Public-IP discovery for NAT / cloud servers ─────────────────
# On cloud VMs (Azure, most NAT setups) the server's public IPv4
# exists only in the provider's NAT - it is on NO interface, so
# list_self_ips can never see it, yet it is unmistakably one of the
# server's own addresses (FR-2). Discovery asks the cloud metadata
# service (link-local, no internet involved); only when no metadata
# service answers does it fall back to an external echo service.
# Every candidate passes nx_is_public_ipv4: metadata/echo replies
# are untrusted input, and a private/documentation/garbage answer
# must never widen the immune set.
NX_PUBLIC_IPS_FILE="${NX_PUBLIC_IPS_FILE:-/etc/antiddos/public-ips.list}"

nx_is_public_ipv4() {
    local ip="${1:-}" o1 o2 o3 o4 extra _o
    case "$ip" in *[!0-9.]*) return 1 ;; esac
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for _o in "$o1" "$o2" "$o3" "$o4"; do
        case "$_o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_o}" -le 3 ] || return 1
        (( 10#$_o <= 255 )) || return 1
    done
    case "$o1" in
        0|10|127) return 1 ;;
        100) [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 1 ;;
        169) [ "$o2" = 254 ] && return 1 ;;
        172) [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 1 ;;
        192) [ "$o2" = 168 ] && return 1
             { [ "$o2" = 0 ] && { [ "$o3" = 0 ] || [ "$o3" = 2 ]; }; } && return 1 ;;
        198) case "$o2" in 18|19|51) return 1 ;; esac ;;
        203) { [ "$o2" = 0 ] && [ "$o3" = 113 ]; } && return 1 ;;
    esac
    [ "$o1" -ge 224 ] && return 1
    return 0
}

nx_metadata_public_ips() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _tok _base="http://169.254.169.254"
    # Azure IMDS (first two addresses on the primary NIC)
    for _idx in 0 1; do
        _ip=$(curl -s -m 2 -H "Metadata: true" \
            "$_base/metadata/instance/network/interface/0/ipv4/ipAddress/$_idx/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
        nx_is_public_ipv4 "$_ip" && echo "$_ip"
    done
    # AWS EC2 IMDS (token first, plain fallback)
    _tok=$(curl -s -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "$_base/latest/api/token" 2>/dev/null)
    if [ -n "$_tok" ]; then
        _ip=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $_tok" \
            "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    else
        _ip=$(curl -s -m 2 "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    fi
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # GCP
    _ip=$(curl -s -m 2 -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # DigitalOcean
    _ip=$(curl -s -m 2 "$_base/metadata/v1/interfaces/public/0/ipv4/address" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # Hetzner Cloud
    _ip=$(curl -s -m 2 "$_base/hetzner/v1/metadata/public-ipv4" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    return 0
}

nx_external_public_ip() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _url
    for _url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me/ip"; do
        _ip=$(curl -s -m 3 "$_url" 2>/dev/null | tr -d ' \r\n')
        nx_is_public_ipv4 "$_ip" && { echo "$_ip"; return 0; }
    done
    return 0
}

# Echo the server's public IPv4s that are NOT on any interface
# (metadata first; external echo only as a last resort).
discover_public_ips() {
    local _found _ip
    _found=$(nx_metadata_public_ips | sort -u)
    [ -z "$_found" ] && _found=$(nx_external_public_ip)
    for _ip in $_found; do
        list_self_ips | grep -qxF "$_ip" || echo "$_ip"
    done
}

# Refresh the cache file; a failed/empty discovery NEVER wipes a
# previously discovered set (an offline reinstall must not disarm
# the immunity). Prints the discovered addresses when any exist.
nx_refresh_public_ips_cache() {
    local _found
    _found=$(discover_public_ips)
    if [ -n "$_found" ]; then
        mkdir -p "$(dirname "$NX_PUBLIC_IPS_FILE")" 2>/dev/null || true
        printf '%s\n' "$_found" > "$NX_PUBLIC_IPS_FILE.tmp" 2>/dev/null && \
            mv "$NX_PUBLIC_IPS_FILE.tmp" "$NX_PUBLIC_IPS_FILE" 2>/dev/null || true
        printf '%s\n' "$_found"
    elif [ -f "$NX_PUBLIC_IPS_FILE" ]; then
        cat "$NX_PUBLIC_IPS_FILE"
    fi
}

# list_self_ips_all - interface addresses PLUS the cached
# discovered public IPs. This is the feed every enforcement layer
# uses for "the server's own addresses" (FR-2 complete: local,
# private, secondary AND NAT-public).
list_self_ips_all() {
    { list_self_ips
      if [ -r "$NX_PUBLIC_IPS_FILE" ]; then
          grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$NX_PUBLIC_IPS_FILE" 2>/dev/null
      fi
    } | sort -u | grep -v '^$'
}
NX_CONFIG_FILE="${NX_CONFIG_FILE:-/etc/antiddos/scoring.conf}"

declare -A _NX_CFG_CACHE=() _NX_CFG_WARNED=()
_NX_CFG_MTIME=""
_NX_CFG_CHECKED=0

_nx_cfg_stat() {
    stat -c %Y "$NX_CONFIG_FILE" 2>/dev/null || echo "absent"
}

# Reload the cache when the file changed (cheap: one stat per second).
_nx_cfg_refresh() {
    local now=$EPOCHSECONDS m
    [ $((now - _NX_CFG_CHECKED)) -lt 1 ] && return 0
    _NX_CFG_CHECKED=$now
    m="$(_nx_cfg_stat)"
    if [ "$m" != "$_NX_CFG_MTIME" ]; then
        _NX_CFG_MTIME="$m"
        _NX_CFG_CACHE=()
    fi
}

_nx_cfg_warn() {
    [ -n "${_NX_CFG_WARNED[$1]:-}" ] && return 0
    _NX_CFG_WARNED[$1]=1
    if declare -F log >/dev/null 2>&1; then
        log " CONFIG: ignoring ${2:-invalid value} for '$1' in $NX_CONFIG_FILE (using default)"
    else
        echo "CONFIG: ignoring ${2:-invalid value} for '$1' in $NX_CONFIG_FILE (using default)" >&2
    fi
}

# L7: sane ranges for every documented scoring key (min:max). A
# value outside its range is ignored with a warning and the default
# is used instead - a typo like conn_threshold=-5 or score_ban=500
# must never silently disarm or invert a gate. Unknown keys are
# unchecked (nx_cfg stays generic). Floats compare via awk.
declare -A _NX_CFG_RANGE=(
    [score_ban]="0:100" [score_hard]="0:100" [score_throttle]="0:100" [score_suspect]="0:100"
    [score_recover_per_min]="0:1000" [probation_recover_per_min]="0:1000" [score_drop_cap_per_min]="0:1000"
    [probation_score]="0:100" [probation_seconds]="0:86400"
    [churn_allow_per_sec]="0:100000" [churn_weight]="0:1000" [churn_cap]="0:100"
    [sust_divisor]="1:100000" [sust_cap]="0:100"
    [syn_min]="0:100000" [syn_ratio]="0:1" [syn_weight]="0:1000" [syn_cap]="0:100"
    [conn_threshold]="0:1000000" [ban_conn_threshold]="0:1000000" [observe_seconds]="0:3600"
    [ban_base_minutes]="1:10080" [ban_max_minutes]="1:43200" [ban_hours_fallback]="0:168"
    [subnet_threshold]="0:1000000" [subnet_ban_threshold]="0:1000000"
    [subnet_min_offenders]="1:100000" [subnet_ban_minutes]="1:10080"
    [stress_gate]="0:1" [adaptive_enabled]="0:1"
    [xdp_syncookie_rate]="0:10000000" [xdp_overflow_rate]="0:10000000" [xdp_syn_rate]="0:10000000"
    [xdp_calm_seconds]="0:86400"
)

nx_cfg() {
    local key="$1" def="$2" raw=""
    _nx_cfg_refresh
    if [ -n "${_NX_CFG_CACHE[$key]+set}" ]; then
        printf '%s' "${_NX_CFG_CACHE[$key]}"
        return 0
    fi
    if [ -f "$NX_CONFIG_FILE" ]; then
        raw=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$NX_CONFIG_FILE" 2>/dev/null \
              | tail -n 1 | cut -d= -f2- | tr -d ' \t\r"')
    fi
    if [ -n "$raw" ]; then
        if [[ "$raw" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
            local _range="${_NX_CFG_RANGE[$key]:-}"
            if [ -n "$_range" ]; then
                local _lo="${_range%%:*}" _hi="${_range#*:}"
                if ! awk -v v="$raw" -v lo="$_lo" -v hi="$_hi" 'BEGIN{exit !(v>=lo && v<=hi)}' 2>/dev/null; then
                    _nx_cfg_warn "$key" "out-of-range value '$raw' (allowed $_lo-$_hi)"
                    _NX_CFG_CACHE[$key]="$def"
                    printf '%s' "$def"
                    return 0
                fi
            fi
            _NX_CFG_CACHE[$key]="$raw"
            printf '%s' "$raw"
            return 0
        fi
        _nx_cfg_warn "$key"
    fi
    _NX_CFG_CACHE[$key]="$def"
    printf '%s' "$def"
}

# Write the default config at install time. NEVER overwrites an existing
# file — admin edits are sacred. Every key is documented inline.
nx_ensure_scoring_config() {
    local f="${NX_CONFIG_FILE:-/etc/antiddos/scoring.conf}"
    [ -f "$f" ] && return 0
    mkdir -p "$(dirname "$f")" 2>/dev/null || return 1
    cat > "$f" <<'EOF'
# NexoShield scoring configuration — every value is optional.
# Delete a line (or this whole file) to return that knob to its default.
# Changes take effect within seconds; the daemon re-reads on mtime.
# All values must be numeric. Invalid values are ignored with a warning.

# ── Score bands (0-100 reputation) ──
score_ban=20            # below: ban (progressive duration)
score_hard=40           # below: hard throttle 50 Mbps
score_throttle=60       # below: throttle 100 Mbps
score_suspect=80        # below: watch only

# ── Score movement (points per minute) ──
score_recover_per_min=6
probation_recover_per_min=10
score_drop_cap_per_min=45
probation_score=50
probation_seconds=1800

# ── Term weights ──
churn_allow_per_sec=2   # free new-connection rate before churn applies
churn_weight=1.2        # points/min per conn/s above the allowance
churn_cap=30
sust_divisor=40         # connections over threshold per point/min
sust_cap=20
syn_min=20              # min half-open conns before the SYN term arms
syn_ratio=0.5           # half-open share that starts costing points
syn_weight=40
syn_cap=15

# ── Gates ──
conn_threshold=120      # active conns from one IP = start watching
ban_conn_threshold=300  # active conns = instant throttle+ban
observe_seconds=45      # watch window before throttle (legit spikes)

# ── Bans ──
ban_base_minutes=30     # first ban; doubles per repeat offence
ban_max_minutes=10080   # cap (7 days)
ban_hours_fallback=4    # legacy flat duration for non-progressive paths

# ── Subnet (/24) ──
subnet_threshold=400        # total conns = start watching
subnet_ban_threshold=1000     # total conns = block (with guardrails)
subnet_min_offenders=5        # distinct IPs that must be over the gate
subnet_ban_minutes=60

# ── Stress gate (Phase 1d) ──
stress_gate=1           # 1: score bans need host stress (or score < 10)

# ── Adaptive thresholds (Phase 2d; needs nxcountd) ──
adaptive_enabled=1      # 1: tighten gates under a global arrival anomaly

# ── XDP emergency shield triggers (Phase 3) ──
xdp_syncookie_rate=500  # syncookies sent per minute that justify line-rate relief
xdp_overflow_rate=1000  # listen overflows per minute that justify relief
xdp_syn_rate=3000       # sustained SYN arrivals/sec that justify relief
xdp_calm_seconds=600    # calm required before the shield detaches
EOF
    chmod 644 "$f" 2>/dev/null || true
}
# nx_install_binary SRC DEST [MODE]
# Atomically replace DEST with SRC: copy to a staging file in the
# SAME directory, then rename over DEST. A plain `cp` onto a
# RUNNING executable fails with ETXTBSY ("Text file busy") - this
# broke 3proxy Install/Update on every live server (v3.16.0 field
# report: the service runs from /usr/local/bin/3proxy while the
# update tried to overwrite that very file). rename(2) swaps the
# path instantly; the running process keeps its old inode and is
# undisturbed until its service restarts onto the new binary.
nx_install_binary() {
    local src="$1" dst="$2" mode="${3:-755}" tmp
    tmp="${dst}.new.$$"
    if cp "$src" "$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$dst"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}
# A counting rule has no -j target: it counts only packets that
# REACH it. Any ACCEPT above it (an antiddos -I insert, or a
# third-party firewall's blanket rule) shadows it, so a counter
# that is merely inserted once silently undercounts. Field report
# v3.16.3: stats_in buried at INPUT #811 below the ESTABLISHED
# accept counted SYNs only (282 pkts / 14 KB while the interface
# moved ~515 MB); stats_out below a blanket OUTPUT accept counted
# exactly zero. The pin below re-asserts the rules at position 1,
# and only moves them when they are NOT already on top, so a
# re-pin never destroys a healthy counter. Moving a target-less
# rule changes no allow/block behaviour - it only counts.
nx_proxy_stats_top() {
    # nx_proxy_stats_top CHAIN COMMENT [PORT] -> 0 if the chain's
    # first rule carries COMMENT (and, when PORT is given, the
    # matching --dport/--sport PORT). LOW-2: a stale other-port
    # rule at position 1 used to satisfy the comment-only check, so
    # the pin became a no-op and the accumulator read the wrong
    # counter. The trailing-space/EOL alternatives keep port 1080
    # from matching 10801.
    local _first
    _first=$(iptables -S "$1" 2>/dev/null | grep -m1 '^-A' || true)
    case "$_first" in *"$2"*) ;; *) return 1 ;; esac
    if [ -n "${3:-}" ]; then
        case "$_first" in
            *"--dport ${3} "*|*"--dport ${3}"|*"--sport ${3} "*|*"--sport ${3}") ;;
            *) return 1 ;;
        esac
    fi
    return 0
}

nx_pin_proxy_stats_rules() {
    # nx_pin_proxy_stats_rules PORT: re-assert both counting rules
    # at position 1. No-op (counter preserved) when already pinned.
    local PORT="$1"
    [ -n "$PORT" ] || return 0
    if ! nx_proxy_stats_top INPUT "3proxy_stats_in" "$PORT"; then
        iptables -D INPUT -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in" 2>/dev/null || true
        iptables -I INPUT 1 -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    fi
    if ! nx_proxy_stats_top OUTPUT "3proxy_stats_out" "$PORT"; then
        iptables -D OUTPUT -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out" 2>/dev/null || true
        iptables -I OUTPUT 1 -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    fi
}

nx_proxy_stats_bytes() {
    # nx_proxy_stats_bytes CHAIN COMMENT [PORT] -> counter bytes
    # (or empty). Same parse as show_stats: the bytes column of
    # `iptables -L`. With PORT, the row must also carry dpt:/spt:
    # PORT (the [^0-9] guard keeps 1080 from matching 10801).
    if [ -n "${3:-}" ]; then
        iptables -L "$1" -v -n -x 2>/dev/null | grep "$2" | grep -E "(dpt|spt):${3}([^0-9]|$)" | awk '{print $2}' | head -1
    else
        iptables -L "$1" -v -n -x 2>/dev/null | grep "$2" | awk '{print $2}' | head -1
    fi
}

nx_proxy_port_from_config() {
    # Live port from the 3proxy config (source of truth, not install.info).
    grep -oP '(?<=socks -p)\s*\K\d+' /etc/3proxy/3proxy.cfg 2>/dev/null | head -1 || true
}

# State file format (one line): LAST_IN LAST_OUT TOTAL_IN TOTAL_OUT.
# Written atomically (tmp + rename). Totals survive reboots and rule
# recreations: a counter that went BACKWARDS means its rule was
# recreated, so the delta is the new counter itself, never negative.
# A missing rule (proxy removed, rules wiped) leaves totals untouched.
nx_proxy_traffic_accum() {
    # LOW-3: the timer, the pin callers and a manual run can overlap
    # (two writers interleaving read-compute-write would lose a
    # delta). A non-blocking lock defers a contended run to the
    # next 5-minute tick instead of blocking the caller - the
    # snapshot is periodic, never urgent. No flock binary: proceed
    # unlocked (the old behaviour), never fail the caller.
    local PORT STATE CUR_IN CUR_OUT LAST_IN LAST_OUT TOT_IN TOT_OUT _lock_fd _rc
    PORT=$(nx_proxy_port_from_config)
    [ -n "$PORT" ] || return 0
    STATE="${NX_PROXY_TRAFFIC_STATE:-/etc/3proxy/traffic-total.state}"
    if command -v flock >/dev/null 2>&1; then
        exec {_lock_fd}>"${STATE}.lock" 2>/dev/null || _lock_fd=""
        if [ -n "$_lock_fd" ]; then
            flock -n "$_lock_fd" 2>/dev/null || { exec {_lock_fd}>&- 2>/dev/null || true; return 0; }
        fi
    fi
    CUR_IN=$(nx_proxy_stats_bytes INPUT "3proxy_stats_in" "$PORT")
    CUR_OUT=$(nx_proxy_stats_bytes OUTPUT "3proxy_stats_out" "$PORT")
    # Release the lock on every exit path: a leaked fd would hold
    # the lock in a long-lived caller (the menu process, the test
    # harness) and starve every later run.
    if [ -z "$CUR_IN" ] || [ -z "$CUR_OUT" ]; then
        [ -n "${_lock_fd:-}" ] && exec {_lock_fd}>&- 2>/dev/null || true
        return 0
    fi
    LAST_IN=""; LAST_OUT=""; TOT_IN=""; TOT_OUT=""
    if [ -f "$STATE" ]; then
        read -r LAST_IN LAST_OUT TOT_IN TOT_OUT < "$STATE" 2>/dev/null || true
    fi
    LAST_IN="${LAST_IN//[^0-9]/}"; LAST_OUT="${LAST_OUT//[^0-9]/}"
    TOT_IN="${TOT_IN//[^0-9]/}"; TOT_OUT="${TOT_OUT//[^0-9]/}"
    LAST_IN="${LAST_IN:-0}"; LAST_OUT="${LAST_OUT:-0}"
    TOT_IN="${TOT_IN:-0}"; TOT_OUT="${TOT_OUT:-0}"
    if [ "$CUR_IN" -ge "$LAST_IN" ] 2>/dev/null; then TOT_IN=$((TOT_IN + CUR_IN - LAST_IN)); else TOT_IN=$((TOT_IN + CUR_IN)); fi
    if [ "$CUR_OUT" -ge "$LAST_OUT" ] 2>/dev/null; then TOT_OUT=$((TOT_OUT + CUR_OUT - LAST_OUT)); else TOT_OUT=$((TOT_OUT + CUR_OUT)); fi
    printf '%s %s %s %s\n' "$CUR_IN" "$CUR_OUT" "$TOT_IN" "$TOT_OUT" > "${STATE}.tmp.$$" 2>/dev/null && mv -f "${STATE}.tmp.$$" "$STATE" 2>/dev/null || true
    # Self-heal shadowing AFTER the snapshot, so a re-pin never
    # destroys counts it has not yet recorded.
    nx_pin_proxy_stats_rules "$PORT"
    _rc=$?
    [ -n "${_lock_fd:-}" ] && exec {_lock_fd}>&- 2>/dev/null || true
    return "$_rc"
}
# Shared ban-state lock (L5): the admin release path must serialize
# against the daemon's bans on the same lock path (see lib/state-lock.sh).
NX_STATE_LOCK_FILE="${NX_STATE_LOCK_FILE:-/run/nexoshield/state.lock}"
NX_STATE_LOCK_DEPTH=0
nx_state_lock() {
    if [ "${NX_STATE_LOCK_DEPTH:-0}" -gt 0 ]; then
        NX_STATE_LOCK_DEPTH=$(( NX_STATE_LOCK_DEPTH + 1 ))
        return 0
    fi
    mkdir -p /run/nexoshield 2>/dev/null || true
    if command -v flock >/dev/null 2>&1; then
        if exec 200>"$NX_STATE_LOCK_FILE" 2>/dev/null; then
            flock -x -w 10 200 2>/dev/null || true
        fi
    fi
    NX_STATE_LOCK_DEPTH=1
}
nx_state_unlock() {
    [ "${NX_STATE_LOCK_DEPTH:-0}" -gt 0 ] || return 0
    NX_STATE_LOCK_DEPTH=$(( NX_STATE_LOCK_DEPTH - 1 ))
    if [ "$NX_STATE_LOCK_DEPTH" -eq 0 ]; then
        flock -u 200 2>/dev/null || true
        exec 200>&- 2>/dev/null || true
    fi
}

# Detect environment
detect_env() {
    RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 512)
    RAM_MB="${RAM_MB//[^0-9]/}"; RAM_MB="${RAM_MB:-512}"
    CPU_CORES=$(nproc 2>/dev/null || echo 1)
    CPU_CORES="${CPU_CORES//[^0-9]/}"; CPU_CORES="${CPU_CORES:-1}"
    VIRT_TYPE="bare-metal"
    systemd-detect-virt 2>/dev/null | grep -qi kvm    && VIRT_TYPE="kvm"    || true
    systemd-detect-virt 2>/dev/null | grep -qi lxc    && VIRT_TYPE="lxc"    || true
    [ -f /proc/vz/version ]                            && VIRT_TYPE="openvz" || true

    SYNPROXY_OK=0;  modprobe xt_SYNPROXY  2>/dev/null && SYNPROXY_OK=1  || true
    HASHLIMIT_OK=0; modprobe xt_hashlimit 2>/dev/null && HASHLIMIT_OK=1 || true
    CONNLIMIT_OK=0; modprobe xt_connlimit 2>/dev/null && CONNLIMIT_OK=1 || true
    CONNTRACK_OK=0; modprobe nf_conntrack 2>/dev/null && CONNTRACK_OK=1 || true

    # Detect main network interface
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    MAIN_IF=${MAIN_IF:-eth0}

    # Count public IPs (for rp_filter decision). The exclusion list is
    # every non-public range, including CGNAT 100.64/10 (L13: it used
    # to be counted as public, skewing the multi-IP decision). The
    # address is extracted first so the match is anchored (an
    # unanchored "10\." also matched 110.x public addresses).
    PUBLIC_IP_COUNT=$(ip -4 addr show 2>/dev/null | grep 'inet ' | \
        grep -oP '(?<=inet )[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        grep -cv '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.64\.)' || true)
    PUBLIC_IP_COUNT="${PUBLIC_IP_COUNT:-0}"

    # Scale rate limits by RAM.
    # CONN_LIMIT_PER_IP tiers (v3.13) sit ABOVE the auto-ban
    # daemon's watch gate (120 concurrent) on every tier, so the
    # behavioural scorer engages before the kernel starts resetting
    # connections - the connlimit is the hard backstop against
    # connection-hold exhaustion, not the first responder. The old
    # 50/100/200 tiers fired below the watch gate and reset
    # legitimate shared IPs (CGNAT, office/home NAT, VPN egress),
    # where one public IP routinely carries 100+ concurrent
    # connections from many real users. BW tiers rose for the same
    # reason: 50 Mbit/s starved a single legitimate proxy/download
    # user on a small box; a per-IP ceiling exists to stop one
    # source monopolising the link, not to ration normal use. On a
    # slower link than the tier value the cap simply never fires.
    if [ "$RAM_MB" -ge 4096 ]; then
        SYN_LIMIT="2000/sec"; SYN_BURST="4000"
        UDP_LIMIT="500/sec";  UDP_BURST="1000"
        ICMP_LIMIT="100/sec"; ICMP_BURST="200"
        CONN_LIMIT_PER_IP="600"
        NEW_CONN_RATE="400/sec"; NEW_CONN_BURST="800"
        # HTTP_REQ_RATE: packets on ESTABLISHED TCP per IP
        # A heavy download = ~1500byte packets = ~800 pkt/s per Gbps
        # Normal user with 100Mbps fiber download = ~80 pkt/s — set 2000 to be safe
        HTTP_REQ_RATE="2000/sec"; HTTP_REQ_BURST="4000"
        BW_PER_IP_MBIT="500"
    elif [ "$RAM_MB" -ge 2048 ]; then
        SYN_LIMIT="1000/sec"; SYN_BURST="2000"
        UDP_LIMIT="300/sec";  UDP_BURST="600"
        ICMP_LIMIT="50/sec";  ICMP_BURST="100"
        CONN_LIMIT_PER_IP="300"
        NEW_CONN_RATE="200/sec"; NEW_CONN_BURST="400"
        HTTP_REQ_RATE="1000/sec"; HTTP_REQ_BURST="2000"
        BW_PER_IP_MBIT="250"
    else
        SYN_LIMIT="500/sec";  SYN_BURST="1000"
        UDP_LIMIT="150/sec";  UDP_BURST="300"
        ICMP_LIMIT="25/sec";  ICMP_BURST="50"
        CONN_LIMIT_PER_IP="150"
        NEW_CONN_RATE="100/sec"; NEW_CONN_BURST="200"
        HTTP_REQ_RATE="500/sec"; HTTP_REQ_BURST="1000"
        BW_PER_IP_MBIT="100"
    fi
}

# ════════════════════════════════════════════════
# LAYER 1: Kernel hardening (sysctl)
# ════════════════════════════════════════════════
apply_sysctl_hardening() {
    info "Applying kernel hardening (sysctl)..."

    # Decide rp_filter: multi-IP servers must use 0
    # (rp_filter=1 breaks asymmetric routing on servers with multiple public IPs)
    RP_FILTER=1
    [ "${PUBLIC_IP_COUNT:-0}" -gt 1 ] && RP_FILTER=0

    cat > "$SYSCTL_FILE" << EOF
# Anti-DDoS Kernel Hardening — $(date)
# Generated by antiddos.sh v${SCRIPT_VERSION}
# rp_filter=$RP_FILTER (multi-IP detection: $PUBLIC_IP_COUNT public IPs)

# ── SYN Flood ─────────────────────────────────
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# ── Connection & TIME_WAIT ────────────────────
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_max_tw_buckets = 1440000
# tcp_max_orphans: limits half-open connections (Hold/Heavy attack defense)
net.ipv4.tcp_max_orphans = 65536
# Keepalive 30s: detect dead connections fast (Slowloris mitigation)
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 3

# ── IP Spoofing & Redirects ───────────────────
net.ipv4.conf.all.rp_filter = $RP_FILTER
net.ipv4.conf.default.rp_filter = $RP_FILTER
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── ICMP ─────────────────────────────────────
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089

# ── conntrack — TIGHT timeouts ────────────────
# syn_recv=8s: attacker's half-open connections expire fast
# established=120s: dead tunnels cleared quickly
# udp=15s, icmp=5s: flood states expire fast
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 8
net.netfilter.nf_conntrack_tcp_timeout_established = 120
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_udp_timeout = 15
# stream=120: WARP/WireGuard keepalive (25s) must never expire the tunnel.
# 120 = ~5x keepalive — absorbs packet-loss/jitter, still < kernel default (180).
# UDP-flood protection comes from hashlimit, not this timeout, so it's safe.
net.netfilter.nf_conntrack_udp_timeout_stream = 120
net.netfilter.nf_conntrack_icmp_timeout = 5
net.netfilter.nf_conntrack_generic_timeout = 60

# ── ARP ──────────────────────────────────────
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192
EOF
    chmod 644 "$SYSCTL_FILE"

    APPLIED=0; SKIPPED=0
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# || -z "${line// }" ]] && continue
        KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
        VAL=$(echo "$line" | cut -d= -f2- | tr -d ' ')
        [ -z "$KEY" ] || [ -z "$VAL" ] && continue
        if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
            APPLIED=$((APPLIED+1))
        else
            SKIPPED=$((SKIPPED+1))
            sed -i "s|^${KEY} =|# [N/A] ${KEY} =|" "$SYSCTL_FILE" 2>/dev/null || true
        fi
    done < "$SYSCTL_FILE"
    success "Kernel: $APPLIED params applied${SKIPPED:+, $SKIPPED skipped}"
}

# ════════════════════════════════════════════════
# LAYER 2: iptables rules
# CRITICAL: CF IPs whitelisted BEFORE any rate-limit
# ════════════════════════════════════════════════

# nx_static_rules_filter: iptables-save output (stdin) -> the STATIC
# ruleset (stdout). Transient enforcement state must never be baked into
# boot persistence (BUG-012): auto-ban/subnet-ban DROP rules and fail2ban
# chains are runtime state, rebuilt by their owners; persisting them made
# expired bans immortal and resurrected removed rules after reboot.
nx_static_rules_filter() {
    grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' || true
}

# save_static_rules <file>: persist only the static ruleset.
save_static_rules() {
    iptables-save 2>/dev/null | nx_static_rules_filter > "$1" || true
}
apply_iptables() {
    info "Applying iptables rules..."

    # BUG-027 (fail closed): with no Cloudflare ranges loaded, every rule
    # below would treat CF IPs as ordinary traffic. Refuse to arm.
    if [ "${#CF_RANGES[@]}" -eq 0 ]; then
        err "Cloudflare range list is empty/missing - refusing to apply iptables rules (CF would lose its exemption)"
        return 1
    fi

    # BUG-063: purge rate rules from any previous run/tier first. The
    # named hashlimit tables are ours by construction; re-applying with
    # different thresholds otherwise APPENDS new rules next to the old
    # ones (same --hashlimit-name), and the old rule - evaluated first -
    # keeps deciding, so a raised limit silently never takes effect.
    # Deletion is by rule number from `iptables -S` (spec deletion breaks
    # on quoted arguments).
    local _pn
    for _pn in $(iptables -S INPUT 2>/dev/null | \
            grep -nE 'hashlimit-name (syn_flood|udp_flood|icmp_flood|rst_flood|bw_per_ip|bw_per_ip_test|new_conn_rate|http_req_rate|udp_reflect_[0-9]+)|nx_connlimit' | \
            cut -d: -f1 | sort -rn); do
        iptables -D INPUT $((_pn - 1)) 2>/dev/null || true
    done

    # Helper: add if not already present
    ipt_add() { iptables -C "$@" 2>/dev/null || iptables -A "$@"; }
    ipt_ins() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }

    # ── Step 0: Loopback ─────────────────────────────
    ipt_ins INPUT -i lo -j ACCEPT

    # ── Step 1: Drop INVALID state ───────────────────
    ipt_ins INPUT   -m conntrack --ctstate INVALID -j DROP
    ipt_ins FORWARD -m conntrack --ctstate INVALID -j DROP
    success "Invalid packet drop: ON"

    # ── Step 2: ESTABLISHED fast path + the two rules that police it ──
    # BUG-002 fix: the ESTABLISHED accept used to sit alone at the top, so
    # the two rules that police ESTABLISHED traffic (bw_per_ip and
    # http_req_rate, appended far below) were unreachable dead code - an
    # established connection was accepted before ever reaching them.
    # Insert order here is deliberate (ipt_ins stacks; last insert = top):
    #   1) ESTABLISHED accept  -> ends up deepest of the three
    #   2) bw_per_ip           -> above the accept, so it can police it
    #   3) http_req_rate       -> above bw_per_ip
    # The whitelist ACCEPTs (Steps 3-4c) are inserted AFTER this step and
    # therefore land ABOVE all three: exempt traffic is never policed,
    # exactly as before. Everything appended later stays below.
    ipt_ins INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ── Step 2a: Per-IP bandwidth cap (polices ESTABLISHED) ──
    # _proc_heavy sends 64MB+ per connection. Byte-mode hashlimit
    # caps per-IP throughput on established flows.
    # Try hashlimit byte-mode (kernel 4.1+), fallback to connlimit
    local BW_APPLIED=0
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        # Test if byte-mode (mbit/s) is supported by this kernel
        if iptables -A INPUT -p tcp \
            -m hashlimit \
            --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
            --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
            --hashlimit-mode srcip \
            --hashlimit-name bw_per_ip_test \
            --hashlimit-htable-expire 5000 \
            -j DROP 2>/dev/null; then
            # Success — remove test rule, add the real one via ipt_ins
            iptables -D INPUT -p tcp \
                -m hashlimit \
                --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
                --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
                --hashlimit-mode srcip \
                --hashlimit-name bw_per_ip_test \
                --hashlimit-htable-expire 5000 \
                -j DROP 2>/dev/null || true
            ipt_ins INPUT -p tcp \
                -m conntrack --ctstate ESTABLISHED,RELATED \
                -m hashlimit \
                --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
                --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
                --hashlimit-mode srcip \
                --hashlimit-name bw_per_ip \
                --hashlimit-htable-expire 5000 \
                -j DROP 2>/dev/null && BW_APPLIED=1
            [ "$BW_APPLIED" -eq 1 ] && \
                success "Per-IP bandwidth cap: ${BW_PER_IP_MBIT}Mbps max per non-CF IP"
        fi
    fi
    if [ "$BW_APPLIED" -eq 0 ]; then
        # Fallback: use connlimit — limit simultaneous connections per IP
        # Each connection ~1-5 Mbps for proxy; 60 conns ≈ 60-300 Mbps cap
        ipt_add INPUT -p tcp \
            -m conntrack --ctstate NEW \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" --connlimit-mask 32 \
            -j DROP 2>/dev/null && \
            success "Per-IP bandwidth cap: connlimit fallback (max $CONN_LIMIT_PER_IP conns/IP — kernel too old for byte-mode)" || \
            warn "Per-IP bandwidth cap: both byte-mode and connlimit fallback failed"
    fi


    # ── Step 2b: HTTP request rate (polices ESTABLISHED) ──
    if [ "$HASHLIMIT_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ]; then
            # ── HTTP request rate (packet rate on established TCP) ────
            # _proc_http_burst sends hundreds of requests on keep-alive.
            # hashlimit on all-TCP-packets (not just NEW) catches this.
            ipt_ins INPUT -p tcp \
                -m conntrack --ctstate ESTABLISHED \
                -m hashlimit \
                --hashlimit-above "$HTTP_REQ_RATE" \
                --hashlimit-burst "$HTTP_REQ_BURST" \
                --hashlimit-mode srcip \
                --hashlimit-name http_req_rate \
                --hashlimit-htable-expire 10000 \
                -j DROP
            success "HTTP burst rate: max $HTTP_REQ_RATE pkt/s per non-CF IP (heavy/http_burst defense)"
    fi

    # ── Step 3: CF IPs → ACCEPT (NO limits ever) ─────
    # This is the MOST CRITICAL rule:
    # CF IPs must be accepted BEFORE any hashlimit/connlimit/rate rule
    # Otherwise, CF tunnel traffic can trigger SYN/UDP limits and kill users
    info "Whitelisting Cloudflare IPs (unlimited, no rate limits)..."
    for CF in "${CF_RANGES[@]}"; do
        ipt_ins INPUT -s "$CF" -m comment --comment "cf_whitelist" -j ACCEPT
    done

    # NAT/cloud public-IP discovery (E-6): on cloud VMs the public
    # address lives only in the provider's NAT - ask the metadata
    # service (echo fallback) and cache it, so the self set below
    # covers it too. A failed discovery keeps the previous cache.
    if nx_refresh_public_ips_cache >/dev/null 2>&1; then
        [ -s "$PUBLIC_IPS_FILE" ] && \
            info "Public-IP discovery: $(tr '\n' ' ' < "$PUBLIC_IPS_FILE")"
    fi

    # ── Step 4: Server own IPs → ACCEPT ──────────────
    # E-4: a display-grade public-only lookup was used here before -
    # private and secondary self addresses were missing, so traffic
    # from the server's own private IP still hit the flood limits.
    # Enforcement uses the exhaustive list_self_ips (loopback
    # excluded, see above).
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        ipt_ins INPUT -s "$SIP/32" -m comment --comment "self_whitelist" -j ACCEPT
    done < <(list_self_ips_all | grep -v '^127\.0\.0\.1$')

    # ── Step 4b: User whitelist → ACCEPT (before ALL limits) ──
    mkdir -p /etc/antiddos
    touch "$WHITELIST_FILE"
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            ipt_ins INPUT -s "$WIP" -m comment --comment "user_whitelist" -j ACCEPT
        done < "$WHITELIST_FILE"
    fi
    success "CF + self whitelist: added (${#CF_RANGES[@]} CF ranges + own IPs)"

    # ── Step 4c: Canonical exempt-set snapshot (D1) ──
    # One file every layer can consult: CF ranges + ALL self IPs + the
    # admin whitelist. Also snapshot the self IPs on their own (FR-2).
    list_self_ips_all > "$SELF_IPS_FILE" 2>/dev/null || true
    { printf '%s\n' "${CF_RANGES[@]}"
      list_self_ips_all
      if [ -f "$WHITELIST_FILE" ]; then
          while IFS= read -r _EX; do
              _EX="${_EX%%#*}"; _EX="${_EX// /}"
              [ -n "$_EX" ] && printf '%s\n' "$_EX"
          done < "$WHITELIST_FILE"
      fi
    } | grep -v '^$' | sort -u > "$EXEMPT_FILE" || true

    # ── Step 5: SYN Flood protection ─────────────────
    # NOTE: CF IPs already accepted above — these rules only apply to non-CF
    if [ "$SYNPROXY_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ] && \
       [ "$VIRT_TYPE" != "openvz" ]; then
        modprobe xt_SYNPROXY 2>/dev/null || true
        # Whitelist CF IPs in raw PREROUTING so SYNPROXY never touches CF traffic
        for CF in "${CF_RANGES[@]}"; do
            iptables -t raw -C PREROUTING -s "$CF" -j ACCEPT 2>/dev/null || \
            iptables -t raw -A PREROUTING -s "$CF" -j ACCEPT
        done
        # Also whitelist server own IPs in raw (E-4: exhaustive list)
        while IFS= read -r SIP; do
            [ -z "$SIP" ] && continue
            iptables -t raw -C PREROUTING -s "$SIP/32" -j ACCEPT 2>/dev/null || \
            iptables -t raw -A PREROUTING -s "$SIP/32" -j ACCEPT
        done < <(list_self_ips_all | grep -v '^127\.0\.0\.1$')
        # Also whitelist user whitelist in raw (SYNPROXY never touches them)
        if [ -f "$WHITELIST_FILE" ]; then
            while IFS= read -r WIP; do
                WIP="${WIP%%#*}"; WIP="${WIP// /}"
                [ -z "$WIP" ] && continue
                iptables -t raw -C PREROUTING -s "$WIP" -j ACCEPT 2>/dev/null || \
                iptables -t raw -A PREROUTING -s "$WIP" -j ACCEPT
            done < "$WHITELIST_FILE"
        fi
        iptables -t raw -C PREROUTING -p tcp --syn \
            -m conntrack --ctstate NEW -j CT --notrack 2>/dev/null || \
        iptables -t raw -A PREROUTING -p tcp --syn \
            -m conntrack --ctstate NEW -j CT --notrack
        iptables -C INPUT -p tcp --syn \
            -m conntrack --ctstate UNTRACKED,INVALID \
            -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 2>/dev/null || \
        iptables -A INPUT -p tcp --syn \
            -m conntrack --ctstate UNTRACKED,INVALID \
            -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
        iptables -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
        iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
        success "SYN Flood: SYNPROXY kernel-level (CF whitelisted in raw table)"
    elif [ "$HASHLIMIT_OK" -eq 1 ]; then
        # Per-IP SYN limit (catches single-source flood)
        ipt_add INPUT -p tcp --syn \
            -m hashlimit \
            --hashlimit-above "$SYN_LIMIT" \
            --hashlimit-burst "$SYN_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name syn_flood \
            --hashlimit-htable-expire 30000 \
            -j DROP
        # Global SYN rate cap — catches spoofed-IP floods where per-IP limit misses
        # Each spoofed SYN uses a unique fake IP so per-IP hashlimit never triggers.
        # A global cap absorbs the total SYN rate regardless of source.
        # Value: 5× per-IP limit to allow bursts from many legit IPs simultaneously.
        local _GS_LIMIT _GS_BURST
        _GS_LIMIT="${SYN_LIMIT//\/sec/}"
        _GS_LIMIT="${_GS_LIMIT//[^0-9]/}"; _GS_LIMIT="${_GS_LIMIT:-500}"
        _GS_BURST="${SYN_BURST:-1000}"
        _GS_BURST="${_GS_BURST//[^0-9]/}"; _GS_BURST="${_GS_BURST:-1000}"
        ipt_add INPUT -p tcp --syn \
            -m limit \
            --limit "$(( _GS_LIMIT * 5 ))/sec" \
            --limit-burst "$(( _GS_BURST * 5 ))" \
            -j ACCEPT
        ipt_add INPUT -p tcp --syn -j DROP
        success "SYN Flood: per-IP hashlimit ($SYN_LIMIT) + global cap ($(( _GS_LIMIT * 5 ))/s) — spoofed-IP resistant"
    else
        ipt_add INPUT -p tcp --syn -m limit --limit 500/s --limit-burst 1000 -j ACCEPT
        ipt_add INPUT -p tcp --syn -j DROP
        success "SYN Flood: global limit (fallback)"
    fi

    # ── Step 6: UDP Flood ─────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p udp \
            -m hashlimit \
            --hashlimit-above "$UDP_LIMIT" \
            --hashlimit-burst "$UDP_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name udp_flood \
            --hashlimit-htable-expire 10000 \
            -j DROP
        success "UDP Flood: hashlimit ($UDP_LIMIT per IP)"

        # UDP amplification ports
        for REFLECT_PORT in 19 111 137 161 1900 5353 11211; do
            ipt_add INPUT -p udp --sport "$REFLECT_PORT" \
                -m hashlimit \
                --hashlimit-above 10/sec \
                --hashlimit-burst 20 \
                --hashlimit-mode srcip \
                --hashlimit-name "udp_reflect_${REFLECT_PORT}" \
                -j DROP
        done
        success "UDP Amplification (chargen/DNS/rpcbind/NetBIOS/NTP/SNMP/SSDP/memcached/mDNS): blocked"
    else
        warn "UDP Flood: hashlimit unavailable - using global limit"
        ipt_add INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT
        ipt_add INPUT -p udp -j DROP
    fi

    # ── Step 7: ICMP Flood ────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p icmp --icmp-type echo-request \
            -m hashlimit \
            --hashlimit-above "$ICMP_LIMIT" \
            --hashlimit-burst "$ICMP_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name icmp_flood \
            -j DROP
        success "ICMP Flood: rate-limited ($ICMP_LIMIT per IP)"
    else
        ipt_add INPUT -p icmp --icmp-type echo-request -m limit \
            --limit 1/s --limit-burst 10 -j ACCEPT
        ipt_add INPUT -p icmp --icmp-type echo-request -j DROP
        success "ICMP Flood: global limit (fallback)"
    fi

    # ── Step 8: HTTP/HTTPS + ALL TCP Flood (connlimit) ──
    # NOTE: CF IPs accepted before this — connlimit only affects non-CF
    if [ "$CONNLIMIT_OK" -eq 1 ]; then
        # HTTP/HTTPS ports — lower connlimit
        for HTTP_PORT in 80 443 8080 8443; do
            # NIT-2: TCP listeners only (-tln) - a UDP listener on
            # the same number (e.g. QUIC on 443) must not trigger a
            # TCP connlimit rule for that port.
            ss -tln 2>/dev/null | grep -q ":${HTTP_PORT} " || continue
            ipt_add INPUT -p tcp --dport "$HTTP_PORT" \
                -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
                --connlimit-mask 32 -m comment --comment "nx_connlimit" \
                -j REJECT --reject-with tcp-reset
            success "HTTP Flood: connlimit :${HTTP_PORT} (max $CONN_LIMIT_PER_IP per non-CF IP)"
        done

        # ── Slowloris / Hold / Heavy attack defense ───────
        # These attacks use few connections but hold them forever with partial data.
        # connlimit on ALL TCP ports (global per-IP) stops this without affecting tunnels.
        # CF IPs are already accepted above — this only hits real attackers.
        # LOG before DROP so fail2ban conn-flood jail can read it from kern.log
        ipt_add INPUT -p tcp \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
            --connlimit-mask 32 -m comment --comment "nx_connlimit" \
            -m limit --limit 10/min --limit-burst 20 \
            -j LOG --log-prefix "[CONNLIMIT DROP] " --log-level 4 2>/dev/null || true
        ipt_add INPUT -p tcp \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
            --connlimit-mask 32 -m comment --comment "nx_connlimit" \
            -j REJECT --reject-with tcp-reset
        success "Slowloris/Hold/Heavy: global connlimit (max $CONN_LIMIT_PER_IP TCP per non-CF IP) + LOG→fail2ban"

        if [ "$HASHLIMIT_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ]; then
            # ── New connection rate per IP (prevents connect-flood) ──
            ipt_add INPUT -p tcp \
                -m conntrack --ctstate NEW \
                -m hashlimit \
                --hashlimit-above "$NEW_CONN_RATE" \
                --hashlimit-burst "$NEW_CONN_BURST" \
                --hashlimit-mode srcip \
                --hashlimit-name new_conn_rate \
                --hashlimit-htable-expire 60000 \
                -j DROP
            success "New TCP conn rate: $NEW_CONN_RATE per non-CF IP"

        fi
    else
        warn "connlimit unavailable - HTTP flood protection limited"
    fi

    # ── Step 9: RST Flood ─────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p tcp --tcp-flags RST RST \
            -m hashlimit \
            --hashlimit-above 200/sec \
            --hashlimit-burst 400 \
            --hashlimit-mode srcip \
            --hashlimit-name rst_flood \
            -j DROP
        success "RST Flood: rate-limited"
    fi

    # ── Step 10: Port Scan signatures ────────────────
    # LOG first (rate-limited) so the portscan fail2ban jail has lines
    # to match - previously nothing logged these, so it never fired.
    ipt_add INPUT -p tcp --tcp-flags ALL NONE \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt_add INPUT -p tcp --tcp-flags ALL ALL \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt_add INPUT -p tcp --tcp-flags ALL FIN \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt_add INPUT -p tcp --tcp-flags ALL NONE -j DROP  # NULL scan
    ipt_add INPUT -p tcp --tcp-flags ALL ALL  -j DROP  # Xmas scan
    ipt_add INPUT -p tcp --tcp-flags ALL FIN  -j DROP  # FIN scan
    ipt_add INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP  # impossible
    ipt_add INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP  # impossible
    success "Port scans: NULL/XMAS/FIN/bogus flags dropped"

    # ── Step 11: Bogus TCP NEW non-SYN ───────────────
    if [ "$CONNTRACK_OK" -eq 1 ]; then
        ipt_add INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
        success "Bogus TCP NEW non-SYN: dropped"
    fi

    # ── Step 12: Fragmented packets ──────────────────
    ipt_add INPUT -f -j DROP
    success "Fragmented packets: dropped"

    # v3.17.0: re-pin the proxy counters on top BEFORE saving. Every
    # -I insert above shadows the target-less stats rules (a plain
    # insert-once counter silently undercounted in the field), and
    # the saved order is the boot-restored order. No-op when the
    # proxy is absent or the rules are already pinned.
    # Snapshot BEFORE the re-pin (MED-1): moving a shadowed rule
    # deletes and recreates it, zeroing its counter, so traffic since
    # the last 5-minute accumulator tick would otherwise be lost on
    # every antiddos apply that finds the rules shadowed. The pin
    # below is kept: the accumulator returns early (and does not
    # pin) when the rules are missing, and the pin creates them.
    nx_proxy_traffic_accum 2>/dev/null || true
    nx_pin_proxy_stats_rules "$(nx_proxy_port_from_config)"

    # Save rules (static only - transient bans/f2b chains excluded, BUG-012)
    save_static_rules "$IPTABLES_SAVE_FILE"
    chmod 600 "$IPTABLES_SAVE_FILE"
    success "iptables rules saved"

    # IPv6 mirror of this design (Wave 9)
    apply_ip6tables
}

# ════════════════════════════════════════════════
# IPv6 mirror of the INPUT design (Wave 9). Same layer order as IPv4:
# exempt ACCEPTs -> request policing -> ESTABLISHED -> flood limits ->
# connlimit -> scan drops. Skipped cleanly when no IPv6 stack exists.
# ════════════════════════════════════════════════
apply_ip6tables() {
    command -v ip6tables >/dev/null 2>&1 || { info "ip6tables unavailable - IPv6 rules skipped"; return 0; }
    ip6tables -L INPUT >/dev/null 2>&1 || { info "IPv6 stack unavailable - IPv6 rules skipped"; return 0; }
    info "Applying IPv6 firewall rules (mirror of the IPv4 design)..."
    ipt6_add() { ip6tables -C "$@" 2>/dev/null || ip6tables -A "$@" 2>/dev/null || true; }

    ipt6_add INPUT -i lo -j ACCEPT

    # Exempt set snapshot (CF v6 + self v6 + whitelist v6 entries)
    : > /etc/antiddos/exempt6.list 2>/dev/null || true
    local _r6 _s6 _w6
    for _r6 in "${CF6_RANGES[@]}"; do
        ipt6_add INPUT -s "$_r6" -m comment --comment "cf_whitelist" -j ACCEPT
        echo "$_r6" >> /etc/antiddos/exempt6.list
    done
    while IFS= read -r _s6; do
        [ -z "$_s6" ] && continue
        ipt6_add INPUT -s "$_s6/128" -m comment --comment "self_whitelist" -j ACCEPT
        echo "$_s6" >> /etc/antiddos/exempt6.list
    done < <(list_self_ips6)
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _w6; do
            _w6="${_w6%%#*}"; _w6="${_w6// /}"
            case "$_w6" in *:*) : ;; *) continue ;; esac
            [ -z "$_w6" ] && continue
            ipt6_add INPUT -s "$_w6" -m comment --comment "user_whitelist" -j ACCEPT
            echo "$_w6" >> /etc/antiddos/exempt6.list
        done < "$WHITELIST_FILE"
    fi

    # M8 migration: pre-v3.18 v6 hashlimit rules used bare --hashlimit
    # (which matches UNDER the rate) with -j DROP, so they dropped
    # normal-rate traffic and passed floods. Delete any old-form rule
    # (a *6 name without --hashlimit-above) before re-adding the
    # fixed form; ipt6_add's -C check cannot see the spec change.
    local _old6
    for _old6 in $(ip6tables -S INPUT 2>/dev/null | grep -nE 'hashlimit-name (syn_limit6|udp_limit6|http_req_rate6|icmp_limit6)' | grep -v 'hashlimit-above' | cut -d: -f1 | sort -rn); do
        ip6tables -D INPUT $((_old6 - 1)) 2>/dev/null || true
    done

    # Request-rate policing BEFORE the established accept (same BUG-002
    # lesson as IPv4: below it, this rule could never fire)
    # M8: --hashlimit-above, not bare --hashlimit (see the migration
    # note above). The 300/min web cap itself is deliberate - it is a
    # coarse per-IP web-port cap with no v4 counterpart, so its value
    # is kept; the tiered established-packet cap is added below.
    ipt6_add INPUT -p tcp -m multiport --dports 80,443 \
        -m hashlimit --hashlimit-name http_req_rate6 --hashlimit-mode srcip \
        --hashlimit-above 300/min --hashlimit-burst 100 -j DROP

    ipt6_add INPUT -m conntrack --ctstate INVALID -j DROP

    # M8: per-IP bandwidth cap + HTTP burst cap, mirrors of the v4
    # Step 2a/2b rules. They MUST sit above the ESTABLISHED accept
    # (BUG-002): below it, established packets never reach them.
    if ip6tables -A INPUT -p tcp \
        -m hashlimit \
        --hashlimit-above "${BW_PER_IP_MBIT:-100}mbit/s" \
        --hashlimit-burst "$(( ${BW_PER_IP_MBIT:-100} * 2 ))mbit" \
        --hashlimit-mode srcip \
        --hashlimit-name bw_per_ip6_test \
        --hashlimit-htable-expire 5000 \
        -j DROP 2>/dev/null; then
        ip6tables -D INPUT -p tcp \
            -m hashlimit \
            --hashlimit-above "${BW_PER_IP_MBIT:-100}mbit/s" \
            --hashlimit-burst "$(( ${BW_PER_IP_MBIT:-100} * 2 ))mbit" \
            --hashlimit-mode srcip \
            --hashlimit-name bw_per_ip6_test \
            --hashlimit-htable-expire 5000 \
            -j DROP 2>/dev/null || true
        ipt6_add INPUT -p tcp \
            -m conntrack --ctstate ESTABLISHED,RELATED \
            -m hashlimit \
            --hashlimit-above "${BW_PER_IP_MBIT:-100}mbit/s" \
            --hashlimit-burst "$(( ${BW_PER_IP_MBIT:-100} * 2 ))mbit" \
            --hashlimit-mode srcip \
            --hashlimit-name bw_per_ip6 \
            --hashlimit-htable-expire 5000 \
            -j DROP
    fi
    ipt6_add INPUT -p tcp \
        -m conntrack --ctstate ESTABLISHED \
        -m hashlimit \
        --hashlimit-above "${HTTP_REQ_RATE:-500/sec}" \
        --hashlimit-burst "${HTTP_REQ_BURST:-1000}" \
        --hashlimit-mode srcip \
        --hashlimit-name http_req_est6 \
        --hashlimit-htable-expire 10000 \
        -j DROP

    ipt6_add INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Flood limits (M8: tiered values + --hashlimit-above direction)
    ipt6_add INPUT -p tcp --syn -m hashlimit --hashlimit-name syn_limit6 \
        --hashlimit-mode srcip --hashlimit-above "${SYN_LIMIT:-500/sec}" --hashlimit-burst "${SYN_BURST:-1000}" -j DROP
    ipt6_add INPUT -p udp -m hashlimit --hashlimit-name udp_limit6 \
        --hashlimit-mode srcip --hashlimit-above "${UDP_LIMIT:-150/sec}" --hashlimit-burst "${UDP_BURST:-300}" -j DROP
    # UDP amplification ports (mirror of v4 Step 6)
    for REFLECT_PORT in 19 111 137 161 1900 5353 11211; do
        ipt6_add INPUT -p udp --sport "$REFLECT_PORT" \
            -m hashlimit \
            --hashlimit-above 10/sec \
            --hashlimit-burst 20 \
            --hashlimit-mode srcip \
            --hashlimit-name "udp_reflect6_${REFLECT_PORT}" \
            -j DROP
    done
    # ICMPv6: NDP must keep working (it is IPv6's ARP) - accept it,
    # rate-limit echo requests, accept the rest.
    ipt6_add INPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT
    ipt6_add INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT
    ipt6_add INPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT
    ipt6_add INPUT -p icmpv6 --icmpv6-type echo-request \
        -m hashlimit --hashlimit-name icmp_limit6 --hashlimit-mode srcip \
        --hashlimit-above "${ICMP_LIMIT:-25/sec}" --hashlimit-burst "${ICMP_BURST:-50}" -j DROP
    ipt6_add INPUT -p icmpv6 -j ACCEPT

    # Connection limit per host (mask 128) with the same LOG prefix the
    # conn-flood fail2ban jail matches
    # M9: the LOG rule carries the same -m limit as v4 (10/min, burst
    # 20) - without it, every excess SYN under a v6 flood writes a
    # kern.log line (log-volume DoS + jail hammering).
    ipt6_add INPUT -p tcp --syn -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
        --connlimit-mask 128 -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[CONNLIMIT DROP] " --log-level 4
    ipt6_add INPUT -p tcp --syn -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
        --connlimit-mask 128 -m comment --comment "nx_connlimit" -j DROP

    # M8: new-connection rate, RST flood, bogus NEW non-SYN and
    # fragments - mirrors of the v4 Step 8/9/11/12 rules.
    ipt6_add INPUT -p tcp \
        -m conntrack --ctstate NEW \
        -m hashlimit \
        --hashlimit-above "${NEW_CONN_RATE:-100/sec}" \
        --hashlimit-burst "${NEW_CONN_BURST:-200}" \
        --hashlimit-mode srcip \
        --hashlimit-name new_conn_rate6 \
        --hashlimit-htable-expire 60000 \
        -j DROP
    ipt6_add INPUT -p tcp --tcp-flags RST RST \
        -m hashlimit \
        --hashlimit-above 200/sec \
        --hashlimit-burst 400 \
        --hashlimit-mode srcip \
        --hashlimit-name rst_flood6 \
        -j DROP
    ipt6_add INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
    # The v6 equivalent of iptables -f (second and further fragments):
    # a fragment header that is NOT the first fragment.
    ipt6_add INPUT -m frag ! --fragfirst -j DROP

    # Scan signatures: LOG ([NX-SCAN], feeds the portscan jail) + DROP
    ipt6_add INPUT -p tcp --tcp-flags ALL NONE \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt6_add INPUT -p tcp --tcp-flags ALL ALL \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt6_add INPUT -p tcp --tcp-flags ALL FIN \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt6_add INPUT -p tcp --tcp-flags ALL NONE -j DROP
    ipt6_add INPUT -p tcp --tcp-flags ALL ALL -j DROP
    ipt6_add INPUT -p tcp --tcp-flags ALL FIN -j DROP
    ipt6_add INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    ipt6_add INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

    ip6tables-save 2>/dev/null | nx_static_rules_filter > /etc/antiddos/ip6tables-antiddos.rules || true
    chmod 600 /etc/antiddos/ip6tables-antiddos.rules 2>/dev/null || true
    success "IPv6 rules applied + saved"
}

# Delete ip6tables rules by pattern (mirror of nx_delete_matching).
nx_delete_matching6() {
    local _c="$1" _p="$2" _n
    command -v ip6tables >/dev/null 2>&1 || return 0
    ip6tables -L "$_c" >/dev/null 2>&1 || return 0
    while true; do
        # -- : patterns starting with a dash ('--comment ...')
        # would otherwise be parsed as grep options (see
        # nx_delete_matching - the same bug killed the '-j CT'
        # remove and the first version of flush_autobans).
        _n=$(ip6tables -S "$_c" 2>/dev/null | grep -nE -- "$_p" | head -1 | cut -d: -f1 || true)
        [ -z "$_n" ] && break
        ip6tables -D "$_c" $((_n - 1)) 2>/dev/null || break
    done
}

# ════════════════════════════════════════════════
# LAYER 3: fail2ban jails
# ════════════════════════════════════════════════
apply_fail2ban() {
    command -v fail2ban-client >/dev/null 2>&1 || {
        warn "fail2ban not installed - installing..."
        if command -v apt-get >/dev/null 2>&1; then
            info "Running apt-get update first..."
            DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban 2>/dev/null || {
                warn "fail2ban install failed - skipping Layer-3"
                return
            }
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q fail2ban 2>/dev/null || {
                warn "fail2ban install failed - skipping Layer-3"
                return
            }
        else
            warn "Cannot install fail2ban - skipping Layer-3"
            return
        fi
    }
    info "Configuring fail2ban jails..."

    # ── Filter: 3proxy abuse ──────────────────────────
    cat > "$F2B_FILTER_DIR/3proxy-ddos.conf" << 'EOF'
[Definition]
# Our 3proxy logformat: L<date> <time> %U %C:%c %R:%r %O %I %E %T
# %E is the error code: 0 = success. The old regex matched EVERY
# connection line, so a legitimate heavy user (100 conns/60s) earned a
# 24h ban (BUG-017). Only lines with a NON-ZERO error code count now:
# fields after <HOST>:port are remote, bytes-out, bytes-in, then %E.
failregex = ^L\d+-\d+-\d+ \d+:\d+:\d+ \S+ <HOST>:\d+ \S+ \d+ \d+ [1-9][0-9]*\s
ignoreregex =
EOF

    # ── Filter: HTTP flood ────────────────────────────
    # Catches HTTP BURST mode (pipeline=500 requests per connection from same IP)
    cat > "$F2B_FILTER_DIR/http-flood.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s
ignoreregex = \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf)
EOF

    # ── Filter: connection flood (any TCP) ────────────
    # Catches slow-trickle and conn-hold modes: many connections from same IP
    # detected via kernel log (connlimit drop messages with [CONNLIMIT DROP] prefix)
    cat > "$F2B_FILTER_DIR/conn-flood.conf" << 'EOF'
[Definition]
# Matches [CONNLIMIT DROP] log lines written by our iptables LOG rule
failregex = \[CONNLIMIT DROP\].*SRC=<HOST>
ignoreregex =
EOF

    # ── Filter: port scan ─────────────────────────────
    cat > "$F2B_FILTER_DIR/portscan.conf" << 'EOF'
[Definition]
# Matches the [NX-SCAN] LOG rules in apply_iptables (Step 10). The old
# patterns waited for UFW blocks or a fantasy "iptables DROP" log format
# that nothing on this system emits, so the jail could never fire.
failregex = \[NX-SCAN\].*SRC=<HOST>
            kernel.*\[UFW BLOCK\].*SRC=<HOST>
ignoreregex =
EOF

    # ── Filter: xray/proxy logs ───────────────────────
    cat > "$F2B_FILTER_DIR/xray-proxy.conf" << 'EOF'
[Definition]
# Matches: failed handshake, timeout, connection reset from same IP
failregex = \[Warning\].*failed to read.*<HOST>
            \[Warning\].*timeout.*<HOST>
            rejected.*<HOST>
ignoreregex =
EOF

    # ── Jails ─────────────────────────────────────────
    # Build ignoreip from the FULL CF range list (753 ranges), chunked 6 per
    # line, so fail2ban NEVER bans a Cloudflare IP. Previously only 16 legacy
    # ranges were listed here, so CF IPs from newer ranges could get false bans.
    _F2B_IGNORE="127.0.0.1/8 ::1"
    # FR-1/FR-2 (BUG-028): fail2ban must ignore the WHOLE exempt set, not
    # just Cloudflare - the server's own IPs and the admin whitelist too.
    while IFS= read -r _F2B_SELF; do
        [ -n "$_F2B_SELF" ] && _F2B_IGNORE="$_F2B_IGNORE $_F2B_SELF/32"
    done < <(list_self_ips_all)
    # E-1 (exemption audit): the server's own IPv6 addresses belong in
    # ignoreip too - only ::1 was covered, so fail2ban could ban the
    # server's own global v6 (e.g. via the sshd jail).
    while IFS= read -r _F2B_SELF6; do
        [ -n "$_F2B_SELF6" ] && _F2B_IGNORE="$_F2B_IGNORE $_F2B_SELF6"
    done < <(list_self_ips6)
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _F2B_WL; do
            _F2B_WL="${_F2B_WL%%#*}"; _F2B_WL="${_F2B_WL// /}"
            [ -n "$_F2B_WL" ] && _F2B_IGNORE="$_F2B_IGNORE $_F2B_WL"
        done < "$WHITELIST_FILE"
    fi
    # IPv6 (Wave 9): CF's v6 ranges join ignoreip too (they are few).
    for _F2B_CF6 in "${CF6_RANGES[@]}"; do
        _F2B_IGNORE="$_F2B_IGNORE $_F2B_CF6"
    done
    _F2B_CF_N=0
    for _F2B_CF in "${CF_RANGES[@]}"; do
        _F2B_CF_N=$((_F2B_CF_N + 1))
        if [ $((_F2B_CF_N % 6)) -eq 1 ]; then
            _F2B_IGNORE="$(printf '%s\n            %s' "$_F2B_IGNORE" "$_F2B_CF")"
        else
            _F2B_IGNORE="$(printf '%s %s' "$_F2B_IGNORE" "$_F2B_CF")"
        fi
    done

    # Field finding T-1 (live test, 2026-10-23): on journal-only images
    # (Debian 12 cloud ships without rsyslog) the classic log files do
    # not exist, and fail2ban refuses to start when ANY enabled jail
    # has no log file at all - the whole service died while the
    # installer reported success. Ensure the syslog-family files exist
    # (empty is fine; rsyslog fills them when present). With no rsyslog
    # at all, kernel/auth jails read the systemd journal instead -
    # otherwise they would run but stay blind forever.
    local _lf
    for _lf in /var/log/kern.log /var/log/auth.log /var/log/secure; do
        [ -e "$_lf" ] || touch "$_lf" 2>/dev/null || true
    done
    local KERN_BACKEND="" SSH_BACKEND="" HTTP_ENABLED="true"
    if ! command -v rsyslogd >/dev/null 2>&1 && command -v journalctl >/dev/null 2>&1; then
        KERN_BACKEND='backend   = systemd
journalmatch = _TRANSPORT=kernel'
        SSH_BACKEND='backend   = systemd'
    fi
    if [ ! -f /var/log/nginx/access.log ] && [ ! -f /var/log/apache2/access.log ]; then
        HTTP_ENABLED="false"
        info "http-flood jail disabled: no nginx/apache access log on this server"
    fi

    cat > "$F2B_JAIL_DIR/antiddos.conf" << EOF
# Anti-DDoS fail2ban jails — generated $(date)
# CF IPs are ignored via ignoreip (no false bans)

[DEFAULT]
# ignoreip built from the full CF range list (${#CF_RANGES[@]} ranges)
ignoreip = ${_F2B_IGNORE}

[3proxy-ddos]
enabled   = true
filter    = 3proxy-ddos
# 3proxy rotates daily: the live file is access.log.YYYY.MM.DD (T-2).
logpath   = /var/log/3proxy/access.log.*
maxretry  = 100
findtime  = 60
bantime   = 86400
action    = iptables-allports[name=3proxy-ddos, protocol=all]

[http-flood]
enabled   = ${HTTP_ENABLED}
filter    = http-flood
# Combined-log-format web servers only. 3proxy's access.log is NOT an
# HTTP access log; its floods are covered by the daemon and 3proxy-ddos.
logpath   = /var/log/nginx/access.log
            /var/log/apache2/access.log
# 200 requests in 30s = flood (normal user: <50 req/30s)
# HTTP BURST mode sends 500 pipelined reqs per conn → caught immediately
maxretry  = 200
findtime  = 30
bantime   = 86400
action    = iptables-allports[name=http-flood, protocol=all]

[conn-flood]
enabled   = true
filter    = conn-flood
logpath   = /var/log/kern.log
            /var/log/syslog
${KERN_BACKEND}
# 20 iptables DROP events from same IP in 10s = flood
# connlimit DROP fires when IP exceeds CONN_LIMIT_PER_IP connections
maxretry  = 20
findtime  = 10
bantime   = 86400
action    = iptables-allports[name=conn-flood, protocol=all]

[portscan]
enabled   = true
filter    = portscan
logpath   = /var/log/kern.log
            /var/log/syslog
${KERN_BACKEND}
maxretry  = 5
findtime  = 30
bantime   = 86400
action    = iptables-allports[name=portscan, protocol=all]

[sshd-aggressive]
enabled   = true
filter    = sshd
logpath   = /var/log/auth.log
            /var/log/secure
${SSH_BACKEND}
maxretry  = 3
findtime  = 30
bantime   = 86400
action    = iptables-allports[name=sshd-aggressive, protocol=all]

[xray-proxy]
enabled   = false
filter    = xray-proxy
logpath   = /var/log/xray/error.log
            /var/log/xray/access.log
maxretry  = 20
findtime  = 60
bantime   = 3600
action    = iptables-allports[name=xray-proxy, protocol=all]
EOF

    # Verify, never assume (T-1): a written config is not a running
    # jail set. Test the configuration, then check the real service.
    if command -v fail2ban-client >/dev/null 2>&1 && \
        ! fail2ban-client -t >/dev/null 2>&1; then
        warn "fail2ban: configuration test FAILED - jails not applied (diagnose: fail2ban-client -t)"
        return 1
    fi
    systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        ACTIVE_JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | \
            sed 's/.*://;s/,/ /g' | wc -w || echo 0)
        success "fail2ban: $ACTIVE_JAILS jails active"
    else
        warn "fail2ban: service is NOT running after apply (diagnose: systemctl status fail2ban)"
        return 1
    fi
}

# Regenerate the jail file (its ignoreip is built from the live exempt
# set) and reload fail2ban. Called by the whitelist manager after every
# add/remove so a whitelisted IP is exempt in fail2ban immediately (FR-1).
update_f2b_ignoreip() {
    [ -f "$F2B_JAIL_DIR/antiddos.conf" ] || return 0
    apply_fail2ban >/dev/null 2>&1 || true
    fail2ban-client reload >/dev/null 2>&1 || \
        systemctl reload fail2ban >/dev/null 2>&1 || true
}

# ════════════════════════════════════════════════
# LAYER 4: Smart throttle+ban (auto-ban.sh)
# Pipeline: watch (45s) → throttle 100Mbps → ban (progressive 30m-7d)
# CF IPs: ALWAYS exempt
# ════════════════════════════════════════════════
setup_autoban() {
    info "Setting up smart throttle+ban..."

    # Phase 1a: install the default scoring config (never overwrites
    # an admin-edited one). The daemon works without it (defaults),
    # but shipping it documents every tunable in place.
    nx_ensure_scoring_config || true

    # Phase 2a: the conntrack event counter feeds the daemon exact
    # arrival/completion data (see setup_countd below).
    setup_countd || true

    # Phase 3: the XDP emergency shield (built only with a BPF
    # toolchain present; dormant otherwise).
    setup_xdp || true

    # Require tcpdump
    if ! command -v tcpdump >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump 2>/dev/null || true
        fi
    fi

    cat > "$AUTOBAN_SCRIPT.nxnew" << 'AUTOBAN_EOF'
#!/bin/bash
# shellcheck disable=SC2015,SC2094
# Reviewed idioms (Wave 10): SC2015 - `cond && ok-print || err-print`
# chains whose middle command is a print helper that cannot fail;
# SC2094 - atomic state writes via tmp-file + rename, which the
# checker flags as same-file pipelines. Both classes were audited
# site-by-site during the fix waves (docs/FIX-PLAN.md).
# ============================================================
#  Smart Throttle+Ban — Anti-DDoS Layer 4
#  Pipeline: watch(120 conns) → throttle(100Mbps) → ban(progressive 30m-7d) | instant ban: 300 conns
#  CF IPs + server own IPs: ALWAYS exempt
# ============================================================

LOG="/var/log/auto-ban.log"
BANNED_LIST="/etc/antiddos/banned.list"
# F5: live state lives under /run/nexoshield (root-owned tmpfs), not
# /tmp — /tmp entries are world-writable, so a pre-planted symlink
# could make a root truncate or append hit an attacker-chosen file.
# Volatility semantics are unchanged (both are tmpfs, cleared on
# reboot); the persistent mirrors stay under /etc/antiddos.
mkdir -p /run/nexoshield 2>/dev/null || true
# L6: single-instance guard. Two daemons would double-apply bans,
# double-count strikes and fight over state files. The lock is held
# for the process lifetime; a second instance exits instead of
# running. If the lock file cannot be created (or no flock binary
# exists), the daemon proceeds unguarded - the old behaviour -
# rather than refusing to start. This runs before log() exists
# (defined in 10-ip-utils.sh), so failures print to stderr.
if command -v flock >/dev/null 2>&1; then
    if exec 9>/run/nexoshield/auto-ban.lock 2>/dev/null; then
        if ! flock -n 9 2>/dev/null; then
            echo "auto-ban: another instance is running, exiting" >&2
            exit 1
        fi
    fi
fi
WATCH_LIST="/run/nexoshield/autoban_watch"
THROTTLE_LIST="/run/nexoshield/autoban_throttle"
# U-11: persistent mirror of the throttle state. The live file sits
# in /run (fast, volatile); the generated tc-setup.sh has always
# re-applied throttles from /etc/antiddos/throttled.list after a
# reboot - but nothing ever WROTE that file, so the restore path was
# dead and every reboot silently dropped all throttles. The daemon
# now mirrors run -> etc once per cycle and restores etc -> run at
# startup when the run file is gone.
THROTTLE_MIRROR="/etc/antiddos/throttled.list"
# User whitelist — IPs/CIDRs exempt from ALL anti-DDoS limits.
# Managed by the user via the menu (never auto-modified). One per line.
# Lines starting with # are comments. Server's own IPs + CF IPs are always
# exempt separately (see is_exempt), this file adds MORE whitelisted IPs.
WHITELIST_FILE="/etc/antiddos/whitelist.list"

# ── Reputation scoring state (persistent across cycles) ────
# Each scored IP keeps: score, last connection count, last timestamp.
# Persisted to disk so the value survives the short-lived shell arrays
# and survives service restarts.
SCORE_DIR="/var/lib/antiddos/scores"
SCORE_FILE="$SCORE_DIR/reputation.dat"
# Tunable scoring config (Phase 1a): every constant below can be
# overridden in /etc/antiddos/scoring.conf; defaults are the historical
# values, so a missing file changes nothing.
NX_CONFIG_FILE="${NX_CONFIG_FILE:-/etc/antiddos/scoring.conf}"

declare -A _NX_CFG_CACHE=() _NX_CFG_WARNED=()
_NX_CFG_MTIME=""
_NX_CFG_CHECKED=0

_nx_cfg_stat() {
    stat -c %Y "$NX_CONFIG_FILE" 2>/dev/null || echo "absent"
}

# Reload the cache when the file changed (cheap: one stat per second).
_nx_cfg_refresh() {
    local now=$EPOCHSECONDS m
    [ $((now - _NX_CFG_CHECKED)) -lt 1 ] && return 0
    _NX_CFG_CHECKED=$now
    m="$(_nx_cfg_stat)"
    if [ "$m" != "$_NX_CFG_MTIME" ]; then
        _NX_CFG_MTIME="$m"
        _NX_CFG_CACHE=()
    fi
}

_nx_cfg_warn() {
    [ -n "${_NX_CFG_WARNED[$1]:-}" ] && return 0
    _NX_CFG_WARNED[$1]=1
    if declare -F log >/dev/null 2>&1; then
        log " CONFIG: ignoring ${2:-invalid value} for '$1' in $NX_CONFIG_FILE (using default)"
    else
        echo "CONFIG: ignoring ${2:-invalid value} for '$1' in $NX_CONFIG_FILE (using default)" >&2
    fi
}

# L7: sane ranges for every documented scoring key (min:max). A
# value outside its range is ignored with a warning and the default
# is used instead - a typo like conn_threshold=-5 or score_ban=500
# must never silently disarm or invert a gate. Unknown keys are
# unchecked (nx_cfg stays generic). Floats compare via awk.
declare -A _NX_CFG_RANGE=(
    [score_ban]="0:100" [score_hard]="0:100" [score_throttle]="0:100" [score_suspect]="0:100"
    [score_recover_per_min]="0:1000" [probation_recover_per_min]="0:1000" [score_drop_cap_per_min]="0:1000"
    [probation_score]="0:100" [probation_seconds]="0:86400"
    [churn_allow_per_sec]="0:100000" [churn_weight]="0:1000" [churn_cap]="0:100"
    [sust_divisor]="1:100000" [sust_cap]="0:100"
    [syn_min]="0:100000" [syn_ratio]="0:1" [syn_weight]="0:1000" [syn_cap]="0:100"
    [conn_threshold]="0:1000000" [ban_conn_threshold]="0:1000000" [observe_seconds]="0:3600"
    [ban_base_minutes]="1:10080" [ban_max_minutes]="1:43200" [ban_hours_fallback]="0:168"
    [subnet_threshold]="0:1000000" [subnet_ban_threshold]="0:1000000"
    [subnet_min_offenders]="1:100000" [subnet_ban_minutes]="1:10080"
    [stress_gate]="0:1" [adaptive_enabled]="0:1"
    [xdp_syncookie_rate]="0:10000000" [xdp_overflow_rate]="0:10000000" [xdp_syn_rate]="0:10000000"
    [xdp_calm_seconds]="0:86400"
)

nx_cfg() {
    local key="$1" def="$2" raw=""
    _nx_cfg_refresh
    if [ -n "${_NX_CFG_CACHE[$key]+set}" ]; then
        printf '%s' "${_NX_CFG_CACHE[$key]}"
        return 0
    fi
    if [ -f "$NX_CONFIG_FILE" ]; then
        raw=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$NX_CONFIG_FILE" 2>/dev/null \
              | tail -n 1 | cut -d= -f2- | tr -d ' \t\r"')
    fi
    if [ -n "$raw" ]; then
        if [[ "$raw" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
            local _range="${_NX_CFG_RANGE[$key]:-}"
            if [ -n "$_range" ]; then
                local _lo="${_range%%:*}" _hi="${_range#*:}"
                if ! awk -v v="$raw" -v lo="$_lo" -v hi="$_hi" 'BEGIN{exit !(v>=lo && v<=hi)}' 2>/dev/null; then
                    _nx_cfg_warn "$key" "out-of-range value '$raw' (allowed $_lo-$_hi)"
                    _NX_CFG_CACHE[$key]="$def"
                    printf '%s' "$def"
                    return 0
                fi
            fi
            _NX_CFG_CACHE[$key]="$raw"
            printf '%s' "$raw"
            return 0
        fi
        _nx_cfg_warn "$key"
    fi
    _NX_CFG_CACHE[$key]="$def"
    printf '%s' "$def"
}

# Write the default config at install time. NEVER overwrites an existing
# file — admin edits are sacred. Every key is documented inline.
nx_ensure_scoring_config() {
    local f="${NX_CONFIG_FILE:-/etc/antiddos/scoring.conf}"
    [ -f "$f" ] && return 0
    mkdir -p "$(dirname "$f")" 2>/dev/null || return 1
    cat > "$f" <<'EOF'
# NexoShield scoring configuration — every value is optional.
# Delete a line (or this whole file) to return that knob to its default.
# Changes take effect within seconds; the daemon re-reads on mtime.
# All values must be numeric. Invalid values are ignored with a warning.

# ── Score bands (0-100 reputation) ──
score_ban=20            # below: ban (progressive duration)
score_hard=40           # below: hard throttle 50 Mbps
score_throttle=60       # below: throttle 100 Mbps
score_suspect=80        # below: watch only

# ── Score movement (points per minute) ──
score_recover_per_min=6
probation_recover_per_min=10
score_drop_cap_per_min=45
probation_score=50
probation_seconds=1800

# ── Term weights ──
churn_allow_per_sec=2   # free new-connection rate before churn applies
churn_weight=1.2        # points/min per conn/s above the allowance
churn_cap=30
sust_divisor=40         # connections over threshold per point/min
sust_cap=20
syn_min=20              # min half-open conns before the SYN term arms
syn_ratio=0.5           # half-open share that starts costing points
syn_weight=40
syn_cap=15

# ── Gates ──
conn_threshold=120      # active conns from one IP = start watching
ban_conn_threshold=300  # active conns = instant throttle+ban
observe_seconds=45      # watch window before throttle (legit spikes)

# ── Bans ──
ban_base_minutes=30     # first ban; doubles per repeat offence
ban_max_minutes=10080   # cap (7 days)
ban_hours_fallback=4    # legacy flat duration for non-progressive paths

# ── Subnet (/24) ──
subnet_threshold=400        # total conns = start watching
subnet_ban_threshold=1000     # total conns = block (with guardrails)
subnet_min_offenders=5        # distinct IPs that must be over the gate
subnet_ban_minutes=60

# ── Stress gate (Phase 1d) ──
stress_gate=1           # 1: score bans need host stress (or score < 10)

# ── Adaptive thresholds (Phase 2d; needs nxcountd) ──
adaptive_enabled=1      # 1: tighten gates under a global arrival anomaly

# ── XDP emergency shield triggers (Phase 3) ──
xdp_syncookie_rate=500  # syncookies sent per minute that justify line-rate relief
xdp_overflow_rate=1000  # listen overflows per minute that justify relief
xdp_syn_rate=3000       # sustained SYN arrivals/sec that justify relief
xdp_calm_seconds=600    # calm required before the shield detaches
EOF
    chmod 644 "$f" 2>/dev/null || true
}

# Bands (see research: adaptive/graduated enforcement beats one-shot ban):
#  100-80 NORMAL    no action (only watched if above CONN_THRESHOLD)
#   79-60 SUSPECT   watch only, no penalty
#   59-40 THROTTLED move to class 1:30 (nominal 100Mbps - setup_tc
#               scales the tree to LINK/10 on sub-gigabit links)
#   39-20 HARD      move to class 1:40 (nominal 50Mbps - LINK/20)
#   <20  BANNED     ban_ip (progressive 30m-7d)
# (values assigned by nx_load_scoring_config below)
# Scoring model v2 (docs/SCORING.md): every score movement is rated in
# points per MINUTE and scaled by the real elapsed time of the sample,
# so an IP's fate depends on its behaviour - never on daemon loop speed.
# Fractional points accumulate in the score file instead of rounding
# away each cycle.
# (recover/drop-cap assigned by nx_load_scoring_config below)
# Probation (D3, FR-3): EVERY ban - reputation, classic or instant - ends
# in the same defined state: the IP returns at PROBATION_SCORE with a
# probation window. During probation, recovery is faster (10/min) but
# score drops are doubled; a ban still requires the score to actually
# reach the ban band again, so one minor spike cannot re-ban (the old
# behaviour: score stayed wherever the ban path left it, often <20, so
# the smallest trigger re-banned instantly - a de-facto permanent ban).
# (probation values assigned by nx_load_scoring_config below)
# When connections are counted we snapshot the previous sample to derive the
# new-connection rate (attacker signature) without per-packet overhead.

# Thresholds
# THRESHOLD: minimum active connections from one IP to start watching.
# Normal user: 5-20 connections (browser + download + streaming).
# Heaviest legitimate user (multiple download managers + several services):
# ~50-60 connections. Attacker: hundreds to thousands.
# Set CONN_THRESHOLD well above ANY legitimate user so normal speed is never
# limited, but far below a flood. OBSERVE allows brief legit spikes (a download
# manager burst) to pass untouched before any action.
THROTTLE_MBPS=100    # Nominal 1-Gbit-tree value for tc class 1:30;
                     # setup_tc scales the class to LINK/10 on
                     # sub-gigabit links, so this is a band label,
                     # not a guaranteed rate on slow links.
# CONN_THRESHOLD / BAN_CONN_THRESHOLD / OBSERVE_SECONDS / BAN_HOURS are
# assigned by nx_load_scoring_config below (defaults 120 / 300 / 45 / 4).
# Sample cadence. 2s (was 4s): churn rate is already normalized per-second, so
# scoring bands are unchanged, but short <4s bursts from a 120+ conn IP are now
# caught instead of being averaged out. Recovery of well-behaved IPs is also 2x
# faster. The CONN_THRESHOLD=120 gate means normal users are never touched.
# (One-way bytes tracking was deliberately NOT added: on a SOCKS5/tunnel proxy,
# server→client relay makes "sent>>received" the NORMAL heavy-download pattern,
# so it would false-positive on legitimate heavy users.)
SAMPLE_INTERVAL=2    # seconds per measurement

# ── Subnet /24 botnet detection ──────────────────────────────
# Botnet distributes connections across many IPs in same /24 subnet.
# Each IP stays under single-IP threshold, but total subnet load is high.
# SUBNET_CONN_THRESHOLD: total connections from a /24 subnet = start watching.
# Normal ISP: ~5-10 users behind NAT/CGNAT, each ~20 conns = ~200 total.
# A very heavy CGNAT node (many legit users) could reach ~400.
# Botnet with 50 IPs × 100+ conns = 5000 → way above threshold.
# SUBNET_THRESHOLD / SUBNET_BAN_THRESHOLD assigned below (defaults 400 / 1000).
SUBNET_WATCH_LIST="/run/nexoshield/autoban_subnet_watch"
touch "$SUBNET_WATCH_LIST" 2>/dev/null || true

# ── Scoring config loader (Phase 1a) ─────────────────────────────
# Every scoring knob resolves through nx_cfg: config file wins, the
# literal default (the historical constant) is the fallback.
_NX_CFG_LOADED_MTIME=""
nx_load_scoring_config() {
    SCORE_BAN=$(nx_cfg score_ban 20)
    SCORE_HARD=$(nx_cfg score_hard 40)
    SCORE_THROTTLE=$(nx_cfg score_throttle 60)
    SCORE_SUSPECT=$(nx_cfg score_suspect 80)
    SCORE_RECOVER_PER_MIN=$(nx_cfg score_recover_per_min 6)
    SCORE_DROP_CAP_PER_MIN=$(nx_cfg score_drop_cap_per_min 45)
    PROBATION_SCORE=$(nx_cfg probation_score 50)
    PROBATION_SECONDS=$(nx_cfg probation_seconds 1800)
    PROBATION_RECOVER_PER_MIN=$(nx_cfg probation_recover_per_min 10)
    CHURN_ALLOW=$(nx_cfg churn_allow_per_sec 2)
    CHURN_WEIGHT=$(nx_cfg churn_weight 1.2)
    CHURN_CAP=$(nx_cfg churn_cap 30)
    SUST_DIV=$(nx_cfg sust_divisor 40)
    SUST_CAP=$(nx_cfg sust_cap 20)
    SYN_MIN=$(nx_cfg syn_min 20)
    SYN_RATIO=$(nx_cfg syn_ratio 0.5)
    SYN_WEIGHT=$(nx_cfg syn_weight 40)
    SYN_CAP=$(nx_cfg syn_cap 15)
    CONN_THRESHOLD=$(nx_cfg conn_threshold 120)
    BAN_CONN_THRESHOLD=$(nx_cfg ban_conn_threshold 300)
    OBSERVE_SECONDS=$(nx_cfg observe_seconds 45)
    BAN_HOURS=$(nx_cfg ban_hours_fallback 4)
    BAN_BASE_MINUTES=$(nx_cfg ban_base_minutes 30)
    BAN_MAX_MINUTES=$(nx_cfg ban_max_minutes 10080)
    SUBNET_THRESHOLD=$(nx_cfg subnet_threshold 400)
    SUBNET_BAN_THRESHOLD=$(nx_cfg subnet_ban_threshold 1000)
    SUBNET_MIN_OFFENDERS=$(nx_cfg subnet_min_offenders 5)
    SUBNET_BAN_MINUTES=$(nx_cfg subnet_ban_minutes 60)
    STRESS_GATE=$(nx_cfg stress_gate 1)
    ADAPTIVE_ENABLED=$(nx_cfg adaptive_enabled 1)
    XDP_SYNCOOKIE_RATE=$(nx_cfg xdp_syncookie_rate 500)
    XDP_OVERFLOW_RATE=$(nx_cfg xdp_overflow_rate 1000)
    XDP_SYN_RATE=$(nx_cfg xdp_syn_rate 3000)
    XDP_CALM_SECONDS=$(nx_cfg xdp_calm_seconds 600)
    _NX_CFG_LOADED_MTIME="$(_nx_cfg_stat)"
}
nx_maybe_reload_scoring_config() {
    [ "$(_nx_cfg_stat)" != "$_NX_CFG_LOADED_MTIME" ] && nx_load_scoring_config
}
nx_load_scoring_config

# Detect main interface
IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
IF=${IF:-eth0}

# Cloudflare ranges (NEVER touched)
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi
# ── Cloudflare IPv6 ranges (loaded from shared data file) ──
CF6_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv6.list ]; then
    while IFS= read -r _cfl6; do
        _cfl6="${_cfl6//[[:space:]]/}"
        [ -n "$_cfl6" ] && CF6_RANGES+=("$_cfl6")
    done < /etc/antiddos/cloudflare-ipv6.list
fi
list_self_ips() {
    { ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+'
      hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    } | sort -u | grep -v '^$'
}

# list_self_ips6 - every local IPv6 address (incl. ::1), one per line.
list_self_ips6() {
    { ip -6 addr show 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+'
      echo "::1"
    } | sort -u | grep -v '^$'
}

# ── Public-IP discovery for NAT / cloud servers ─────────────────
# On cloud VMs (Azure, most NAT setups) the server's public IPv4
# exists only in the provider's NAT - it is on NO interface, so
# list_self_ips can never see it, yet it is unmistakably one of the
# server's own addresses (FR-2). Discovery asks the cloud metadata
# service (link-local, no internet involved); only when no metadata
# service answers does it fall back to an external echo service.
# Every candidate passes nx_is_public_ipv4: metadata/echo replies
# are untrusted input, and a private/documentation/garbage answer
# must never widen the immune set.
NX_PUBLIC_IPS_FILE="${NX_PUBLIC_IPS_FILE:-/etc/antiddos/public-ips.list}"

nx_is_public_ipv4() {
    local ip="${1:-}" o1 o2 o3 o4 extra _o
    case "$ip" in *[!0-9.]*) return 1 ;; esac
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for _o in "$o1" "$o2" "$o3" "$o4"; do
        case "$_o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_o}" -le 3 ] || return 1
        (( 10#$_o <= 255 )) || return 1
    done
    case "$o1" in
        0|10|127) return 1 ;;
        100) [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 1 ;;
        169) [ "$o2" = 254 ] && return 1 ;;
        172) [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 1 ;;
        192) [ "$o2" = 168 ] && return 1
             { [ "$o2" = 0 ] && { [ "$o3" = 0 ] || [ "$o3" = 2 ]; }; } && return 1 ;;
        198) case "$o2" in 18|19|51) return 1 ;; esac ;;
        203) { [ "$o2" = 0 ] && [ "$o3" = 113 ]; } && return 1 ;;
    esac
    [ "$o1" -ge 224 ] && return 1
    return 0
}

nx_metadata_public_ips() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _tok _base="http://169.254.169.254"
    # Azure IMDS (first two addresses on the primary NIC)
    for _idx in 0 1; do
        _ip=$(curl -s -m 2 -H "Metadata: true" \
            "$_base/metadata/instance/network/interface/0/ipv4/ipAddress/$_idx/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
        nx_is_public_ipv4 "$_ip" && echo "$_ip"
    done
    # AWS EC2 IMDS (token first, plain fallback)
    _tok=$(curl -s -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "$_base/latest/api/token" 2>/dev/null)
    if [ -n "$_tok" ]; then
        _ip=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $_tok" \
            "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    else
        _ip=$(curl -s -m 2 "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    fi
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # GCP
    _ip=$(curl -s -m 2 -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # DigitalOcean
    _ip=$(curl -s -m 2 "$_base/metadata/v1/interfaces/public/0/ipv4/address" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # Hetzner Cloud
    _ip=$(curl -s -m 2 "$_base/hetzner/v1/metadata/public-ipv4" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    return 0
}

nx_external_public_ip() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _url
    for _url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me/ip"; do
        _ip=$(curl -s -m 3 "$_url" 2>/dev/null | tr -d ' \r\n')
        nx_is_public_ipv4 "$_ip" && { echo "$_ip"; return 0; }
    done
    return 0
}

# Echo the server's public IPv4s that are NOT on any interface
# (metadata first; external echo only as a last resort).
discover_public_ips() {
    local _found _ip
    _found=$(nx_metadata_public_ips | sort -u)
    [ -z "$_found" ] && _found=$(nx_external_public_ip)
    for _ip in $_found; do
        list_self_ips | grep -qxF "$_ip" || echo "$_ip"
    done
}

# Refresh the cache file; a failed/empty discovery NEVER wipes a
# previously discovered set (an offline reinstall must not disarm
# the immunity). Prints the discovered addresses when any exist.
nx_refresh_public_ips_cache() {
    local _found
    _found=$(discover_public_ips)
    if [ -n "$_found" ]; then
        mkdir -p "$(dirname "$NX_PUBLIC_IPS_FILE")" 2>/dev/null || true
        printf '%s\n' "$_found" > "$NX_PUBLIC_IPS_FILE.tmp" 2>/dev/null && \
            mv "$NX_PUBLIC_IPS_FILE.tmp" "$NX_PUBLIC_IPS_FILE" 2>/dev/null || true
        printf '%s\n' "$_found"
    elif [ -f "$NX_PUBLIC_IPS_FILE" ]; then
        cat "$NX_PUBLIC_IPS_FILE"
    fi
}

# list_self_ips_all - interface addresses PLUS the cached
# discovered public IPs. This is the feed every enforcement layer
# uses for "the server's own addresses" (FR-2 complete: local,
# private, secondary AND NAT-public).
list_self_ips_all() {
    { list_self_ips
      if [ -r "$NX_PUBLIC_IPS_FILE" ]; then
          grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$NX_PUBLIC_IPS_FILE" 2>/dev/null
      fi
    } | sort -u | grep -v '^$'
}

mkdir -p /etc/antiddos
touch "$LOG" && chmod 600 "$LOG"
touch "$BANNED_LIST" "$WATCH_LIST" "$THROTTLE_LIST" 2>/dev/null || true

# Collect all server IPs at startup (never ban these): interface
# addresses PLUS any cached NAT/cloud public IPs (E-6).
SELF_IPS=()
while IFS= read -r sip; do
    [ -n "$sip" ] && SELF_IPS+=("$sip")
done < <(list_self_ips_all)

# IPv6 self addresses (Wave 9): the same hard immunity as IPv4 (FR-2).
SELF6_IPS=()
while IFS= read -r sip6; do
    [ -n "$sip6" ] && SELF6_IPS+=("$sip6")
done < <(list_self_ips6)

# BUG-020: precompute Cloudflare network integers ONCE. is_cf_ip() then
# costs zero forks per check (previously up to ~1,500 per call: 753 ranges
# x 2 subshells in ip_to_int, paid for every hot IP every cycle).
declare -a CF_NET_INT=() CF_SHIFT=()
ip_int() {
    local IFS=. _a _b _c _d
    read -r _a _b _c _d <<< "$1"
    IP_INT=$(( (10#$_a << 24) + (10#$_b << 16) + (10#$_c << 8) + 10#$_d ))
}
for _cfr in "${CF_RANGES[@]}"; do
    ip_int "${_cfr%%/*}"
    CF_NET_INT+=("$IP_INT")
    CF_SHIFT+=("$(( 32 - ${_cfr#*/} ))")
done
unset _cfr

# BUG-019: every iptables call in this script takes the xtables lock with
# a 5s wait. The daemon, fail2ban and the menus mutate rules concurrently;
# without -w a contended call fails with "Resource temporarily
# unavailable" and the failure is usually swallowed by || true - rules
# silently never landed. (iptables-save/-restore are separate binaries
# and are not affected by this wrapper.)
iptables() { command iptables -w 5 "$@"; }

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# Shared ban-state lock (L5): included here so the daemon and every
# state helper serialize on the same path (see src/lib/state-lock.sh).
NX_STATE_LOCK_FILE="${NX_STATE_LOCK_FILE:-/run/nexoshield/state.lock}"
NX_STATE_LOCK_DEPTH=0
nx_state_lock() {
    if [ "${NX_STATE_LOCK_DEPTH:-0}" -gt 0 ]; then
        NX_STATE_LOCK_DEPTH=$(( NX_STATE_LOCK_DEPTH + 1 ))
        return 0
    fi
    mkdir -p /run/nexoshield 2>/dev/null || true
    if command -v flock >/dev/null 2>&1; then
        if exec 200>"$NX_STATE_LOCK_FILE" 2>/dev/null; then
            flock -x -w 10 200 2>/dev/null || true
        fi
    fi
    NX_STATE_LOCK_DEPTH=1
}
nx_state_unlock() {
    [ "${NX_STATE_LOCK_DEPTH:-0}" -gt 0 ] || return 0
    NX_STATE_LOCK_DEPTH=$(( NX_STATE_LOCK_DEPTH - 1 ))
    if [ "$NX_STATE_LOCK_DEPTH" -eq 0 ]; then
        flock -u 200 2>/dev/null || true
        exec 200>&- 2>/dev/null || true
    fi
}

# ── Exact state-file matching (BUG-003) ─────────────
# State files are "IP field field..." per line. The ONLY correct match
# is field 1 == IP, exactly. The old grep -qF "$ip" / sed "/$ip/d"
# substring+regex patterns made 1.2.3.4 match 11.2.3.4 and 1.2.3.45,
# corrupting other IPs' watch/ban/throttle state.
state_has_ip() {  # <file> <ip>
    [ -f "$1" ] || return 1
    awk -v x="$2" '$1==x{f=1} END{exit !f}' "$1" 2>/dev/null
}
state_get_field() {  # <file> <ip> <field#> -> prints the field (or empty)
    [ -f "$1" ] || return 0
    awk -v x="$2" -v n="$3" '$1==x{print $n; exit}' "$1" 2>/dev/null
}
state_del_ip() {  # <file> <ip>  (atomic rewrite, state-locked)
    [ -f "$1" ] || return 0
    nx_state_lock
    awk -v x="$2" '$1!=x' "$1" > "$1.tmp.$$" 2>/dev/null && mv "$1.tmp.$$" "$1"
    local _rc=$?
    nx_state_unlock
    return "$_rc"
}

# Convert IP to integer for CIDR comparison
ip_to_int() {
    local IFS=.
    # shellcheck disable=SC2206
    local -a A=($1)
    echo $(( (A[0]<<24) + (A[1]<<16) + (A[2]<<8) + A[3] ))
}

# Check if IP is inside a CIDR range (e.g. "104.16.0.0/13")
ip_in_cidr() {
    local ip="$1" cidr="$2"
    local base mask_bits ip_int base_int mask
    base="${cidr%/*}"; mask_bits="${cidr#*/}"
    ip_int=$(ip_to_int "$ip")     2>/dev/null || return 1
    base_int=$(ip_to_int "$base") 2>/dev/null || return 1
    mask=$(( 0xFFFFFFFF << (32 - mask_bits) & 0xFFFFFFFF ))
    [ $(( ip_int & mask )) -eq $(( base_int & mask )) ]
}

# Check if IP is in CF ranges (pure bash CIDR match — no ipcalc needed)
is_cf_ip() {
    # Fast path (BUG-020): precomputed network integers, zero forks.
    local _i
    ip_int "$1"
    for _i in "${!CF_NET_INT[@]}"; do
        [ $(( IP_INT >> CF_SHIFT[_i] )) -eq $(( CF_NET_INT[_i] >> CF_SHIFT[_i] )) ] && return 0
    done
    return 1
}

# ── IPv6 (Wave 9) ───────────────────────────────────
ip6tables() { command ip6tables -w 5 "$@"; }

# ip6_in_cidr <ip> <cidr> — pure-awk membership test (no strtonum, so
# it works under mawk too). Handles "::" compression, mixed case and
# fully-expanded forms on either side.
ip6_in_cidr() {
    awk -v ip="$1" -v cidr="$2" '
    function pad(h) { while (length(h) < 4) h = "0" h; return h }
    function expand(a,    k,lp,rp,ln,rn,out,i) {
        a = tolower(a)
        k = index(a, "::")
        if (k > 0) {
            lp = substr(a, 1, k - 1); rp = substr(a, k + 2)
            ln = (lp == "") ? 0 : split(lp, L, ":")
            rn = (rp == "") ? 0 : split(rp, G, ":")
            out = ""
            for (i = 1; i <= ln; i++) out = out pad(L[i])
            for (i = 1; i <= 8 - ln - rn; i++) out = out "0000"
            for (i = 1; i <= rn; i++) out = out pad(G[i])
            return out
        }
        split(a, P, ":"); out = ""
        for (i = 1; i <= 8; i++) out = out pad(P[i])
        return out
    }
    function hv(c) { return index("0123456789abcdef", c) - 1 }
    BEGIN {
        np = split(cidr, C, "/"); pfx = (np < 2 || C[2] == "") ? 128 : C[2] + 0
        e1 = expand(ip); e2 = expand(C[1])
        full = int(pfx / 4)
        if (substr(e1, 1, full) != substr(e2, 1, full)) exit 1
        rem = pfx % 4
        if (rem > 0) {
            # keep the top `rem` bits of the nibble (arithmetic, since
            # mawk has no bitwise and() builtin)
            keep = 2 ^ (4 - rem)
            if (int(hv(substr(e1, full + 1, 1)) / keep) != int(hv(substr(e2, full + 1, 1)) / keep)) exit 1
        }
        exit 0
    }' 2>/dev/null
}

is_cf6_ip() {
    local _r6
    for _r6 in "${CF6_RANGES[@]}"; do
        ip6_in_cidr "$1" "$_r6" && return 0
    done
    return 1
}

is_exempt6() {
    local ip="$1" _s6 _w6
    is_cf6_ip "$ip" && return 0
    for _s6 in "${SELF6_IPS[@]}"; do
        ip6_in_cidr "$ip" "$_s6/128" && return 0
    done
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _w6; do
            _w6="${_w6%%#*}"; _w6="${_w6// /}"
            case "$_w6" in *:*) : ;; *) continue ;; esac
            [ -n "$_w6" ] && ip6_in_cidr "$ip" "$_w6" && return 0
        done < "$WHITELIST_FILE"
    fi
    return 1
}

# Family-dispatching wrappers: the pipeline below speaks v4 names;
# these route IPv6 peers to the v6 enforcers.
is_exempt_any() { case "$1" in *:*) is_exempt6 "$1" ;; *) is_exempt "$1" ;; esac; }
nx_ban() { case "$1" in *:*) ban_ip6 "$1" ;; *) ban_ip "$1" ;; esac; }
nx_throttle() { case "$1" in *:*) throttle_ip6 "$1" ;; *) throttle_ip "$1" ;; esac; }
nx_hard_throttle() { case "$1" in *:*) hard_throttle_ip6 "$1" ;; *) hard_throttle_ip "$1" ;; esac; }

# nx_extract_peer_ips — peer column (stdin) -> one IP per line, v4+v6.
# Single-pass extraction (H1): the old `{ grep v4; grep v6; }` pair ran
# on one stdin, so the second grep always read EOF and no IPv6 peer
# ever entered the daemon's counters. A v4-mapped ::ffff:a.b.c.d peer
# is normalized back to its v4 form, preserving the old counting.
nx_extract_peer_ips() {
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[[0-9a-fA-F:]+\]' | tr -d '[]' | \
        sed -E 's/^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/\1/'
}

# subnet_overlaps_cf <a.b.c> — TRUE range-overlap test between a /24 and
# every CF range (BUG-011: the old check tested only the .1 address, so
# a CF range starting mid-/24 was missed).
subnet_overlaps_cf() {
    local subnet="$1" CF
    for CF in "${CF_RANGES[@]}"; do
        ip_in_cidr "${subnet}.0" "$CF" 2>/dev/null && return 0
        ip_in_cidr "${CF%%/*}" "${subnet}.0/24" 2>/dev/null && return 0
    done
    return 1
}

# Check if IP is server's own IP
is_self_ip() {
    local ip="$1"
    for sip in "${SELF_IPS[@]}"; do
        [ "$sip" = "$ip" ] && return 0
    done
    ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | grep -qxF "$ip" && return 0
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -qxF "$ip" && return 0
    # Freshness fallback: the installer's self-IP snapshot (FR-2)
    [ -f /etc/antiddos/self-ips.list ] && \
        grep -qxF "$ip" /etc/antiddos/self-ips.list 2>/dev/null && return 0
    return 1
}

# Check if IP is in the user whitelist (exact or within a listed CIDR)
is_user_whitelisted() {
    local ip="$1" entry
    [ -f "$WHITELIST_FILE" ] || return 1
    while IFS= read -r entry; do
        entry="${entry%%#*}"            # strip comments
        entry="${entry// /}"            # drop spaces
        [ -z "$entry" ] && continue
        case "$entry" in
            */*)
                # BUG-029 (daemon half): a malformed mask must NEVER widen
                # the match (arithmetic on garbage treated it as a number).
                # Invalid entries are skipped, never "close enough".
                _m="${entry#*/}"
                case "$_m" in ''|*[!0-9]*) continue ;; esac
                [ "${#_m}" -le 2 ] || continue
                (( 10#$_m <= 32 )) || continue
                ip_in_cidr "$ip" "$entry" 2>/dev/null && return 0 ;;
            *)   [ "$entry" = "$ip" ] && return 0 ;;
        esac
    done < "$WHITELIST_FILE"
    return 1
}

# Check if IP should be exempt (CF or self or user-whitelisted)
# E-3 (exemption audit): the self-IP sets are captured at daemon
# start. An address added to the host later (failover IP, new v6
# prefix) would not be immune until a restart. The main loop calls
# this on the slow cadence; additions are logged, removals apply
# silently (a reassigned address must not stay immune).
refresh_self_ips() {
    local _ip _o _found
    local _new4=() _new6=()
    # E-6: on hosts where a public-IP cache exists (cloud/NAT), keep
    # it fresh - a reallocated public address must become immune
    # without a reinstall. Metadata is link-local and fast; hosts
    # without a cache never pay for the probes.
    if [ -f "$NX_PUBLIC_IPS_FILE" ]; then
        nx_metadata_public_ips 2>/dev/null | sort -u > "$NX_PUBLIC_IPS_FILE.nxnew" && \
            [ -s "$NX_PUBLIC_IPS_FILE.nxnew" ] && \
            mv "$NX_PUBLIC_IPS_FILE.nxnew" "$NX_PUBLIC_IPS_FILE" || \
            rm -f "$NX_PUBLIC_IPS_FILE.nxnew"
    fi
    while IFS= read -r _ip; do [ -n "$_ip" ] && _new4+=("$_ip"); done < <(list_self_ips_all)
    while IFS= read -r _ip; do [ -n "$_ip" ] && _new6+=("$_ip"); done < <(list_self_ips6)
    for _ip in "${_new4[@]}"; do
        _found=0
        for _o in "${SELF_IPS[@]}"; do [ "$_o" = "$_ip" ] && { _found=1; break; }; done
        [ "$_found" -eq 0 ] && log " SELF: new own IPv4 detected: $_ip (immune)"
    done
    for _ip in "${_new6[@]}"; do
        _found=0
        for _o in "${SELF6_IPS[@]}"; do [ "$_o" = "$_ip" ] && { _found=1; break; }; done
        [ "$_found" -eq 0 ] && log " SELF: new own IPv6 detected: $_ip (immune)"
    done
    SELF_IPS=("${_new4[@]}")
    SELF6_IPS=("${_new6[@]}")
}

is_exempt() {
    local ip="$1"
    is_self_ip "$ip"  && return 0
    is_cf_ip   "$ip"  && return 0
    is_user_whitelisted "$ip" && return 0
    return 1
}

# Reserved tc filter priority bands (must never overlap):
#   whitelist (CF + server-own + user)  : 10 .. <10000  (allocated in tc-setup.sh)
#   throttle (nominal 100Mbps class 1:30) : 10000 ..
#   hard-throttle (nominal 50Mbps class 1:40): 20000 ..
# This guarantees a throttle filter can NEVER collide with a Cloudflare/server
# whitelist filter, so CF and the server itself stay exempt even at ban time
# (ban_ip deletes only the recorded throttle-band prio).

# ── tc helpers (Wave 2) ─────────────────────────────
# next_tc_prio: persistent monotonic prio allocator. The old schemes
# collided (soft = 10000 + line count of a file other code also rewrites;
# hard = 20000 + RANDOM%4000), and 'tc filter del prio X' deletes EVERY
# filter at that prio - a collision could wipe a CF whitelist filter.
# Daemon filter prios now come only from this counter (>= 20001), far
# above the setup bands (10..<10000) and never reused.
next_tc_prio() {
    local f v
    f="$(dirname "$THROTTLE_LIST")/tc-prio.seq"
    v=$(cat "$f" 2>/dev/null || echo 20000)
    v="${v//[^0-9]/}"; v="${v:-20000}"
    [ "$v" -lt 20000 ] && v=20000
    v=$(( v + 1 ))
    echo "$v" > "$f" 2>/dev/null || true
    echo "$v"
}

tc_class_exists() {
    tc class show dev "$IF" 2>/dev/null | grep -q "class htb $1[[:space:]]"
}

# reapply_throttles: after a reboot (or any qdisc rebuild that did not go
# through tc-setup.sh), restore the daemon's recorded throttle filters so
# THROTTLE_LIST and the kernel agree again (BUG-022/BUG-004 family).
reapply_throttles() {
    [ -f "$THROTTLE_LIST" ] || return 0
    local ip prio ts band flow
    while read -r ip prio ts band; do
        [ -z "$ip" ] && continue
        case "$prio" in ''|*[!0-9]*) continue ;; esac
        flow=1:30; [ "$band" = "hard" ] && flow=1:40
        tc_class_exists "$flow" || flow=1:30
        tc_class_exists "$flow" || continue
        case "$ip" in
            *:*)
                tc filter del dev "$IF" parent 1: protocol ip6 prio "$prio" 2>/dev/null || true
                tc filter add dev "$IF" parent 1: protocol ip6 prio "$prio" \
                    u32 match ip6 dst "$ip" flowid $flow 2>/dev/null || true ;;
            *)
                tc filter del dev "$IF" parent 1: protocol ip prio "$prio" 2>/dev/null || true
                tc filter add dev "$IF" parent 1: protocol ip prio "$prio" \
                    u32 match ip dst "$ip/32" flowid $flow 2>/dev/null || true ;;
        esac
    done < "$THROTTLE_LIST"
}
# U-11: keep the persistent mirror in sync with the live tmp state,
# and restore from it after a reboot (tmp is wiped; the mirror and
# tc-setup.sh's re-apply both read /etc/antiddos/throttled.list).
mirror_throttle_state() {
    [ -f "$THROTTLE_LIST" ] || return 0
    cmp -s "$THROTTLE_LIST" "$THROTTLE_MIRROR" 2>/dev/null && return 0
    cp "$THROTTLE_LIST" "$THROTTLE_MIRROR.tmp.$$" 2>/dev/null && \
        mv "$THROTTLE_MIRROR.tmp.$$" "$THROTTLE_MIRROR" 2>/dev/null || true
}
restore_throttle_state() {
    if [ ! -f "$THROTTLE_LIST" ] && [ -s "$THROTTLE_MIRROR" ]; then
        cp "$THROTTLE_MIRROR" "$THROTTLE_LIST" 2>/dev/null || true
        log " STATE: throttle list restored from persistent mirror"
    fi
}

throttle_ip() {
    local ip="$1"
    is_exempt "$ip" && return 0
    state_has_ip "$THROTTLE_LIST" "$ip" && return 0
    # BUG-024: never record state for a throttle that does not exist.
    # In autoban-only mode there are no tc classes at all - say so.
    if ! tc_class_exists 1:30; then
        log " THROTTLE SKIP: $ip - tc class 1:30 missing on $IF (autoban-only mode? run the full antiddos setup to enable bandwidth throttling)"
        return 1
    fi
    local HANDLE; HANDLE=$(next_tc_prio)
    # BUG-001: egress qdisc - the client is the DESTINATION.
    if tc filter add dev "$IF" parent 1: protocol ip prio "$HANDLE" \
        u32 match ip dst "$ip/32" flowid 1:30 2>/dev/null; then
        echo "$ip $HANDLE $(date +%s) soft" >> "$THROTTLE_LIST"
        log " THROTTLE: $ip -> 100Mbps (will ban in ${OBSERVE_SECONDS}s if continues)"
    else
        log " THROTTLE FAIL: $ip - tc filter add failed; state NOT recorded"
        return 1
    fi
}

# Hard-throttle: move an IP to class 1:40 (50Mbps). Used by the reputation
# scoring system when score falls into the worst (pre-ban) band but the IP is
# not yet confirmed as an attack. Keeps the connection open (legit heavy user
# stays online) while crushing throughput so a flood can't starve the box.
# Class 1:40 must exist (added by install alongside 1:30). If it does not,
# fall back to the (nominal 100Mbps) class 1:30 rather than failing.
hard_throttle_ip() {
    local ip="$1"
    is_exempt "$ip" && return 0
    # R-7 (deep review): already hard-throttled = nothing to do. The
    # old code deleted + re-added the filter on EVERY scoring cycle -
    # filter churn, a burned prio per cycle, log spam.
    if state_has_ip "$THROTTLE_LIST" "$ip" && \
        [ "$(state_get_field "$THROTTLE_LIST" "$ip" 4)" = "hard" ]; then
        return 0
    fi
    # Drop any earlier throttle entry for this IP so the tc filter list stays
    # consistent and no stale prio is left behind (its filter would still match).
    local _OLD
    _OLD=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
    [ -n "$_OLD" ] && tc filter del dev "$IF" parent 1: prio "$_OLD" 2>/dev/null || true
    state_del_ip "$THROTTLE_LIST" "$ip"
    # Pick the strongest class that actually exists (BUG-024: state is
    # written only after the filter lands).
    local FLOW=""
    if tc_class_exists 1:40; then FLOW=1:40
    elif tc_class_exists 1:30; then FLOW=1:30
    else
        log " HARD-THROTTLE SKIP: $ip - no tc throttle classes on $IF"
        return 1
    fi
    local HANDLE; HANDLE=$(next_tc_prio)
    if tc filter add dev "$IF" parent 1: protocol ip prio "$HANDLE" \
        u32 match ip dst "$ip/32" flowid $FLOW 2>/dev/null; then
        echo "$ip $HANDLE $(date +%s) hard" >> "$THROTTLE_LIST"
        log " HARD-THROTTLE: $ip -> $FLOW (reputation low)"
    else
        log " HARD-THROTTLE FAIL: $ip - tc filter add failed; state NOT recorded"
        return 1
    fi
}

# ── Ban backend (Phase 1b): nftables timed sets ──────────────────
# State files stay the source of truth; the kernel side is a projection.
# With the nft backend, bans live in ONE inet table whose sets give
# ~O(1) lookup (vs one iptables rule per ban, scanned per packet) and
# the kernel itself expires elements (timeout = ban duration). The
# chain checks the EXEMPT set before the ban set: defence in depth
# behind the ban-choke guards, so FR-1/FR-2 hold even inside the
# drop path. Backend resolves ONCE at daemon startup (nx_resolve_ban_
# backend); until then, and whenever nft is unusable, the historical
# iptables path applies — a stock install can never get worse.
NX_BAN_BACKEND="${NX_BAN_BACKEND:-iptables}"

nx_nft_ensure() {
    nft list table inet nexoshield >/dev/null 2>&1 && return 0
    nft -f - >/dev/null 2>&1 <<'NXNFT'
table inet nexoshield {
    set ban4 { type ipv4_addr; flags interval, timeout; }
    set ban6 { type ipv6_addr; flags interval, timeout; }
    set exempt4 { type ipv4_addr; flags interval; }
    set exempt6 { type ipv6_addr; flags interval; }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @exempt4 accept
        ip6 saddr @exempt6 accept
        ip saddr @ban4 drop
        ip6 saddr @ban6 drop
      }
    }
NXNFT
}

nx_resolve_ban_backend() {
    if command -v nft >/dev/null 2>&1 && nx_nft_ensure; then
        NX_BAN_BACKEND=nft
        nx_nft_sync_exempt
    else
        NX_BAN_BACKEND=iptables
    fi
    log " BAN BACKEND: $NX_BAN_BACKEND"
}

# Project the exemption universe into the nft exempt sets: self IPs
# (arrays + snapshots + discovered public IPs), the admin whitelist,
# and the Cloudflare ranges — the same sources is_exempt* consult.
nx_nft_sync_exempt() {
    [ "$NX_BAN_BACKEND" = "nft" ] || return 0
    local v4="" v6="" e
    for e in "${SELF_IPS[@]}"; do [ -n "$e" ] && v4="${v4}${e}, "; done
    for e in "${SELF6_IPS[@]}"; do [ -n "$e" ] && v6="${v6}${e}, "; done
    for e in "${CF_RANGES[@]}"; do v4="${v4}${e}, "; done
    for e in "${CF6_RANGES[@]}"; do v6="${v6}${e}, "; done
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r e; do
            e="${e%%#*}"; e="${e// /}"
            [ -z "$e" ] && continue
            case "$e" in *:*) v6="${v6}${e}, " ;; *) v4="${v4}${e}, " ;; esac
        done < "$WHITELIST_FILE"
    fi
    local snap
    for snap in /etc/antiddos/self-ips.list /etc/antiddos/public-ips.list; do
        [ -f "$snap" ] || continue
        while IFS= read -r e; do
            [ -z "$e" ] && continue
            case "$e" in *:*) v6="${v6}${e}, " ;; *) v4="${v4}${e}, " ;; esac
        done < "$snap"
    done
    nft flush set inet nexoshield exempt4 2>/dev/null || true
    nft flush set inet nexoshield exempt6 2>/dev/null || true
    [ -n "$v4" ] && nft add element inet nexoshield exempt4 "{ ${v4%, } }" 2>/dev/null || true
    [ -n "$v6" ] && nft add element inet nexoshield exempt6 "{ ${v6%, } }" 2>/dev/null || true
}

# nx_ban_apply <ip|cidr> <duration-sec> [comment] — enforce one ban in
# the kernel via the active backend. Legacy fallback on any nft error.
nx_ban_apply() {
    local ip="$1" dur="$2" comment="${3:-auto-ban}" set
    if [ "$NX_BAN_BACKEND" = "nft" ]; then
        case "$ip" in *:*) set=ban6 ;; *) set=ban4 ;; esac
        nft delete element inet nexoshield "$set" "{ $ip }" >/dev/null 2>&1 || true
        if nft add element inet nexoshield "$set" "{ $ip timeout ${dur}s }" >/dev/null 2>&1; then
            return 0
        fi
        log " NFT BAN FAILED for $ip - falling back to iptables"
    fi
    case "$ip" in
        *:*) ip6tables -C INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null || \
             ip6tables -I INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null ;;
        *)   iptables -C INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null || \
             iptables -I INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null ;;
    esac
}

# nx_ban_remove_fw <ip|cidr> — kernel-side removal for the nft backend
# (legacy iptables deletes stay at the call sites as belt-and-braces).
nx_ban_remove_fw() {
    [ "$NX_BAN_BACKEND" = "nft" ] || return 0
    local set
    case "$1" in *:*) set=ban6 ;; *) set=ban4 ;; esac
    nft delete element inet nexoshield "$set" "{ $1 }" >/dev/null 2>&1 || true
}

# ── Host stress (Phase 1d) ────────────────────────────────────────
# nx_update_stress runs once per cycle: it watches the kernel counters
# that stay truthful under syncookies (RFC 4987) — ListenOverflows —
# plus conntrack pressure. nx_host_stressed is the gate's oracle.
NX_STRESSED_UNTIL=0
_NX_OVF_PREV=""
_NX_SYNCOOK_PREV=""
_NX_SYNCOOK_LAST_LOG=0
NX_OVF_DELTA=0
NX_SYNCOOK_DELTA=0
nx_update_stress() {
    local now ovf scook
    now=$(date +%s)
    read -r ovf scook <<< "$(awk '
        /^TcpExt:/ { if (!h) { for (i=2;i<=NF;i++) { if ($i=="ListenOverflows") co=i; if ($i=="SyncookiesSent") cs=i } h=1; next }
                     print $(co), $(cs); exit }' /proc/net/netstat 2>/dev/null)"
    ovf="${ovf//[^0-9]/}"; scook="${scook//[^0-9]/}"
    NX_OVF_DELTA=0
    NX_SYNCOOK_DELTA=0
    if [ -n "$ovf" ]; then
        if [ -n "$_NX_OVF_PREV" ]; then
            NX_OVF_DELTA=$(( ovf - _NX_OVF_PREV ))
            [ "$NX_OVF_DELTA" -lt 0 ] && NX_OVF_DELTA=0
            [ "$ovf" -gt "$_NX_OVF_PREV" ] && NX_STRESSED_UNTIL=$(( now + 60 ))
        fi
        _NX_OVF_PREV="$ovf"
    fi
    if [ -n "$scook" ]; then
        if [ -n "$_NX_SYNCOOK_PREV" ]; then
            NX_SYNCOOK_DELTA=$(( scook - _NX_SYNCOOK_PREV ))
            [ "$NX_SYNCOOK_DELTA" -lt 0 ] && NX_SYNCOOK_DELTA=0
        fi
        if [ -n "$_NX_SYNCOOK_PREV" ] && [ "$scook" -gt "$_NX_SYNCOOK_PREV" ] \
           && [ $(( now - _NX_SYNCOOK_LAST_LOG )) -ge 60 ]; then
            log " SYNPRESSURE: syncookies engaged (+$(( scook - _NX_SYNCOOK_PREV )) since last check) - SYN-RECV state is being absorbed by the kernel"
            _NX_SYNCOOK_LAST_LOG=$now
        fi
        _NX_SYNCOOK_PREV="$scook"
    fi
}
nx_host_stressed() {
    local now; now=$(date +%s)
    [ "$now" -lt "$NX_STRESSED_UNTIL" ] && return 0
    # Load pressure: load1 >= 0.9 * cores
    local l1 nc
    l1=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    nc=$(nproc 2>/dev/null || echo 1)
    if [ -n "$l1" ] && awk -v l="$l1" -v c="$nc" 'BEGIN{ exit !(l >= 0.9*c) }'; then
        return 0
    fi
    # Conntrack pressure: usage >= 80% of the table
    local cc cm
    cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
    cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
    cc="${cc//[^0-9]/}"; cm="${cm//[^0-9]/}"
    if [ -n "$cc" ] && [ -n "$cm" ] && [ "$cm" -gt 0 ] && [ $(( cc * 100 / cm )) -ge 80 ]; then
        return 0
    fi
    return 1
}

ban_ip() {
    local ip="$1"
    # FR-2 choke-point guard: ban_ip is the funnel for EVERY ban path
    # (classic, reputation, instant). A self IP must never pass, even if
    # some other check regresses.
    if is_self_ip "$ip"; then
        log " SELF-GUARD: refused to ban the server's own IP $ip"
        return 1
    fi
    is_exempt "$ip" && return 0
    # L5: the has-check + backend + append below must be atomic
    # against a concurrent nx_release_ban rewrite, or the ban lands
    # in the kernel but is lost from state (or duplicated).
    nx_state_lock
    if state_has_ip "$BANNED_LIST" "$ip"; then nx_state_unlock; return 0; fi
    # Already blocked by a range ban? A covering /24 in state means
    # the kernel already drops this IP; a single-IP element would
    # fail on nft (interval overlap) and duplicate state. Treat as
    # done — the range entry governs its expiry.
    local _entry
    while IFS=' ' read -r _entry _rest; do
        case "$_entry" in
            */*) ip_in_cidr "$ip" "$_entry" 2>/dev/null && { nx_state_unlock; return 0; } ;;
        esac
    done < "$BANNED_LIST" 2>/dev/null || true
    # Phase 1c: progressive duration (explicit $2 wins - manual paths).
    local DUR="${2:-$(rep_ban_duration_secs "$ip")}"
    local UNBAN_TIME
    UNBAN_TIME=$(date -d "+${DUR} seconds" '+%H:%M:%S' 2>/dev/null || echo "N/A")
    # M5: never record state for a ban the kernel refused - ban_subnet
    # already refuses this way, and an unrecorded ban is retried by
    # the next cycle instead of sitting in state while unenforced.
    if ! nx_ban_apply "$ip" "$DUR" "auto-ban"; then
        log " BAN FAILED: $ip - backend refused; state NOT recorded"
        nx_state_unlock
        return 1
    fi
    echo "$ip $(date +%s) $DUR" >> "$BANNED_LIST"
    nx_state_unlock
    # Remove ONLY this IP's throttle/hard-throttle tc filter.
    # NOTE: never run 'tc filter del dev "$IF" parent 1:' here — that deletes
    # EVERY filter including the Cloudflare + server-own whitelist, which would
    # throttle CF traffic. We remove the one filter recorded for this IP.
    local _PRIO
    _PRIO=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
    [ -n "$_PRIO" ] && tc filter del dev "$IF" parent 1: prio "$_PRIO" 2>/dev/null || true
    state_del_ip "$THROTTLE_LIST" "$ip"
    log " BANNED: $ip | unban: $UNBAN_TIME"
}

# ════════════════════════════════════════════════════════════
# Reputation scoring — heuristic behavior-based scoring.
# Idea: instead of a hard 80/200 connection cut, score each IP 100..0 and
# escalate gradually. Human/browser traffic opens connections slowly and holds
# them; bots open many new short-lived connections rapidly. We derive the
# new-connection rate from successive connection-count samples (no per-packet
# cost), which is the strongest single discriminator.
#   - well-behaved  → score recovers (auto-release of throttle)
#   - rapid churn   → score drops fast → graduated penalty → ban
# ════════════════════════════════════════════════════════════

# ensure SCORE_DIR exists and SCORE_FILE is readable

# ── IPv6 enforcers (Wave 9): mirrors of the v4 functions ──
_throttle6() {  # <ip> <soft|hard>
    local ip="$1" band="${2:-soft}" flow="1:30"
    [ "$band" = "hard" ] && flow="1:40"
    is_exempt6 "$ip" && return 0
    # R-7: same-band = no-op; soft->hard upgrades by replacing the
    # filter (the old blanket state check made v6 upgrades impossible).
    if state_has_ip "$THROTTLE_LIST" "$ip"; then
        [ "$(state_get_field "$THROTTLE_LIST" "$ip" 4)" = "$band" ] && return 0
        local _op; _op=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
        [ -n "$_op" ] && tc filter del dev "$IF" parent 1: protocol ip6 prio "$_op" 2>/dev/null || true
        state_del_ip "$THROTTLE_LIST" "$ip"
    fi
    tc_class_exists "$flow" || flow="1:30"
    if ! tc_class_exists "$flow"; then
        log " THROTTLE SKIP (v6): $ip - no tc classes on $IF (autoban-only mode)"
        return 0
    fi
    local prio
    prio=$(next_tc_prio)
    if tc filter add dev "$IF" parent 1: protocol ip6 prio "$prio" \
        u32 match ip6 dst "$ip" flowid $flow 2>/dev/null; then
        echo "$ip $prio $(date +%s) $band" >> "$THROTTLE_LIST"
        log " THROTTLED (v6): $ip -> $flow (prio $prio)"
    else
        log " THROTTLE FAILED (v6): $ip - tc refused the filter; state not recorded"
    fi
}
throttle_ip6() { _throttle6 "$1" soft; }
hard_throttle_ip6() { _throttle6 "$1" hard; }

ban_ip6() {
    local ip="$1" _s6 DUR="${2:-$(rep_ban_duration_secs "$1")}"
    is_exempt6 "$ip" && return 0
    # Self-IP choke guard (FR-2): refuse, always, no exceptions.
    for _s6 in "${SELF6_IPS[@]}"; do
        if ip6_in_cidr "$ip" "$_s6/128"; then
            log " REFUSED: $ip is a server IPv6 address (self-IP immunity)"
            return 1
        fi
    done
    # L5: same lock as ban_ip — the has-check + backend + append
    # must be atomic against a concurrent release rewrite.
    nx_state_lock
    if state_has_ip "$BANNED_LIST" "$ip"; then nx_state_unlock; return 0; fi
    # M5: same refusal as ban_ip - no state for a refused ban. The
    # throttle cleanup runs only after a successful ban (as in
    # ban_ip): a failed ban must not also strip the throttle.
    if ! nx_ban_apply "$ip" "$DUR" "auto-ban"; then
        log " BAN FAILED (v6): $ip - backend refused; state NOT recorded"
        nx_state_unlock
        return 1
    fi
    echo "$ip $(date +%s) $DUR" >> "$BANNED_LIST"
    nx_state_unlock
    local _PRIO
    _PRIO=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
    [ -n "$_PRIO" ] && tc filter del dev "$IF" parent 1: protocol ip6 prio "$_PRIO" 2>/dev/null || true
    state_del_ip "$THROTTLE_LIST" "$ip"
    log " BANNED (v6): $ip for $((DUR / 60))min (progressive)"
}
#
# Phase 2 measurement core. nxcountd publishes exact conntrack event
# aggregates every second; this loader diffs consecutive snapshots
# into per-cycle arrival deltas and 60 s window sums. When the
# snapshot is missing or stale, NX_EV_OK=0 and EVERY Phase-2 term
# disarms — behaviour is then exactly the pre-Phase-2 daemon.

NX_COUNTERS_FILE="${NX_COUNTERS_FILE:-/run/nexoshield/counters.dat}"
declare -A EV_SYN60 EV_EST60 EV_CLOSED EV_BYTES EV_AGE
declare -A EV_DSYN EV_DEST EV_PSYN EV_PEST
NX_EV_OK=0
NX_EV_BASE=""
NX_EV_TOT_DSYN=0
NX_EV_TOT_DEST=0
# L4: nxcountd's own loss counters (emitted in the header since
# Phase 2 but never read). NX_EV_DROPPED is the cumulative count of
# netlink messages the helper dropped (ENOBUFS) and
# NX_EV_FLOWS_DROPPED the flows lost with them; NX_EV_DROP_DELTA is
# the increase since the previous cycle. A nonzero delta is logged
# so a lossy cycle is never silently read as "low arrivals".
NX_EV_DROPPED=0
NX_EV_FLOWS_DROPPED=0
NX_EV_DROP_DELTA=0
NX_EV_DT=2
_NX_EV_PREV_TS=""
_NX_EV_PREV_TOTSYN=""
_NX_EV_PREV_TOTEST=""
_NX_EV_PREV_DROPPED=""
_NX_EV_PREV_FLOWS_DROPPED=""

nx_load_event_counters() {
    NX_EV_OK=0
    NX_EV_TOT_DSYN=0
    NX_EV_TOT_DEST=0
    [ -f "$NX_COUNTERS_FILE" ] || return 0
    local hdr kv ts="" base="" totsyn="" totest="" now dropped="" flows_dropped=""
    hdr=$(head -n 1 "$NX_COUNTERS_FILE" 2>/dev/null) || return 0
    case "$hdr" in "# nxcountd 1 "*) ;; *) return 0 ;; esac
    for kv in $hdr; do
        case "$kv" in
            ts=*) ts="${kv#ts=}" ;;
            base=*) base="${kv#base=}" ;;
            totalsyn=*) totsyn="${kv#totalsyn=}" ;;
            totalest=*) totest="${kv#totalest=}" ;;
            dropped=*) dropped="${kv#dropped=}" ;;
            flows_dropped=*) flows_dropped="${kv#flows_dropped=}" ;;
        esac
    done
    ts="${ts//[^0-9]/}"; [ -n "$ts" ] || return 0
    now=$(date +%s)
    # Fresh = published within the last 5 s (clock skew tolerated).
    [ $(( now - ts )) -gt 5 ] && return 0
    [ $(( ts - now )) -gt 5 ] && return 0
    if [ "$base" != "$NX_EV_BASE" ]; then
        # Helper (re)started: cumulative counters reset — re-base the
        # delta windows instead of diffing across the restart.
        NX_EV_BASE="$base"
        EV_PSYN=(); EV_PEST=()
        _NX_EV_PREV_TOTSYN=""
        _NX_EV_PREV_DROPPED=""
        _NX_EV_PREV_FLOWS_DROPPED=""
        log " EVENTS: nxcountd counters (re)based - arrival windows re-arming"
    fi
    totsyn="${totsyn//[^0-9]/}"; totest="${totest//[^0-9]/}"
    if [ -n "$_NX_EV_PREV_TOTSYN" ] && [ -n "$totsyn" ]; then
        NX_EV_TOT_DSYN=$(( totsyn - _NX_EV_PREV_TOTSYN ))
        [ "$NX_EV_TOT_DSYN" -lt 0 ] && NX_EV_TOT_DSYN=0
        NX_EV_TOT_DEST=$(( totest - _NX_EV_PREV_TOTEST ))
        [ "$NX_EV_TOT_DEST" -lt 0 ] && NX_EV_TOT_DEST=0
    fi
    _NX_EV_PREV_TOTSYN="${totsyn:-}"
    _NX_EV_PREV_TOTEST="${totest:-}"
    # L4: surface the helper's loss counters (same delta discipline
    # as the arrival totals - clamped, re-based on restart).
    dropped="${dropped//[^0-9]/}"; flows_dropped="${flows_dropped//[^0-9]/}"
    NX_EV_DROPPED="${dropped:-0}"; NX_EV_FLOWS_DROPPED="${flows_dropped:-0}"
    NX_EV_DROP_DELTA=0
    if [ -n "$_NX_EV_PREV_DROPPED" ] && [ -n "$dropped" ]; then
        NX_EV_DROP_DELTA=$(( dropped - _NX_EV_PREV_DROPPED ))
        [ "$NX_EV_DROP_DELTA" -lt 0 ] && NX_EV_DROP_DELTA=0
        if [ "$NX_EV_DROP_DELTA" -gt 0 ]; then
            local _fd=$(( ${flows_dropped:-0} - ${_NX_EV_PREV_FLOWS_DROPPED:-0} ))
            [ "$_fd" -lt 0 ] && _fd=0
            log " EVENTS: nxcountd lost $NX_EV_DROP_DELTA netlink messages ($_fd flows) since last cycle - arrival counts are a lower bound (cumulative: $NX_EV_DROPPED messages, $NX_EV_FLOWS_DROPPED flows)"
        fi
    fi
    _NX_EV_PREV_DROPPED="${dropped:-}"
    _NX_EV_PREV_FLOWS_DROPPED="${flows_dropped:-}"
    if [ -n "$_NX_EV_PREV_TS" ]; then
        local _ddt=$(( ts - _NX_EV_PREV_TS ))
        [ "$_ddt" -ge 1 ] && [ "$_ddt" -le 30 ] && NX_EV_DT="$_ddt"
    fi
    _NX_EV_PREV_TS="$ts"
    EV_SYN60=(); EV_EST60=(); EV_CLOSED=(); EV_BYTES=(); EV_AGE=(); EV_DSYN=(); EV_DEST=()
    local ip s e s60 e60 cl b a ps pe d
    while read -r ip s e s60 e60 _ _ cl b a; do
        case "$ip" in \#*|"") continue ;; esac
        EV_SYN60["$ip"]="$s60"; EV_EST60["$ip"]="$e60"
        EV_CLOSED["$ip"]="$cl"; EV_BYTES["$ip"]="$b"; EV_AGE["$ip"]="$a"
        ps="${EV_PSYN[$ip]:-}"; pe="${EV_PEST[$ip]:-}"
        if [ -n "$ps" ]; then
            d=$(( s - ps )); [ "$d" -lt 0 ] && d=0; EV_DSYN["$ip"]="$d"
            d=$(( e - pe )); [ "$d" -lt 0 ] && d=0; EV_DEST["$ip"]="$d"
        else
            EV_DSYN["$ip"]=0; EV_DEST["$ip"]=0
        fi
        EV_PSYN["$ip"]="$s"; EV_PEST["$ip"]="$e"
    done < <(tail -n +2 "$NX_COUNTERS_FILE" 2>/dev/null)
    NX_EV_OK=1
}

# ── Adaptive global thresholds (Phase 2d) ────────────────────────
# EWMA mean/deviation of total SYN arrivals per cycle. ATTACK state
# (z >= 4 sustained 3 cycles) tightens the gates and FREEZES the
# baseline — attack traffic must never train its own threshold
# (F5's rule; Wang et al.'s 3-sigma stage is the same shape).
# Calm resumes after z < 2 for 30 cycles (hysteresis). Without event
# data the adaptive layer simply does not move: EFF_* stay at the
# configured values.
NX_ADAPT_FILE="${NX_ADAPT_FILE:-/etc/antiddos/adaptive.dat}"
NX_MU=""
NX_SIG=""
NX_ATTACK=0
_NX_AD_HI=0
_NX_AD_LO=0
_NX_AD_INIT=0
_NX_AD_CYC=0
_NX_AD_PREV=0
EFF_CONN_THRESHOLD=120
EFF_OBSERVE=45

nx_update_adaptive() {
    EFF_CONN_THRESHOLD="$CONN_THRESHOLD"
    EFF_OBSERVE="$OBSERVE_SECONDS"
    [ "${ADAPTIVE_ENABLED:-1}" = "1" ] || return 0
    [ "$NX_EV_OK" = "1" ] || return 0
    if [ "$_NX_AD_INIT" -eq 0 ]; then
        _NX_AD_INIT=1
        if [ -f "$NX_ADAPT_FILE" ]; then
            read -r NX_MU NX_SIG NX_ATTACK < "$NX_ADAPT_FILE" || true
            [[ "${NX_MU:-}" =~ ^[0-9.]+$ ]] || NX_MU=""
            [[ "${NX_SIG:-}" =~ ^[0-9.]+$ ]] || NX_SIG=""
            [ "${NX_ATTACK:-0}" = "1" ] || NX_ATTACK=0
        fi
    fi
    read -r NX_MU NX_SIG NX_ATTACK _NX_AD_HI _NX_AD_LO <<< "$(awk \
        -v A="$NX_EV_TOT_DSYN" -v mu="${NX_MU:-0}" -v sig="${NX_SIG:-0}" \
        -v atk="$NX_ATTACK" -v hi="$_NX_AD_HI" -v lo="$_NX_AD_LO" 'BEGIN{
            if (mu == 0 && sig == 0) { mu = A; sig = (A > 0 ? A * 0.25 : 1); }
            z = (sig > 0.5) ? (A - mu) / sig : ((A > mu * 3 && A > 50) ? 99 : 0);
            if (!atk) {
                if (z >= 4) { hi++; lo = 0; } else { hi = 0; }
                if (hi >= 3) { atk = 1; hi = 0; lo = 0; }
                else {
                    d = A - mu; mu += 0.02 * d;
                    ad = (d < 0 ? -d : d) * 1.2533; sig += 0.02 * (ad - sig);
                    if (sig < 0.5) sig = 0.5;
                }
            } else {
                if (z < 2) { lo++; } else { lo = 0; }
                if (lo >= 30) { atk = 0; lo = 0; hi = 0; }
            }
            printf "%.4f %.4f %d %d %d", mu, sig, atk, hi, lo;
        }')"
    if [ "$NX_ATTACK" = "1" ]; then
        EFF_CONN_THRESHOLD=$(awk -v t="$CONN_THRESHOLD" 'BEGIN{ v = int(t * 0.6); if (v < 40) v = 40; if (v > 400) v = 400; print v }')
        EFF_OBSERVE=$(awk -v o="$OBSERVE_SECONDS" 'BEGIN{ v = int(o * 0.5); if (v < 10) v = 10; print v }')
    fi
    _NX_AD_CYC=$(( _NX_AD_CYC + 1 ))
    if [ $(( _NX_AD_CYC % 30 )) -eq 0 ]; then
        printf '%s %s %s\n' "$NX_MU" "$NX_SIG" "$NX_ATTACK" > "$NX_ADAPT_FILE.tmp.$$" 2>/dev/null && \
            mv "$NX_ADAPT_FILE.tmp.$$" "$NX_ADAPT_FILE" 2>/dev/null || true
    fi
    if [ "$NX_ATTACK" != "$_NX_AD_PREV" ]; then
        if [ "$NX_ATTACK" = "1" ]; then
            log " ADAPTIVE: ATTACK state - gates tightened (conn=$EFF_CONN_THRESHOLD observe=${EFF_OBSERVE}s), baseline frozen"
        else
            log " ADAPTIVE: calm - baseline learning resumed (mu=$NX_MU sig=$NX_SIG)"
        fi
        _NX_AD_PREV="$NX_ATTACK"
    fi
}
#
# The shield is DORMANT: the daemon attaches it only while kernel
# distress signals say the netfilter path is drowning (syncookie
# storms, listen-backlog overflows, or an extreme sustained SYN
# arrival rate from nxcountd), syncs the SAME ban/exempt state the
# nft backend enforces, and detaches after a sustained calm. If the
# loader/object were never built (no clang/libbpf at install time)
# every function here is a no-op.

NX_XDP_BIN="${NX_XDP_BIN:-/usr/local/bin/nx-xdp}"
NX_XDP_OBJ="${NX_XDP_OBJ:-/usr/local/lib/nx_xdp.o}"
NX_XDP_DIR="${NX_XDP_DIR:-/run/nexoshield}"
NX_XDP_BANS_FILE="$NX_XDP_DIR/xdp-bans.list"
NX_XDP_EXEMPT_FILE="$NX_XDP_DIR/xdp-exempt.list"
NX_XDP_AVAILABLE=0
NX_XDP_ATTACHED=""
NX_XDP_IFACE=""
_NX_XDP_HOT=0
_NX_XDP_CALM_SINCE=0
_NX_XDP_WIN_START=0
_NX_XDP_OVF_WIN=0
_NX_XDP_SCOOK_WIN=0
_NX_XDP_BANS_MT=0
_NX_XDP_LAST_DROPS=""

nx_xdp_init() {
    if [ -x "$NX_XDP_BIN" ] && [ -f "$NX_XDP_OBJ" ]; then
        NX_XDP_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
        [ -n "$NX_XDP_IFACE" ] && NX_XDP_AVAILABLE=1
    fi
    [ "$NX_XDP_AVAILABLE" = "1" ] && \
        log " XDP: emergency shield available on $NX_XDP_IFACE (dormant)"
    return 0
}

nx_xdp_build_files() {
    mkdir -p "$NX_XDP_DIR" || return 1
    local now ip ts dur rem e f
    now=$(date +%s)
    : > "$NX_XDP_BANS_FILE.tmp"
    while read -r ip ts dur; do
        [ -n "$ip" ] || continue
        dur="${dur:-$(( ${BAN_HOURS:-4} * 3600 ))}"
        rem=$(( ts + dur - now ))
        [ "$rem" -gt 0 ] && printf '%s %s\n' "$ip" "$rem" >> "$NX_XDP_BANS_FILE.tmp"
    done < "$BANNED_LIST"
    mv "$NX_XDP_BANS_FILE.tmp" "$NX_XDP_BANS_FILE"
    {
        for e in "${SELF_IPS[@]}" "${SELF6_IPS[@]}"; do [ -n "$e" ] && printf '%s\n' "$e"; done
        for e in "${CF_RANGES[@]}" "${CF6_RANGES[@]}"; do [ -n "$e" ] && printf '%s\n' "$e"; done
        for f in "$WHITELIST_FILE" /etc/antiddos/self-ips.list /etc/antiddos/public-ips.list /etc/antiddos/exempt.list; do
            [ -f "$f" ] && cat "$f"
        done
    } | grep -E '^[0-9a-fA-F:./]+$' | sort -u > "$NX_XDP_EXEMPT_FILE.tmp"
    mv "$NX_XDP_EXEMPT_FILE.tmp" "$NX_XDP_EXEMPT_FILE"
}

nx_xdp_attach() {
    local reason="$1"
    nx_xdp_build_files || return 1
    if ! "$NX_XDP_BIN" check "$NX_XDP_BANS_FILE" "$NX_XDP_EXEMPT_FILE" >/dev/null 2>&1; then
        log " XDP: sync files failed validation - NOT attaching"
        return 1
    fi
    if "$NX_XDP_BIN" load "$NX_XDP_IFACE" "$NX_XDP_OBJ" >> "${LOG_FILE:-/dev/null}" 2>&1; then
        "$NX_XDP_BIN" sync-bans "$NX_XDP_BANS_FILE" >/dev/null 2>&1 || true
        "$NX_XDP_BIN" sync-exempt "$NX_XDP_EXEMPT_FILE" >/dev/null 2>&1 || true
        NX_XDP_ATTACHED="$NX_XDP_IFACE"
        _NX_XDP_CALM_SINCE=0
        _NX_XDP_LAST_DROPS=""
        _NX_XDP_BANS_MT=$(stat -c %Y "$BANNED_LIST" 2>/dev/null || echo 0)
        log " XDP: emergency shield ATTACHED on $NX_XDP_IFACE ($reason) - line-rate SYN relief active"
    else
        log " XDP: attach FAILED on $NX_XDP_IFACE - continuing with nft/iptables only"
        return 1
    fi
}

nx_xdp_detach() {
    # L16: the old code cleared NX_XDP_ATTACHED even when the unload
    # failed, so the daemon believed the shield was gone while it was
    # still attached - and never retried. Keep the attached state on
    # failure (fail-closed: the shield keeps dropping) and retry
    # after a fresh calm window.
    if "$NX_XDP_BIN" unload "$NX_XDP_ATTACHED" >> "${LOG_FILE:-/dev/null}" 2>&1; then
        log " XDP: shield detached from $NX_XDP_ATTACHED ($1)"
        NX_XDP_ATTACHED=""
        _NX_XDP_HOT=0
        _NX_XDP_CALM_SINCE=0
    else
        log " XDP: detach FAILED on $NX_XDP_ATTACHED - keeping shield attached, will retry"
        _NX_XDP_CALM_SINCE=$(date +%s)
    fi
}

nx_xdp_tick() {
    [ "$NX_XDP_AVAILABLE" = "1" ] || return 0
    local now rate=0 mt _nxdrops
    now=$(date +%s)
    [ "$_NX_XDP_WIN_START" -eq 0 ] && _NX_XDP_WIN_START=$now
    _NX_XDP_OVF_WIN=$(( _NX_XDP_OVF_WIN + ${NX_OVF_DELTA:-0} ))
    _NX_XDP_SCOOK_WIN=$(( _NX_XDP_SCOOK_WIN + ${NX_SYNCOOK_DELTA:-0} ))
    if [ "${NX_EV_OK:-0}" = "1" ] && [ "${NX_EV_DT:-0}" -gt 0 ]; then
        rate=$(( NX_EV_TOT_DSYN / NX_EV_DT ))
    fi
    if [ -z "$NX_XDP_ATTACHED" ]; then
        if [ "$rate" -gt "${XDP_SYN_RATE:-3000}" ]; then
            _NX_XDP_HOT=$(( _NX_XDP_HOT + 1 ))
        else
            _NX_XDP_HOT=0
        fi
        if [ "$_NX_XDP_HOT" -ge 15 ]; then
            nx_xdp_attach "SYN arrival rate ${rate}/s sustained" || true
            return 0
        fi
        if [ $(( now - _NX_XDP_WIN_START )) -ge 60 ]; then
            if [ "$_NX_XDP_OVF_WIN" -gt "${XDP_OVERFLOW_RATE:-1000}" ]; then
                nx_xdp_attach "listen overflows ${_NX_XDP_OVF_WIN}/min" || true
            elif [ "$_NX_XDP_SCOOK_WIN" -gt "${XDP_SYNCOOKIE_RATE:-500}" ]; then
                nx_xdp_attach "syncookies ${_NX_XDP_SCOOK_WIN}/min" || true
            fi
            _NX_XDP_WIN_START=$now; _NX_XDP_OVF_WIN=0; _NX_XDP_SCOOK_WIN=0
        fi
    else
        mt=$(stat -c %Y "$BANNED_LIST" 2>/dev/null || echo 0)
        if [ "$mt" != "$_NX_XDP_BANS_MT" ]; then
            _NX_XDP_BANS_MT="$mt"
            if nx_xdp_build_files; then
                "$NX_XDP_BIN" sync-bans "$NX_XDP_BANS_FILE" >/dev/null 2>&1 || true
                "$NX_XDP_BIN" sync-exempt "$NX_XDP_EXEMPT_FILE" >/dev/null 2>&1 || true
            fi
        fi
        # M6: the old calm test ignored what the shield was actually
        # doing - a flood whose SYNs all die in XDP leaves no
        # overflows, no syncookies and a low netfilter SYN rate, so
        # the shield detached mid-flood and re-attached in a loop.
        # A rising drops counter means the flood is NOT over: reset
        # the calm timer. An unreadable counter changes nothing.
        _nxdrops=$("$NX_XDP_BIN" stats 2>/dev/null | sed -n 's/.*drops=\([0-9]*\).*/\1/p' | head -1)
        if [ -n "$_nxdrops" ]; then
            [ "$_nxdrops" != "$_NX_XDP_LAST_DROPS" ] && _NX_XDP_CALM_SINCE=0
            _NX_XDP_LAST_DROPS="$_nxdrops"
        fi
        if [ "${NX_OVF_DELTA:-0}" -eq 0 ] && [ "${NX_SYNCOOK_DELTA:-0}" -eq 0 ] && [ "$rate" -lt 500 ]; then
            [ "$_NX_XDP_CALM_SINCE" -eq 0 ] && _NX_XDP_CALM_SINCE=$now
            if [ $(( now - _NX_XDP_CALM_SINCE )) -ge "${XDP_CALM_SECONDS:-600}" ]; then
                nx_xdp_detach "calm for ${XDP_CALM_SECONDS:-600}s"
            fi
        else
            _NX_XDP_CALM_SINCE=0
        fi
        if [ $(( now - _NX_XDP_WIN_START )) -ge 60 ]; then
            _NX_XDP_WIN_START=$now; _NX_XDP_OVF_WIN=0; _NX_XDP_SCOOK_WIN=0
        fi
    fi
}
score_init() {
    mkdir -p "$SCORE_DIR" 2>/dev/null || true
    touch "$SCORE_FILE" 2>/dev/null || true
}

# load_reputation <ip> -> sets REP_SCORE, REP_PREV_CNT, REP_TS,
# REP_PROB_UNTIL (or defaults). Exact field-1 match (BUG-003: the old
# grep -F "$ip " also matched 11.2.3.4 when asked for 1.2.3.4).
# Format: IP SCORE PREV_CNT TS PROB_UNTIL   (PROB_UNTIL added by D3;
# older 4-field lines read as 0.)
load_reputation() {
    local ip="$1"
    REP_SCORE=100
    REP_PREV_CNT=0
    REP_TS=0
    REP_PROB_UNTIL=0
    REP_FRAC=0
    REP_RATE=0
    REP_STRIKES=0
    REP_LAST_BAN=0
    REP_CUSUM_ARR=0
    REP_CUSUM_SYN=0
    local line prev prob frac rate strikes lastban
    line=$(awk -v x="$ip" '$1==x' "$SCORE_FILE" 2>/dev/null | tail -1 || true)
    [ -z "$line" ] && return 0
    REP_SCORE=$(echo "$line" | awk '{print $2}')
    prev=$(echo "$line" | awk '{print $3}')
    REP_TS=$(echo "$line" | awk '{print $4}')
    prob=$(echo "$line" | awk '{print $5}')
    frac=$(echo "$line" | awk '{print $6}')
    rate=$(echo "$line" | awk '{print $7}')
    strikes=$(echo "$line" | awk '{print $8}')
    lastban=$(echo "$line" | awk '{print $9}')
    REP_SCORE="${REP_SCORE:-100}"; REP_SCORE="${REP_SCORE//[^0-9]/}"; REP_SCORE="${REP_SCORE:-100}"
    REP_PREV_CNT="${prev:-0}"; REP_PREV_CNT="${REP_PREV_CNT//[^0-9]/}"; REP_PREV_CNT="${REP_PREV_CNT:-0}"
    REP_TS="${REP_TS:-0}"; REP_TS="${REP_TS//[^0-9]/}"; REP_TS="${REP_TS:-0}"
    REP_PROB_UNTIL="${prob:-0}"; REP_PROB_UNTIL="${REP_PROB_UNTIL//[^0-9]/}"; REP_PROB_UNTIL="${REP_PROB_UNTIL:-0}"
    REP_FRAC="${frac:-0}"; [[ "$REP_FRAC" =~ ^-?[0-9]+$ ]] || REP_FRAC=0
    REP_RATE="${rate:-0}"; REP_RATE="${REP_RATE//[^0-9]/}"; REP_RATE="${REP_RATE:-0}"
    REP_STRIKES="${strikes:-0}"; REP_STRIKES="${REP_STRIKES//[^0-9]/}"; REP_STRIKES="${REP_STRIKES:-0}"
    REP_LAST_BAN="${lastban:-0}"; REP_LAST_BAN="${REP_LAST_BAN//[^0-9]/}"; REP_LAST_BAN="${REP_LAST_BAN:-0}"
    local cusarr cussyn
    cusarr=$(echo "$line" | awk '{print $10}')
    cussyn=$(echo "$line" | awk '{print $11}')
    REP_CUSUM_ARR="${cusarr:-0}"; REP_CUSUM_ARR="${REP_CUSUM_ARR//[^0-9]/}"; REP_CUSUM_ARR="${REP_CUSUM_ARR:-0}"
    REP_CUSUM_SYN="${cussyn:-0}"; REP_CUSUM_SYN="${REP_CUSUM_SYN//[^0-9]/}"; REP_CUSUM_SYN="${REP_CUSUM_SYN:-0}"
    [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
}

# save_reputation: atomic rewrite (tmp + rename, BUG-033) - a crash
# mid-write can no longer corrupt the whole score file.
save_reputation() {
    local ip="$1"
    awk -v x="$ip" '$1!=x' "$SCORE_FILE" > "$SCORE_FILE.tmp.$$" 2>/dev/null || true
    echo "$ip $REP_SCORE $REP_PREV_CNT $(date +%s) ${REP_PROB_UNTIL:-0} ${REP_FRAC:-0} ${REP_RATE:-0} ${REP_STRIKES:-0} ${REP_LAST_BAN:-0} ${REP_CUSUM_ARR:-0} ${REP_CUSUM_SYN:-0}" >> "$SCORE_FILE.tmp.$$"
    mv "$SCORE_FILE.tmp.$$" "$SCORE_FILE" 2>/dev/null || true
}

# clear_reputation <ip> — remove score after cleanup
clear_reputation() {
    local ip="$1"
    state_del_ip "$SCORE_FILE" "$ip"
}

# rep_on_unban <ip> — the D3 release transition, identical for EVERY ban
# path: a served ban ends in PROBATION (score PROBATION_SCORE + window),
# never in a stale low score and never wiped to a fresh 100.
rep_on_ban() {
    local ip="$1" now dur
    now=$(date +%s)
    load_reputation "$ip"
    REP_SCORE="$PROBATION_SCORE"
    REP_FRAC=0
    REP_RATE=0
    # Phase 1c: probation starts when the ACTUAL ban (progressive
    # duration recorded in the state file) ends, not a flat BAN_HOURS.
    dur=$(state_get_field "$BANNED_LIST" "$ip" 3)
    dur="${dur//[^0-9]/}"; [ -n "$dur" ] && [ "$dur" -gt 0 ] || dur=$((BAN_HOURS * 3600))
    REP_PROB_UNTIL=$(( now + dur + PROBATION_SECONDS ))
    # Strike bookkeeping: a ban older than 7 days stops counting.
    if [ "$REP_LAST_BAN" -gt 0 ] && [ $(( now - REP_LAST_BAN )) -gt 604800 ]; then
        REP_STRIKES=0
    fi
    REP_STRIKES=$(( REP_STRIKES + 1 ))
    REP_LAST_BAN=$now
    save_reputation "$ip"
}

# rep_ban_duration_secs <ip> - progressive ban length (Phase 1c):
# ban_base_minutes doubling per strike, capped at ban_max_minutes.
# Reads the reputation record directly (never disturbs REP_* state).
rep_ban_duration_secs() {
    local ip="$1" now strikes=0 lastban=0 mins i
    now=$(date +%s)
    if [ -f "$SCORE_FILE" ]; then
        strikes=$(awk -v x="$ip" '$1==x{print $8}' "$SCORE_FILE" 2>/dev/null | tail -1)
        lastban=$(awk -v x="$ip" '$1==x{print $9}' "$SCORE_FILE" 2>/dev/null | tail -1)
    fi
    strikes="${strikes//[^0-9]/}"; strikes="${strikes:-0}"
    lastban="${lastban//[^0-9]/}"; lastban="${lastban:-0}"
    if [ "$lastban" -gt 0 ] && [ $(( now - lastban )) -gt 604800 ]; then strikes=0; fi
    [ "$strikes" -gt 10 ] && strikes=10
    mins=${BAN_BASE_MINUTES:-30}
    for (( i=0; i<strikes; i++ )); do mins=$(( mins * 2 )); done
    [ "$mins" -gt "${BAN_MAX_MINUTES:-10080}" ] && mins=${BAN_MAX_MINUTES:-10080}
    echo $(( mins * 60 ))
}

rep_on_unban() {
    local ip="$1" now
    now=$(date +%s)
    load_reputation "$ip"
    if state_has_ip "$SCORE_FILE" "$ip"; then
        [ "$REP_SCORE" -lt "$PROBATION_SCORE" ] && REP_SCORE="$PROBATION_SCORE"
        [ "$REP_PROB_UNTIL" -lt $(( now + PROBATION_SECONDS )) ] && \
            REP_PROB_UNTIL=$(( now + PROBATION_SECONDS ))
    else
        REP_SCORE="$PROBATION_SCORE"
        REP_PREV_CNT=0
        REP_PROB_UNTIL=$(( now + PROBATION_SECONDS ))
    fi
    save_reputation "$ip"
}

# reputation_sweep — recovery for QUIET IPs (FR-3/BUG-034: update_score
# only ever ran for hot IPs, so a quiet low score could never recover).
# Runs every cycle over the score file: clean quiet IPs regain points
# (+SCORE_RECOVER, or +PROBATION_RECOVER during probation); banned IPs
# are frozen; fully-recovered stale entries (>24h) are pruned. IPs the
# main loop scored this cycle (hot right now) are left to update_score.
reputation_sweep() {
    [ -f "$SCORE_FILE" ] || return 0
    local now ip score prev ts prob frac rate rec gain acc apply ns elapsed
    now=$(date +%s)
    local tmp="$SCORE_FILE.sweep.$$"
    : > "$tmp"
    while read -r ip score prev ts prob frac rate strikes lastban cusarr cussyn; do
        [ -z "$ip" ] && continue
        score="${score//[^0-9]/}"; score="${score:-100}"
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        prob="${prob//[^0-9]/}"; prob="${prob:-0}"
        [[ "${frac:-}" =~ ^-?[0-9]+$ ]] || frac=0
        rate="${rate//[^0-9]/}"; rate="${rate:-0}"
        strikes="${strikes//[^0-9]/}"; strikes="${strikes:-0}"
        lastban="${lastban//[^0-9]/}"; lastban="${lastban:-0}"
        cusarr="${cusarr//[^0-9]/}"; cusarr="${cusarr:-0}"
        cussyn="${cussyn//[^0-9]/}"; cussyn="${cussyn:-0}"
        if state_has_ip "$BANNED_LIST" "$ip"; then
            echo "$ip $score $prev $ts $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"; continue
        fi
        if [ "${CONN_COUNT[$ip]:-0}" -ge "${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" ]; then
            echo "$ip $score $prev $ts $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"; continue
        fi
        if [ "$score" -ge 100 ] && [ "$prob" -le "$now" ] && [ $(( now - ts )) -gt 86400 ]; then
            continue  # prune fully-recovered stale entries
        fi
        if [ "$score" -lt 100 ]; then
            # Scoring v2: recovery is time-based (points per minute of
            # quiet), accumulated through the fractional field - the old
            # flat per-cycle gain made recovery speed depend on how
            # often the daemon happened to loop.
            elapsed=$(( now - ts )); [ "$elapsed" -lt 0 ] && elapsed=0
            [ "$elapsed" -gt 3600 ] && elapsed=3600
            rec="$SCORE_RECOVER_PER_MIN"; [ "$prob" -gt "$now" ] && rec="$PROBATION_RECOVER_PER_MIN"
            gain=$(( rec * 100 * elapsed / 60 ))
            acc=$(( frac + gain ))
            apply=$(( acc / 100 ))
            frac=$(( acc - apply * 100 ))
            ns=$(( score + apply )); [ "$ns" -gt 100 ] && ns=100
            echo "$ip $ns $prev $now $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"
        else
            echo "$ip $score $prev $ts $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"
        fi
    done < "$SCORE_FILE"
    mv "$tmp" "$SCORE_FILE" 2>/dev/null || true
}

# update_score <ip> <current_conn_count> <syn_recv_count> <elapsed_hint>
# Scoring model v2 (docs/SCORING.md): continuous, time-normalized terms
# with fractional accumulation; adjusts REP_SCORE, enforces the band.
update_score() {
    local ip="$1" cur="$2" syn="${3:-0}" dt="${4:-2}"
    [ "$dt" -lt 1 ] && dt=1
    is_exempt_any "$ip" && { clear_reputation "$ip"; return 0; }
    state_has_ip "$SCORE_FILE" "$ip" || echo "$ip 100 0 0 0 0 0" >> "$SCORE_FILE" 2>/dev/null || true

    load_reputation "$ip"

    # Real elapsed time (BUG-020/D3): measured from the persisted
    # timestamp, clamped - the caller value is only a fallback.
    local now; now=$(date +%s)
    if [ "$REP_TS" -gt 0 ] && [ "$REP_TS" -le "$now" ]; then
        dt=$(( now - REP_TS ))
        [ "$dt" -lt 1 ] && dt=1
        [ "$dt" -gt 60 ] && dt=60
    fi

    # D3 normalization (FR-3): a score in the ban band while the IP is
    # NOT banned is a leftover from a ban that ended outside this path.
    # Normalize it to a probation release instead of re-banning.
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ] && ! state_has_ip "$BANNED_LIST" "$ip"; then
        REP_SCORE="$PROBATION_SCORE"
        REP_PROB_UNTIL=$(( now + PROBATION_SECONDS ))
        log " REP-PROBATION: $ip | stale post-ban score normalized to $PROBATION_SCORE (probation ${PROBATION_SECONDS}s)"
    fi

    local old_score="$REP_SCORE"
    local in_prob=0; [ "$now" -lt "${REP_PROB_UNTIL:-0}" ] && in_prob=1

    # ── Scoring v2 terms, all in points per minute (docs/SCORING.md) ──
    # churn: EWMA-smoothed new-connection rate above a 2/s allowance,
    #   continuous (the v1 step table jumped +2 -> +18 between 49 and
    #   50 conn/s); sustained: concurrent-connection excess over the
    #   watch threshold; syn: half-open share of the total (the SYN
    #   flood signature v1 could not see - it merged SYN-RECV into the
    #   same counter as ESTABLISHED). First sample of a tracked IP
    #   (prev=0): every connection is new within the window.
    # ── Phase 2 event terms: armed only with a fresh nxcountd snapshot.
    # Completion ratio (2b) and slow-attack features (2e) feed the awk
    # below; CUSUM accumulators (2c) update here from this cycle's exact
    # arrival deltas, paired with the true inter-snapshot interval.
    local EVOK=0 S60=0 E60=0 AGES=0 BPC=0 CLOSEDN=0 CUSUM_PTS=0 R60="0.00" CRT=0 SLOW=0
    if [ "${NX_EV_OK:-0}" = "1" ]; then
        EVOK=1
        S60="${EV_SYN60[$ip]:-0}"; E60="${EV_EST60[$ip]:-0}"
        CLOSEDN="${EV_CLOSED[$ip]:-0}"
        if [ "$CLOSEDN" -gt 0 ]; then
            AGES=$(( ${EV_AGE[$ip]:-0} / CLOSEDN / 1000 ))
            BPC=$(( ${EV_BYTES[$ip]:-0} / CLOSEDN ))
        fi
        [ "$S60" -gt 0 ] && R60=$(awk -v e="$E60" -v s="$S60" 'BEGIN{ printf "%.2f", e / s }')
        local _a="${EV_DSYN[$ip]:-0}" _d="${EV_DEST[$ip]:-0}" _inc=0 _edt="${NX_EV_DT:-2}"
        [ "$_a" -gt "$_d" ] && _inc=$(( _a - _d ))
        REP_CUSUM_ARR=$(( ${REP_CUSUM_ARR:-0} + _a * 100 - 200 * _edt ))
        [ "$REP_CUSUM_ARR" -lt 0 ] && REP_CUSUM_ARR=0
        REP_CUSUM_SYN=$(( ${REP_CUSUM_SYN:-0} + _inc * 100 - 25 * _edt ))
        [ "$REP_CUSUM_SYN" -lt 0 ] && REP_CUSUM_SYN=0
        [ "$REP_CUSUM_ARR" -ge 12000 ] && CUSUM_PTS=$(( CUSUM_PTS + 8 ))
        [ "$REP_CUSUM_SYN" -ge 6000 ] && CUSUM_PTS=$(( CUSUM_PTS + 8 ))
    fi

    local CHURN SUST SYNP RS
    read -r CHURN SUST SYNP RS CRT SLOW <<< "$(awk \
        -v cur="$cur" -v prev="$REP_PREV_CNT" -v syn="$syn" \
        -v dt="$dt" -v rate_prev="${REP_RATE:-0}" -v thr="${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" \
        -v evok="$EVOK" -v s60="$S60" -v e60="$E60" -v ages="$AGES" -v bpc="$BPC" -v cln="$CLOSEDN" \
        -v ca="${CHURN_ALLOW:-2}" -v cw="${CHURN_WEIGHT:-1.2}" -v ccap="${CHURN_CAP:-30}" \
        -v sdiv="${SUST_DIV:-40}" -v scap="${SUST_CAP:-20}" \
        -v smin="${SYN_MIN:-20}" -v srat="${SYN_RATIO:-0.5}" -v sw="${SYN_WEIGHT:-40}" -v sycap="${SYN_CAP:-15}" \
        'BEGIN{
            r = (prev > 0) ? ((cur >= prev) ? (cur - prev) / dt : 0) : cur / dt;
            rs = 0.5 * r + 0.5 * (rate_prev / 100);
            churn = (rs <= ca) ? 0 : (rs - ca) * cw; if (churn > ccap) churn = ccap;
            ex = cur - thr; sust = (ex <= 0) ? 0 : ex / sdiv; if (sust > scap) sust = scap;
            synp = 0;
            if (syn >= smin && cur > 0) { ratio = syn / cur; if (ratio > srat) { synp = (ratio - srat) * sw; if (synp > sycap) synp = sycap; } }
            crt = 0;
            if (evok && s60 >= smin) { rr = e60 / s60; if (rr < srat) { crt = (srat - rr) * sw; if (crt > sycap) crt = sycap; } }
            if (crt > synp) synp = crt;
            slow = 0;
            if (evok && cln >= 10 && ages >= 120 && bpc <= 2000 && cur >= 30) { slow = (cur - 30) / 10; if (slow > 10) slow = 10; }
            printf "%.2f %.2f %.2f %.2f %.2f %.2f", churn, sust, synp, rs, crt, slow;
        }')"
    REP_RATE=$(awk -v rs="$RS" 'BEGIN{ printf "%d", rs * 100 + 0.5 }')

    # Probation: drops count double; the total is capped per minute.
    local total_x100 acc apply
    total_x100=$(awk -v c="$CHURN" -v s="$SUST" -v y="$SYNP" \
        -v cu="$CUSUM_PTS" -v sl="$SLOW" \
        -v prob="$in_prob" -v cap="$SCORE_DROP_CAP_PER_MIN" 'BEGIN{
            t = c + s + y + cu + sl; if (prob) t *= 2; if (t > cap) t = cap;
            printf "%d", t * 100 + 0.5 }')
    if [ "$total_x100" -gt 0 ]; then
        acc=$(( REP_FRAC - total_x100 * dt / 60 ))
    else
        local rec="$SCORE_RECOVER_PER_MIN"
        [ "$in_prob" -eq 1 ] && rec="$PROBATION_RECOVER_PER_MIN"
        acc=$(( REP_FRAC + rec * 100 * dt / 60 ))
    fi
    apply=$(( acc / 100 ))
    REP_FRAC=$(( acc - apply * 100 ))
    REP_SCORE=$(( REP_SCORE + apply ))
    [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
    REP_PREV_CNT="$cur"
    save_reputation "$ip"

    # Structured, explainable logging: every material score change is
    # recorded with the exact terms that produced it.
    if [ "$apply" -ne 0 ]; then
        local dstr; [ "$apply" -ge 0 ] && dstr="+$apply" || dstr="$apply"
        local evlog=""
        [ "$EVOK" = "1" ] && evlog=" | ev comp=${CRT}/min cusum=${CUSUM_PTS}/min slow=${SLOW}/min r=$R60"
        log " SCORE: $ip | $old_score->$REP_SCORE (d$dstr) | churn=${CHURN}/min sust=${SUST}/min syn=${SYNP}/min rate=${RS}/s syn_n=$syn dt=${dt}s prob=$in_prob$evlog"
    fi

    # ── Enforce band (graduated, only escalate) ──
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ]; then
        if ! state_has_ip "$BANNED_LIST" "$ip"; then
            # Stress gate (Phase 1d, F5 pattern): on a host that is NOT
            # under stress, a first offence in the shallow ban band is
            # a throttle, not a ban — anomalies alone do not prove the
            # host needs relief. Deep scores (<10) and repeat offenders
            # (strikes > 0) always ban.
            if [ "${STRESS_GATE:-1}" = "1" ] && [ "$REP_SCORE" -ge 10 ] \
               && [ "${REP_STRIKES:-0}" -eq 0 ] && ! nx_host_stressed; then
                nx_hard_throttle "$ip"
                log " GATE: $ip | score $REP_SCORE - ban deferred (host not stressed) -> hard throttle"
            else
                # M5 applied to strikes: ban_ip already refuses state
                # for a refused ban, so a strike/probation must only
                # follow a ban that actually landed — otherwise a
                # degraded backend inflates strikes while the IP is
                # still unblocked, and the loop retries without the
                # phantom record.
                nx_throttle "$ip"
                if nx_ban "$ip"; then
                    log " REP-BAN: $ip | score $REP_SCORE (below $SCORE_BAN) -> ban (progressive)"
                    rep_on_ban "$ip"
                else
                    log " REP-BAN FAILED: $ip | score $REP_SCORE - ban refused, no strike recorded (retry next cycle)"
                fi
            fi
        fi
    elif [ "$REP_SCORE" -lt "$SCORE_HARD" ]; then
        nx_hard_throttle "$ip"
        log " REP-HARD: $ip | score $REP_SCORE -> 50Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_THROTTLE" ]; then
        nx_throttle "$ip"
        log " REP-THROTTLE: $ip | score $REP_SCORE -> 100Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_SUSPECT" ]; then
        if ! state_has_ip "$WATCH_LIST" "$ip"; then
            echo "$ip $(date +%s)" >> "$WATCH_LIST" 2>/dev/null || true
        fi
    fi
}

# ── Subnet /24 ban — blocks entire /24 CIDR ──────────────────
# Used when a botnet sends many IPs from the same subnet, each under per-IP threshold.
# Exempt: CF ranges and own IPs — checked via is_cf_ip on the subnet base.
ban_subnet() {
    local subnet="$1"   # e.g. "1.2.3"  (first 3 octets)
    local cidr="${subnet}.0/24"
    # Don't ban if any CF range overlaps this /24 (BUG-011: the old
    # check tested only the .1 address and missed ranges starting
    # mid-/24; subnet_overlaps_cf tests real range intersection)
    subnet_overlaps_cf "$subnet" && { log " SUBNET SKIP: $cidr overlaps a Cloudflare range"; return 0; }
    # Don't ban own server subnet - check EVERY local address (BUG-065:
    # the old code compared only the first `ip addr` line via head -1)
    local _sip
    for _sip in "${SELF_IPS[@]}"; do
        [ "${_sip%.*}" = "$subnet" ] && { log " SUBNET SKIP: $cidr contains own IP $_sip"; return 0; }
    done
    if [ -f /etc/antiddos/self-ips.list ]; then
        while IFS= read -r _sip; do
            [ "${_sip%.*}" = "$subnet" ] && { log " SUBNET SKIP: $cidr contains own IP $_sip (snapshot)"; return 0; }
        done < /etc/antiddos/self-ips.list
    fi
    # Don't ban if any user-whitelisted IP/CIDR falls inside this /24 subnet —
    # whitelisted users must never be dropped even under distributed attacks.
    local _ENTRY _EIP
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _ENTRY; do
            _ENTRY="${_ENTRY%%#*}"; _ENTRY="${_ENTRY// /}"
            [ -z "$_ENTRY" ] && continue
            case "$_ENTRY" in
                */*) _EIP="${_ENTRY%%/*}" ;;
                *)   _EIP="$_ENTRY" ;;
            esac
            _ECIDR="$_ENTRY"; case "$_ECIDR" in */*) ;; *) _ECIDR="${_ECIDR}/32" ;; esac
            if ip_in_cidr "${subnet}.0" "$_ECIDR" 2>/dev/null || \
               ip_in_cidr "$_EIP" "${subnet}.0/24" 2>/dev/null; then
                log " SUBNET SKIP: $cidr overlaps whitelisted $_ENTRY"
                return 0
            fi
        done < "$WHITELIST_FILE"
    fi
    # Already banned? (state is the source of truth, Phase 1b)
    state_has_ip "$BANNED_LIST" "$cidr" && return 0
    nx_state_lock
    # nft overlap: members already individually banned would make the
    # interval add fail (overlapping intervals). Supersede them
    # first — kernel element + rule + state entry — so the range add
    # succeeds. (Uses the daemon's own removal primitives, not
    # nx_release_ban: that lives in antiddos.sh, a separate program.)
    local _mip
    while IFS=' ' read -r _mip _rest; do
        [ -z "$_mip" ] && continue
        case "$_mip" in */*) continue ;; esac
        if ip_in_cidr "$_mip" "$cidr" 2>/dev/null; then
            nx_ban_remove_fw "$_mip"
            iptables -D INPUT -s "$_mip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || true
            state_del_ip "$BANNED_LIST" "$_mip"
        fi
    done < "$BANNED_LIST" 2>/dev/null || true
    # Phase 1c: subnet bans are short (guardrail vs shared-egress
    # collateral) and ride the same backend as single-IP bans.
    if ! nx_ban_apply "$cidr" $((${SUBNET_BAN_MINUTES:-60} * 60)) "subnet-ban"; then
        log " SUBNET BAN FAILED: $cidr - backend refused; state NOT recorded"
        nx_state_unlock
        return 1
    fi
    echo "$cidr $(date +%s) $((${SUBNET_BAN_MINUTES:-60} * 60))" >> "$BANNED_LIST"
    nx_state_unlock
    log " SUBNET BAN: $cidr | botnet distributed attack detected | unban: ${SUBNET_BAN_MINUTES:-60}min"
}

unban_subnet_expired() {
    local NOW; NOW=$(date +%s)
    [ ! -f "$BANNED_LIST" ] && return
    local NEWLIST=""
    while IFS=' ' read -r ip ts duration; do
        [ -z "$ip" ] && continue
        # Only process subnet entries (contain /)
        [[ "$ip" != *"/"* ]] && NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n" && continue
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        duration="${duration//[^0-9]/}"; duration="${duration:-14400}"
        local EXPIRE=$(( ts + duration ))
        if [ "$NOW" -gt "$EXPIRE" ]; then
            nx_ban_remove_fw "$ip"
            iptables -D INPUT -s "$ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || true
            log " SUBNET UNBANNED: $ip (expired)"
        else
            NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n"
        fi
    done < "$BANNED_LIST"
    printf "%b" "$NEWLIST" > "$BANNED_LIST.tmp.$$" 2>/dev/null && \
        mv "$BANNED_LIST.tmp.$$" "$BANNED_LIST" 2>/dev/null || true
}

unban_expired() {
    local NOW; NOW=$(date +%s)
    [ ! -f "$BANNED_LIST" ] && return
    local NEWLIST=""
    while IFS=' ' read -r ip ts duration; do
        [ -z "$ip" ] && continue
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        duration="${duration//[^0-9]/}"; duration="${duration:-14400}"
        local EXPIRE=$(( ts + duration ))
        if [ "$NOW" -gt "$EXPIRE" ]; then
            # Skip subnet bans — handled by unban_subnet_expired
            [[ "$ip" == *"/"* ]] && NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n" && continue
            nx_ban_remove_fw "$ip"
            [[ "$ip" == *":"* ]] && ip6tables -D INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || true
            iptables -D INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP \
                2>/dev/null || true
            # D3 (FR-3): expiry is a probation release, never a return to
            # a stale low score - identical for every ban path.
            rep_on_unban "$ip"
            log " UNBANNED: $ip (ban expired) → probation (score $PROBATION_SCORE, ${PROBATION_SECONDS}s)"
        else
            NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n"
        fi
    done < "$BANNED_LIST"
    printf "%b" "$NEWLIST" > "$BANNED_LIST.tmp.$$" 2>/dev/null && \
        mv "$BANNED_LIST.tmp.$$" "$BANNED_LIST" 2>/dev/null || true
}

# reconcile_bans (BUG-004/D6): state files and the kernel drifted apart
# across reboots - bans were recorded in BANNED_LIST but the iptables
# rules were gone, while the loop skipped those IPs as "already banned".
# At startup, re-apply every unexpired ban to the kernel; expiry (with
# the D3 probation transition) is handled by unban_expired right after.
reconcile_bans() {
    [ -f "$BANNED_LIST" ] || return 0
    local now ip ts duration
    now=$(date +%s)
    while read -r ip ts duration; do
        [ -z "$ip" ] && continue
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        duration="${duration//[^0-9]/}"; duration="${duration:-14400}"
        [ $(( ts + duration )) -le "$now" ] && continue
        # Phase 1b: re-apply through the active backend with the
        # REMAINING duration (nft elements lost their timeouts in a
        # reboot; iptables rules are simply absent).
        case "$ip" in
            */*) nx_ban_apply "$ip" $(( ts + duration - now )) "subnet-ban" ;;
            *)   nx_ban_apply "$ip" $(( ts + duration - now )) "auto-ban" ;;
        esac
    done < "$BANNED_LIST"
    unban_expired
    unban_subnet_expired
    log " RECONCILE: unexpired bans re-applied via $NX_BAN_BACKEND backend from state"
}

# FR-2 watchdog (D2): if a DROP rule or throttle entry ever targets one
# of the server's own IPs (our bug, a foreign tool, a manual mistake),
# remove it and log loudly. "Never block our own IPs" is a monitored
# invariant, not a hope.
self_guard() {
    local _sip _esc _n _removed=0
    for _sip in "${SELF_IPS[@]}"; do
        [ -z "$_sip" ] && continue
        _esc=$(printf '%s' "$_sip" | sed 's/\./\\./g')
        # M3: delete by RULE NUMBER, not by re-parsing the spec. The
        # old word-split delete passed the -S rendering's literal
        # quote characters (every daemon ban is comment-tagged), so
        # it never matched a real rule; -S line 1 is the policy, so
        # rule number = line number - 1 (same math as
        # nx_delete_matching). The DROP must end the line, or a
        # comment merely mentioning "-j DROP" would false-match.
        while true; do
            _n=$(iptables -S INPUT 2>/dev/null | grep -nE -- "-s ${_esc}(/32)?[[:space:]].*-j DROP$" | head -1 | cut -d: -f1 || true)
            [ -z "$_n" ] && break
            iptables -D INPUT $((_n - 1)) 2>/dev/null || break
            _removed=1
            log " SELF-GUARD: removed DROP rule hitting own IP $_sip"
        done
        nx_ban_remove_fw "$_sip"
        state_del_ip "$BANNED_LIST" "$_sip"
    done
    # IPv6 self sweep (Wave 9): the same hard guarantee for v6,
    # including the comment-tagged rules the old bare -C/-D sweep
    # never matched, plus the nft ban6 set.
    local _sip6 _esc6
    for _sip6 in "${SELF6_IPS[@]}"; do
        [ -z "$_sip6" ] && continue
        _esc6=$(printf '%s' "$_sip6" | sed 's/\./\\./g')
        while true; do
            _n=$(ip6tables -S INPUT 2>/dev/null | grep -nE -- "-s ${_esc6}(/128)?[[:space:]].*-j DROP$" | head -1 | cut -d: -f1 || true)
            [ -z "$_n" ] && break
            ip6tables -D INPUT $((_n - 1)) 2>/dev/null || break
            _removed=1
            log " SELF-GUARD: removed DROP rule for own IPv6 $_sip6"
        done
        nx_ban_remove_fw "$_sip6"
        state_del_ip "$BANNED_LIST" "$_sip6"
    done
    if [ -f "$THROTTLE_LIST" ]; then
        local _prio
        for _sip in "${SELF_IPS[@]}"; do
            if state_has_ip "$THROTTLE_LIST" "$_sip"; then
                _prio=$(state_get_field "$THROTTLE_LIST" "$_sip" 2)
                [ -n "$_prio" ] && tc filter del dev "$IF" parent 1: prio "$_prio" 2>/dev/null || true
                state_del_ip "$THROTTLE_LIST" "$_sip"
                _removed=1
                log " SELF-GUARD: removed throttle state for own IP $_sip"
            fi
        done
    fi
    # L8: a self IP blocked in fail2ban is the same violation, but
    # asking fail2ban every cycle is expensive - sweep the jails only
    # when this call actually removed something above.
    if [ "$_removed" -eq 1 ] && command -v fail2ban-client >/dev/null 2>&1; then
        local _j
        fail2ban-client status 2>/dev/null | grep "Jail list" | \
            sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r _j; do
            [ -z "$_j" ] && continue
            for _sip in "${SELF_IPS[@]}" "${SELF6_IPS[@]}"; do
                [ -z "$_sip" ] && continue
                fail2ban-client set "$_j" unbanip "$_sip" 2>/dev/null || true
            done
        done
    fi
}

log " Smart throttle+ban started (conn_threshold:${CONN_THRESHOLD} ban_threshold:${BAN_CONN_THRESHOLD} subnet_threshold:${SUBNET_THRESHOLD} observe:${OBSERVE_SECONDS}s throttle:${THROTTLE_MBPS}Mbps ban:${BAN_HOURS}h)"
if [ -f "$NX_COUNTERS_FILE" ]; then
    log " EVENTS: nxcountd snapshot present - exact arrival counting armed (Phase 2 terms active)"
else
    log " EVENTS: no nxcountd snapshot - polling mode (Phase 2 terms disarmed)"
fi

score_init

# Phase 1b: pick the ban backend before reconcile projects state into it.
nx_resolve_ban_backend
nx_xdp_init

# Restore throttle filters recorded before a restart/reboot (the qdisc
# may have been rebuilt without them - see reapply_throttles, BUG-022).
# After a reboot /run is empty: pull the state back from the mirror
# first (U-11), or reapply has nothing to work with.
restore_throttle_state
reapply_throttles

# Re-apply recorded bans to the kernel (BUG-004) and expire the stale
# ones through the D3 transition.
reconcile_bans

CYCLE=0
NX_WIN_OFF=0
while true; do
    nx_maybe_reload_scoring_config
    nx_update_stress
    nx_xdp_tick
    CYCLE=$((CYCLE + 1))

    # Keep the persistent throttle mirror current (U-11).
    mirror_throttle_state

    # Every 150 s (75 cycles x 2 s): pick up any newly assigned own
    # IPs (E-3), then unban expired IPs and subnets
    [ $((CYCLE % 75)) -eq 0 ] && refresh_self_ips && unban_expired && unban_subnet_expired

    # Every cycle: enforce self-IP immunity (cheap; iptables -S scan)
    self_guard

    # Measure active connections per IP. Counting definition (BUG-030):
    # only ESTABLISHED and SYN-RECV sockets count (the old `ss -tn`
    # sample also counted TIME-WAIT/CLOSING states), and flows whose
    # LOCAL port is ephemeral (>=32768) are the server's own OUTBOUND
    # connections - the peer of an outbound flow is not an attacker.
    # Exception (high-port fix): a high local port that something
    # LISTENS on is a real service (e.g. a panel on 40000), not an
    # ephemeral port — its peers are scored like any other.
    # No head truncation here (top-100 fix): CONN_COUNT/SYN_COUNT
    # stay complete for the subnet section and the sweeps; the
    # per-peer scoring loop windows the ordered list instead.
    LISTEN_PORTS=$(ss -tlnH 2>/dev/null | awk '{ split($4, L, ":"); print L[length(L)] }' | sort -u | paste -sd, - 2>/dev/null || true)
    declare -A CONN_COUNT
    PEER_ORDER=()
    SS_OUT=$({ ss -tnH state established 2>/dev/null; ss -tnH state syn-recv 2>/dev/null; } | \
        awk -v listen="$LISTEN_PORTS" 'BEGIN { n = split(listen, LP, ","); for (i = 1; i <= n; i++) listen_set[LP[i]] = 1 }
               { split($4, L, ":"); lp = L[length(L)];
               if (lp !~ /^[0-9]+$/) next;
               if (lp >= 32768 && !(lp in listen_set)) next;
               print $5 }' | \
        nx_extract_peer_ips | \
        sort | uniq -c | sort -rn || true)
    if [ -n "$SS_OUT" ]; then
        while IFS= read -r line; do
            CNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            [ -n "$IP" ] && [ -n "$CNT" ] && CONN_COUNT["$IP"]="$CNT"
            [ -n "$IP" ] && PEER_ORDER+=("$IP")
        done <<< "$SS_OUT"
    fi
    # SYN-RECV per IP (scoring v2): half-open sockets are the SYN-flood
    # signature; v1 merged them into the same counter as ESTABLISHED,
    # so scoring could not tell a flood from honest load.
    declare -A SYN_COUNT
    SS_SYN=$(ss -tnH state syn-recv 2>/dev/null | \
        awk -v listen="$LISTEN_PORTS" 'BEGIN { n = split(listen, LP, ","); for (i = 1; i <= n; i++) listen_set[LP[i]] = 1 }
               { split($4, L, ":"); lp = L[length(L)];
               if (lp !~ /^[0-9]+$/) next;
               if (lp >= 32768 && !(lp in listen_set)) next;
               print $5 }' | \
        nx_extract_peer_ips | \
        sort | uniq -c | sort -rn || true)
    if [ -n "$SS_SYN" ]; then
        while IFS= read -r line; do
            CNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            [ -n "$IP" ] && [ -n "$CNT" ] && SYN_COUNT["$IP"]="$CNT"
        done <<< "$SS_SYN"
    fi
    sleep "$SAMPLE_INTERVAL"

    # Phase 2: exact event aggregates for this cycle + adaptive gates.
    nx_load_event_counters
    nx_update_adaptive

    # Process results — based on real connection count, not packets.
    # Rotating window (top-100 hole fix): at most 100 peers are
    # scored per cycle (cycle-time bound), but the window ADVANCES
    # each cycle, so every above-threshold peer is scored within
    # ceil(N/100) cycles instead of peers ranked 101+ never being
    # scored. Peers are count-ordered, so the heaviest are always in
    # the first window (instant bans never wait); the delay only
    # touches the lightest above-threshold peers, which the old code
    # ignored forever. CONN_COUNT stays complete: the subnet section
    # and the watch/throttle sweeps still see every peer.
    _WIN_TOTAL=${#PEER_ORDER[@]}
    WIN_PEERS=()
    if [ "$_WIN_TOTAL" -le 100 ]; then
        WIN_PEERS=("${PEER_ORDER[@]}")
    else
        [ "$NX_WIN_OFF" -ge "$_WIN_TOTAL" ] && NX_WIN_OFF=0
        _WIN_I=0
        while [ "$_WIN_I" -lt 100 ]; do
            WIN_PEERS+=("${PEER_ORDER[$(( (NX_WIN_OFF + _WIN_I) % _WIN_TOTAL ))]}")
            _WIN_I=$((_WIN_I + 1))
        done
        NX_WIN_OFF=$(( (NX_WIN_OFF + 100) % _WIN_TOTAL ))
    fi
    for ip in "${WIN_PEERS[@]}"; do
        count="${CONN_COUNT[$ip]}"
        [ "${count:-0}" -lt "${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" ] && continue

        # Skip exempt IPs (CF + self)
        is_exempt_any "$ip" && continue

        # Skip already banned
        state_has_ip "$BANNED_LIST" "$ip" && continue

        # Reputation scoring: adjust score for this sample and enforce band.
        # Uses the connection count and the interval since the last sample.
        update_score "$ip" "$count" "${SYN_COUNT[$ip]:-0}" "$SAMPLE_INTERVAL"

        # M1: update_score's REP-BAN path already throttled, banned and
        # recorded the strike for this IP. Without this guard the
        # instant/watch blocks below would ban and strike a SECOND
        # time for the same offence (the pre-check above ran before
        # update_score, so it cannot see this cycle's REP-BAN).
        if state_has_ip "$BANNED_LIST" "$ip"; then
            state_del_ip "$WATCH_LIST" "$ip"
            continue
        fi

        # Immediate action if way over limit (≥ BAN_CONN_THRESHOLD conns)
        if [ "${count:-0}" -ge "$BAN_CONN_THRESHOLD" ]; then
            if ! state_has_ip "$THROTTLE_LIST" "$ip"; then
                nx_throttle "$ip"
            fi
            # M5 for strikes: only a ban that actually landed earns a
            # strike and the log line; a refused ban retries next cycle.
            if nx_ban "$ip"; then
                rep_on_ban "$ip"
                state_del_ip "$WATCH_LIST" "$ip"
                log " INSTANT BAN: $ip | ${count} active connections (>=${BAN_CONN_THRESHOLD})"
            fi
            continue
        fi

        if state_has_ip "$WATCH_LIST" "$ip"; then
            # Was being watched — check if still high
            WATCH_START=$(state_get_field "$WATCH_LIST" "$ip" 2)
            WATCH_START="${WATCH_START//[^0-9]/}"
            NOW=$(date +%s)
            ELAPSED=$(( NOW - ${WATCH_START:-$NOW} ))

            if [ "$ELAPSED" -ge "${EFF_OBSERVE:-$OBSERVE_SECONDS}" ]; then
                # Watched for full period and still high
                if state_has_ip "$THROTTLE_LIST" "$ip"; then
                    # Already throttled — now ban (ban_ip cleans the
                    # throttle filter + its state entry itself). On a
                    # refused ban the watch entry is KEPT, so the next
                    # cycle retries immediately instead of re-watching.
                    if nx_ban "$ip"; then
                        rep_on_ban "$ip"
                        state_del_ip "$WATCH_LIST" "$ip"
                    fi
                else
                    # Not yet throttled — throttle now
                    nx_throttle "$ip"
                    # Reset watch timer
                    state_del_ip "$WATCH_LIST" "$ip"
                    echo "$ip $(date +%s)" >> "$WATCH_LIST"
                fi
            fi
        else
            # Start watching
            echo "$ip $(date +%s)" >> "$WATCH_LIST"
            log " WATCHING: $ip | ${count} active connections (threshold: ${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD})"
        fi
    done

    # Clean watch list: remove IPs that went quiet (dropped below threshold)
    while IFS=' ' read -r ip ts; do
        [ -z "$ip" ] && continue
        # If IP is now below threshold and not being throttled, remove from watch
        if [ "${CONN_COUNT[$ip]:-0}" -lt "${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" ] && \
           ! state_has_ip "$THROTTLE_LIST" "$ip"; then
            state_del_ip "$WATCH_LIST" "$ip"
        fi
    done < "$WATCH_LIST" 2>/dev/null || true

    # ── Auto-release throttled IPs that have calmed down ──
    # A throttled IP that drops back below the safe threshold (e.g. a legit heavy
    # download that ended) should be released back to the normal class instead of
    # being held forever. This is the "recover reputation" half of scoring.
    # CF + own IPs are always exempt; banned IPs stay banned until expiry.
    while IFS=' ' read -r ip ts; do
        [ -z "$ip" ] && continue
        is_exempt_any "$ip" && continue
        state_has_ip "$BANNED_LIST" "$ip" && continue
        # Still hot → keep throttled, let scoring manage it.
        [ "${CONN_COUNT[$ip]:-0}" -ge "${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" ] && continue
        # Not banned, no longer hot → release to normal class (1:20).
        # Remove THIS IP's throttle filter by its recorded prio (never a bare
        # 'parent 1:' delete, and never a competing add — an added release
        # filter would out-prio the throttle band and permanently defeat
        # re-throttling of this IP, plus it would accumulate on the iface).
        # R-2 (deep review 2026-10-23): release only once the
        # reputation has genuinely recovered. A single quiet sample
        # used to release the filter AND wipe the score
        # (clear_reputation), so a pulsing source - hot 40s, quiet 3s -
        # erased its history every cycle. Quiet recovery is the
        # sweep's job now; the entry is left for it to finish.
        _REL_SCORE=$(state_get_field "$SCORE_FILE" "$ip" 2)
        _REL_SCORE="${_REL_SCORE//[^0-9]/}"; _REL_SCORE="${_REL_SCORE:-100}"
        [ "$_REL_SCORE" -lt "$SCORE_THROTTLE" ] && continue
        _RELEASE_PRIO=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
        [ -n "$_RELEASE_PRIO" ] && \
            tc filter del dev "$IF" parent 1: prio "$_RELEASE_PRIO" 2>/dev/null || true
        state_del_ip "$THROTTLE_LIST" "$ip"
        state_del_ip "$WATCH_LIST" "$ip"
        log " AUTO-RELEASE: $ip (calmed down, score $_REL_SCORE) → normal class (1:20)"
    done < "$THROTTLE_LIST" 2>/dev/null || true

    # ── Subnet /24 botnet detection ──────────────────────────
    # Aggregate connections by /24 subnet to detect distributed botnets
    # where each attacker IP stays under the per-IP threshold.
    declare -A SUBNET_COUNT SUBNET_OFFENDERS
    for ip in "${!CONN_COUNT[@]}"; do
        # BUG-011: exempt traffic (CF/self/whitelist) never counts toward
        # a subnet ban - it used to inflate the totals.
        is_exempt_any "$ip" && continue
        case "$ip" in *:*) continue ;; esac
        subnet=$(echo "$ip" | grep -oP '^\d+\.\d+\.\d+')
        [ -z "$subnet" ] && continue
        SUBNET_COUNT["$subnet"]=$(( ${SUBNET_COUNT[$subnet]:-0} + ${CONN_COUNT[$ip]:-0} ))
        # Phase 1c guardrail: count DISTINCT member IPs that are each
        # individually over the per-IP gate. A /24 whose total comes
        # from one heavy member (or a CGNAT pool of normal users) is
        # not a botnet signature.
        [ "${CONN_COUNT[$ip]:-0}" -ge "${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" ] && \
            SUBNET_OFFENDERS["$subnet"]=$(( ${SUBNET_OFFENDERS[$subnet]:-0} + 1 ))
    done

    for subnet in "${!SUBNET_COUNT[@]}"; do
        total="${SUBNET_COUNT[$subnet]:-0}"
        [ "$total" -lt "$SUBNET_THRESHOLD" ] && continue
        # Skip if a CF range overlaps this /24 (real overlap test)
        subnet_overlaps_cf "$subnet" && continue
        # Already banned as subnet? (state, Phase 1b)
        state_has_ip "$BANNED_LIST" "${subnet}.0/24" && continue

        if [ "$total" -ge "$SUBNET_BAN_THRESHOLD" ]; then
            if [ "${SUBNET_OFFENDERS[$subnet]:-0}" -ge "$SUBNET_MIN_OFFENDERS" ]; then
                ban_subnet "$subnet"
            elif ! state_has_ip "$SUBNET_WATCH_LIST" "$subnet"; then
                echo "$subnet $(date +%s)" >> "$SUBNET_WATCH_LIST"
                log " SUBNET GUARD: ${subnet}.0/24 | $total conns but only ${SUBNET_OFFENDERS[$subnet]:-0} distinct offenders (< $SUBNET_MIN_OFFENDERS) - not banning (shared-egress guardrail)"
            fi
        else
            # Watch mode: log first sighting
            if ! state_has_ip "$SUBNET_WATCH_LIST" "$subnet"; then
                echo "$subnet $(date +%s)" >> "$SUBNET_WATCH_LIST"
                log " SUBNET WATCHING: ${subnet}.0/24 | ${total} total conns from subnet"
            else
                SWATCH_START=$(state_get_field "$SUBNET_WATCH_LIST" "$subnet" 2)
                SWATCH_START="${SWATCH_START//[^0-9]/}"; SWATCH_START="${SWATCH_START:-$(date +%s)}"
                SELAPSED=$(( $(date +%s) - SWATCH_START ))
                # BUG-011: the sustained path may only ban at the BAN
                # threshold. Sustained traffic at the WATCH level (400)
                # for OBSERVE_SECONDS used to ban a /24 the design says
                # to merely watch - the effective trigger was 400/45s,
                # not the documented 1000.
                if [ "$SELAPSED" -ge "${EFF_OBSERVE:-$OBSERVE_SECONDS}" ] && [ "$total" -ge "$SUBNET_BAN_THRESHOLD" ] \
                   && [ "${SUBNET_OFFENDERS[$subnet]:-0}" -ge "$SUBNET_MIN_OFFENDERS" ]; then
                    log " SUBNET HIGH: ${subnet}.0/24 | ${total} conns for ${SELAPSED}s → banning"
                    ban_subnet "$subnet"
                    state_del_ip "$SUBNET_WATCH_LIST" "$subnet"
                fi
            fi
        fi
    done

    # Clean subnet watch list: remove subnets that calmed down
    while IFS=' ' read -r subnet ts; do
        [ -z "$subnet" ] && continue
        if [ "${SUBNET_COUNT[$subnet]:-0}" -lt "$SUBNET_THRESHOLD" ]; then
            state_del_ip "$SUBNET_WATCH_LIST" "$subnet"
        fi
    done < "$SUBNET_WATCH_LIST" 2>/dev/null || true

    # Recovery for quiet IPs (D3): hot IPs were handled by update_score.
    reputation_sweep

    unset CONN_COUNT SUBNET_COUNT SUBNET_OFFENDERS SYN_COUNT
done
AUTOBAN_EOF

    # Staged activation (BUG-025): never truncate the live daemon script
    if ! bash -n "$AUTOBAN_SCRIPT.nxnew" 2>/dev/null; then
        rm -f "$AUTOBAN_SCRIPT.nxnew"
        err "generated auto-ban script failed its syntax check - keeping the previous one"
        return 1
    fi
    [ -f "$AUTOBAN_SCRIPT" ] && cp -a "$AUTOBAN_SCRIPT" "$AUTOBAN_SCRIPT.prev" 2>/dev/null || true
    mv "$AUTOBAN_SCRIPT.nxnew" "$AUTOBAN_SCRIPT"
    chmod +x "$AUTOBAN_SCRIPT"

    # Create systemd service
    cat > "$AUTOBAN_SERVICE" << EOF
[Unit]
Description=Auto-ban DDoS detection (smart throttle+ban)
After=network.target iptables.service

[Service]
Type=simple
ExecStart=$AUTOBAN_SCRIPT
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable auto-ban.service >/dev/null 2>&1
    systemctl restart auto-ban.service 2>/dev/null || true
    sleep 2

    if systemctl is-active auto-ban >/dev/null 2>&1; then
        success "Auto-ban service: running (watch:120 conns, instant ban:300 conns, bans progressive 30m-7d - tunable in scoring.conf)"
    else
        warn "Auto-ban service failed to start - check: journalctl -u auto-ban"
    fi
}

# ════════════════════════════════════════════════
# LAYER 5: tc bandwidth control
# CF=unlimited, others=500Mbps, throttled=100Mbps
# Uses SRC IP (not DST) to avoid breaking tunnels
# ════════════════════════════════════════════════

# setup_countd (Phase 2a): build + install nxcountd when a compiler
# and the conntrack netlink headers are available. ANY failure is a
# warning, never an install failure: without the snapshot file the
# daemon simply keeps its polling behaviour.
setup_countd() {
    if ! command -v cc >/dev/null 2>&1 || [ ! -f /usr/include/linux/netfilter/nfnetlink_conntrack.h ]; then
        warn "nxcountd: compiler/headers missing - event counting unavailable (daemon polls instead)"
        return 0
    fi
    local build_dir
    build_dir=$(mktemp -d) || return 0
    cat > "$build_dir/nxcountd.c" << 'NXCOUNTD_EOF'
/*
 * nxcountd — NexoShield conntrack event counter (DPI upgrade Phase 2a).
 *
 * Subscribes to kernel conntrack events (NEW/UPDATE/DESTROY) over a
 * raw NETLINK_NETFILTER socket and maintains exact per-source-IP
 * aggregates for inbound TCP flows:
 *
 *   syn_cum / est_cum   cumulative SYN births / handshake completions
 *   syn60 / est60       the same over a rolling 60 s window
 *   cur_syn / cur_est   current half-open / established concurrency
 *   closed_cum          completed flows
 *   bytes_cum           originator bytes of closed flows
 *   age_ms_cum          total lifetime of closed flows
 *
 * Every second the top-500 active sources are published atomically
 * (tmp + rename) to the snapshot file the auto-ban daemon reads.
 * Polling `ss` samples a stock; these counters measure the flow —
 * Little's Law (L = lambda * W) makes arrival rate underivable from
 * concurrency deltas, which is the gap this helper closes.
 *
 * Only libc + kernel headers. Flows originated BY this host (source
 * is a local address) are ignored: the daemon scores clients, and the
 * sampler it replaces deliberately subtracted outbound traffic too.
 *
 * `--selftest` feeds synthetic conntrack messages through the same
 * parser/aggregator and prints the resulting snapshot body, so the
 * parser is unit-testable without a live kernel.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FLOW_SLOTS 16384
#define IP_SLOTS   32768
#define TOP_N      500
#define RING       60

/* tcp_conntrack states (linux/netfilter/nf_conntrack_tcp.h) */
enum { TS_NONE = 0, TS_SYN_SENT = 1, TS_SYN_RECV = 2, TS_ESTABLISHED = 3 };

static int is_syn_state(int s) { return s == TS_SYN_SENT || s == TS_SYN_RECV || s == 12; }

/* ── local address set (flows FROM these are outbound: skip) ── */
static uint32_t g_local4[64]; static int g_nlocal4;
static uint8_t  g_local6[32][16]; static int g_nlocal6;

static int is_local4(uint32_t be)
{
    if ((ntohl(be) >> 24) == 127) return 1;
    for (int i = 0; i < g_nlocal4; i++) if (g_local4[i] == be) return 1;
    return 0;
}
static int is_local6(const uint8_t *ip)
{
    static const uint8_t lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (!memcmp(ip, lo, 16)) return 1;
    for (int i = 0; i < g_nlocal6; i++) if (!memcmp(g_local6[i], ip, 16)) return 1;
    return 0;
}

static void load_local_addrs(void)
{
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) return;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        if (p->ifa_addr->sa_family == AF_INET && g_nlocal4 < 64) {
            g_local4[g_nlocal4++] = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
        } else if (p->ifa_addr->sa_family == AF_INET6 && g_nlocal6 < 32) {
            memcpy(g_local6[g_nlocal6++], &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr, 16);
        }
    }
    freeifaddrs(ifa);
}

/* ── flow table (by conntrack ID) ── */
typedef struct {
    uint32_t id; uint8_t used, family, state;
    uint8_t ip[16];
    uint64_t created_ms, last_ms, last_bytes;
} Flow;
static Flow g_flows[FLOW_SLOTS];
static uint64_t g_flows_dropped;

/* ── per-IP aggregates ── */
typedef struct {
    uint8_t used, family;
    uint8_t ip[16];
    uint64_t syn_cum, est_cum, closed_cum, bytes_cum, age_ms_cum;
    int64_t  cur_syn, cur_est;
    uint32_t ring_syn[RING], ring_est[RING];
    int64_t  last_seen_s;
} Agg;
static Agg g_ips[IP_SLOTS];
static uint64_t g_total_syn, g_total_est, g_dropped_msgs;

static uint64_t hash_bytes(const uint8_t *p, int n, uint32_t seed)
{
    uint64_t h = 1469598103934665603ULL ^ seed;
    for (int i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static Agg *agg_get(const uint8_t *ip, int family, int create, int64_t now_s)
{
    int len = family == AF_INET ? 4 : 16;
    uint64_t h = hash_bytes(ip, len, family) % IP_SLOTS;
    for (uint64_t k = 0; k < IP_SLOTS; k++) {
        Agg *a = &g_ips[(h + k) % IP_SLOTS];
        if (!a->used) {
            if (!create) return NULL;
            memset(a, 0, sizeof *a);
            a->used = 1; a->family = (uint8_t)family;
            memcpy(a->ip, ip, len);
            a->last_seen_s = now_s;
            return a;
        }
        if (a->family == family && !memcmp(a->ip, ip, len)) {
            a->last_seen_s = now_s;
            return a;
        }
    }
    return NULL;
}

static Flow *flow_get(uint32_t id, int create)
{
    uint64_t h = (id * 2654435761u) % FLOW_SLOTS;
    for (uint64_t k = 0; k < FLOW_SLOTS; k++) {
        Flow *f = &g_flows[(h + k) % FLOW_SLOTS];
        if (!f->used) {
            if (!create) return NULL;
            memset(f, 0, sizeof *f);
            f->used = 1; f->id = id;
            return f;
        }
        if (f->id == id) return f;
    }
    if (create) g_flows_dropped++;
    return NULL;
}

/* ── event application (shared by live loop and selftest) ── */
typedef struct {
    uint32_t id; int family; uint8_t ip[16];
    int has_state, state;
    uint64_t bytes; int is_destroy;
} Event;

static void apply_event(const Event *e, uint64_t now_ms, int64_t now_s)
{
    if (e->family == AF_INET  && is_local4(*(const uint32_t *)e->ip)) return;
    if (e->family == AF_INET6 && is_local6(e->ip)) return;

    Flow *f = flow_get(e->id, !e->is_destroy);
    Agg *a = agg_get(e->ip, e->family, 1, now_s);
    if (!a) return;
    int slot = (int)(now_s % RING);

    if (e->is_destroy) {
        if (f && f->used) {
            if (is_syn_state(f->state)) a->cur_syn--;
            else if (f->state == TS_ESTABLISHED) a->cur_est--;
            a->closed_cum++;
            a->age_ms_cum += now_ms - f->created_ms;
            a->bytes_cum += e->bytes ? e->bytes : f->last_bytes;
            f->used = 0;
        }
        return;
    }
    if (!f) return;
    if (!f->created_ms) {           /* first sighting of this flow */
        f->family = (uint8_t)e->family;
        memcpy(f->ip, e->ip, e->family == AF_INET ? 4 : 16);
        f->created_ms = now_ms;
        f->state = TS_NONE;
    }
    f->last_ms = now_ms;
    if (e->bytes > f->last_bytes) f->last_bytes = e->bytes;
    if (!e->has_state) return;
    int prev = f->state, cur = e->state;
    if (prev == cur) return;
    if (is_syn_state(cur) && !is_syn_state(prev) && prev != TS_ESTABLISHED) {
        a->syn_cum++; g_total_syn++;
        a->ring_syn[slot]++; a->cur_syn++;
    }
    if (cur == TS_ESTABLISHED && is_syn_state(prev)) {
        a->est_cum++; g_total_est++;
        a->ring_est[slot]++; a->cur_syn--; a->cur_est++;
    }
    if (cur == TS_ESTABLISHED && prev == TS_NONE) {
        /* First seen already established (we missed the SYN, e.g.
         * helper started mid-flow): count the completion only. */
        a->est_cum++; g_total_est++;
        a->ring_est[slot]++; a->cur_est++;
    }
    if (is_syn_state(prev) && !is_syn_state(cur) && cur != TS_ESTABLISHED && prev != TS_NONE) {
        a->cur_syn--;               /* SYN died without completing */
    }
    /* Leaving ESTABLISHED for a closing state releases concurrency
     * only at DESTROY (age accounting lives there too), so cur_est
     * stays until the flow is finalized. */
    f->state = (uint8_t)cur;
}

/* ── netlink attribute walking ── */
#define NX_NLA_TYPE(a) ((a)->nla_type & 0x3fff)
static const struct nlattr *find_attr(const char *p, int len, int type)
{
    while (len >= (int)sizeof(struct nlattr)) {
        const struct nlattr *a = (const struct nlattr *)p;
        if (a->nla_len < (int)sizeof(struct nlattr) || a->nla_len > len) break;
        if (NX_NLA_TYPE(a) == type) return a;
        int adv = NLA_ALIGN(a->nla_len);
        p += adv; len -= adv;
    }
    return NULL;
}
static const char *attr_payload(const struct nlattr *a, int *len)
{
    *len = a->nla_len - NLA_HDRLEN;
    return (const char *)a + NLA_HDRLEN;
}

static int parse_message(const struct nlmsghdr *nlh, Event *e)
{
    memset(e, 0, sizeof *e);
    int len = NLMSG_PAYLOAD(nlh, sizeof(struct nfgenmsg));
    const char *p = (const char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
    const struct nfgenmsg *fg = NLMSG_DATA(nlh);
    e->family = fg->nfgen_family;
    e->is_destroy = ((nlh->nlmsg_type & 0xff) == IPCTNL_MSG_CT_DELETE);

    const struct nlattr *a;
    int plen;
    if ((a = find_attr(p, len, CTA_ID))) {
        const char *v = attr_payload(a, &plen);
        if (plen >= 4) e->id = ntohl(*(const uint32_t *)v);
    }
    const struct nlattr *tup = find_attr(p, len, CTA_TUPLE_ORIG);
    if (!tup) return -1;
    const char *tp = attr_payload(tup, &plen);
    int tlen = plen;
    const struct nlattr *ipn = find_attr(tp, tlen, CTA_TUPLE_IP);
    if (!ipn) return -1;
    const char *ipp = attr_payload(ipn, &plen);
    if (e->family == AF_INET) {
        const struct nlattr *s = find_attr(ipp, plen, CTA_IP_V4_SRC);
        if (!s) return -1;
        memcpy(e->ip, attr_payload(s, &plen), 4);
    } else if (e->family == AF_INET6) {
        const struct nlattr *s = find_attr(ipp, plen, CTA_IP_V6_SRC);
        if (!s) return -1;
        memcpy(e->ip, attr_payload(s, &plen), 16);
    } else return -1;
    const struct nlattr *pro = find_attr(tp, tlen, CTA_TUPLE_PROTO);
    if (pro) {
        const char *pp = attr_payload(pro, &plen);
        const struct nlattr *pn = find_attr(pp, plen, CTA_PROTO_NUM);
        if (pn) {
            const char *v = attr_payload(pn, &plen);
            if (plen >= 1 && *(const uint8_t *)v != 6) return -1; /* TCP only */
        }
    }
    const struct nlattr *pi = find_attr(p, len, CTA_PROTOINFO);
    if (pi) {
        const char *pp = attr_payload(pi, &plen);
        const struct nlattr *tcp = find_attr(pp, plen, CTA_PROTOINFO_TCP);
        if (tcp) {
            const char *tcpp = attr_payload(tcp, &plen);
            const struct nlattr *st = find_attr(tcpp, plen, CTA_PROTOINFO_TCP_STATE);
            if (st) {
                const char *v = attr_payload(st, &plen);
                if (plen >= 1) { e->has_state = 1; e->state = *(const uint8_t *)v; }
            }
        }
    }
    const struct nlattr *cnt = find_attr(p, len, CTA_COUNTERS_ORIG);
    if (cnt) {
        const char *cp = attr_payload(cnt, &plen);
        const struct nlattr *b = find_attr(cp, plen, CTA_COUNTERS_BYTES);
        if (b) {
            const char *v = attr_payload(b, &plen);
            if (plen >= 8) {
                uint64_t be; memcpy(&be, v, 8);
                e->bytes = be64toh(be);
            }
        }
    }
    return 0;
}

/* ── snapshot ── */
static uint64_t g_base;
static int cmp_agg(const void *x, const void *y)
{
    const Agg *a = *(Agg *const *)x, *b = *(Agg *const *)y;
    uint64_t sa = a->syn_cum + a->est_cum, sb = b->syn_cum + b->est_cum;
    return sa < sb ? 1 : sa > sb ? -1 : 0;
}

static void write_snapshot(const char *path, int64_t now_s)
{
    static Agg *top[TOP_N];
    int n = 0;
    for (int i = 0; i < IP_SLOTS; i++) {
        Agg *a = &g_ips[i];
        if (!a->used) continue;
        if (a->syn_cum + a->est_cum == 0 && a->cur_syn + a->cur_est == 0 && a->closed_cum == 0) continue;
        if (n < TOP_N) top[n++] = a;
        else {
            /* keep the TOP_N largest by activity */
            int min = 0;
            for (int j = 1; j < n; j++)
                if (top[j]->syn_cum + top[j]->est_cum < top[min]->syn_cum + top[min]->est_cum) min = j;
            if (a->syn_cum + a->est_cum > top[min]->syn_cum + top[min]->est_cum) top[min] = a;
        }
    }
    qsort(top, n, sizeof top[0], cmp_agg);
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return;
    fprintf(fp, "# nxcountd 1 ts=%lld base=%llu dropped=%llu flows_dropped=%llu totalsyn=%llu totalest=%llu\n",
            (long long)now_s, (unsigned long long)g_base,
            (unsigned long long)g_dropped_msgs, (unsigned long long)g_flows_dropped,
            (unsigned long long)g_total_syn, (unsigned long long)g_total_est);
    for (int i = 0; i < n; i++) {
        Agg *a = top[i];
        char ipbuf[INET6_ADDRSTRLEN];
        inet_ntop(a->family, a->ip, ipbuf, sizeof ipbuf);
        uint64_t s60 = 0, e60 = 0;
        for (int r = 0; r < RING; r++) { s60 += a->ring_syn[r]; e60 += a->ring_est[r]; }
        fprintf(fp, "%s %llu %llu %llu %llu %lld %lld %llu %llu %llu\n",
                ipbuf,
                (unsigned long long)a->syn_cum, (unsigned long long)a->est_cum,
                (unsigned long long)s60, (unsigned long long)e60,
                (long long)a->cur_syn, (long long)a->cur_est,
                (unsigned long long)a->closed_cum,
                (unsigned long long)a->bytes_cum,
                (unsigned long long)a->age_ms_cum);
    }
    fclose(fp);
    rename(tmp, path);
}

/* Ring hygiene: slot (second % 60) must be zeroed when its second
 * rolls into the window, BEFORE that second's increments land —
 * otherwise the slot still holds the data of the second that just
 * fell out of the window (60 s ago, same slot). Epoch-checked so
 * each slot is zeroed exactly once per minute. */
static int64_t g_slot_epoch[RING];
static void ring_zero_slot(int64_t now_s)
{
    int slot = (int)(now_s % RING);
    if (g_slot_epoch[slot] == now_s) return;
    g_slot_epoch[slot] = now_s;
    for (int i = 0; i < IP_SLOTS; i++) {
        if (!g_ips[i].used) continue;
        g_ips[i].ring_syn[slot] = 0;
        g_ips[i].ring_est[slot] = 0;
    }
}

/* Stale-flow expiry: a flow whose DESTROY was missed (event loss
 * under flood is exactly when drops happen) would otherwise pin
 * cur_* counts forever. Sweep a rotating slice of the flow table
 * once per second; flows silent for 30 min are finalized as if
 * destroyed (bytes = last counter seen). */
static void flow_sweep_slice(uint64_t now_ms, int64_t now_s)
{
    static int cursor;
    int span = FLOW_SLOTS / 60 + 1;
    for (int k = 0; k < span; k++) {
        Flow *f = &g_flows[(cursor + k) % FLOW_SLOTS];
        if (f->used && f->last_ms && now_ms - f->last_ms > 1800000ULL) {
            Agg *a = agg_get(f->ip, f->family, 0, now_s);
            if (a) {
                if (is_syn_state(f->state)) a->cur_syn--;
                else if (f->state == TS_ESTABLISHED) a->cur_est--;
                a->closed_cum++;
                a->age_ms_cum += now_ms - f->created_ms;
                a->bytes_cum += f->last_bytes;
            }
            f->used = 0;
        }
    }
    cursor = (cursor + span) % FLOW_SLOTS;
}

/* ── selftest: synthetic messages through the real parser ── */
static void put_attr(char *buf, int *off, uint16_t type, const void *data, int len)
{
    struct nlattr *a = (struct nlattr *)(buf + *off);
    a->nla_len = NLA_HDRLEN + len;
    a->nla_type = type;
    memcpy(buf + *off + NLA_HDRLEN, data, len);
    *off += NLA_ALIGN(a->nla_len);
}
static void nest_start(char *buf, int *off, uint16_t type, int *save)
{
    *save = *off;
    struct nlattr *a = (struct nlattr *)(buf + *off);
    a->nla_type = type | NLA_F_NESTED;
    *off += NLA_HDRLEN;
}
static void nest_end(char *buf, int *off, int save)
{
    struct nlattr *a = (struct nlattr *)(buf + save);
    a->nla_len = *off - save;
    *off = save + NLA_ALIGN(a->nla_len);
}

static int selftest(void)
{
    load_local_addrs();
    /* pretend 10.0.0.5 is local for the outbound-filter case */
    struct in_addr la; inet_pton(AF_INET, "10.0.0.5", &la);
    g_local4[g_nlocal4++] = la.s_addr;

    static char buf[4096];
    int64_t now_s = 1700000000;
    uint64_t now_ms = 1700000000000ULL;
    g_base = 42;

    struct { uint32_t id; const char *ip; int fam; int state; int destroy; uint64_t bytes; } script[] = {
        {100, "203.0.113.7", AF_INET,  TS_SYN_RECV,   0, 0},
        {100, "203.0.113.7", AF_INET,  TS_ESTABLISHED,0, 0},
        {101, "203.0.113.7", AF_INET,  TS_SYN_RECV,   0, 0},
        {101, "203.0.113.7", AF_INET,  0,             1, 4000},
        {102, "10.0.0.5",    AF_INET,  TS_SYN_RECV,   0, 0},   /* local: ignored */
        {103, "2001:db8::1", AF_INET6, TS_SYN_SENT,   0, 0},
        {103, "2001:db8::1", AF_INET6, 0,             1, 500},
    };
    for (unsigned k = 0; k < sizeof script / sizeof script[0]; k++) {
        memset(buf, 0, sizeof buf);
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | (script[k].destroy ? IPCTNL_MSG_CT_DELETE : IPCTNL_MSG_CT_NEW);
        struct nfgenmsg *fg = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
        fg->nfgen_family = (uint8_t)script[k].fam;
        int off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
        uint32_t idbe = htonl(script[k].id);
        put_attr(buf, &off, CTA_ID, &idbe, 4);
        int s1, s2;
        nest_start(buf, &off, CTA_TUPLE_ORIG, &s1);
        nest_start(buf, &off, CTA_TUPLE_IP, &s2);
        if (script[k].fam == AF_INET) {
            struct in_addr a4; inet_pton(AF_INET, script[k].ip, &a4);
            put_attr(buf, &off, CTA_IP_V4_SRC, &a4, 4);
        } else {
            struct in6_addr a6; inet_pton(AF_INET6, script[k].ip, &a6);
            put_attr(buf, &off, CTA_IP_V6_SRC, &a6, 16);
        }
        nest_end(buf, &off, s2);
        nest_start(buf, &off, CTA_TUPLE_PROTO, &s2);
        uint8_t proto = 6;
        put_attr(buf, &off, CTA_PROTO_NUM, &proto, 1);
        nest_end(buf, &off, s2);
        nest_end(buf, &off, s1);
        if (!script[k].destroy) {
            nest_start(buf, &off, CTA_PROTOINFO, &s1);
            nest_start(buf, &off, CTA_PROTOINFO_TCP, &s2);
            uint8_t st = (uint8_t)script[k].state;
            put_attr(buf, &off, CTA_PROTOINFO_TCP_STATE, &st, 1);
            nest_end(buf, &off, s2);
            nest_end(buf, &off, s1);
        } else {
            nest_start(buf, &off, CTA_COUNTERS_ORIG, &s1);
            uint64_t be = htobe64(script[k].bytes);
            put_attr(buf, &off, CTA_COUNTERS_BYTES, &be, 8);
            nest_end(buf, &off, s1);
        }
        nlh->nlmsg_len = off;
        Event e;
        if (script[k].destroy) now_ms += 5000;   /* flows lived 5 s */
        if (parse_message(nlh, &e) == 0) apply_event(&e, now_ms, now_s);
    }
    /* write the snapshot body to stdout (no header semantics needed) */
    char path[] = "/tmp/nxcountd-selftest-XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0) close(fd);
    write_snapshot(path, now_s);
    FILE *fp = fopen(path, "r");
    if (fp) { char line[512]; while (fgets(line, sizeof line, fp)) fputs(line, stdout); fclose(fp); }
    unlink(path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--selftest")) return selftest();
    const char *out = argc > 1 ? argv[1] : "/run/nexoshield/counters.dat";

    FILE *rnd = fopen("/dev/urandom", "r");
    if (rnd) { if (fread(&g_base, 1, sizeof g_base, rnd) != sizeof g_base) g_base = 0; fclose(rnd); }
    if (!g_base) g_base = (uint64_t)getpid() << 32 | (uint64_t)time(NULL);

    load_local_addrs();

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) { perror("socket"); return 1; }
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    struct sockaddr_nl sa = {0};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = (1u << (NFNLGRP_CONNTRACK_NEW - 1)) |
                   (1u << (NFNLGRP_CONNTRACK_UPDATE - 1)) |
                   (1u << (NFNLGRP_CONNTRACK_DESTROY - 1));
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("bind"); return 1; }

    static char buf[65536];
    int64_t last_snap = 0;
    for (;;) {
        struct timespec ts0;
        clock_gettime(CLOCK_MONOTONIC, &ts0);
        uint64_t now_ms0 = (uint64_t)ts0.tv_sec * 1000 + ts0.tv_nsec / 1000000;
        int64_t now_s0 = time(NULL);
        if (now_s0 != last_snap) {
            last_snap = now_s0;
            ring_zero_slot(now_s0);
            flow_sweep_slice(now_ms0, now_s0);
            write_snapshot(out, now_s0);
        }
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 250);
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        int64_t now_s = time(NULL);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            for (;;) {
                ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
                if (n <= 0) {
                    if (n < 0 && errno == ENOBUFS) g_dropped_msgs++;
                    break;
                }
                for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
                     NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
                    if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_DONE) continue;
                    Event e;
                    if (parse_message(nlh, &e) == 0) apply_event(&e, now_ms, now_s);
                }
            }
        }
    }
    return 0;
}
NXCOUNTD_EOF
    if ! cc -O2 -o "$build_dir/nxcountd" "$build_dir/nxcountd.c" 2>/dev/null; then
        warn "nxcountd: build failed - event counting unavailable (daemon polls instead)"
        rm -rf "$build_dir"
        return 0
    fi
    # Atomic replace - compiling straight onto /usr/local/bin
    # failed with ETXTBSY whenever the counter service was running,
    # so updates silently kept the old binary forever.
    if ! nx_install_binary "$build_dir/nxcountd" /usr/local/bin/nxcountd 755; then
        warn "nxcountd: install failed - keeping the previous binary (daemon polls if none)"
        rm -rf "$build_dir"
        return 0
    fi
    rm -rf "$build_dir"
    cat > /etc/systemd/system/nexoshield-countd.service << 'EOF'
[Unit]
Description=NexoShield conntrack event counter
After=network.target
Before=auto-ban.service

[Service]
Type=simple
ExecStart=/usr/local/bin/nxcountd /run/nexoshield/counters.dat
Restart=always
RestartSec=5
RuntimeDirectory=nexoshield
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run/nexoshield
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable nexoshield-countd.service >/dev/null 2>&1
    systemctl restart nexoshield-countd.service 2>/dev/null || true
    success "nxcountd: conntrack event counter installed (exact arrival counting)"
}

# setup_xdp (Phase 3): build the XDP emergency shield when clang and
# libbpf headers are available (one best-effort package attempt,
# house style). Any failure leaves the feature dormant - the daemon
# probes for the files and simply never attaches.
setup_xdp() {
    if ! command -v clang >/dev/null 2>&1 || [ ! -f /usr/include/bpf/libbpf.h ]; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libbpf-dev >/dev/null 2>&1 || true
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y clang libbpf-devel >/dev/null 2>&1 || true
        fi
    fi
    if ! command -v clang >/dev/null 2>&1 || [ ! -f /usr/include/bpf/libbpf.h ]; then
        info "XDP shield: no clang/libbpf - dormant feature skipped"
        return 0
    fi
    local build_dir
    build_dir=$(mktemp -d) || return 0
    cat > "$build_dir/nx_xdp.c" << 'NXXDP_EOF'
/*
 * nx_xdp — NexoShield emergency XDP shield (DPI upgrade Phase 3).
 *
 * Dormant line-rate relief for volumetric SYN floods. The daemon
 * attaches this program ONLY while the host is drowning (syncookie
 * storms / backlog overflows / extreme SYN arrival rates) and
 * detaches it when calm returns. It drops NEW connection attempts
 * (pure SYNs) from sources present in the ban LPM tries — the same
 * ban state the nftables backend enforces at netfilter — before
 * conntrack allocation, which is the resource a SYN flood actually
 * exhausts. Established traffic and non-SYN packets pass untouched;
 * exempt sources (self / whitelist / Cloudflare) are checked first
 * and always pass: FR-1/FR-2 hold at line rate too.
 *
 * Ban values are monotonic-clock expiry stamps (ns), mirroring the
 * timed nft sets; an expired entry passes (the daemon's state files
 * remain the source of truth and re-sync while attached).
 *
 * Counters (per-CPU): 0 = SYNs seen, 1 = drops, 2 = exempt passes.
 *
 * Built only when clang + libbpf headers exist at install time.
 * Known limits: no VLAN tag parsing (cloud NICs are untagged);
 * XDP_PASS for anything unparsable — fail-open by design.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct lpm4_key { __u32 prefixlen; __u32 addr; };
struct lpm6_key { __u32 prefixlen; __u8 addr[16]; };

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm4_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ban4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm6_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ban6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm4_key);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} exempt4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm6_key);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} exempt6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} counters SEC(".maps");

enum { C_SYN = 0, C_DROP = 1, C_EXEMPT_PASS = 2 };

static __always_inline void bump(__u32 k)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &k);
    if (v) (*v)++;
}

SEC("xdp")
int nx_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    __u16 proto = bpf_ntohs(eth->h_proto);
    __u64 now = bpf_ktime_get_ns();

    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        if (tcp->syn) bump(C_SYN);
        if (!tcp->syn || tcp->ack) return XDP_PASS;
        struct lpm4_key ek = { .prefixlen = 32, .addr = ip->saddr };
        if (bpf_map_lookup_elem(&exempt4, &ek)) { bump(C_EXEMPT_PASS); return XDP_PASS; }
        struct lpm4_key bk = { .prefixlen = 32, .addr = ip->saddr };
        __u64 *exp = bpf_map_lookup_elem(&ban4, &bk);
        if (exp && *exp > now) { bump(C_DROP); return XDP_DROP; }
        return XDP_PASS;
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        if (ip6->nexthdr != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        if (tcp->syn) bump(C_SYN);
        if (!tcp->syn || tcp->ack) return XDP_PASS;
        struct lpm6_key ek = { .prefixlen = 128 };
        __builtin_memcpy(ek.addr, &ip6->saddr, 16);
        if (bpf_map_lookup_elem(&exempt6, &ek)) { bump(C_EXEMPT_PASS); return XDP_PASS; }
        struct lpm6_key bk = { .prefixlen = 128 };
        __builtin_memcpy(bk.addr, &ip6->saddr, 16);
        __u64 *exp = bpf_map_lookup_elem(&ban6, &bk);
        if (exp && *exp > now) { bump(C_DROP); return XDP_DROP; }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
NXXDP_EOF
    cat > "$build_dir/nx-xdp-loader.c" << 'NXLOADER_EOF'
/*
 * nx-xdp — loader/sync tool for the NexoShield XDP shield (Phase 3).
 *
 *   nx-xdp load <iface> <obj.o>   attach (native, else generic), pin maps
 *   nx-xdp unload <iface>         detach + unpin
 *   nx-xdp sync-bans <file>       lines: <ip|cidr> <ttl_seconds>
 *   nx-xdp sync-exempt <file>     lines: <ip|cidr>
 *   nx-xdp stats                  syn= drops= exempt_pass= (per-CPU sums)
 *   nx-xdp check <bans> <exempt>  parse-only validation (no BPF touched)
 *
 * Maps are pinned under /sys/fs/bpf/nexoshield so the daemon can
 * re-sync ban state while the program is attached without holding
 * the object open. Ban values are CLOCK_MONOTONIC nanosecond expiry
 * stamps, exactly what the XDP program compares against
 * bpf_ktime_get_ns().
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PIN_DIR "/sys/fs/bpf/nexoshield"

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── sync-file parsing (shared by check + sync; unit-testable) ── */
typedef struct {
    int family;              /* AF_INET / AF_INET6 */
    int prefix;              /* 0..32 / 0..128 */
    uint8_t addr[16];
    uint64_t ttl;            /* bans only */
} Entry;

static int parse_cidr(const char *text, int *family, int *prefix, uint8_t *addr)
{
    char buf[128];
    snprintf(buf, sizeof buf, "%s", text);
    char *slash = strchr(buf, '/');
    int pfx = -1;
    if (slash) {
        /* L1: the old atoi() accepted junk - "/abc" became /0 (a
         * whole-Internet ban), "/-1" silently became /32, and
         * "/32junk" passed. A prefix must be all digits in range;
         * anything else is a bad line, not a guessed entry. */
        char *end = NULL;
        long v = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || v < 0) return -1;
        *slash = 0;
        pfx = (int)v;
    }
    if (strchr(buf, ':')) {
        if (inet_pton(AF_INET6, buf, addr) != 1) return -1;
        if (pfx < 0) pfx = 128;
        if (pfx > 128) return -1;
        *family = AF_INET6;
    } else {
        if (inet_pton(AF_INET, buf, addr) != 1) return -1;
        if (pfx < 0) pfx = 32;
        if (pfx > 32) return -1;
        *family = AF_INET;
    }
    *prefix = pfx;
    return 0;
}

/* Returns entry count, or -1 with *badline set (1-based). */
static int parse_file(const char *path, int with_ttl, Entry *out, int max, int *badline)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[256], cidr[128], extra[64];
    unsigned long long ttl;
    int n = 0, ln = 0;
    while (fgets(line, sizeof line, fp)) {
        ln++;
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        int got = with_ttl ? sscanf(line, " %127s %llu %63s", cidr, &ttl, extra)
                           : sscanf(line, " %127s %63s", cidr, extra);
        if (got <= 0) continue;                    /* blank/comment */
        if (with_ttl && got != 2) { *badline = ln; fclose(fp); return -1; }
        if (!with_ttl && got != 1) { *badline = ln; fclose(fp); return -1; }
        if (n >= max) { *badline = ln; fclose(fp); return -1; }
        Entry *e = &out[n];
        memset(e, 0, sizeof *e);
        if (parse_cidr(cidr, &e->family, &e->prefix, e->addr) != 0) {
            *badline = ln; fclose(fp); return -1;
        }
        e->ttl = with_ttl ? ttl : 0;
        n++;
    }
    fclose(fp);
    return n;
}

static int cmd_check(const char *bans_path, const char *exempt_path)
{
    static Entry entries[65536];
    int bad = 0;
    int nb = parse_file(bans_path, 1, entries, 65536, &bad);
    if (nb < 0) { fprintf(stderr, "check: %s: invalid (line %d or unreadable)\n", bans_path, bad); return 1; }
    int ne = parse_file(exempt_path, 0, entries, 65536, &bad);
    if (ne < 0) { fprintf(stderr, "check: %s: invalid (line %d or unreadable)\n", exempt_path, bad); return 1; }
    printf("bans=%d exempt=%d\n", nb, ne);
    return 0;
}

/* ── map helpers ── */
static int open_pinned(const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", PIN_DIR, name);
    int fd = bpf_obj_get(path);
    if (fd < 0) fprintf(stderr, "nx-xdp: cannot open pinned map %s (shield attached?)\n", path);
    return fd;
}

static void clear_map(int fd, size_t key_size)
{
    uint8_t *key = calloc(1, key_size), *next = calloc(1, key_size);
    if (!key || !next) { free(key); free(next); return; }
    int first = 1;
    /* collect-then-delete: deleting while iterating an LPM trie is unsafe */
    size_t cap = 1024, cnt = 0;
    uint8_t *all = malloc(cap * key_size);
    if (!all) { free(key); free(next); return; }
    while (bpf_map_get_next_key(fd, first ? NULL : key, next) == 0) {
        memcpy(key, next, key_size);
        first = 0;
        if (cnt == cap) { cap *= 2; all = realloc(all, cap * key_size); if (!all) { free(key); free(next); return; } }
        memcpy(all + cnt * key_size, next, key_size);
        cnt++;
    }
    for (size_t i = 0; i < cnt; i++) bpf_map_delete_elem(fd, all + i * key_size);
    free(key); free(next); free(all);
}

static int sync_map(const char *map_name, const Entry *entries, int n, int is_ban, size_t key_size)
{
    int fd = open_pinned(map_name);
    if (fd < 0) return 1;
    clear_map(fd, key_size);
    uint64_t now = mono_ns();
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const Entry *e = &entries[i];
        uint8_t key[20];
        memset(key, 0, sizeof key);
        uint32_t pfx = (uint32_t)e->prefix;
        memcpy(key, &pfx, 4);
        if (e->family == AF_INET) memcpy(key + 4, e->addr, 4);
        else memcpy(key + 4, e->addr, 16);
        if (is_ban) {
            uint64_t exp = now + e->ttl * 1000000000ULL;
            if (bpf_map_update_elem(fd, key, &exp, BPF_ANY) != 0) rc = 1;
        } else {
            uint32_t one = 1;
            if (bpf_map_update_elem(fd, key, &one, BPF_ANY) != 0) rc = 1;
        }
    }
    close(fd);
    return rc;
}

static int cmd_sync(const char *path, int is_ban)
{
    static Entry entries[65536];
    int bad = 0;
    int n = parse_file(path, is_ban, entries, 65536, &bad);
    if (n < 0) { fprintf(stderr, "nx-xdp: %s invalid (line %d)\n", path, bad); return 1; }
    int rc = 0, v4 = 0, v6 = 0;
    static Entry fam4[65536], fam6[65536];
    for (int i = 0; i < n; i++)
        if (entries[i].family == AF_INET) fam4[v4++] = entries[i];
        else fam6[v6++] = entries[i];
    if (sync_map(is_ban ? "ban4" : "exempt4", fam4, v4, is_ban, 8) != 0) rc = 1;
    if (sync_map(is_ban ? "ban6" : "exempt6", fam6, v6, is_ban, 20) != 0) rc = 1;
    if (!rc) printf("synced %s: %d entries\n", is_ban ? "bans" : "exempt", n);
    return rc;
}

static int cmd_load(const char *iface, const char *obj_path)
{
    unsigned ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "nx-xdp: no such interface %s\n", iface); return 1; }
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) { fprintf(stderr, "nx-xdp: cannot open %s\n", obj_path); return 1; }
    if (bpf_object__load(obj) != 0) { fprintf(stderr, "nx-xdp: cannot load %s\n", obj_path); return 1; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "nx_xdp_prog");
    if (!prog) { fprintf(stderr, "nx-xdp: program not found in %s\n", obj_path); return 1; }
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    const char *mode = "native";
    if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_DRV_MODE, NULL) != 0) {
        if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL) != 0) {
            fprintf(stderr, "nx-xdp: attach failed on %s (native and generic)\n", iface);
            return 1;
        }
        mode = "generic";
    }
    mkdir(PIN_DIR, 0755);
    const char *names[5] = { "ban4", "ban6", "exempt4", "exempt6", "counters" };
    for (int i = 0; i < 5; i++) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, names[i]);
        if (!m) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", PIN_DIR, names[i]);
        unlink(path);
        bpf_map__pin(m, path);
    }
    printf("attached %s (%s mode)\n", iface, mode);
    return 0;
}

static int cmd_unload(const char *iface)
{
    unsigned ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "nx-xdp: no such interface %s\n", iface); return 1; }
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    const char *names[5] = { "ban4", "ban6", "exempt4", "exempt6", "counters" };
    for (int i = 0; i < 5; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", PIN_DIR, names[i]);
        unlink(path);
    }
    rmdir(PIN_DIR);
    printf("detached %s\n", iface);
    return 0;
}

static int cmd_stats(void)
{
    int fd = open_pinned("counters");
    if (fd < 0) return 1;
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 1) cpus = 1;
    uint64_t *vals = calloc((size_t)cpus, sizeof(uint64_t));
    if (!vals) { close(fd); return 1; }
    uint64_t sums[3] = {0, 0, 0};
    for (uint32_t k = 0; k < 3; k++) {
        if (bpf_map_lookup_elem(fd, &k, vals) == 0)
            for (int c = 0; c < cpus; c++) sums[k] += vals[c];
    }
    printf("syn=%llu drops=%llu exempt_pass=%llu\n",
           (unsigned long long)sums[0], (unsigned long long)sums[1],
           (unsigned long long)sums[2]);
    free(vals);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (argc >= 2 && !strcmp(argv[1], "check") && argc == 4) return cmd_check(argv[2], argv[3]);
    if (argc >= 2 && !strcmp(argv[1], "sync-bans") && argc == 3) return cmd_sync(argv[2], 1);
    if (argc >= 2 && !strcmp(argv[1], "sync-exempt") && argc == 3) return cmd_sync(argv[2], 0);
    if (argc >= 2 && !strcmp(argv[1], "load") && argc == 4) return cmd_load(argv[2], argv[3]);
    if (argc >= 2 && !strcmp(argv[1], "unload") && argc == 3) return cmd_unload(argv[2]);
    if (argc >= 2 && !strcmp(argv[1], "stats") && argc == 2) return cmd_stats();
    fprintf(stderr, "usage: nx-xdp load <iface> <obj> | unload <iface> | sync-bans <file> | sync-exempt <file> | stats | check <bans> <exempt>\n");
    return 2;
}
NXLOADER_EOF
    mkdir -p /usr/local/lib
    if clang -O2 -target bpf -c "$build_dir/nx_xdp.c" -o "$build_dir/nx_xdp.o" 2>/dev/null \
       && cc -O2 -o "$build_dir/nx-xdp" "$build_dir/nx-xdp-loader.c" -lbpf 2>/dev/null \
       && nx_install_binary "$build_dir/nx_xdp.o" /usr/local/lib/nx_xdp.o 644 \
       && nx_install_binary "$build_dir/nx-xdp" /usr/local/bin/nx-xdp 755; then
        success "XDP emergency shield: built (dormant; attaches only under flood pressure)"
    else
        # A failed rebuild leaves any previous working install
        # untouched (the old code deleted it - an update could
        # destroy a working shield).
        warn "XDP shield: build failed - feature stays dormant (previous install kept)"
    fi
    rm -rf "$build_dir"
}
setup_tc() {
    command -v tc >/dev/null 2>&1 || {
        warn "tc (iproute2) not installed - skipping bandwidth control"
        return
    }
    info "Configuring tc bandwidth control..."

    # Remove old config (record what was there first - BUG-032: never
    # silently destroy a pre-existing qdisc without a trace)
    mkdir -p /etc/antiddos
    tc qdisc show dev "$MAIN_IF" 2>/dev/null | head -1 > /etc/antiddos/tc-qdisc-before.txt || true
    tc qdisc del dev "$MAIN_IF" root 2>/dev/null || true

    # R-21 (deep review 2026-10-23): HTB only shapes when its rates
    # are the real bottleneck. The tree was hardcoded to 1 Gbit - on a
    # 200 Mbit VPS the qdisc never engages and the "100 Mbit throttle"
    # is fiction. Scale the tree to the detected link speed, keeping
    # the designed ratios (default S/2, throttle S/10, hard S/20);
    # at 1 Gbit the values are exactly the historical ones.
    local LINK_MBPS=1000 _spd=""
    _spd=$(cat "/sys/class/net/$MAIN_IF/speed" 2>/dev/null || echo "")
    case "$_spd" in ''|*[!0-9]*) _spd="" ;; esac
    if [ -n "$_spd" ] && [ "$_spd" -ge 50 ] && [ "$_spd" -lt 1000 ]; then
        LINK_MBPS="$_spd"
        info "tc: link speed ${LINK_MBPS}Mbps - shaping tree scaled to match"
    fi
    local R_ROOT="${LINK_MBPS}mbit" R_DEF="$(( LINK_MBPS / 2 ))mbit" \
          R_SOFT="$(( LINK_MBPS / 10 ))mbit" R_HARD="$(( LINK_MBPS / 20 ))mbit"

    # HTB root — default class 1:20 (normal non-CF)
    tc qdisc add dev "$MAIN_IF" root handle 1: htb default 20
    tc class add dev "$MAIN_IF" parent 1: classid 1:1  htb rate $R_ROOT ceil $R_ROOT
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:10 htb rate $R_ROOT  ceil $R_ROOT  burst 25Mb    # CF unlimited
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:20 htb rate $R_DEF ceil $R_DEF burst 6400Kb # normal
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:30 htb rate $R_SOFT ceil $R_SOFT burst 1280Kb # throttled
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:40 htb rate $R_HARD  ceil $R_HARD  burst 640Kb  # hard-throttled

    # BUG-001 fix: this qdisc sits on EGRESS. A client's packets leave
    # TOWARDS the client, so the client is the DESTINATION. All filters
    # classify by ip dst; "match ip src <client>" could never match.
    # CF IPs → class 1:10 (match by DST IP)
    local HANDLE=10
    for CF in "${CF_RANGES[@]}"; do
        tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip dst "$CF" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done

    # CF IPv6 → class 1:10 (Wave 9: protocol ip6 / match ip6 dst)
    for CF6 in "${CF6_RANGES[@]}"; do
        tc filter add dev "$MAIN_IF" parent 1: protocol ip6 prio $HANDLE \
            u32 match ip6 dst "$CF6" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done

    # Server own IPs → class 1:10 (E-4: exhaustive list, like the
    # firewall steps - public-only left private self traffic shaped)
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip dst "$SIP/32" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done < <(list_self_ips_all | grep -v '^127\.0\.0\.1$')

    # User whitelist → class 1:10 (unlimited, same as CF/self)
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
                u32 match ip dst "$WIP" flowid 1:10 2>/dev/null || true
            HANDLE=$((HANDLE + 1))
        done < "$WHITELIST_FILE"
    fi

    # HIGH-2: re-apply live daemon throttles (BUG-022). The qdisc
    # delete above just destroyed every throttle filter the daemon
    # recorded - the boot script re-applies them, but the LIVE path
    # never did, so every proxy Install/Update and every whitelist
    # change silently gave throttled attackers full speed until the
    # daemon restarted. Same loop as the boot script, reading the
    # live file first: it is fresher than the mirror, which lags up
    # to one daemon cycle, and a stale mirror entry must never
    # resurrect a filter the daemon already replaced.
    while read -r TIP TPRIO _TS TBAND; do
        [ -z "$TIP" ] && continue
        TFLOW=1:30; [ "$TBAND" = "hard" ] && TFLOW=1:40
        case "$TIP" in
            *:*) tc filter add dev "$MAIN_IF" parent 1: protocol ip6 prio $TPRIO \
                     u32 match ip6 dst "$TIP" flowid $TFLOW 2>/dev/null || true ;;
            *)   tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $TPRIO \
                     u32 match ip dst "$TIP/32" flowid $TFLOW 2>/dev/null || true ;;
        esac
    done < <(cat "${THROTTLE_LIST:-/run/nexoshield/autoban_throttle}" /etc/antiddos/throttled.list 2>/dev/null | awk '!seen[$1]++')

    # ── WARP / WireGuard awareness ──────────────────────────
    if ip link show 2>/dev/null | grep -qE '^\s*[0-9]+:\s+(wg|utm|warp)[0-9]*[:@]'; then
        warn "WARP/WireGuard tunnel detected — tc shapes '${MAIN_IF}' (default route)."
        warn "Tunneled (WARP) traffic egresses via the tunnel device and is NOT shaped; inbound anti-DDoS (iptables) still applies."
    fi

    success "tc: CF=unlimited ($R_ROOT), others=$R_DEF, throttled=$R_SOFT, hard=$R_HARD"

    # Save to persistent script
    cat > /opt/proxy-manager/tc-setup.sh << 'TCEOF'
#!/bin/bash
# TC persistent setup — auto-generated
IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
IF="${IF:-eth0}"
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi
list_self_ips() {
    { ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+'
      hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    } | sort -u | grep -v '^$'
}

# list_self_ips6 - every local IPv6 address (incl. ::1), one per line.
list_self_ips6() {
    { ip -6 addr show 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+'
      echo "::1"
    } | sort -u | grep -v '^$'
}

# ── Public-IP discovery for NAT / cloud servers ─────────────────
# On cloud VMs (Azure, most NAT setups) the server's public IPv4
# exists only in the provider's NAT - it is on NO interface, so
# list_self_ips can never see it, yet it is unmistakably one of the
# server's own addresses (FR-2). Discovery asks the cloud metadata
# service (link-local, no internet involved); only when no metadata
# service answers does it fall back to an external echo service.
# Every candidate passes nx_is_public_ipv4: metadata/echo replies
# are untrusted input, and a private/documentation/garbage answer
# must never widen the immune set.
NX_PUBLIC_IPS_FILE="${NX_PUBLIC_IPS_FILE:-/etc/antiddos/public-ips.list}"

nx_is_public_ipv4() {
    local ip="${1:-}" o1 o2 o3 o4 extra _o
    case "$ip" in *[!0-9.]*) return 1 ;; esac
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for _o in "$o1" "$o2" "$o3" "$o4"; do
        case "$_o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_o}" -le 3 ] || return 1
        (( 10#$_o <= 255 )) || return 1
    done
    case "$o1" in
        0|10|127) return 1 ;;
        100) [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 1 ;;
        169) [ "$o2" = 254 ] && return 1 ;;
        172) [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 1 ;;
        192) [ "$o2" = 168 ] && return 1
             { [ "$o2" = 0 ] && { [ "$o3" = 0 ] || [ "$o3" = 2 ]; }; } && return 1 ;;
        198) case "$o2" in 18|19|51) return 1 ;; esac ;;
        203) { [ "$o2" = 0 ] && [ "$o3" = 113 ]; } && return 1 ;;
    esac
    [ "$o1" -ge 224 ] && return 1
    return 0
}

nx_metadata_public_ips() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _tok _base="http://169.254.169.254"
    # Azure IMDS (first two addresses on the primary NIC)
    for _idx in 0 1; do
        _ip=$(curl -s -m 2 -H "Metadata: true" \
            "$_base/metadata/instance/network/interface/0/ipv4/ipAddress/$_idx/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
        nx_is_public_ipv4 "$_ip" && echo "$_ip"
    done
    # AWS EC2 IMDS (token first, plain fallback)
    _tok=$(curl -s -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "$_base/latest/api/token" 2>/dev/null)
    if [ -n "$_tok" ]; then
        _ip=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $_tok" \
            "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    else
        _ip=$(curl -s -m 2 "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    fi
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # GCP
    _ip=$(curl -s -m 2 -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # DigitalOcean
    _ip=$(curl -s -m 2 "$_base/metadata/v1/interfaces/public/0/ipv4/address" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # Hetzner Cloud
    _ip=$(curl -s -m 2 "$_base/hetzner/v1/metadata/public-ipv4" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    return 0
}

nx_external_public_ip() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _url
    for _url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me/ip"; do
        _ip=$(curl -s -m 3 "$_url" 2>/dev/null | tr -d ' \r\n')
        nx_is_public_ipv4 "$_ip" && { echo "$_ip"; return 0; }
    done
    return 0
}

# Echo the server's public IPv4s that are NOT on any interface
# (metadata first; external echo only as a last resort).
discover_public_ips() {
    local _found _ip
    _found=$(nx_metadata_public_ips | sort -u)
    [ -z "$_found" ] && _found=$(nx_external_public_ip)
    for _ip in $_found; do
        list_self_ips | grep -qxF "$_ip" || echo "$_ip"
    done
}

# Refresh the cache file; a failed/empty discovery NEVER wipes a
# previously discovered set (an offline reinstall must not disarm
# the immunity). Prints the discovered addresses when any exist.
nx_refresh_public_ips_cache() {
    local _found
    _found=$(discover_public_ips)
    if [ -n "$_found" ]; then
        mkdir -p "$(dirname "$NX_PUBLIC_IPS_FILE")" 2>/dev/null || true
        printf '%s\n' "$_found" > "$NX_PUBLIC_IPS_FILE.tmp" 2>/dev/null && \
            mv "$NX_PUBLIC_IPS_FILE.tmp" "$NX_PUBLIC_IPS_FILE" 2>/dev/null || true
        printf '%s\n' "$_found"
    elif [ -f "$NX_PUBLIC_IPS_FILE" ]; then
        cat "$NX_PUBLIC_IPS_FILE"
    fi
}

# list_self_ips_all - interface addresses PLUS the cached
# discovered public IPs. This is the feed every enforcement layer
# uses for "the server's own addresses" (FR-2 complete: local,
# private, secondary AND NAT-public).
list_self_ips_all() {
    { list_self_ips
      if [ -r "$NX_PUBLIC_IPS_FILE" ]; then
          grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$NX_PUBLIC_IPS_FILE" 2>/dev/null
      fi
    } | sort -u | grep -v '^$'
}
tc qdisc del dev "$IF" root 2>/dev/null || true
tc qdisc add dev "$IF" root handle 1: htb default 20
tc class add dev "$IF" parent 1: classid 1:1  htb rate 1gbit ceil 1gbit
tc class add dev "$IF" parent 1:1 classid 1:10 htb rate 1gbit  ceil 1gbit  burst 25Mb
tc class add dev "$IF" parent 1:1 classid 1:20 htb rate 500mbit ceil 500mbit burst 6400Kb
tc class add dev "$IF" parent 1:1 classid 1:30 htb rate 100mbit ceil 100mbit burst 1280Kb
tc class add dev "$IF" parent 1:1 classid 1:40 htb rate 50mbit  ceil 50mbit  burst 640Kb
H=10
for CF in "${CF_RANGES[@]}"; do
    tc filter add dev "$IF" parent 1: protocol ip prio $H \
        u32 match ip dst "$CF" flowid 1:10 2>/dev/null || true; H=$((H+1))
done
# CF IPv6 ranges (Wave 9), loaded from the runtime data file
if [ -f /etc/antiddos/cloudflare-ipv6.list ]; then
    while IFS= read -r CF6; do
        [ -z "$CF6" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip6 prio $H \
            u32 match ip6 dst "$CF6" flowid 1:10 2>/dev/null || true; H=$((H+1))
    done < /etc/antiddos/cloudflare-ipv6.list
fi
for SIP in $(list_self_ips_all 2>/dev/null | grep -v '^127\.0\.0\.1$'); do
    tc filter add dev "$IF" parent 1: protocol ip prio $H \
        u32 match ip dst "$SIP/32" flowid 1:10 2>/dev/null || true; H=$((H+1))
done
if [ -f /etc/antiddos/whitelist.list ]; then
    while IFS= read -r WIP; do
        WIP="${WIP%%#*}"; WIP="${WIP// /}"
        [ -z "$WIP" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $H \
            u32 match ip dst "$WIP" flowid 1:10 2>/dev/null || true; H=$((H+1))
    done < /etc/antiddos/whitelist.list
fi
# Re-apply live daemon throttles (BUG-022): rebuilding the qdisc must not
# silently drop enforcement state recorded by the auto-ban daemon.
if [ -f /etc/antiddos/throttled.list ]; then
    while read -r TIP TPRIO _TS TBAND; do
        [ -z "$TIP" ] && continue
        TFLOW=1:30; [ "$TBAND" = "hard" ] && TFLOW=1:40
        case "$TIP" in
            *:*) tc filter add dev "$IF" parent 1: protocol ip6 prio $TPRIO \
                     u32 match ip6 dst "$TIP" flowid $TFLOW 2>/dev/null || true ;;
            *)   tc filter add dev "$IF" parent 1: protocol ip prio $TPRIO \
                     u32 match ip dst "$TIP/32" flowid $TFLOW 2>/dev/null || true ;;
        esac
    done < /etc/antiddos/throttled.list
fi
TCEOF
    chmod +x /opt/proxy-manager/tc-setup.sh
    # R-21: the persistent script must use the same scaled rates.
    if [ "$LINK_MBPS" -lt 1000 ]; then
        sed -i -E \
            -e "s/rate 1gbit[[:space:]]+ceil 1gbit/rate ${R_ROOT} ceil ${R_ROOT}/g" \
            -e "s/rate 500mbit[[:space:]]+ceil 500mbit/rate ${R_DEF} ceil ${R_DEF}/g" \
            -e "s/rate 100mbit[[:space:]]+ceil 100mbit/rate ${R_SOFT} ceil ${R_SOFT}/g" \
            -e "s/rate 50mbit[[:space:]]+ceil 50mbit/rate ${R_HARD} ceil ${R_HARD}/g" \
            /opt/proxy-manager/tc-setup.sh
    fi

    # systemd service for tc persistence
    cat > /etc/systemd/system/tc-proxy-limit.service << EOF
[Unit]
Description=TC bandwidth shaping (proxy server)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/proxy-manager/tc-setup.sh $MAIN_IF
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    # if-up.d for NetworkManager
    mkdir -p /etc/network/if-up.d
    ln -sf /opt/proxy-manager/tc-setup.sh /etc/network/if-up.d/tc-proxy-limit 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable tc-proxy-limit.service >/dev/null 2>&1 || true
    success "tc persistence: systemd + if-up.d configured"
}

# ════════════════════════════════════════════════
# Persist iptables on reboot
# ════════════════════════════════════════════════
setup_persistence() {
    info "Setting up iptables persistence..."

    # Debian/Ubuntu: iptables-persistent
    if command -v apt-get >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent 2>/dev/null || true
        save_static_rules /etc/iptables/rules.v4
    fi

    # Restore script
    RESTORE_SCRIPT="/etc/antiddos/restore-rules.sh"
    cat > "$RESTORE_SCRIPT" << 'EOF'
#!/bin/bash
RULES="/etc/antiddos/iptables-antiddos.rules"
[ -f "$RULES" ] && iptables-restore < "$RULES" 2>/dev/null || true
[ -f /etc/antiddos/ip6tables-antiddos.rules ] && \
    ip6tables-restore < /etc/antiddos/ip6tables-antiddos.rules 2>/dev/null || true
[ -f /etc/sysctl.d/98-antiddos-hardening.conf ] && \
    sysctl -p /etc/sysctl.d/98-antiddos-hardening.conf >/dev/null 2>&1 || true
EOF
    chmod +x "$RESTORE_SCRIPT"

    # systemd service
    cat > /etc/systemd/system/antiddos-restore.service << EOF
[Unit]
Description=Restore Anti-DDoS iptables rules on boot
After=network.target
Before=3proxy.service auto-ban.service

[Service]
Type=oneshot
ExecStart=$RESTORE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable antiddos-restore.service >/dev/null 2>&1
    success "iptables persistence: enabled (antiddos-restore)"

    # Log rotation (BUG-045): the daemon logs every cycle's events with
    # no rotation - an unbounded /var/log/auto-ban.log on a busy box.
    cat > /etc/logrotate.d/nexoshield << 'LREOF'
/var/log/auto-ban.log /var/log/antiddos.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    copytruncate
}
LREOF
    success "logrotate: /etc/logrotate.d/nexoshield"
}

# ════════════════════════════════════════════════
# Status
# ════════════════════════════════════════════════
show_status() {
    sep; echo -e "  ${CYAN}${BOLD}Anti-DDoS Status${NC}"; sep

    echo -e "  ${DIM}iptables:${NC}"
    INPUT_RULES=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep -c "^[0-9]" || echo 0)
    CF_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "cf_whitelist" || echo 0)
    BANNED_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "auto-ban" || echo 0)
    echo -e "    INPUT rules  : ${WHITE}$INPUT_RULES${NC}  (CF whitelist: $CF_RULES, auto-ban: $BANNED_RULES)"

    if [ -d /proc/net/ipt_hashlimit ]; then
        echo -e "  ${DIM}hashlimit tables:${NC}"
        ls /proc/net/ipt_hashlimit 2>/dev/null | while read -r t; do
            COUNT=$(wc -l < "/proc/net/ipt_hashlimit/$t" 2>/dev/null || echo 0)
            echo -e "    ${CYAN}$t${NC}: ${WHITE}$COUNT IPs${NC}"
        done
    fi

    if [ -f /proc/net/nf_conntrack ]; then
        CURR=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo 0)
        CURR="${CURR//[^0-9]/}"; CURR="${CURR:-0}"
        MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 1)
        MAX="${MAX//[^0-9]/}"; MAX="${MAX:-1}"
        if [ "$MAX" -gt 0 ]; then
            PCT=$(awk "BEGIN{printf \"%.0f\", ${CURR}*100/${MAX}}")
        else
            PCT="?"
        fi
        echo -e "  ${DIM}conntrack:${NC} ${WHITE}$CURR${NC} / ${WHITE}$MAX${NC} (${PCT}%)"
    fi

    if command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "  ${DIM}fail2ban:${NC}"
        fail2ban-client status 2>/dev/null | grep "Jail list" | \
            sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r jail; do
            [ -z "$jail" ] && continue
            BANNED=$(fail2ban-client status "$jail" 2>/dev/null | \
                grep "Banned IP list" | sed 's/.*://;s/^ *//')
            COUNT=$(echo "$BANNED" | tr ' ' '\n' | grep -c '\.' 2>/dev/null | tr -d '\n' || echo 0)
            printf "    %-25s %s\n" "$jail:" "$COUNT IPs banned"
        done
    fi

    echo -e "  ${DIM}auto-ban service:${NC}"
    if systemctl is-active auto-ban >/dev/null 2>&1; then
        echo -e "    ${GREEN}● Running${NC}"
        BANS=$(grep -c "BANNED:" /var/log/auto-ban.log 2>/dev/null || echo 0)
        echo -e "    Total bans: $BANS"
        echo -e "    ${DIM}Last entries:${NC}"
        tail -5 /var/log/auto-ban.log 2>/dev/null | while read -r line; do
            echo "    $line"
        done
    else
        echo -e "    ${RED}○ Not running${NC}"
    fi

    echo -e "  ${DIM}tc bandwidth:${NC}"
    IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -n "$IF" ] && tc class show dev "$IF" 2>/dev/null | grep -q "1:10"; then
        echo -e "    ${GREEN}● Active${NC} (CF=unlimited, others=500Mbps, throttled=100Mbps)"
    else
        echo -e "    ${YELLOW}○ Not configured${NC}"
    fi

    echo -e "  ${DIM}kernel key params:${NC}"
    for P in net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter \
              net.ipv4.tcp_keepalive_time \
              net.netfilter.nf_conntrack_tcp_timeout_established \
              net.netfilter.nf_conntrack_tcp_timeout_syn_recv; do
        V=$(sysctl -n "$P" 2>/dev/null || echo "N/A")
        printf "    ${DIM}%-52s${NC} %s\n" "$P" "$V"
    done

    sep
    # shellcheck disable=SC1090  # STATE_FILE is a fixed path held in a variable
    [ -f "$STATE_FILE" ] && . "$STATE_FILE" 2>/dev/null && \
        echo -e "  ${GREEN}✓ Installed${NC} - $(grep '^DATE=' "$STATE_FILE" | cut -d= -f2-)" || \
        echo -e "  ${YELLOW}○ Not installed${NC}"
    sep
}

# ════════════════════════════════════════════════
# Remove all rules
# ════════════════════════════════════════════════
# nx_delete_matching <table> <chain> <pattern> — delete every rule whose
# `iptables -S` text matches the pattern, by rule NUMBER recomputed
# after each delete (spec-based deletion breaks on quoted arguments,
# BUG-031/063). Top-level (F1): it used to be nested inside
# remove_rules(), so flush_autobans() — which calls it directly —
# aborted with "command not found" in a fresh process under set -e.
nx_delete_matching() {
    local _t="$1" _c="$2" _p="$3" _n
    while true; do
        # The -- matters: patterns like '--comment "auto-ban"' or
        # '-j CT' start with a dash, and without it grep parses
        # them as options, errors, and nothing is ever deleted
        # (found by the v3.18.0 flush test - the old '-j CT' call
        # in remove_rules was silently dead for the same reason).
        _n=$(iptables -t "$_t" -S "$_c" 2>/dev/null | grep -nE -- "$_p" | head -1 | cut -d: -f1 || true)
        [ -z "$_n" ] && break
        # -S line 1 is the chain policy (-P): rule number = line - 1
        iptables -t "$_t" -D "$_c" $((_n - 1)) 2>/dev/null || break
    done
}

remove_rules() {
    sep; echo -e "  ${RED}Removing Anti-DDoS rules...${NC}"
    # CONF_R can be pre-set by --remove-force to skip prompt
    if [[ "${CONF_R:-}" != "y" && "${CONF_R:-}" != "Y" ]]; then
        printf '%s' "  Are you sure? This will remove ALL protection. (y/N): " >/dev/tty; read -r CONF_R </dev/tty || CONF_R=""
    fi
    [[ "$CONF_R" != "y" && "$CONF_R" != "Y" ]] && echo -e "  ${DIM}Cancelled.${NC}" && return

    # Phase 2a: the event counter leaves with the rest of the daemon.
    systemctl disable --now nexoshield-countd.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/nexoshield-countd.service /usr/local/bin/nxcountd 2>/dev/null || true
    # Phase 3: detach + remove the XDP shield if it was ever built.
    if [ -x /usr/local/bin/nx-xdp ]; then
        _nx_if=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
        [ -n "$_nx_if" ] && /usr/local/bin/nx-xdp unload "$_nx_if" >/dev/null 2>&1 || true
    fi
    rm -f /usr/local/bin/nx-xdp /usr/local/lib/nx_xdp.o 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true

    # Sysctl (note: removing the file does not reset values already
    # loaded into the running kernel - they reset at reboot)
    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true
    success "Kernel hardening: file removed (running values reset at reboot)"

    # iptables — delete by matching the `iptables -S` text (BUG-031).
    # The old code matched `iptables -L` output, which never renders rule
    # comments, so every comment-tagged rule (all 753 CF ACCEPTs, the
    # whitelist, ...) silently survived a "full removal"; several
    # untagged rules (loopback, ESTABLISHED accept, flag scans) survived
    # too. Deletion is by rule NUMBER recomputed from -S after each
    # delete - spec-based deletion breaks on quoted arguments.
    local RULE_PAT='hashlimit|SYNPROXY|connlimit|cf_whitelist|auto-ban|subnet-ban|self_whitelist|user_whitelist|nx_connlimit|--ctstate INVALID|--tcp-flags| -f -j DROP|! --syn|-i lo|--ctstate ESTABLISHED,RELATED -j ACCEPT'
    nx_delete_matching filter INPUT "$RULE_PAT"
    nx_delete_matching filter FORWARD "$RULE_PAT"

    # IPv6 cleanup (Wave 9): same pattern set against ip6tables
    nx_delete_matching6 INPUT "$RULE_PAT"
    nx_delete_matching6 FORWARD "$RULE_PAT"
    rm -f /etc/antiddos/ip6tables-antiddos.rules 2>/dev/null || true

    # raw table: delete ONLY our own ACCEPTs - those whose source is a CF
    # range, a self IP or a whitelist entry. The old loop's bare "ACCEPT"
    # token deleted other software's raw PREROUTING rules (BUG-031).
    local _snap _del="" _idx=0 _line _src _ours _r _w _n
    _snap=$(iptables -t raw -S PREROUTING 2>/dev/null || true)
    while IFS= read -r _line; do
        _idx=$((_idx + 1))
        case "$_line" in *'-j ACCEPT'*) : ;; *) continue ;; esac
        _src=$(printf '%s' "$_line" | grep -oP '(?<=-s )[0-9./]+' || true)
        [ -z "$_src" ] && continue
        _ours=0
        for _r in "${CF_RANGES[@]}"; do [ "$_src" = "$_r" ] && _ours=1 && break; done
        if [ "$_ours" -eq 0 ]; then
            while IFS= read -r _w; do
                { [ "$_src" = "$_w" ] || [ "$_src" = "$_w/32" ]; } && _ours=1
            done < <(list_self_ips)
        fi
        if [ "$_ours" -eq 0 ] && [ -f "$WHITELIST_FILE" ]; then
            while IFS= read -r _w; do
                _w="${_w%%#*}"; _w="${_w// /}"
                [ -n "$_w" ] && [ "$_src" = "$_w" ] && _ours=1
            done < "$WHITELIST_FILE"
        fi
        [ "$_ours" -eq 1 ] && _del="$_del $((_idx - 1))"
    done << NXRAW
$_snap
NXRAW
    for _n in $(printf '%s
' $_del | sort -rn); do
        [ -n "$_n" ] && iptables -t raw -D PREROUTING "$_n" 2>/dev/null || true
    done
    nx_delete_matching raw PREROUTING '-j CT'
    success "iptables rules: removed"

    # fail2ban
    rm -f "$F2B_JAIL_DIR/antiddos.conf"
    rm -f "$F2B_FILTER_DIR/3proxy-ddos.conf" \
          "$F2B_FILTER_DIR/http-flood.conf" \
          "$F2B_FILTER_DIR/conn-flood.conf" \
          "$F2B_FILTER_DIR/portscan.conf" \
          "$F2B_FILTER_DIR/xray-proxy.conf"
    systemctl reload fail2ban 2>/dev/null || true
    success "fail2ban jails: removed"

    # Auto-ban
    systemctl stop auto-ban.service 2>/dev/null || true
    systemctl disable auto-ban.service 2>/dev/null || true
    rm -f "$AUTOBAN_SERVICE"
    systemctl daemon-reload
    # Remove subnet-ban iptables rules
    iptables-save 2>/dev/null | grep '"subnet-ban"' | \
        sed 's/^-A/iptables -D/' | bash 2>/dev/null || true
    # Clean temp files
    rm -f "${WATCH_LIST:-/run/nexoshield/autoban_watch}" "${THROTTLE_LIST:-/run/nexoshield/autoban_throttle}" "${SUBNET_WATCH_LIST:-/run/nexoshield/autoban_subnet_watch}" 2>/dev/null || true
    # M7: "Remove all rules" must also remove the nft backend's table
    # and the ban memory, or a later reinstall reconciles the
    # surviving state and resurrects old bans (the daemon's startup
    # reconcile re-applies banned.list, and its throttle restore
    # re-applies throttled.list).
    if command -v nft >/dev/null 2>&1 && nft list table inet nexoshield >/dev/null 2>&1; then
        nft delete table inet nexoshield 2>/dev/null || true
    fi
    : > "$BANNED_LIST" 2>/dev/null || true
    : > /etc/antiddos/throttled.list 2>/dev/null || true
    rm -rf /var/lib/antiddos/scores 2>/dev/null || true
    rm -f /etc/antiddos/adaptive.dat 2>/dev/null || true
    success "Auto-ban service: removed"

    # tc
    IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    [ -n "$IF" ] && tc qdisc del dev "$IF" root 2>/dev/null || true
    systemctl disable tc-proxy-limit.service 2>/dev/null || true
    rm -f /etc/systemd/system/tc-proxy-limit.service
    rm -f /etc/network/if-up.d/tc-proxy-limit
    success "tc bandwidth control: removed"

    # Persistence
    systemctl disable antiddos-restore.service 2>/dev/null || true
    rm -f /etc/systemd/system/antiddos-restore.service
    systemctl daemon-reload
    rm -f "$STATE_FILE" /opt/proxy-manager/tc-setup.sh \
          /etc/antiddos/restore-rules.sh "$IPTABLES_SAVE_FILE"
    # Regenerate the persistent ruleset from the now-cleaned live state,
    # or the next boot would resurrect the removed rules (BUG-012/031).
    if [ -d /etc/iptables ]; then
        save_static_rules /etc/iptables/rules.v4
    fi
    success "All Anti-DDoS rules removed."
}

# ════════════════════════════════════════════════
# Full install
# ════════════════════════════════════════════════
do_install() {
    sep; echo -e "  ${CYAN}${BOLD}Anti-DDoS Full Install v${SCRIPT_VERSION}${NC}"; sep
    echo -e "  ${DIM}RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | Virt: ${VIRT_TYPE} | IF: ${MAIN_IF}${NC}"
    echo -e "  ${DIM}SYNPROXY: $([ $SYNPROXY_OK -eq 1 ] && echo 'YES' || echo 'NO')  hashlimit: $([ $HASHLIMIT_OK -eq 1 ] && echo 'YES' || echo 'NO')  conntrack: $([ $CONNTRACK_OK -eq 1 ] && echo 'YES' || echo 'NO')${NC}"
    echo -e "  ${DIM}Public IPs: $PUBLIC_IP_COUNT  (rp_filter: $([ "${PUBLIC_IP_COUNT:-0}" -gt 1 ] && echo '0' || echo '1'))${NC}"
    echo ""
    echo -e "  Layers to install:"
    echo -e "    ${CYAN}1.${NC} Kernel sysctl  (keepalive=30s, conntrack tight timeouts)"
    echo -e "    ${CYAN}2.${NC} iptables       (CF whitelist first, then rate-limits)"
    echo -e "    ${CYAN}3.${NC} fail2ban       (3proxy-ddos/portscan/sshd/xray)"
    echo -e "    ${CYAN}4.${NC} Smart ban      (watch->throttle->ban pipeline)"
    echo -e "    ${CYAN}5.${NC} tc bandwidth   (CF=unlimited, others=500Mbps)"
    echo -e "    ${CYAN}6.${NC} Boot persist   (systemd + iptables-persistent)"
    echo ""
    printf '%s' "  Continue? (y/N): " >/dev/tty
    read -r CF_I </dev/tty || CF_I=""
    [[ "$CF_I" != "y" && "$CF_I" != "Y" ]] && return

    apply_sysctl_hardening
    apply_iptables
    apply_fail2ban
    setup_autoban
    setup_tc
    setup_persistence

    cat > "$STATE_FILE" << EOF
DATE=$(date)
VERSION=${SCRIPT_VERSION}
VIRT_TYPE=${VIRT_TYPE}
RAM_MB=${RAM_MB}
SYNPROXY=${SYNPROXY_OK}
HASHLIMIT=${HASHLIMIT_OK}
MAIN_IF=${MAIN_IF}
EOF

    sep
    success "Anti-DDoS installation complete!"
    echo ""
    echo -e "  ${CYAN}Protection summary:${NC}"
    echo -e "    ${GREEN}✓${NC}  SYN Flood   - $([ $SYNPROXY_OK -eq 1 ] && echo 'SYNPROXY (kernel)' || echo 'hashlimit')"
    echo -e "    ${GREEN}✓${NC}  UDP Flood   - hashlimit per-IP + amplification blocked"
    echo -e "    ${GREEN}✓${NC}  ICMP Flood  - rate-limited per source"
    echo -e "    ${GREEN}✓${NC}  Port Scans  - NULL/XMAS/FIN/bogus dropped"
    echo -e "    ${GREEN}✓${NC}  RST Flood   - rate-limited"
    echo -e "    ${GREEN}✓${NC}  Smart Ban   - watch(45s)->throttle(100M)->ban(progressive 30m-7d)"
    echo -e "    ${GREEN}✓${NC}  CF Users    - ALWAYS unlimited, never throttled/banned"
    echo -e "    ${GREEN}✓${NC}  Bandwidth   - CF=unlimited, non-CF=500Mbps max"
    echo -e "    ${GREEN}✓${NC}  Slowloris   - keepalive_time=30s"
    echo -e "    ${GREEN}✓${NC}  fail2ban    - 3proxy/portscan/sshd/xray jails"
    sep
}

show_thresholds() {
    sep; echo -e "  ${CYAN}${BOLD}Current Thresholds${NC}"; sep
    printf "  %-35s ${WHITE}%s${NC}\n" "SYN rate limit:"        "$SYN_LIMIT (burst: $SYN_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "UDP rate limit:"        "$UDP_LIMIT (burst: $UDP_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "ICMP rate limit:"       "$ICMP_LIMIT (burst: $ICMP_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "HTTP req rate limit:"   "${HTTP_REQ_RATE:-N/A} (burst: ${HTTP_REQ_BURST:-N/A})"
    printf "  %-35s ${WHITE}%s${NC}\n" "New conn rate limit:"   "${NEW_CONN_RATE:-N/A} (burst: ${NEW_CONN_BURST:-N/A})"
    printf "  %-35s ${WHITE}%s${NC}\n" "Per-IP bandwidth cap:"  "${BW_PER_IP_MBIT:-N/A} Mbps"
    printf "  %-35s ${WHITE}%s${NC}\n" "HTTP conns/non-CF IP:"  "$CONN_LIMIT_PER_IP"
    # L12: daemon gates read through nx_cfg (scoring.conf wins, the
    # historical constants are the fallback) - the old code printed
    # the defaults even when the admin had tuned them.
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban watch threshold:"   "$(nx_cfg conn_threshold 120) active conns/IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban instant-ban:"       "$(nx_cfg ban_conn_threshold 300) active conns/IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban subnet watch:"      "$(nx_cfg subnet_threshold 400) total conns from /24"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban subnet ban:"        "$(nx_cfg subnet_ban_threshold 1000) total conns from /24"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban observe:"           "$(nx_cfg observe_seconds 45)s watch before throttle"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban throttle:"          "100Mbps"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban duration:"          "Progressive: 30 min, doubling to 7 days"
    printf "  %-35s ${WHITE}%s${NC}\n" "Reputation scoring:"         "ON (100→0, human-vs-bot)"
    printf "  %-35s ${WHITE}%s${NC}\n" "  bands:"                    "80+normal 60+watch 40+100M 20+50M <20 ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "  auto-release:"             "ON (throttled→normal when calmed)"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban 3proxy:"       "100 req/60s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban HTTP burst:"    "200 req/30s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban conn-flood:"    "20 drops/10s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban SSH:"          "3 fails/30s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "Cloudflare IPs:"        "UNLIMITED at all layers"
    sep
}

# Validate an IPv4 address or CIDR (e.g. 1.2.3.4 or 5.6.7.0/24).
# Returns 0 when valid, 1 otherwise. Guards the whitelist manager so a
# typo can't silently add a non-address that iptables then ignores.
valid_ip_or_cidr() {
    local input="${1:-}" addr mask o slashed=0
    case "$input" in
        */*) addr="${input%%/*}"; mask="${input#*/}"; slashed=1 ;;
        *)   addr="$input"; mask="" ;;
    esac
    case "$addr" in
        ""|.*|*.|*..*|*[!0-9.]*) return 1 ;;
    esac
    local o1 o2 o3 o4 extra
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$addr"
    [ -z "${extra:-}" ] || return 1
    for o in "$o1" "$o2" "$o3" "$o4"; do
        case "$o" in
            ""|*[!0-9]*) return 1 ;;
        esac
        [ "${#o}" -le 3 ] || return 1
        # L10: leading zeros are octal to some parsers ("010.0.0.1"
        # is 8.0.0.1 to the kernel), so only a lone "0" may start
        # with zero - anything else is rejected, not reinterpreted.
        case "$o" in 0?*) return 1 ;; esac
        (( 10#$o <= 255 )) || return 1
    done
    if [ "$slashed" = 1 ]; then
        case "$mask" in
            ""|*[!0-9]*) return 1 ;;
        esac
        [ "${#mask}" -le 2 ] || return 1
        (( 10#$mask <= 32 )) || return 1
    fi
    return 0
}

# ── Exempt-set membership (D1) ─────────────────────────────
nx_ip_to_int() {
    local IFS=. a b c d
    read -r a b c d <<< "$1"
    echo $(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))
}

nx_ip_in_cidr() {
    local ip="$1" cidr="$2" net mask ni ii sh
    net="${cidr%%/*}"; mask="${cidr#*/}"
    case "$mask" in ''|*[!0-9]*) return 1 ;; esac
    (( 10#$mask <= 32 )) || return 1
    ni=$(nx_ip_to_int "$net"); ii=$(nx_ip_to_int "$ip")
    [ "$mask" -eq 0 ] && return 0
    sh=$(( 32 - 10#$mask ))
    [ $(( ii >> sh )) -eq $(( ni >> sh )) ]
}

# exempt_check <ip> — per-layer exemption status for one IP.
# Exit: 0 = member of the exempt set (CF / self / whitelist), 1 = not
# exempt, 2 = invalid input. Manual block flows MUST refuse on 0 (FR-1/2).
# flush_autobans — remove every auto-ban/subnet-ban rule and clear the
# daemon's ban/throttle/watch state. Backs the menu's "Flush all
# auto-bans" (BUG-008): the old menu implementation grepped
# `iptables -L` output for the comment text - comments never appear in
# -L listings, so it flushed nothing while reporting success. Rules
# are deleted by number from `iptables -S` (nx_delete_matching) and
# recorded tc throttle filters are removed by their prios.
flush_autobans() {
    # F1: these calls used to pass two arguments to a three-argument
    # helper (table missing) AND the helper was nested inside
    # remove_rules(), so in a fresh process this aborted under set -e
    # before deleting anything. Both are fixed: the helper is
    # top-level now and the calls carry the table.
    nx_delete_matching filter INPUT '--comment "auto-ban"'
    nx_delete_matching filter INPUT '--comment "subnet-ban"'
    nx_delete_matching6 INPUT '--comment "auto-ban"'
    nx_delete_matching6 INPUT '--comment "subnet-ban"'
    # H2: under the nft backend the kernel ban state lives in the
    # ban4/ban6 sets, not in iptables rules - flush those too, or
    # the bans persist to their timeouts (up to 7 days) while the
    # state files below claim they were flushed.
    if command -v nft >/dev/null 2>&1 && nft list table inet nexoshield >/dev/null 2>&1; then
        nft flush set inet nexoshield ban4 2>/dev/null || true
        nft flush set inet nexoshield ban6 2>/dev/null || true
    fi
    local _iface _f _ip _prio _rest
    _iface=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    for _f in "${THROTTLE_LIST:-/run/nexoshield/autoban_throttle}" /etc/antiddos/throttled.list; do
        [ -f "$_f" ] || continue
        while read -r _ip _prio _rest; do
            if [ -n "${_prio:-}" ] && [ -n "$_iface" ]; then
                tc filter del dev "$_iface" parent 1: prio "$_prio" 2>/dev/null || true
            fi
        done < "$_f"
        : > "$_f" 2>/dev/null || true
    done
    : > /etc/antiddos/banned.list 2>/dev/null || true
    : > "${WATCH_LIST:-/run/nexoshield/autoban_watch}" 2>/dev/null || true
    : > "${SUBNET_WATCH_LIST:-/run/nexoshield/autoban_subnet_watch}" 2>/dev/null || true
    success "All auto-bans flushed (iptables + ip6tables + nft + daemon state)"
}

# valid_ip6_or_cidr - IPv6 counterpart of valid_ip_or_cidr (E-5).
# The whitelist was v4-only end to end: every layer HONOURS v6
# entries (daemon is_exempt6, ip6tables, fail2ban ignoreip) but the
# admin could never add one, and --exempt-check rejected v6 targets
# as "invalid". Charset + group-count validation; embedded-IPv4
# forms are rejected (whitelist the v4 form instead).
valid_ip6_or_cidr() {
    local input="${1:-}" addr mask
    case "$input" in
        */*) addr="${input%%/*}"; mask="${input#*/}"
             case "$mask" in ''|*[!0-9]*) return 1 ;; esac
             [ "${#mask}" -le 3 ] || return 1
             (( 10#$mask <= 128 )) || return 1 ;;
        *)   addr="$input" ;;
    esac
    case "$addr" in
        *[!0-9a-fA-F:]*) return 1 ;;
        *:::*) return 1 ;;
    esac
    case "$addr" in
        *::*) case "${addr#*::}" in *::*) return 1 ;; esac ;;
    esac
    [ "$addr" = "::" ] && return 0
    local _groups=0 _g
    local _oldIFS="$IFS"; IFS=':'
    # shellcheck disable=SC2086
    set -- $addr
    IFS="$_oldIFS"
    for _g in "$@"; do
        [ -z "$_g" ] && continue
        [ "${#_g}" -le 4 ] || return 1
        _groups=$((_groups + 1))
    done
    case "$addr" in
        *::*) [ "$_groups" -le 7 ] || return 1 ;;
        *)    [ "$_groups" -eq 8 ] || return 1 ;;
    esac
    return 0
}

# nx_ip6_in_cidr - the antiddos-side twin of the daemon's ip6_in_cidr
# (same awk nibble-compare; a missing mask means /128).
nx_ip6_in_cidr() {
    awk -v ip="$1" -v cidr="$2" '
    function hv(c) { return index("0123456789abcdef", c) - 1 }
    function pad(h) { while (length(h) < 4) h = "0" h; return h }
    function expand(a,    k,lp,rp,ln,rn,out,i) {
        a = tolower(a)
        k = index(a, "::")
        if (k > 0) {
            lp = substr(a, 1, k - 1); rp = substr(a, k + 2)
            ln = (lp == "") ? 0 : split(lp, L, ":")
            rn = (rp == "") ? 0 : split(rp, G, ":")
            out = ""
            for (i = 1; i <= ln; i++) out = out pad(L[i])
            for (i = 1; i <= 8 - ln - rn; i++) out = out "0000"
            for (i = 1; i <= rn; i++) out = out pad(G[i])
            return out
        }
        split(a, P, ":"); out = ""
        for (i = 1; i <= 8; i++) out = out pad(P[i])
        return out
    }
    BEGIN {
        np = split(cidr, C, "/"); pfx = (np < 2 || C[2] == "") ? 128 : C[2] + 0
        e1 = expand(ip); e2 = expand(C[1])
        full = int(pfx / 4)
        if (substr(e1, 1, full) != substr(e2, 1, full)) exit 1
        rem = pfx % 4
        if (rem > 0) {
            keep = 2 ^ (4 - rem)
            if (int(hv(substr(e1, full + 1, 1)) / keep) != int(hv(substr(e2, full + 1, 1)) / keep)) exit 1
        }
        exit 0
    }'
}

exempt_check() {
    local ip="${1:-}" rc=1 _e
    [ -n "$ip" ] || { echo "usage: --exempt-check <ip>"; return 2; }
    case "$ip" in
        *:*)
            valid_ip6_or_cidr "$ip" || { echo "invalid IPv6/CIDR: $ip"; return 2; }
            ip="${ip%%/*}"
            echo "Exemption check for $ip (IPv6):"
            local cf=no self=no wl=no
            for _e in "${CF6_RANGES[@]}"; do nx_ip6_in_cidr "$ip" "$_e" && { cf=yes; break; }; done
            list_self_ips6 2>/dev/null | grep -qxF "$ip" && self=yes
            if [ -f "$WHITELIST_FILE" ]; then
                while IFS= read -r _e; do
                    _e="${_e%%#*}"; _e="${_e// /}"
                    case "$_e" in *:*) : ;; *) continue ;; esac
                    [ -n "$_e" ] && nx_ip6_in_cidr "$ip" "$_e" && { wl=yes; break; }
                done < "$WHITELIST_FILE"
            fi
            echo "  cloudflare ranges : $cf"
            echo "  server own IP     : $self"
            echo "  admin whitelist   : $wl"
            { [ "$cf" = yes ] || [ "$self" = yes ] || [ "$wl" = yes ]; } && rc=0
            [ "$rc" -eq 0 ] && echo "  VERDICT: EXEMPT" || echo "  VERDICT: not exempt"
            return $rc ;;
    esac
    valid_ip_or_cidr "$ip" || { echo "invalid IP/CIDR: $ip"; return 2; }
    ip="${ip%%/*}"
    echo "Exemption check for $ip:"
    local cf=no self=no wl=no
    for _e in "${CF_RANGES[@]}"; do nx_ip_in_cidr "$ip" "$_e" && { cf=yes; break; }; done
    list_self_ips_all 2>/dev/null | grep -qxF "$ip" && self=yes
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _e; do
            _e="${_e%%#*}"; _e="${_e// /}"
            [ -z "$_e" ] && continue
            case "$_e" in
                */*) nx_ip_in_cidr "$ip" "$_e" && { wl=yes; break; } ;;
                *)   [ "$_e" = "$ip" ] && { wl=yes; break; } ;;
            esac
        done < "$WHITELIST_FILE"
    fi
    echo "  cloudflare ranges : $cf"
    echo "  server own IP     : $self"
    echo "  admin whitelist   : $wl"
    { [ "$cf" = yes ] || [ "$self" = yes ] || [ "$wl" = yes ]; } && rc=0
    if [ -f "$F2B_JAIL_DIR/antiddos.conf" ]; then
        if grep -qw "$ip" "$F2B_JAIL_DIR/antiddos.conf" 2>/dev/null; then
            echo "  fail2ban ignoreip : listed"
        else
            echo "  fail2ban ignoreip : NOT listed by exact IP (CIDR entries may still cover it)"
        fi
    fi
    if iptables -S INPUT 2>/dev/null | grep -F -- "-s $ip" | grep -q -- '-j ACCEPT'; then
        echo "  iptables INPUT    : ACCEPT rule present for this exact IP"
    fi
    [ "$rc" -eq 0 ] && echo "  VERDICT: EXEMPT" || echo "  VERDICT: not exempt"
    return $rc
}

# nx_release_ban <ip|cidr> — release ONE ban from every layer: the
# nft ban-set element, the tagged iptables/ip6tables DROP rules, the
# recorded tc throttle filter, banned.list, and every fail2ban jail.
# Returns 0 when anything was actually removed, 1 when the IP was
# found nowhere — so callers never print "fully unblocked" for a
# no-op (H2/H3). Shared by the menu Unban option and the
# whitelist-add release (M2); the menu's nx_unban_ip is the same
# logic in the menu program (it cannot call this file).
nx_release_ban() {
    local _ip="$1" _removed=0 _tf _prio _if _j
    # L5: the whole release (kernel deletes + file rewrites) runs
    # under the shared state lock, so a concurrent daemon ban cannot
    # land between the read and the rewrite and get lost.
    nx_state_lock
    if command -v nft >/dev/null 2>&1; then
        case "$_ip" in
            *:*) nft delete element inet nexoshield ban6 "{ $_ip }" >/dev/null 2>&1 && _removed=1 || true ;;
            *)   nft delete element inet nexoshield ban4 "{ $_ip }" >/dev/null 2>&1 && _removed=1 || true ;;
        esac
    fi
    case "$_ip" in
        *:*)
            ip6tables -D INPUT -s "$_ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null && _removed=1 || true ;;
        *)
            if iptables -D INPUT -s "$_ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null; then
                _removed=1
            elif iptables -D INPUT -s "$_ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null; then
                _removed=1
            elif iptables -D INPUT -s "$_ip" -j DROP 2>/dev/null; then
                _removed=1
            fi ;;
    esac
    for _tf in "${THROTTLE_LIST:-/run/nexoshield/autoban_throttle}" /etc/antiddos/throttled.list; do
        [ -f "$_tf" ] || continue
        _prio=$(awk -v x="$_ip" '$1==x{print $2}' "$_tf" 2>/dev/null | head -1)
        if [ -n "$_prio" ]; then
            _removed=1
            _if=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
            [ -n "$_if" ] && tc filter del dev "$_if" parent 1: prio "$_prio" 2>/dev/null || true
        fi
        awk -v x="$_ip" '$1!=x' "$_tf" > "$_tf.tmp.$$" 2>/dev/null && mv "$_tf.tmp.$$" "$_tf"
    done
    if [ -f "$BANNED_LIST" ]; then
        awk -v x="$_ip" '$1==x{found=1} END{exit !found}' "$BANNED_LIST" 2>/dev/null && _removed=1 || true
        awk -v x="$_ip" '$1!=x' "$BANNED_LIST" > "$BANNED_LIST.tmp.$$" 2>/dev/null && \
            mv "$BANNED_LIST.tmp.$$" "$BANNED_LIST"
    fi
    fail2ban-client status 2>/dev/null | grep "Jail list" | \
        sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r _j; do
        [ -z "$_j" ] && continue
        fail2ban-client set "$_j" unbanip "$_ip" 2>/dev/null || true
    done
    nx_state_unlock
    [ "$_removed" -eq 1 ]
}

# _wl_covered <banned-entry> <whitelist-entry> — true when whitelisting
# the entry releases the banned entry: same value, a plain IP inside
# a whitelist CIDR, or a banned subnet inside a wider whitelist CIDR.
# A single whitelisted IP never lifts a subnet ban (the /24 rule
# still drops it; whitelist the /24 itself to lift it).
_wl_covered() {
    local _b="$1" _e="$2"
    [ "$_b" = "$_e" ] && return 0
    case "$_e" in */*) : ;; *) return 1 ;; esac
    case "$_b" in */*) _b="${_b%%/*}" ;; esac
    case "$_b" in
        *:*)
            case "$_e" in *:*) nx_ip6_in_cidr "$_b" "$_e" ;; *) return 1 ;; esac ;;
        *)
            case "$_e" in *:* ) return 1 ;; *) nx_ip_in_cidr "$_b" "$_e" ;; esac ;;
    esac
}

# wl_release_bans_for <entry> — when an IP/CIDR is newly whitelisted
# (M2), release every ban it covers. A banned IP that is now exempt
# must not stay blocked in the kernel until its timeout, and the
# entry must join the nft exempt set so the kernel path honors it
# immediately (the daemon skips exempt IPs, but only the kernel
# state decides what actually gets dropped).
wl_release_bans_for() {
    local _entry="$1" _bip
    # The loop reads an awk snapshot (pipe), so nx_release_ban's
    # in-place banned.list rewrite cannot disturb the iteration.
    while IFS= read -r _bip; do
        [ -z "$_bip" ] && continue
        _wl_covered "$_bip" "$_entry" && { nx_release_ban "$_bip" || true; }
    done < <(awk '{print $1}' "$BANNED_LIST" 2>/dev/null || true)
    if command -v nft >/dev/null 2>&1 && nft list table inet nexoshield >/dev/null 2>&1; then
        case "$_entry" in
            *:*) nft add element inet nexoshield exempt6 "{ $_entry }" 2>/dev/null || true ;;
            *)   nft add element inet nexoshield exempt4 "{ $_entry }" 2>/dev/null || true ;;
        esac
    fi
}

# ── Whitelist manager ──────────────────────────────────────
manage_whitelist() {
    local WL="$WHITELIST_FILE"
    mkdir -p /etc/antiddos
    [ -f "$WL" ] || touch "$WL"

    while true; do
        clear; sep
        echo -e "  ${CYAN}${BOLD}Whitelist Manager${NC}"
        echo -e "  ${DIM}IPs/CIDRs here are exempt from ALL anti-DDoS limits:${NC}"
        echo -e "  ${DIM}iptables rate-limit, connlimit, SYNPROXY, tc bandwidth, auto-ban.${NC}"
        sep
        if [ -s "$WL" ]; then
            echo -e "  ${CYAN}Current whitelist:${NC}"
            local N=0
            while IFS= read -r E; do
                [ -z "${E%%#*}" ] && continue
                E="${E// /}"
                [ -z "$E" ] && continue
                N=$((N + 1))
                printf "    ${GREEN}%s.${NC} %s\n" "$N" "$E"
            done < "$WL"
            echo ""
        else
            echo -e "  ${YELLOW}Whitelist is empty.${NC} (Server's own IPs + Cloudflare are always exempt automatically.)"
            echo ""
        fi
        echo -e "  ${CYAN}a.${NC} Add IP/CIDR"
        echo -e "  ${CYAN}d.${NC} Remove entry"
        echo -e "  ${CYAN}c.${NC} Check an IP (is it exempt from all layers?)"
        echo -e "  ${CYAN}0.${NC} Back"
        sep
        printf '%s' "  Enter choice: " >/dev/tty; read -r WCH </dev/tty || WCH=""
        case "$WCH" in
            a|A)
                printf '%s' "  IP or CIDR to whitelist (e.g. 1.2.3.4 or 5.6.7.0/24): " >/dev/tty
                read -r WIP </dev/tty || WIP=""
                WIP="${WIP// /}"
                if [ -z "$WIP" ]; then
                    echo -e "  ${YELLOW}No input.${NC}"
                elif ! valid_ip_or_cidr "$WIP" && ! valid_ip6_or_cidr "$WIP"; then
                    echo -e "  ${RED}Invalid IP/CIDR: $WIP${NC}"
                elif grep -qxF "$WIP" "$WL" 2>/dev/null; then
                    echo -e "  ${YELLOW}Already in whitelist.${NC}"
                else
                    echo "$WIP" >> "$WL"
                    echo -e "  ${GREEN}✓ Added: $WIP${NC}"
                    # M2: a newly exempt entry must not stay banned in
                    # the kernel until its timeout - release every ban
                    # it covers and join the nft exempt set first,
                    # then re-apply the layers around the new state.
                    wl_release_bans_for "$WIP" || true
                    # Apply to iptables + tc immediately (re-apply both)
                    apply_iptables >/dev/null 2>&1 || true
                    apply_tc_runtime "$MAIN_IF" >/dev/null 2>&1 || true
                    update_f2b_ignoreip || true
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            c|C)
                printf '%s' "  IP to check: " >/dev/tty
                read -r CIP </dev/tty || CIP=""
                CIP="${CIP// /}"
                if [ -n "$CIP" ]; then
                    exempt_check "$CIP"
                else
                    echo -e "  ${YELLOW}No input.${NC}"
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            d|D)
                printf '%s' "  Entry to remove (paste the exact IP/CIDR): " >/dev/tty
                read -r RIP </dev/tty || RIP=""
                RIP="${RIP// /}"
                if [ -n "$RIP" ] && grep -qF "$RIP" "$WL" 2>/dev/null; then
                    grep -vxF "$RIP" "$WL" > "$WL.tmp" && mv "$WL.tmp" "$WL"
                    # Clean the empty case
                    sed -i '/^[[:space:]]*$/d' "$WL" 2>/dev/null || true
                    echo -e "  ${GREEN}✓ Removed: $RIP${NC}"
                    apply_iptables >/dev/null 2>&1 || true
                    apply_tc_runtime "$MAIN_IF" >/dev/null 2>&1 || true
                    update_f2b_ignoreip || true
                else
                    echo -e "  ${YELLOW}Not found.${NC}"
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            0) return 0 ;;
            *) echo -e "  ${YELLOW}Invalid choice.${NC}"; sleep 1 ;;
        esac
    done
}

# Runtime tc re-apply for a single interface (used by whitelist manager)
apply_tc_runtime() {
    local IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
    [ -z "$IF" ] && IF="eth0"
    # Only re-run if tc is already configured
    tc qdisc show dev "$IF" 2>/dev/null | grep -q htb || return 0
    setup_tc "$IF" >/dev/null 2>&1 || true
    # BUG-036: verify the rebuild actually produced the throttle classes
    # instead of reporting success on faith.
    tc class show dev "$IF" 2>/dev/null | grep -q 'class htb 1:30' || \
        warn "tc re-apply: class 1:30 missing on $IF after rebuild - throttling unavailable"
}

# CLI args
# MED-6: action flags propagate the action's exit code instead of
# exiting 0 regardless. F6: unknown flags error out instead of
# silently falling through to the interactive menu.
case "${1:-}" in
    --install|-i)    detect_env; do_install; exit $? ;;
    --remove|-r)     detect_env; remove_rules; exit $? ;;
    --remove-force)  detect_env; CONF_R="y"; remove_rules; exit $? ;;
    --status|-s)     detect_env; show_status; exit $? ;;
    --exempt-check)  exempt_check "${2:-}"; exit $? ;;
    --flush-autobans) flush_autobans; exit $? ;;
    --thresholds|-t) detect_env; show_thresholds; exit $? ;;
    --sysctl)        detect_env; apply_sysctl_hardening; exit $? ;;
    --iptables)      detect_env; apply_iptables; exit $? ;;
    --fail2ban)      detect_env; apply_fail2ban; exit $? ;;
    --autoban)       detect_env; setup_autoban; exit $? ;;
    --whitelist|-w)  detect_env; manage_whitelist; exit $? ;;
    --tc)            detect_env; setup_tc; exit $? ;;
    --auto|-y)
        detect_env
        sep
        echo -e "  ${CYAN}${BOLD}Anti-DDoS Full Install v${SCRIPT_VERSION}${NC}"; sep
        echo -e "  ${DIM}RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | Virt: ${VIRT_TYPE} | IF: ${MAIN_IF}${NC}"
        echo ""
        _auto_rc=0
        apply_sysctl_hardening || _auto_rc=1
        apply_iptables || _auto_rc=1
        apply_fail2ban || _auto_rc=1
        setup_autoban || _auto_rc=1
        setup_tc || _auto_rc=1
        setup_persistence || _auto_rc=1
        cat > "$STATE_FILE" << EOF
DATE=$(date)
VERSION=${SCRIPT_VERSION}
VIRT_TYPE=${VIRT_TYPE}
RAM_MB=${RAM_MB}
SYNPROXY=${SYNPROXY_OK}
HASHLIMIT=${HASHLIMIT_OK}
MAIN_IF=${MAIN_IF}
EOF
        sep
        if [ "$_auto_rc" -eq 0 ]; then
            success "Anti-DDoS installation complete!"
        else
            warn "Anti-DDoS installation finished with errors - see above."
        fi
        exit "$_auto_rc" ;;
    *)  if [ -n "${1:-}" ]; then err "Unknown option: $1"; exit 2; fi ;;
esac

# Interactive menu
detect_env

# LOW-8: without a terminal the menu loop below cannot read choices.
if ! : </dev/tty 2>/dev/null; then
    err "Interactive menu requires a terminal (use CLI flags for scripting)."
    exit 1
fi

while true; do
    clear; sep
    echo -e "  ${CYAN}${BOLD}Anti-DDoS Manager v${SCRIPT_VERSION}${NC}"; sep
    [ -f "$STATE_FILE" ] && \
        echo -e "  Status: ${GREEN}✓ Installed${NC}" || \
        echo -e "  Status: ${YELLOW}○ Not installed${NC}"
    _AB_ST=$(systemctl is-active auto-ban 2>/dev/null || echo "inactive")
    [ "$_AB_ST" = "active" ] && \
        echo -e "  auto-ban: \033[0;32mRunning\033[0m" || \
        echo -e "  auto-ban: \033[0;31mStopped\033[0m"
    echo ""
    echo -e "  ${CYAN}1.${NC}  Full install (all layers)"
    echo -e "  ${CYAN}2.${NC}  Status & active bans"
    echo -e "  ${CYAN}3.${NC}  View thresholds"
    echo -e "  ${CYAN}4.${NC}  Kernel sysctl only"
    echo -e "  ${CYAN}5.${NC}  iptables only"
    echo -e "  ${CYAN}6.${NC}  fail2ban only"
    echo -e "  ${CYAN}7.${NC}  Smart ban only"
    echo -e "  ${CYAN}8.${NC}  tc bandwidth only"
    echo -e "  ${CYAN}9.${NC}  Unban IP (all layers)"
    echo -e "  ${CYAN}w.${NC}  Manage whitelist (IPs exempt from ALL limits)"
    echo -e "  ${CYAN}r.${NC}  Remove all rules"
    echo -e "  ${CYAN}0.${NC}  Back"
    sep
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) do_install; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) show_status; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        3) show_thresholds; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        4) apply_sysctl_hardening; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        5) apply_iptables; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        6) apply_fail2ban; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        7) setup_autoban; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        8) setup_tc; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        9) echo -e "  ${CYAN}Unban IP${NC}"; echo ""
           printf '%s' "  Enter IP to unban (iptables + fail2ban): " >/dev/tty; read -r UIP </dev/tty || UIP=""
           if [ -n "$UIP" ] && ! valid_ip_or_cidr "$UIP" && ! valid_ip6_or_cidr "$UIP"; then
               echo -e "  ${RED}✗ Invalid IP/CIDR: $UIP${NC}"
               UIP=""
           fi
           [ -n "$UIP" ] && {
               # One unban path (H2/H3): nft set element, tagged
               # iptables/ip6tables rules, throttle filter, state
               # file and fail2ban - and an honest result: success
               # is printed only when something was actually removed.
               if nx_release_ban "$UIP"; then
                   echo -e "  ${GREEN}✓ $UIP fully unblocked${NC}"
               else
                   echo -e "  ${YELLOW}⚠ $UIP was not found in any layer (nothing removed)${NC}"
               fi
           }
           printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        w|W) manage_whitelist ;;
        r) remove_rules; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
ANTIDDOS_SCRIPT

# ── Activate staged module scripts (BUG-025) ───────────────
# Each module was written to a staging name. Verify ALL of them first;
# if any is broken, keep the previous install untouched and abort.
for _NXF in 3proxy-socks5.sh optimize-sysctl.sh proxy-menu.sh antiddos.sh; do
    _NXSTAGED="$INSTALL_DIR/.$_NXF.nxnew"
    if [ ! -s "$_NXSTAGED" ] || ! bash -n "$_NXSTAGED" 2>/dev/null; then
        err "Staged script $_NXF is missing or invalid - previous install left untouched."
        rm -f "$INSTALL_DIR"/.*.nxnew
        exit 1
    fi
done
for _NXF in 3proxy-socks5.sh optimize-sysctl.sh proxy-menu.sh antiddos.sh; do
    [ -f "$INSTALL_DIR/$_NXF" ] && \
        cp -a "$INSTALL_DIR/$_NXF" "$INSTALL_DIR/$_NXF.prev" 2>/dev/null || true
    mv "$INSTALL_DIR/.$_NXF.nxnew" "$INSTALL_DIR/$_NXF"
done
ok "Module scripts verified and activated (previous versions kept as *.prev)"

# ── Permissions ───────────────────────────────────────────
chmod +x "$INSTALL_DIR/3proxy-socks5.sh" \
         "$INSTALL_DIR/optimize-sysctl.sh" \
         "$INSTALL_DIR/proxy-menu.sh" \
         "$INSTALL_DIR/antiddos.sh"
ok "Files created"

# ── Link shield command ───────────────────────────────────
# LOW-4: the BUG-058 guard for the old 'proxy' link, applied to the
# new name too - never silently replace a foreign /usr/local/bin/
# shield (another tool, a user's script). Replace only when absent,
# already ours, or a NexoShield menu from a previous install.
info "Installing shield command..."
if [ -e "$BIN_LINK" ] && [ ! -L "$BIN_LINK" ]; then
    warn "$BIN_LINK exists and is not a symlink - leaving it untouched; run $INSTALL_DIR/proxy-menu.sh directly."
elif [ -L "$BIN_LINK" ] && [ "$(readlink "$BIN_LINK" 2>/dev/null)" != "$INSTALL_DIR/proxy-menu.sh" ] && \
     [ "$(readlink "$BIN_LINK" 2>/dev/null)" != "$INSTALL_DIR/proxy-menu.sh.prev" ]; then
    warn "$BIN_LINK points elsewhere ($(readlink "$BIN_LINK" 2>/dev/null)) - leaving it untouched; run $INSTALL_DIR/proxy-menu.sh directly."
else
    ln -sf "$INSTALL_DIR/proxy-menu.sh" "$BIN_LINK"
    chmod +x "$BIN_LINK"
    ok "Command ${W}shield${NC} installed"
fi
# Pre-v3.11 installs linked the menu as /usr/local/bin/proxy. Drop
# that link on upgrade - but only if it is OURS (a symlink to this
# menu); never touch a foreign binary of the same name (BUG-058).
if [ "/usr/local/bin/proxy" != "$BIN_LINK" ] && [ -L /usr/local/bin/proxy ] && \
   [ "$(readlink /usr/local/bin/proxy 2>/dev/null)" = "$INSTALL_DIR/proxy-menu.sh" ]; then
    rm -f /usr/local/bin/proxy
    info "Removed the old 'proxy' command link (the menu is 'shield' now)"
fi

# ── Final result ──────────────────────────────────────────
echo ""
sep
echo -e "  ${G}${BOLD}✓ Installation complete! v${VERSION}${NC}"
sep
echo -e "  Install path : ${DIM}$INSTALL_DIR${NC}"
echo -e "  Command      : ${W}${BOLD}shield${NC}"
echo -e "  Install log  : ${DIM}$LOG${NC}"
echo ""
echo -e "  ${C}Scripts installed:${NC}"
echo -e "  ${DIM}->${NC}  3proxy-socks5.sh    (SOCKS5 proxy + CF unlimited)"
echo -e "  ${DIM}->${NC}  optimize-sysctl.sh  (kernel optimization)"
echo -e "  ${DIM}->${NC}  antiddos.sh         (5-layer DDoS protection)"
echo -e "  ${DIM}->${NC}  proxy-menu.sh       (main control panel)"
echo ""
echo -e "  ${C}Run now:${NC}"
echo -e "  ${W}${BOLD}  shield${NC}"
sep
