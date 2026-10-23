#!/bin/bash
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
LOG_FILE="/var/log/proxy-manager.log"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
W='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

[ "$EUID" -ne 0 ] && echo -e "${R}Root required: sudo proxy${NC}" && exit 1
touch "$LOG_FILE" 2>/dev/null && chmod 600 "$LOG_FILE" 2>/dev/null || true
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }
sep()  { echo -e "${C}════════════════════════════════════════════════${NC}"; }
sep2() { echo -e "${DIM}────────────────────────────────────────────────${NC}"; }
ok()   { echo -e "  ${G}✓${NC}  $*"; }
err()  { echo -e "  ${R}✗${NC}  $*"; }
warn() { echo -e "  ${Y}⚠${NC}  $*"; }
press_enter() { echo ""; printf '%s\n' "  Press Enter to go back..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; }

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
    curl -s -4 --max-time 4 https://api.ipify.org 2>/dev/null || \
    ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127\.' | \
        head -1 | awk '{print $2}' | cut -d/ -f1 || echo "?"
}

draw_header() {
    clear 2>/dev/null || true
    echo -e "${C}${BOLD}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║       Proxy Manager  v${VERSION}  Anti-DDoS       ║"
    echo "  ╚══════════════════════════════════════════════╝${NC}"
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
menu_proxy() {
    while true; do
        draw_header; echo -e "  ${C}${BOLD}SOCKS5 Proxy (3proxy)${NC}"; echo ""
        local ST PORT
        ST=$(svc_status "3proxy")
        PORT=$(get_proxy_port)
        echo -e "  Status : $ST   $(svc_enabled "3proxy")"
        [ -n "$PORT" ] && echo -e "  Port   : ${C}$PORT${NC}"
        [ -f /etc/3proxy/install.info ] && {
            # shellcheck disable=SC1091
            # Read vars with prefix to avoid conflict with bash $USER builtin
            _INFO_USER=$(grep '^USER=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "")
            _INFO_PASS=$(grep '^PASS=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "")
            echo -e "  User   : ${G}${_INFO_USER:-?}${NC}   Pass: ${G}${_INFO_PASS:-?}${NC}"
            echo -e "  Link   : ${G}socks5://${_INFO_USER:-?}:${_INFO_PASS:-?}@$(get_ip):${PORT:-?}${NC}"
        }
        echo ""; sep2
        echo -e "  ${C}1.${NC} Install/Update  ${C}2.${NC} Remove      ${C}3.${NC} Start"
        echo -e "  ${C}4.${NC} Stop            ${C}5.${NC} Restart     ${C}6.${NC} Live log"
        echo -e "  ${C}7.${NC} Traffic stats   ${C}8.${NC} Change pass ${C}9.${NC} Suspicious IPs"
        echo -e "  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
        case "$CH" in
            1) # Ensure the Cloudflare whitelist file exists before install so CF
               # IPs are ALWAYS excluded from throttling (it can be deleted by an
               # earlier uninstall/antiddos --remove in the same session).
               mkdir -p /etc/antiddos
               [ -s /etc/antiddos/cloudflare-ipv4.list ] || \
                   printf "%s\n" "${CF_RANGES[@]}" > /etc/antiddos/cloudflare-ipv4.list
               bash "$PROXY_SCRIPT" --install < /dev/tty; press_enter ;;
            2) echo ""
               printf '%s' "  Remove 3proxy completely? (y/N): " >/dev/tty; read -r _RC </dev/tty || _RC=""
               [[ "$_RC" == "y" || "$_RC" == "Y" ]] && bash "$PROXY_SCRIPT" --remove < /dev/tty || echo -e "  ${DIM}Cancelled.${NC}"
               press_enter ;;
            3) bash "$PROXY_SCRIPT" --start; press_enter ;;
            4) bash "$PROXY_SCRIPT" --stop;  press_enter ;;
            5) bash "$PROXY_SCRIPT" --restart; press_enter ;;
            6) bash "$PROXY_SCRIPT" --log ;;
            7) bash "$PROXY_SCRIPT" --stats ;;
            8) bash "$PROXY_SCRIPT" --change-pass; press_enter ;;
            9) _proxy_suspicious ;;
            0) return ;;
        esac
    done
}

_proxy_stats() {
    clear; PORT=$(get_proxy_port); sep
    echo -e "  ${C}Traffic Stats - port $PORT${NC}"; sep
    ACTIVE=$(ss -tnp 2>/dev/null | grep ":$PORT " | grep -v LISTEN | wc -l || echo 0)
    echo -e "  Active connections: ${G}$ACTIVE${NC}"

    _fmt() {
        # Format bytes without depending on `bc` (absent on some systems → used to show blank)
        awk -v n="${1:-0}" 'BEGIN{
            if (n>=1073741824) printf "%.2f GB\n", n/1073741824;
            else if (n>=1048576) printf "%.2f MB\n", n/1048576;
            else if (n>=1024) printf "%.2f KB\n", n/1024;
            else printf "%d B\n", n;
        }'
    }
    IN_B=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "3proxy_stats_in" | awk '{print $2}' | head -1)
    OUT_B=$(iptables -L OUTPUT -v -n -x 2>/dev/null | grep "3proxy_stats_out" | awk '{print $2}' | head -1)
    # 3proxy_stats_in  = bytes clients SENT to proxy (upload)
    # 3proxy_stats_out = bytes proxy   SENT to clients (download)
    echo -e "  Download (proxy -> client): ${G}$(_fmt "$OUT_B")${NC}"
    echo -e "  Upload   (client -> proxy): ${G}$(_fmt "$IN_B")${NC}"

    # Banned IPs (auto-ban)
    if [ -f /var/log/auto-ban.log ]; then
        BANNED_COUNT=$(grep -c "BANNED:" /var/log/auto-ban.log 2>/dev/null || echo 0)
        echo -e "  Auto-bans today: ${Y}$BANNED_COUNT${NC}"
    fi

    [ -f /var/log/3proxy/access.log ] && {
        echo ""
        echo -e "  ${C}Last 10 connections:${NC}"
        tail -10 /var/log/3proxy/access.log 2>/dev/null || true
    }
    press_enter
}

_proxy_change_pass() {
    clear; echo -e "  ${C}Change Password${NC}"; echo ""
    [ ! -f /etc/3proxy/3proxy.cfg ] && warn "3proxy not installed" && press_enter && return
    echo -e "  ${DIM}Leave empty to generate a random password.${NC}"; echo ""
    printf '%s' "  New password (empty = random): " >/dev/tty; read -r NP </dev/tty || NP=""
    [ -z "$NP" ] && NP=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16 || echo "proxy$(date +%s)")
    CU=$(grep -oP '(?<=allow )\S+' /etc/3proxy/3proxy.cfg 2>/dev/null | head -1 || echo "")
    [ -z "$CU" ] && warn "Cannot find username" && press_enter && return
    echo "users ${CU}:CL:${NP}" > /etc/3proxy/users.cfg
    [ -f /etc/3proxy/install.info ] && \
        sed -i "s/^PASS=.*/PASS=${NP}/" /etc/3proxy/install.info 2>/dev/null || true
    systemctl restart 3proxy 2>/dev/null && ok "Password changed" || err "Restart failed"
    echo -e "  ${G}socks5://${CU}:${NP}@$(get_ip):$(get_proxy_port)${NC}"
    press_enter
}

_proxy_suspicious() {
    clear; echo -e "  ${C}Threat IPs (real blocked/throttled attackers)${NC}"; echo ""
    echo -e "  ${DIM}These are actual attackers auto-ban has blocked or throttled,"${NC}
    echo -e "  ${DIM}not your normal heavy users.${NC}"; sep2

    # Currently banned (iptables DROP rules tagged by auto-ban / subnet-ban)
    local _banned=""
    _banned=$(iptables -L INPUT -n 2>/dev/null | grep -E 'auto-ban|subnet-ban' | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?' | \
        grep -v '^0\.0\.0\.0' | sort -u | head -20)

    # Currently throttled (reputation-suspected, pre-ban)
    local _throttled=""
    _throttled=$(awk '{print $1}' /tmp/autoban_throttle 2>/dev/null | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -10)

    local _empty=1
    if [ -n "$_banned" ]; then
        echo -e "  ${R}── Currently BANNED ──${NC}"
        echo "$_banned" | while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            echo -e "  ${R}✗ $ip${NC}   (iptables DROP)"
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
    printf '%s' "  Block IP (empty = skip): " >/dev/tty; read -r BIP </dev/tty || BIP=""
    if [ -n "$BIP" ]; then
        iptables -I INPUT -s "$BIP" -m comment --comment "auto-ban" -j DROP 2>/dev/null && \
            ok "$BIP blocked" || warn "Could not block $BIP"
    fi
    press_enter
}

# ── sysctl Menu ───────────────────────────────────────────
menu_sysctl() {
    while true; do
        draw_header; echo -e "  ${C}${BOLD}Network Optimization${NC}"; echo ""
        if [ -f /etc/sysctl.d/99-vpn-optimized.conf ]; then
            echo -e "  Status  : ${G}✓ Optimized${NC}"
        else
            echo -e "  Status  : ${Y}○ Default settings${NC}"
            echo -e "  ${DIM}  → Choose option 1 to enable BBR + optimize for proxy${NC}"
        fi
        echo -e "  BBR     : ${G}$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')${NC} + $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
        echo -e "  Keepalive: $(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || echo '?')s  ${DIM}(30s = optimal for proxy)${NC}"
        echo ""; sep2
        echo -e "  ${G}1.${NC} Install / Optimize   ${DIM}(analyze + apply)${NC}"
        echo -e "  ${C}2.${NC} Rollback              ${DIM}(restore previous settings)${NC}"
        echo -e "  ${C}3.${NC} Current values"
        echo -e "  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
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
        draw_header; echo -e "  ${C}${BOLD}Monitoring${NC}"; echo ""
        echo -e "  ${C}1.${NC} Live Threat Monitor  ${C}2.${NC} Connections"
        echo -e "  ${C}3.${NC} CPU & RAM            ${C}4.${NC} Disk"
        echo -e "  ${C}5.${NC} Logs                 ${C}6.${NC} Auto-ban log"
        echo -e "  ${C}7.${NC} Traffic top IPs      ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
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
            7) # Top IPs from 3proxy log
               [ -f /var/log/3proxy/access.log ] && {
                   echo -e "  ${C}Top 20 source IPs:${NC}"; sep2
                   awk '{print $5}' /var/log/3proxy/access.log 2>/dev/null | \
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
        PREV_BAN_COUNT=$(grep -c "BANNED:" "$BAN_LOG" 2>/dev/null || echo 0)
        PREV_BAN_COUNT="${PREV_BAN_COUNT//[^0-9]/}"; PREV_BAN_COUNT="${PREV_BAN_COUNT:-0}"
    fi
    local PREV_RX=0 PREV_TX=0 PREV_TIME=0
    local RESET_TIME; RESET_TIME=$(date '+%H:%M:%S')

    clear
    while true; do
        # ── Non-blocking key check ──────────────────────────
        read -t 0.8 -n 1 K 2>/dev/null || true
        [ "$K" = "q" ] || [ "$K" = "Q" ] && break
        if [ "$K" = "r" ] || [ "$K" = "R" ]; then
            PREV_BAN_COUNT=$(grep -c "BANNED:" "$BAN_LOG" 2>/dev/null || echo 0)
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
            ACTIVE_CONNS=$(ss -tnp 2>/dev/null | grep -c ":$PORT " || echo 0)
            ACTIVE_CONNS="${ACTIVE_CONNS//[^0-9]/}"; ACTIVE_CONNS="${ACTIVE_CONNS:-0}"
        fi
        local TOTAL_CONNS=0
        TOTAL_CONNS=$(ss -tn 2>/dev/null | grep -c ESTAB || echo 0)
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
            CUR_BAN_COUNT=$(grep -c "BANNED:" "$BAN_LOG" 2>/dev/null || echo 0)
            CUR_BAN_COUNT="${CUR_BAN_COUNT//[^0-9]/}"
            CUR_BAN_COUNT="${CUR_BAN_COUNT:-0}"
        fi
        local _DIFF=$(( CUR_BAN_COUNT - PREV_BAN_COUNT ))
        [ "$_DIFF" -lt 0 ] 2>/dev/null && _DIFF=0
        NEW_BANS_SINCE=$_DIFF

        # ── iptables drops ──────────────────────────────────
        local DROP_RULES=0 SYNPROXY_HIT=0
        DROP_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "^DROP" 2>/dev/null || echo 0)
        DROP_RULES="${DROP_RULES//[^0-9]/}"; DROP_RULES="${DROP_RULES:-0}"
        if [ -f /proc/net/stat/synproxy ]; then
            SYNPROXY_HIT=$(awk 'NR>1{s+=$8}END{print s+0}' /proc/net/stat/synproxy 2>/dev/null || echo 0)
            SYNPROXY_HIT="${SYNPROXY_HIT//[^0-9]/}"; SYNPROXY_HIT="${SYNPROXY_HIT:-0}"
        fi

        # ── Currently blocked attackers (REAL: from iptables DROP rules that
        #    auto-ban/subnet-ban actually inserted; never the server's own IP) ──
        local CUR_BANNED
        CUR_BANNED=$(iptables -L INPUT -n 2>/dev/null | \
            grep -E 'auto-ban|subnet-ban' | \
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?' | \
            grep -v '^0\.0\.0\.0' | sort -u | head -6)

        # ── Currently throttled (reputation-suspected, pre-ban) ──
        local CUR_THROTTLED
        CUR_THROTTLED=$(awk '{print $1}' /tmp/autoban_throttle 2>/dev/null | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -4)

        # ── Recently banned IPs (last 8 from log) ───────────
        local RECENT_BANS=""
        [ -f "$BAN_LOG" ] && RECENT_BANS=$(grep "BANNED:" "$BAN_LOG" 2>/dev/null | \
            tail -8 | awk '{print $1,$2,$NF}' | sed 's/^/  /')

        # ── Currently throttled ─────────────────────────────
        local THROTTLED=0
        if [ -f /tmp/autoban_throttle ]; then
            THROTTLED=$(wc -l < /tmp/autoban_throttle 2>/dev/null || echo 0)
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
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
        case "$CH" in
            1) less +G /var/log/3proxy/access.log 2>/dev/null || \
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
        draw_header; echo -e "  ${C}${BOLD}Security${NC}"; echo ""
        echo -e "  ${C}1.${NC} Blocked IPs (all)       ${C}2.${NC} Block IP"
        echo -e "  ${C}3.${NC} Unblock IP              ${C}4.${NC} iptables rules"
        echo -e "  ${C}5.${NC} SSH brute force          ${C}6.${NC} Auto-ban status"
        echo -e "  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
        case "$CH" in
             1) clear 2>/dev/null || true
               echo -e "  ${C}fail2ban bans:${NC}"
               fail2ban-client status 2>/dev/null | grep "Jail list" | \
                   sed 's/.*://g' | tr ',' '\n' | while read -r j; do
                   j=$(echo "$j" | tr -d ' '); [ -z "$j" ] && continue
                   BCOUNT=$(fail2ban-client status "$j" 2>/dev/null | \
                       grep "Banned IP" | grep -oP '\d+$' || echo 0)
                   [ "${BCOUNT:-0}" -gt 0 ] && echo -e "  ${Y}$j${NC}: $BCOUNT IPs"
               done
               echo ""
               echo -e "  ${C}iptables DROP rules:${NC}"
               iptables -L INPUT -n 2>/dev/null | grep DROP | \
                   grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | \
                   while read -r ip; do echo -e "  ${R}$ip${NC}"; done | head -30
               press_enter ;;
            2) echo -e "  ${C}Block IP${NC}"; echo ""
               printf '%s' "  Enter IP or CIDR to block (e.g. 1.2.3.4 or 1.2.3.0/24): " >/dev/tty; read -r BIP </dev/tty || BIP=""
               [ -n "$BIP" ] && iptables -I INPUT -s "$BIP" -j DROP 2>/dev/null && \
                   ok "$BIP blocked" || warn "No IP entered"
               press_enter ;;
            3) echo -e "  ${C}Unblock IP${NC}"; echo ""
               printf '%s' "  Enter IP to unblock: " >/dev/tty; read -r UIP </dev/tty || UIP=""
               [ -n "$UIP" ] && {
                   iptables -D INPUT -s "$UIP" -j DROP 2>/dev/null && ok "iptables: unblocked" || true
                   # Remove from auto-ban if running
                   [ -f /opt/proxy-manager/auto-ban.sh ] && {
                       # Remove ONLY this IP's throttle filter (never 'parent 1:'
                       # bare — that deletes every filter incl. the CF whitelist).
                       local _IFP _PRIO
                       _IFP=$(ip route show default | awk '/default/{print $5}' | head -1)
                       _PRIO=$(grep -F "$UIP " /tmp/autoban_throttle 2>/dev/null | \
                               awk '{print $2}' | head -1 || true)
                       [ -n "$_PRIO" ] && tc filter del dev "$_IFP" parent 1: prio "$_PRIO" 2>/dev/null || true
                       sed -i "/^$UIP /d" /tmp/autoban_throttle 2>/dev/null || true
                   }
                   fail2ban-client status 2>/dev/null | grep "Jail list" | \
                       sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r j; do
                       [ -z "$j" ] && continue
                       fail2ban-client set "$j" unbanip "$UIP" 2>/dev/null && \
                           ok "fail2ban $j: unblocked" || true
                   done
               }
               press_enter ;;
            4) iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -40; press_enter ;;
            5) grep 'Failed password\|Invalid user' /var/log/auth.log 2>/dev/null | \
               grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -15 | \
               awk '{printf "  %-8s %s\n", $1, $2}'
               press_enter ;;
            6) # Auto-ban status
               if systemctl is-active auto-ban >/dev/null 2>&1; then
                   echo -e "  ${G}● auto-ban: Running${NC}"
                   BANS=$(grep -c "BANNED:" /var/log/auto-ban.log 2>/dev/null || echo 0)
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
            systemctl list-unit-files "${S}.service" >/dev/null 2>&1 && SERVICES+=("$S") || true
        done
        # Always show 3proxy and auto-ban even if not installed yet
        for S in 3proxy auto-ban; do
            printf '%s\n' "${SERVICES[@]}" | grep -qx "$S" || SERVICES+=("$S")
        done
        draw_header; echo -e "  ${C}${BOLD}Services${NC}"; echo ""
        for i in "${!SERVICES[@]}"; do
            printf "  ${C}%d.${NC}  %-20s %s  %s\n" "$((i+1))" \
                "${SERVICES[$i]}" \
                "$(svc_status "${SERVICES[$i]}")" \
                "$(svc_enabled "${SERVICES[$i]}")"
        done
        echo ""; sep2
        echo -e "  ${C}a.${NC} Start all   ${C}z.${NC} Restart all   ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
        if [[ "$CH" =~ ^[0-9]+$ ]] && [ "$CH" -ge 1 ] && [ "$CH" -le "${#SERVICES[@]}" ]; then
            SVC="${SERVICES[$((CH-1))]}"
            clear; echo -e "  ${C}${BOLD}$SVC${NC}  $(svc_status "$SVC")"; echo ""
            echo -e "  ${C}1.${NC} Start   ${C}2.${NC} Stop   ${C}3.${NC} Restart   ${C}4.${NC} Status   ${C}0.${NC} Back"
            echo ""; sep2
            printf '%s' "  Choice: " >/dev/tty; read -r A </dev/tty || A=""
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

# ── System Menu ───────────────────────────────────────────
menu_system() {
    while true; do
        draw_header; echo -e "  ${C}${BOLD}System${NC}"; echo ""
        echo -e "  ${C}1.${NC} Server info    ${C}2.${NC} Update"
        echo -e "  ${C}3.${NC} Clean logs     ${C}4.${NC} Reboot"
        echo -e "  ${C}5.${NC} Backup config  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
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
               printf '%s' "  Update system packages? (y/N): " >/dev/tty; read -r _UC </dev/tty || _UC=""
               if [[ "$_UC" == "y" || "$_UC" == "Y" ]]; then
                   command -v apt-get >/dev/null && apt-get update -y && apt-get upgrade -y || yum update -y
                   ok "Update complete"
               else
                   echo -e "  ${DIM}Cancelled.${NC}"
               fi
               press_enter ;;
            3) BEFORE=$(df / 2>/dev/null | awk 'NR==2{print $3}' || echo 0)
               journalctl --vacuum-size=100M 2>/dev/null || true
               find /var/log -name "*.gz" -mtime +3 -delete 2>/dev/null || true
               apt-get clean 2>/dev/null || true
               AFTER=$(df / 2>/dev/null | awk 'NR==2{print $3}' || echo 0)
               ok "Freed: $(echo "scale=1; (${BEFORE:-0}-${AFTER:-0})/1024" | bc 2>/dev/null || echo '?') MB"
               press_enter ;;
            4) echo ""
               printf '%s' "  Reboot server now? (y/N): " >/dev/tty; read -r _RBC </dev/tty || _RBC=""
               if [[ "$_RBC" == "y" || "$_RBC" == "Y" ]]; then
                   ok "Rebooting in 5 seconds..."
                   sleep 5 && reboot
               else
                   echo -e "  ${DIM}Cancelled.${NC}"; press_enter
               fi ;;
            5) BACKUP="/root/proxy-manager-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
               tar -czf "$BACKUP" \
                   /etc/3proxy/ \
                   /etc/antiddos/ \
                   /etc/fail2ban/jail.d/ \
                   /etc/sysctl.d/ \
                   /opt/proxy-manager/ \
                   2>/dev/null || true
               ok "Backup saved: $BACKUP"
               press_enter ;;
            0) return ;;
        esac
    done
}

# ── Anti-DDoS Menu ────────────────────────────────────────
menu_antiddos() {
    while true; do
        draw_header
        echo -e "  ${C}${BOLD}Anti-DDoS Protection${NC}"; echo ""

        # Status at a glance
        if [ -f /etc/antiddos/state.conf ]; then
            echo -e "  Status  : ${G}✓ Installed & Active${NC}"
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
            iptables -L INPUT -n 2>/dev/null | grep -qE 'cf_whitelist|hashlimit|syn_flood|SYNPROXY' && \
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

        echo ""; sep2
        echo -e "  ${G}1.${NC}  Install / Re-install all layers"
        echo -e "  ${C}2.${NC}  Status & active bans"
        echo -e "  ${C}3.${NC}  Unban an IP"
        echo -e "  ${C}4.${NC}  Auto-ban control (start/stop/log)"
        echo -e "  ${Y}5.${NC}  Remove all protection"
        echo -e "  ${C}0.${NC}  Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
        case "$CH" in
            1) _antiddos_install ;;
            2) bash "$ANTIDDOS_SCRIPT" --status < /dev/tty; press_enter ;;
            3) echo -e "  ${C}Unban IP${NC}"; echo ""
               printf '%s' "  Enter IP to unban (removes from iptables + fail2ban): " >/dev/tty; read -r UIP </dev/tty || UIP=""
               [ -n "$UIP" ] && {
                   iptables -D INPUT -s "$UIP" -j DROP 2>/dev/null && ok "iptables: unblocked" || true
                   [ -f /etc/antiddos/banned.list ] && \
                       sed -i "/$UIP/d" /etc/antiddos/banned.list 2>/dev/null || true
                   fail2ban-client status 2>/dev/null | grep "Jail list" | \
                       sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r j; do
                       [ -z "$j" ] && continue
                       fail2ban-client set "$j" unbanip "$UIP" 2>/dev/null && \
                           ok "fail2ban $j: unblocked" || true
                   done
                   ok "$UIP unblocked (all layers)"
               } || warn "No IP entered"
               press_enter ;;
            4) _autoban_control ;;
            5) echo ""
               echo -e "  ${R}${BOLD}⚠  Remove ALL Anti-DDoS Protection${NC}"
               echo -e "  ${DIM}This will remove: iptables rules, sysctl hardening, fail2ban jails,"
               echo -e "  auto-ban service, tc bandwidth shaping, and boot persistence.${NC}"
               echo ""
               printf '%s' "  Are you sure? (y/N): " >/dev/tty; read -r _RMCONF </dev/tty || _RMCONF=""
               if [[ "$_RMCONF" == "y" || "$_RMCONF" == "Y" ]]; then
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
    echo -e "  ${C}[5/5]${NC} Bandwidth cap    — unlimited for CF, 500Mbps for others"
    echo ""
    echo -e "  ${DIM}Cloudflare IPs are never affected by any limit.${NC}"
    echo ""
    if [ -f /etc/antiddos/state.conf ]; then
        echo -e "  ${Y}⚠  Already installed — re-installing will refresh all rules.${NC}"
        echo ""
    fi
    sep2
    printf '%s' "  Start installation? (y/N): " >/dev/tty; read -r CF_I </dev/tty || CF_I=""
    [[ "$CF_I" != "y" && "$CF_I" != "Y" ]] && echo -e "  ${DIM}Cancelled.${NC}" && return

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
    sep
    press_enter
}

_autoban_control() {
    while true; do
        clear; sep
        echo -e "  ${C}Auto-ban Control${NC}"; sep
        echo -e "  Status: $(svc_status 'auto-ban')"
        echo ""
        echo -e "  ${C}1.${NC} Start auto-ban"
        echo -e "  ${C}2.${NC} Stop auto-ban"
        echo -e "  ${C}3.${NC} View log (last 30)"
        echo -e "  ${C}4.${NC} Current banned IPs"
        echo -e "  ${C}5.${NC} Flush all auto-bans"
        echo -e "  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
        case "$CH" in
            1) systemctl start auto-ban 2>/dev/null && ok "auto-ban started" || err "Failed (not installed?)"
               press_enter ;;
            2) systemctl stop auto-ban 2>/dev/null && ok "auto-ban stopped"
               press_enter ;;
            3) tail -30 /var/log/auto-ban.log 2>/dev/null || warn "Log not found"
               press_enter ;;
            4) echo -e "  ${C}Currently banned IPs:${NC}"
               [ -f /etc/antiddos/banned.list ] && cat /etc/antiddos/banned.list 2>/dev/null || \
               iptables -L INPUT -n 2>/dev/null | grep DROP | \
                   grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | head -30 | \
                   while read -r ip; do echo -e "  ${R}$ip${NC}"; done
               press_enter ;;
            5) echo -e "  ${Y}Flushing all auto-ban blocks...${NC}"
               # Delete by matching rule content (safe: line numbers shift after each delete)
               while iptables -L INPUT -n 2>/dev/null | grep -q '"auto-ban"'; do
                   iptables -D INPUT \
                       "$(iptables -L INPUT -n --line-numbers 2>/dev/null | \
                          grep '"auto-ban"' | awk '{print $1}' | head -1)" \
                       2>/dev/null || break
               done
               [ -f /etc/antiddos/banned.list ] && : > /etc/antiddos/banned.list
               [ -f /tmp/autoban_throttle ]     && : > /tmp/autoban_throttle
               [ -f /tmp/autoban_watch ]        && : > /tmp/autoban_watch
               ok "All auto-bans flushed"
               press_enter ;;
            0) return ;;
        esac
    done
}

# ── Main Menu ─────────────────────────────────────────────
log "START: proxy manager v$VERSION"
while true; do
    draw_header
    echo -e "  ${C}${BOLD}Main Menu${NC}"; echo ""

    # Show inline status for key items
    _PROXY_ST="$(systemctl is-active 3proxy 2>/dev/null)"
    _DDOS_ST="$([ -f /etc/antiddos/state.conf ] && echo 'active' || echo 'inactive')"
    _NET_ST="$([ -f /etc/sysctl.d/99-vpn-optimized.conf ] && echo 'active' || echo 'inactive')"

    [ "$_PROXY_ST" = "active" ] && _P="${G}● Running${NC}" || _P="${Y}○ Not running${NC}"
    [ "$_DDOS_ST"  = "active" ] && _D="${G}● Active${NC}"  || _D="${Y}○ Not installed${NC}"
    [ "$_NET_ST"   = "active" ] && _N="${G}● Optimized${NC}" || _N="${Y}○ Default${NC}"

    echo -e "  ${C}1.${NC}  SOCKS5 Proxy         $_P"
    echo -e "  ${C}2.${NC}  Network Optimization $_N"
    echo -e "  ${C}3.${NC}  Anti-DDoS            $_D"
    echo -e "  ${C}4.${NC}  Monitoring"
    echo -e "  ${C}5.${NC}  Security"
    echo -e "  ${C}6.${NC}  Services"
    echo -e "  ${C}7.${NC}  System"
    echo -e "  ${C}0.${NC}  Exit"; echo ""
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) menu_proxy ;;
        2) menu_sysctl ;;
        3) menu_antiddos ;;
        4) menu_monitor ;;
        5) menu_security ;;
        6) menu_services ;;
        7) menu_system ;;
        0) clear; exit 0 ;;
    esac
done
