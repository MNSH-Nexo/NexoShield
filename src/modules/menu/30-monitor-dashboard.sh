# @part modules/menu/30-monitor-dashboard.sh - _monitor_dashboard + _monitor_logs
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
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
        ui_input CH "  Enter number: "
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
