# @part modules/menu/20-sysctl-monitor-menus.sh - menu_sysctl + menu_monitor
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
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

