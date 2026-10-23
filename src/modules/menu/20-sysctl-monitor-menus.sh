# @part modules/menu/20-sysctl-monitor-menus.sh - menu_sysctl + menu_monitor
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
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

