# @part modules/menu/60-autoban-main.sh - _autoban_control + main menu loop
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
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
