# @part modules/menu/60-autoban-main.sh - _autoban_control + main menu loop
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
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
case "${1:-}" in
    --status)  nx_status_plain; exit 0 ;;
    --bans)    nx_bans_plain; exit 0 ;;
    --version) echo "NexoShield v$VERSION"; exit 0 ;;
    --help)    echo "Usage: proxy-menu.sh [--status|--bans|--version]  (no flag = interactive menu)"; exit 0 ;;
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
