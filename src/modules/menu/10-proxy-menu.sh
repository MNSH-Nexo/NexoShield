# @part modules/menu/10-proxy-menu.sh - menu_proxy + stats/password/suspicious sub-screens
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
menu_proxy() {
    while true; do
        ui_title "SOCKS5 Proxy (3proxy)"
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
        echo ""
        ui_options "1|Install/Update" "2|Remove" "3|Start" "4|Stop" \
            "5|Restart" "6|Live log" "7|Traffic stats" "8|Change password" \
            "9|Suspicious IPs" "0|Back"
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
            9) _proxy_suspicious ;;
            0) return ;;
        esac
    done
}



_proxy_suspicious() {
    clear; echo -e "  ${C}Threat IPs (real blocked/throttled attackers)${NC}"; echo ""
    echo -e "  ${DIM}These are actual attackers auto-ban has blocked or throttled,"${NC}
    echo -e "  ${DIM}not your normal heavy users.${NC}"; sep2

    # U-1 (UI redesign): state files are the source of truth. The old
    # code scraped iptables -L for bans and read throttles from
    # /tmp/autoban_throttle - a path nothing in the product writes,
    # so the throttled section was permanently empty.
    local _banned=""
    _banned=$(awk '{print $1}' "$NX_STATE_DIR/banned.list" 2>/dev/null | head -20)
    local _throttled=""
    _throttled=$(awk '{print $1}' "$NX_STATE_DIR/throttled.list" 2>/dev/null | head -10)

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
