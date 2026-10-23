# @part modules/menu/50-antiddos-menu.sh - menu_antiddos + _antiddos_install
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
menu_antiddos() {
    while true; do
        ui_title "Anti-DDoS Protection"

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

        echo ""
        ui_options "1|Install / Re-install all layers" "2|Status & active bans" \
            "3|Unban an IP" "4|Auto-ban control (start/stop/log)" \
            "5|Remove all protection" "0|Back"
        ui_input CH "  Enter number: "
        case "$CH" in
            1) _antiddos_install ;;
            2) bash "$ANTIDDOS_SCRIPT" --status < /dev/tty; press_enter ;;
            3) echo -e "  ${C}Unban IP${NC}"; echo ""
               ui_input UIP "  Enter IP to unban (removes from iptables + fail2ban): "
               [ -n "$UIP" ] && {
                   # Exact deletes (BUG-038): match the tagged specs the
                   # daemon creates; state edit by exact field 1 (the
                   # old substring sed also removed 11.2.3.4's entry
                   # when unbanning 1.2.3.4).
                   iptables -D INPUT -s "$UIP" -m comment --comment "auto-ban" -j DROP 2>/dev/null || \
                   iptables -D INPUT -s "$UIP" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || \
                   iptables -D INPUT -s "$UIP" -j DROP 2>/dev/null || true
                   ok "iptables: unblocked"
                   if [ -f /etc/antiddos/banned.list ]; then
                       awk -v x="$UIP" '$1!=x' /etc/antiddos/banned.list > /etc/antiddos/banned.list.tmp 2>/dev/null && \
                           mv /etc/antiddos/banned.list.tmp /etc/antiddos/banned.list
                   fi
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
    echo -e "  ${C}[5/5]${NC} Bandwidth cap    — unlimited for CF, 500Mbps for others"
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
    sep
    press_enter
}

