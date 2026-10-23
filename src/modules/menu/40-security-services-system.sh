# @part modules/menu/40-security-services-system.sh - menu_security, menu_services, menu_system
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
menu_security() {
    while true; do
        ui_title "Security"
        echo -e "  ${C}1.${NC} Blocked IPs (all)       ${C}2.${NC} Block IP"
        echo -e "  ${C}3.${NC} Unblock IP              ${C}4.${NC} iptables rules"
        echo -e "  ${C}5.${NC} SSH brute force          ${C}6.${NC} Auto-ban status"
        echo -e "  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        ui_input CH "  Enter number: "
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
            systemctl list-unit-files "${S}.service" >/dev/null 2>&1 && SERVICES+=("$S") || true
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

# ── System Menu ───────────────────────────────────────────
menu_system() {
    while true; do
        ui_title "System"
        echo -e "  ${C}1.${NC} Server info    ${C}2.${NC} Update"
        echo -e "  ${C}3.${NC} Clean logs     ${C}4.${NC} Reboot"
        echo -e "  ${C}5.${NC} Backup config  ${C}0.${NC} Back"; echo ""
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
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
               ui_input _UC "  Update system packages? (y/N): "
               if [[ "$_UC" == "y" || "$_UC" == "Y" ]]; then
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
               ui_input _RBC "  Reboot server now? (y/N): "
               if [[ "$_RBC" == "y" || "$_RBC" == "Y" ]]; then
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
