# @part modules/menu/40-security-services-system.sh - menu_security, menu_services, menu_system
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
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
                   # daemon's next reconcile.
                   nx_unban_ip "$UIP"
                   ok "$UIP unblocked (all layers)"
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
       ! grep -q "^VERSION=\"$_latest\"" "$_tmp/install.sh"; then
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
    ok "Updated to NexoShield v$_latest."
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
