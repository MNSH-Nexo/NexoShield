# @part modules/menu/10-proxy-menu.sh - menu_proxy + stats/password/suspicious sub-screens
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
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
        BANNED_COUNT=$(cnt "BANNED:" /var/log/auto-ban.log)
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
    if [ -z "$NP" ]; then
        NP=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16)
        if [ -z "$NP" ]; then
            warn "Failed to generate a secure password (/dev/urandom unavailable)"
            press_enter
            return 1
        fi
    fi
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
