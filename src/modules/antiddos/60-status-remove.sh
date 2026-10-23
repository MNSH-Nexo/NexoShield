# @part modules/antiddos/60-status-remove.sh - show_status, remove_rules, do_install
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
show_status() {
    sep; echo -e "  ${CYAN}${BOLD}Anti-DDoS Status${NC}"; sep

    echo -e "  ${DIM}iptables:${NC}"
    INPUT_RULES=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep -c "^[0-9]" || echo 0)
    CF_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "cf_whitelist" || echo 0)
    BANNED_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "auto-ban" || echo 0)
    echo -e "    INPUT rules  : ${WHITE}$INPUT_RULES${NC}  (CF whitelist: $CF_RULES, auto-ban: $BANNED_RULES)"

    if [ -d /proc/net/ipt_hashlimit ]; then
        echo -e "  ${DIM}hashlimit tables:${NC}"
        ls /proc/net/ipt_hashlimit 2>/dev/null | while read -r t; do
            COUNT=$(wc -l < "/proc/net/ipt_hashlimit/$t" 2>/dev/null || echo 0)
            echo -e "    ${CYAN}$t${NC}: ${WHITE}$COUNT IPs${NC}"
        done
    fi

    if [ -f /proc/net/nf_conntrack ]; then
        CURR=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo 0)
        CURR="${CURR//[^0-9]/}"; CURR="${CURR:-0}"
        MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 1)
        MAX="${MAX//[^0-9]/}"; MAX="${MAX:-1}"
        if [ "$MAX" -gt 0 ]; then
            PCT=$(awk "BEGIN{printf \"%.0f\", ${CURR}*100/${MAX}}")
        else
            PCT="?"
        fi
        echo -e "  ${DIM}conntrack:${NC} ${WHITE}$CURR${NC} / ${WHITE}$MAX${NC} (${PCT}%)"
    fi

    if command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "  ${DIM}fail2ban:${NC}"
        fail2ban-client status 2>/dev/null | grep "Jail list" | \
            sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r jail; do
            [ -z "$jail" ] && continue
            BANNED=$(fail2ban-client status "$jail" 2>/dev/null | \
                grep "Banned IP list" | sed 's/.*://;s/^ *//')
            COUNT=$(echo "$BANNED" | tr ' ' '\n' | grep -c '\.' 2>/dev/null | tr -d '\n' || echo 0)
            printf "    %-25s %s\n" "$jail:" "$COUNT IPs banned"
        done
    fi

    echo -e "  ${DIM}auto-ban service:${NC}"
    if systemctl is-active auto-ban >/dev/null 2>&1; then
        echo -e "    ${GREEN}● Running${NC}"
        BANS=$(grep -c "BANNED:" /var/log/auto-ban.log 2>/dev/null || echo 0)
        echo -e "    Total bans: $BANS"
        echo -e "    ${DIM}Last entries:${NC}"
        tail -5 /var/log/auto-ban.log 2>/dev/null | while read -r line; do
            echo "    $line"
        done
    else
        echo -e "    ${RED}○ Not running${NC}"
    fi

    echo -e "  ${DIM}tc bandwidth:${NC}"
    IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -n "$IF" ] && tc class show dev "$IF" 2>/dev/null | grep -q "1:10"; then
        echo -e "    ${GREEN}● Active${NC} (CF=unlimited, others=500Mbps, throttled=100Mbps)"
    else
        echo -e "    ${YELLOW}○ Not configured${NC}"
    fi

    echo -e "  ${DIM}kernel key params:${NC}"
    for P in net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter \
              net.ipv4.tcp_keepalive_time \
              net.netfilter.nf_conntrack_tcp_timeout_established \
              net.netfilter.nf_conntrack_tcp_timeout_syn_recv; do
        V=$(sysctl -n "$P" 2>/dev/null || echo "N/A")
        printf "    ${DIM}%-52s${NC} %s\n" "$P" "$V"
    done

    sep
    # shellcheck disable=SC1090  # STATE_FILE is a fixed path held in a variable
    [ -f "$STATE_FILE" ] && . "$STATE_FILE" 2>/dev/null && \
        echo -e "  ${GREEN}✓ Installed${NC} - $(grep '^DATE=' "$STATE_FILE" | cut -d= -f2-)" || \
        echo -e "  ${YELLOW}○ Not installed${NC}"
    sep
}

# ════════════════════════════════════════════════
# Remove all rules
# ════════════════════════════════════════════════
remove_rules() {
    sep; echo -e "  ${RED}Removing Anti-DDoS rules...${NC}"
    # CONF_R can be pre-set by --remove-force to skip prompt
    if [[ "${CONF_R:-}" != "y" && "${CONF_R:-}" != "Y" ]]; then
        printf '%s' "  Are you sure? This will remove ALL protection. (y/N): " >/dev/tty; read -r CONF_R </dev/tty || CONF_R=""
    fi
    [[ "$CONF_R" != "y" && "$CONF_R" != "Y" ]] && echo -e "  ${DIM}Cancelled.${NC}" && return

    # Sysctl
    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true
    success "Kernel hardening: removed"

    # iptables — delete by content match (line numbers shift after each delete, so loop)
    MATCH_PAT="hashlimit\|SYNPROXY\|connlimit\|cf_whitelist\|auto-ban\|self_whitelist\|user_whitelist\|syn_flood\|udp_flood\|icmp_flood\|rst_flood\|bw_per_ip\|new_conn_rate\|http_req_rate"
    for TABLE in INPUT FORWARD; do
        while iptables -L "$TABLE" -n 2>/dev/null | grep -qE "$MATCH_PAT"; do
            RNUM=$(iptables -L "$TABLE" -n --line-numbers 2>/dev/null | \
                  grep -E "$MATCH_PAT" | awk '{print $1}' | head -1 || true)
            [ -z "$RNUM" ] && break
            iptables -D "$TABLE" "$RNUM" 2>/dev/null || break
        done
    done
    # raw table
    while iptables -t raw -L PREROUTING -n 2>/dev/null | grep -qE "CT|notrack|cf_whitelist|self_whitelist|user_whitelist"; do
        RNUM=$(iptables -t raw -L PREROUTING -n --line-numbers 2>/dev/null | \
              grep -E "CT|notrack|ACCEPT" | awk '{print $1}' | head -1 || true)
        [ -z "$RNUM" ] && break
        iptables -t raw -D PREROUTING "$RNUM" 2>/dev/null || break
    done
    success "iptables rules: removed"

    # fail2ban
    rm -f "$F2B_JAIL_DIR/antiddos.conf"
    rm -f "$F2B_FILTER_DIR/3proxy-ddos.conf" \
          "$F2B_FILTER_DIR/http-flood.conf" \
          "$F2B_FILTER_DIR/conn-flood.conf" \
          "$F2B_FILTER_DIR/portscan.conf" \
          "$F2B_FILTER_DIR/xray-proxy.conf"
    systemctl reload fail2ban 2>/dev/null || true
    success "fail2ban jails: removed"

    # Auto-ban
    systemctl stop auto-ban.service 2>/dev/null || true
    systemctl disable auto-ban.service 2>/dev/null || true
    rm -f "$AUTOBAN_SERVICE"
    systemctl daemon-reload
    # Remove subnet-ban iptables rules
    iptables-save 2>/dev/null | grep '"subnet-ban"' | \
        sed 's/^-A/iptables -D/' | bash 2>/dev/null || true
    # Clean temp files
    rm -f /tmp/autoban_watch /tmp/autoban_throttle /tmp/autoban_subnet_watch 2>/dev/null || true
    success "Auto-ban service: removed"

    # tc
    IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    [ -n "$IF" ] && tc qdisc del dev "$IF" root 2>/dev/null || true
    systemctl disable tc-proxy-limit.service 2>/dev/null || true
    rm -f /etc/systemd/system/tc-proxy-limit.service
    rm -f /etc/network/if-up.d/tc-proxy-limit
    success "tc bandwidth control: removed"

    # Persistence
    systemctl disable antiddos-restore.service 2>/dev/null || true
    rm -f /etc/systemd/system/antiddos-restore.service
    systemctl daemon-reload
    rm -f "$STATE_FILE"
    success "All Anti-DDoS rules removed."
}

# ════════════════════════════════════════════════
# Full install
# ════════════════════════════════════════════════
do_install() {
    sep; echo -e "  ${CYAN}${BOLD}Anti-DDoS Full Install v${SCRIPT_VERSION}${NC}"; sep
    echo -e "  ${DIM}RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | Virt: ${VIRT_TYPE} | IF: ${MAIN_IF}${NC}"
    echo -e "  ${DIM}SYNPROXY: $([ $SYNPROXY_OK -eq 1 ] && echo 'YES' || echo 'NO')  hashlimit: $([ $HASHLIMIT_OK -eq 1 ] && echo 'YES' || echo 'NO')  conntrack: $([ $CONNTRACK_OK -eq 1 ] && echo 'YES' || echo 'NO')${NC}"
    echo -e "  ${DIM}Public IPs: $PUBLIC_IP_COUNT  (rp_filter: $([ "${PUBLIC_IP_COUNT:-0}" -gt 1 ] && echo '0' || echo '1'))${NC}"
    echo ""
    echo -e "  Layers to install:"
    echo -e "    ${CYAN}1.${NC} Kernel sysctl  (keepalive=30s, conntrack tight timeouts)"
    echo -e "    ${CYAN}2.${NC} iptables       (CF whitelist first, then rate-limits)"
    echo -e "    ${CYAN}3.${NC} fail2ban       (3proxy-ddos/portscan/sshd/xray)"
    echo -e "    ${CYAN}4.${NC} Smart ban      (watch->throttle->ban pipeline)"
    echo -e "    ${CYAN}5.${NC} tc bandwidth   (CF=unlimited, others=500Mbps)"
    echo -e "    ${CYAN}6.${NC} Boot persist   (systemd + iptables-persistent)"
    echo ""
    printf '%s' "  Continue? (y/N): " >/dev/tty
    read -r CF_I </dev/tty || CF_I=""
    [[ "$CF_I" != "y" && "$CF_I" != "Y" ]] && return

    apply_sysctl_hardening
    apply_iptables
    apply_fail2ban
    setup_autoban
    setup_tc
    setup_persistence

    cat > "$STATE_FILE" << EOF
DATE=$(date)
VERSION=${SCRIPT_VERSION}
VIRT_TYPE=${VIRT_TYPE}
RAM_MB=${RAM_MB}
SYNPROXY=${SYNPROXY_OK}
HASHLIMIT=${HASHLIMIT_OK}
MAIN_IF=${MAIN_IF}
EOF

    sep
    success "Anti-DDoS installation complete!"
    echo ""
    echo -e "  ${CYAN}Protection summary:${NC}"
    echo -e "    ${GREEN}✓${NC}  SYN Flood   - $([ $SYNPROXY_OK -eq 1 ] && echo 'SYNPROXY (kernel)' || echo 'hashlimit')"
    echo -e "    ${GREEN}✓${NC}  UDP Flood   - hashlimit per-IP + amplification blocked"
    echo -e "    ${GREEN}✓${NC}  ICMP Flood  - rate-limited per source"
    echo -e "    ${GREEN}✓${NC}  Port Scans  - NULL/XMAS/FIN/bogus dropped"
    echo -e "    ${GREEN}✓${NC}  RST Flood   - rate-limited"
    echo -e "    ${GREEN}✓${NC}  Smart Ban   - watch(45s)->throttle(100M)->ban(4h)"
    echo -e "    ${GREEN}✓${NC}  CF Users    - ALWAYS unlimited, never throttled/banned"
    echo -e "    ${GREEN}✓${NC}  Bandwidth   - CF=unlimited, non-CF=500Mbps max"
    echo -e "    ${GREEN}✓${NC}  Slowloris   - keepalive_time=30s"
    echo -e "    ${GREEN}✓${NC}  fail2ban    - 3proxy/portscan/sshd/xray jails"
    sep
}

