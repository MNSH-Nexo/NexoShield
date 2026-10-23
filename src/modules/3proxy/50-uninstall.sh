# @part modules/3proxy/50-uninstall.sh - uninstall_proxy
# Assembled into 3proxy-socks5.sh by tools/build.py - not a standalone script.
uninstall_proxy() {
    sep; echo -e "${RED}Removing 3proxy...${NC}"; sep

    echo -e "${YELLOW}Stopping services...${NC}"

    # ── Stop & disable 3proxy ─────────────────────────────
    systemctl stop    3proxy 2>/dev/null || true
    systemctl disable 3proxy 2>/dev/null || true
    # Also stop any apt-installed 3proxy
    systemctl stop    3proxy.service 2>/dev/null || true

    # ── Stop & disable autoban ────────────────────────────
    systemctl stop    auto-ban  2>/dev/null || true
    systemctl disable auto-ban  2>/dev/null || true
    systemctl stop    auto-ban.service 2>/dev/null || true
    pkill -f "auto-ban.sh" 2>/dev/null || true

    # ── Stop & disable tc service ─────────────────────────
    systemctl stop    tc-proxy-limit  2>/dev/null || true
    systemctl disable tc-proxy-limit  2>/dev/null || true

    # ── Detect port before removing config ────────────────
    PORT=$(get_current_port 2>/dev/null || true)
    # Fallback: read from install.info
    if [ -z "$PORT" ] && [ -f /etc/3proxy/install.info ]; then
        PORT=$(grep -oP '(?<=^PORT=)\d+' /etc/3proxy/install.info 2>/dev/null | head -1 || true)
    fi

    # ── Remove iptables rules ─────────────────────────────
    if [ -n "$PORT" ]; then
        echo -e "${YELLOW}Cleaning iptables rules for port $PORT...${NC}"
        # CF-specific port rules (delete spec mirrors create, incl. the
        # comment match - BUG-013)
        for CF in "${CF_RANGES[@]}"; do
            [[ "$CF" == *":"* ]] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" \
                -m comment --comment "3proxy_cf_allow" -j ACCEPT 2>/dev/null || true
        done
        # User-whitelist rules for this port (Wave 1 create; remove here)
        if [ -f /etc/antiddos/whitelist.list ]; then
            while IFS= read -r WIP; do
                WIP="${WIP%%#*}"; WIP="${WIP// /}"
                [ -z "$WIP" ] && continue
                iptables -D INPUT -p tcp --dport "$PORT" -s "$WIP" \
                    -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
            done < /etc/antiddos/whitelist.list
        fi
        # Self-IP rules for this port
        while IFS= read -r SIP; do
            [ -z "$SIP" ] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
                -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
        done < <(get_server_ips)
        # Rate-limit rules for this port - by enumeration (BUG-014: the
        # hitcount was MAX_CONN*3 at create, not a fixed 60)
        local _rn
        for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_${PORT}" | cut -d: -f1 | sort -rn); do
            iptables -D INPUT $((_rn - 1)) 2>/dev/null || true
        done
        # connlimit rule for this port
        iptables -D INPUT -p tcp --dport "$PORT" \
            -m connlimit --connlimit-above 30 --connlimit-mask 32 \
            -j REJECT --reject-with tcp-reset 2>/dev/null || true
        # hashlimit rules for this port
        iptables -D INPUT -p tcp --dport "$PORT" \
            -m conntrack --ctstate NEW \
            -m hashlimit --hashlimit-above 200/min --hashlimit-burst 50 \
            --hashlimit-mode srcip --hashlimit-name "proxy_${PORT}" -j DROP 2>/dev/null || true
        # Stats counters
        iptables -D INPUT  -p tcp --dport "$PORT" \
            -m comment --comment "3proxy_stats_in"  2>/dev/null || true
        iptables -D OUTPUT -p tcp --sport "$PORT" \
            -m comment --comment "3proxy_stats_out" 2>/dev/null || true
        # Plain ACCEPT rule
        iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
        # UFW / firewalld
        command -v ufw >/dev/null 2>&1 && ufw delete allow "$PORT"/tcp 2>/dev/null || true
        command -v firewall-cmd >/dev/null 2>&1 && {
            firewall-cmd --remove-port="${PORT}/tcp" --permanent 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
        }
    else
        echo -e "${YELLOW}⚠ Could not detect port — skipping port-specific iptables rules${NC}"
    fi

    # Remove auto-ban iptables rules (tagged with "auto-ban")
    iptables -S INPUT 2>/dev/null | grep '"auto-ban"' | while read -r rule; do
        # shellcheck disable=SC2086  # intentional: $rule expands to multiple iptables arguments
        iptables -D INPUT ${rule#-A INPUT } 2>/dev/null || true
    done

    # ── Remove tc bandwidth shaping ───────────────────────
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    MAIN_IF=${MAIN_IF:-eth0}
    tc qdisc del dev "$MAIN_IF" root 2>/dev/null || true
    rm -f /etc/systemd/system/tc-proxy-limit.service
    rm -f /etc/network/if-up.d/tc-proxy-limit
    rm -f /opt/proxy-manager/tc-setup.sh

    # ── Remove fail2ban jails for 3proxy ─────────────────
    rm -f /etc/fail2ban/jail.d/3proxy-ddos.conf   2>/dev/null || true
    rm -f /etc/fail2ban/jail.d/3proxy.conf        2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy-ddos.conf 2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy.conf      2>/dev/null || true
    command -v fail2ban-client >/dev/null 2>&1 && {
        fail2ban-client stop  3proxy-ddos 2>/dev/null || true
        fail2ban-client unban --all       2>/dev/null || true
        systemctl reload fail2ban 2>/dev/null || true
    }

    # ── Remove systemd service files ─────────────────────
    rm -f "$SERVICE_FILE"
    rm -f /etc/systemd/system/auto-ban.service
    rm -f /etc/systemd/system/tc-proxy-limit.service

    # ── Remove binary ─────────────────────────────────────
    # Only remove our binary — don't touch apt-installed one if it differs
    if [ -L "$PROXY_BIN" ]; then
        rm -f "$PROXY_BIN"   # it's a symlink we created
    elif [ -f "$PROXY_BIN" ]; then
        rm -f "$PROXY_BIN"   # compiled binary we installed
    fi

    # ── Remove config, logs, state ────────────────────────
    rm -rf /etc/3proxy
    rm -rf "$PROXY_LOG_DIR"
    rm -f  /etc/logrotate.d/3proxy
    rm -rf /etc/antiddos
    rm -rf /var/lib/antiddos
    rm -f  /var/log/antiddos.log
    rm -f  /tmp/autoban_watch /tmp/autoban_throttle /tmp/autoban_banned 2>/dev/null || true

    # ── Reload systemd ────────────────────────────────────
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed  2>/dev/null || true

    sep
    echo -e "${GREEN}✓ 3proxy and all related components removed.${NC}"
    echo -e "${YELLOW}  Note: Anti-DDoS iptables rules (SYN/UDP/connlimit) are kept${NC}"
    echo -e "${YELLOW}  to protect the server. Run 'antiddos --remove' to remove them too.${NC}"
    sep
    sleep 2
}

