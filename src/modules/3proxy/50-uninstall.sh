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

    # BUG-037: the auto-ban daemon belongs to the Anti-DDoS module, NOT
    # to 3proxy. It is not stopped, killed or removed here - uninstall
    # Anti-DDoS separately (antiddos.sh --remove) if you want it gone.

    # ── Stop & disable tc service ─────────────────────────
    # The tc setup is shared with Anti-DDoS; only remove it when the
    # Anti-DDoS module is not installed (BUG-015).
    if [ ! -f /etc/antiddos/state.conf ]; then
        systemctl stop    tc-proxy-limit  2>/dev/null || true
        systemctl disable tc-proxy-limit  2>/dev/null || true
    else
        echo -e "${CYAN}Anti-DDoS is installed - leaving shared tc setup in place.${NC}"
    fi

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
        done < <(list_self_ips_all)
        # Rate-limit rules for this port - by enumeration (BUG-014:
        # older versions created them with varying hitcounts)
        local _rn
        for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_${PORT}[^0-9]" | cut -d: -f1 | sort -rn); do
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

    # MED-2: the ruleset changed - rewrite the persistent saves from
    # the cleaned live state (same filter antiddos remove uses), or
    # the next boot resurrects the removed proxy rules. The
    # antiddos save is refreshed only if antiddos already owns one.
    if [ -d /etc/iptables ]; then
        iptables-save 2>/dev/null | grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    if [ -f /etc/antiddos/iptables-antiddos.rules ]; then
        iptables-save 2>/dev/null | grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' > /etc/antiddos/iptables-antiddos.rules 2>/dev/null || true
    fi

    # LOW-1: NO auto-ban cleanup here. The loop this replaces fed
    # `iptables -S` output (comments rendered quoted) through
    # word-splitting, so it never matched anything - and making it
    # work would mass-unban every daemon ban while the daemon keeps
    # running. Daemon bans belong to the daemon (BUG-037): it
    # expires them itself.

    # ── Remove tc bandwidth shaping ───────────────────────
    if [ ! -f /etc/antiddos/state.conf ]; then
        MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
        MAIN_IF=${MAIN_IF:-eth0}
        # LOW-13: the recorded pre-existing qdisc is dropped, not
        # restored - exact restore is infeasible from the one-line
        # record, so say so instead of silently dropping it.
        if [ -s /etc/antiddos/tc-qdisc-before.txt ]; then
            echo -e "${YELLOW}Note: the pre-existing qdisc ($(cat /etc/antiddos/tc-qdisc-before.txt 2>/dev/null)) is dropped on uninstall (exact restore is not possible from the one-line record).${NC}"
        fi
        tc qdisc del dev "$MAIN_IF" root 2>/dev/null || true
        rm -f /etc/systemd/system/tc-proxy-limit.service
        rm -f /etc/network/if-up.d/tc-proxy-limit
        rm -f /opt/proxy-manager/tc-setup.sh
    fi

    # ── Remove fail2ban jails for 3proxy ─────────────────
    rm -f /etc/fail2ban/jail.d/3proxy-ddos.conf   2>/dev/null || true
    rm -f /etc/fail2ban/jail.d/3proxy.conf        2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy-ddos.conf 2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy.conf      2>/dev/null || true
    command -v fail2ban-client >/dev/null 2>&1 && {
        fail2ban-client stop  3proxy-ddos 2>/dev/null || true
        # BUG-060: NO "unban --all" here - it released EVERY fail2ban
        # ban on the box (sshd brute-forcers included), not just ours.
        systemctl reload fail2ban 2>/dev/null || true
    }

    # ── Restore apt sources if the mirror was opted into (BUG-016) ──
    if [ -f /etc/apt/sources.list.bak ]; then
        mv /etc/apt/sources.list.bak /etc/apt/sources.list 2>/dev/null || true
        for _bak in /etc/apt/sources.list.d/*.bak; do
            [ -e "$_bak" ] && mv "$_bak" "${_bak%.bak}" 2>/dev/null || true
        done
        echo -e "${GREEN}Original apt sources restored from backup.${NC}"
    fi

    # ── Remove traffic accumulator (v3.17.0) ─────────────
    systemctl stop    nx-proxy-traffic-accum.timer 2>/dev/null || true
    systemctl disable nx-proxy-traffic-accum.timer 2>/dev/null || true
    rm -f /etc/systemd/system/nx-proxy-traffic-accum.service
    rm -f /etc/systemd/system/nx-proxy-traffic-accum.timer
    rm -f /usr/local/bin/nx-proxy-traffic-accum

    # ── Remove the proxy's own restore unit (MED-3) ──────
    # Anti-DDoS's restore service, when present, owns rules.v4
    # instead; this unit self-disables there, but uninstall removes
    # it outright.
    systemctl stop    nx-3proxy-restore.service 2>/dev/null || true
    systemctl disable nx-3proxy-restore.service 2>/dev/null || true
    rm -f /etc/systemd/system/nx-3proxy-restore.service

    # ── Remove systemd service files ─────────────────────
    rm -f "$SERVICE_FILE"
    [ -f /etc/antiddos/state.conf ] || rm -f /etc/systemd/system/tc-proxy-limit.service

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
    # BUG-015: /etc/antiddos, /var/lib/antiddos, the daemon log and its
    # state files belong to the Anti-DDoS module and are NOT touched.
    # Remove the dedicated nexoproxy user (created by this module for
    # the proxy service; the service is already stopped above).
    id nexoproxy >/dev/null 2>&1 && \
        userdel nexoproxy 2>/dev/null || true

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

