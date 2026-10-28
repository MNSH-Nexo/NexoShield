# @part modules/antiddos/50-tc.sh - setup_tc + setup_persistence
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
setup_tc() {
    command -v tc >/dev/null 2>&1 || {
        warn "tc (iproute2) not installed - skipping bandwidth control"
        return
    }
    info "Configuring tc bandwidth control..."

    # Remove old config (record what was there first - BUG-032: never
    # silently destroy a pre-existing qdisc without a trace)
    mkdir -p /etc/antiddos
    tc qdisc show dev "$MAIN_IF" 2>/dev/null | head -1 > /etc/antiddos/tc-qdisc-before.txt || true
    tc qdisc del dev "$MAIN_IF" root 2>/dev/null || true

    # R-21 (deep review 2026-10-23): HTB only shapes when its rates
    # are the real bottleneck. The tree was hardcoded to 1 Gbit - on a
    # 200 Mbit VPS the qdisc never engages and the "100 Mbit throttle"
    # is fiction. Scale the tree to the detected link speed, keeping
    # the designed ratios (default S/2, throttle S/10, hard S/20);
    # at 1 Gbit the values are exactly the historical ones.
    local LINK_MBPS=1000 _spd=""
    _spd=$(cat "/sys/class/net/$MAIN_IF/speed" 2>/dev/null || echo "")
    case "$_spd" in ''|*[!0-9]*) _spd="" ;; esac
    if [ -n "$_spd" ] && [ "$_spd" -ge 50 ] && [ "$_spd" -lt 1000 ]; then
        LINK_MBPS="$_spd"
        info "tc: link speed ${LINK_MBPS}Mbps - shaping tree scaled to match"
    fi
    local R_ROOT="${LINK_MBPS}mbit" R_DEF="$(( LINK_MBPS / 2 ))mbit" \
          R_SOFT="$(( LINK_MBPS / 10 ))mbit" R_HARD="$(( LINK_MBPS / 20 ))mbit"

    # HTB root — default class 1:20 (normal non-CF)
    tc qdisc add dev "$MAIN_IF" root handle 1: htb default 20
    tc class add dev "$MAIN_IF" parent 1: classid 1:1  htb rate $R_ROOT ceil $R_ROOT
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:10 htb rate $R_ROOT  ceil $R_ROOT  burst 25Mb    # CF unlimited
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:20 htb rate $R_DEF ceil $R_DEF burst 6400Kb # normal
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:30 htb rate $R_SOFT ceil $R_SOFT burst 1280Kb # throttled
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:40 htb rate $R_HARD  ceil $R_HARD  burst 640Kb  # hard-throttled

    # BUG-001 fix: this qdisc sits on EGRESS. A client's packets leave
    # TOWARDS the client, so the client is the DESTINATION. All filters
    # classify by ip dst; "match ip src <client>" could never match.
    # CF IPs → class 1:10 (match by DST IP)
    local HANDLE=10
    for CF in "${CF_RANGES[@]}"; do
        tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip dst "$CF" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done

    # CF IPv6 → class 1:10 (Wave 9: protocol ip6 / match ip6 dst)
    for CF6 in "${CF6_RANGES[@]}"; do
        tc filter add dev "$MAIN_IF" parent 1: protocol ip6 prio $HANDLE \
            u32 match ip6 dst "$CF6" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done

    # Server own IPs → class 1:10 (E-4: exhaustive list, like the
    # firewall steps - public-only left private self traffic shaped)
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip dst "$SIP/32" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done < <(list_self_ips_all | grep -v '^127\.0\.0\.1$')

    # User whitelist → class 1:10 (unlimited, same as CF/self)
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
                u32 match ip dst "$WIP" flowid 1:10 2>/dev/null || true
            HANDLE=$((HANDLE + 1))
        done < "$WHITELIST_FILE"
    fi

    # HIGH-2: re-apply live daemon throttles (BUG-022). The qdisc
    # delete above just destroyed every throttle filter the daemon
    # recorded - the boot script re-applies them, but the LIVE path
    # never did, so every proxy Install/Update and every whitelist
    # change silently gave throttled attackers full speed until the
    # daemon restarted. Same loop as the boot script, reading the
    # live file first: it is fresher than the mirror, which lags up
    # to one daemon cycle, and a stale mirror entry must never
    # resurrect a filter the daemon already replaced.
    while read -r TIP TPRIO _TS TBAND; do
        [ -z "$TIP" ] && continue
        TFLOW=1:30; [ "$TBAND" = "hard" ] && TFLOW=1:40
        case "$TIP" in
            *:*) tc filter add dev "$MAIN_IF" parent 1: protocol ip6 prio $TPRIO \
                     u32 match ip6 dst "$TIP" flowid $TFLOW 2>/dev/null || true ;;
            *)   tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $TPRIO \
                     u32 match ip dst "$TIP/32" flowid $TFLOW 2>/dev/null || true ;;
        esac
    done < <(cat "${THROTTLE_LIST:-/run/nexoshield/autoban_throttle}" /etc/antiddos/throttled.list 2>/dev/null | awk '!seen[$1]++')

    # ── WARP / WireGuard awareness ──────────────────────────
    if ip link show 2>/dev/null | grep -qE '^\s*[0-9]+:\s+(wg|utm|warp)[0-9]*[:@]'; then
        warn "WARP/WireGuard tunnel detected — tc shapes '${MAIN_IF}' (default route)."
        warn "Tunneled (WARP) traffic egresses via the tunnel device and is NOT shaped; inbound anti-DDoS (iptables) still applies."
    fi

    success "tc: CF=unlimited ($R_ROOT), others=$R_DEF, throttled=$R_SOFT, hard=$R_HARD"

    # Save to persistent script
    cat > /opt/proxy-manager/tc-setup.sh << 'TCEOF'
#!/bin/bash
# TC persistent setup — auto-generated
IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
IF="${IF:-eth0}"
# @include lib/cloudflare-loader.sh
# @include lib/self-ips.sh
tc qdisc del dev "$IF" root 2>/dev/null || true
tc qdisc add dev "$IF" root handle 1: htb default 20
tc class add dev "$IF" parent 1: classid 1:1  htb rate 1gbit ceil 1gbit
tc class add dev "$IF" parent 1:1 classid 1:10 htb rate 1gbit  ceil 1gbit  burst 25Mb
tc class add dev "$IF" parent 1:1 classid 1:20 htb rate 500mbit ceil 500mbit burst 6400Kb
tc class add dev "$IF" parent 1:1 classid 1:30 htb rate 100mbit ceil 100mbit burst 1280Kb
tc class add dev "$IF" parent 1:1 classid 1:40 htb rate 50mbit  ceil 50mbit  burst 640Kb
H=10
for CF in "${CF_RANGES[@]}"; do
    tc filter add dev "$IF" parent 1: protocol ip prio $H \
        u32 match ip dst "$CF" flowid 1:10 2>/dev/null || true; H=$((H+1))
done
# CF IPv6 ranges (Wave 9), loaded from the runtime data file
if [ -f /etc/antiddos/cloudflare-ipv6.list ]; then
    while IFS= read -r CF6; do
        [ -z "$CF6" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip6 prio $H \
            u32 match ip6 dst "$CF6" flowid 1:10 2>/dev/null || true; H=$((H+1))
    done < /etc/antiddos/cloudflare-ipv6.list
fi
for SIP in $(list_self_ips_all 2>/dev/null | grep -v '^127\.0\.0\.1$'); do
    tc filter add dev "$IF" parent 1: protocol ip prio $H \
        u32 match ip dst "$SIP/32" flowid 1:10 2>/dev/null || true; H=$((H+1))
done
if [ -f /etc/antiddos/whitelist.list ]; then
    while IFS= read -r WIP; do
        WIP="${WIP%%#*}"; WIP="${WIP// /}"
        [ -z "$WIP" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $H \
            u32 match ip dst "$WIP" flowid 1:10 2>/dev/null || true; H=$((H+1))
    done < /etc/antiddos/whitelist.list
fi
# Re-apply live daemon throttles (BUG-022): rebuilding the qdisc must not
# silently drop enforcement state recorded by the auto-ban daemon.
if [ -f /etc/antiddos/throttled.list ]; then
    while read -r TIP TPRIO _TS TBAND; do
        [ -z "$TIP" ] && continue
        TFLOW=1:30; [ "$TBAND" = "hard" ] && TFLOW=1:40
        case "$TIP" in
            *:*) tc filter add dev "$IF" parent 1: protocol ip6 prio $TPRIO \
                     u32 match ip6 dst "$TIP" flowid $TFLOW 2>/dev/null || true ;;
            *)   tc filter add dev "$IF" parent 1: protocol ip prio $TPRIO \
                     u32 match ip dst "$TIP/32" flowid $TFLOW 2>/dev/null || true ;;
        esac
    done < /etc/antiddos/throttled.list
fi
TCEOF
    chmod +x /opt/proxy-manager/tc-setup.sh
    # R-21: the persistent script must use the same scaled rates.
    if [ "$LINK_MBPS" -lt 1000 ]; then
        sed -i -E \
            -e "s/rate 1gbit[[:space:]]+ceil 1gbit/rate ${R_ROOT} ceil ${R_ROOT}/g" \
            -e "s/rate 500mbit[[:space:]]+ceil 500mbit/rate ${R_DEF} ceil ${R_DEF}/g" \
            -e "s/rate 100mbit[[:space:]]+ceil 100mbit/rate ${R_SOFT} ceil ${R_SOFT}/g" \
            -e "s/rate 50mbit[[:space:]]+ceil 50mbit/rate ${R_HARD} ceil ${R_HARD}/g" \
            /opt/proxy-manager/tc-setup.sh
    fi

    # systemd service for tc persistence
    cat > /etc/systemd/system/tc-proxy-limit.service << EOF
[Unit]
Description=TC bandwidth shaping (proxy server)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/proxy-manager/tc-setup.sh $MAIN_IF
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    # if-up.d for NetworkManager
    mkdir -p /etc/network/if-up.d
    ln -sf /opt/proxy-manager/tc-setup.sh /etc/network/if-up.d/tc-proxy-limit 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable tc-proxy-limit.service >/dev/null 2>&1 || true
    success "tc persistence: systemd + if-up.d configured"
}

# ════════════════════════════════════════════════
# Persist iptables on reboot
# ════════════════════════════════════════════════
setup_persistence() {
    info "Setting up iptables persistence..."

    # Debian/Ubuntu: iptables-persistent
    if command -v apt-get >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent 2>/dev/null || true
        save_static_rules /etc/iptables/rules.v4
    fi

    # Restore script
    RESTORE_SCRIPT="/etc/antiddos/restore-rules.sh"
    cat > "$RESTORE_SCRIPT" << 'EOF'
#!/bin/bash
RULES="/etc/antiddos/iptables-antiddos.rules"
[ -f "$RULES" ] && iptables-restore < "$RULES" 2>/dev/null || true
[ -f /etc/antiddos/ip6tables-antiddos.rules ] && \
    ip6tables-restore < /etc/antiddos/ip6tables-antiddos.rules 2>/dev/null || true
[ -f /etc/sysctl.d/98-antiddos-hardening.conf ] && \
    sysctl -p /etc/sysctl.d/98-antiddos-hardening.conf >/dev/null 2>&1 || true
EOF
    chmod +x "$RESTORE_SCRIPT"

    # systemd service
    cat > /etc/systemd/system/antiddos-restore.service << EOF
[Unit]
Description=Restore Anti-DDoS iptables rules on boot
After=network.target
Before=3proxy.service auto-ban.service

[Service]
Type=oneshot
ExecStart=$RESTORE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable antiddos-restore.service >/dev/null 2>&1
    success "iptables persistence: enabled (antiddos-restore)"

    # Log rotation (BUG-045): the daemon logs every cycle's events with
    # no rotation - an unbounded /var/log/auto-ban.log on a busy box.
    cat > /etc/logrotate.d/nexoshield << 'LREOF'
/var/log/auto-ban.log /var/log/antiddos.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    copytruncate
}
LREOF
    success "logrotate: /etc/logrotate.d/nexoshield"
}

# ════════════════════════════════════════════════
# Status
# ════════════════════════════════════════════════
