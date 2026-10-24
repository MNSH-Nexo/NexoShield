# @part modules/antiddos/20-iptables.sh - apply_iptables (single cohesive function)
# Assembled into antiddos.sh by tools/build.py - not a standalone script.

# nx_static_rules_filter: iptables-save output (stdin) -> the STATIC
# ruleset (stdout). Transient enforcement state must never be baked into
# boot persistence (BUG-012): auto-ban/subnet-ban DROP rules and fail2ban
# chains are runtime state, rebuilt by their owners; persisting them made
# expired bans immortal and resurrected removed rules after reboot.
nx_static_rules_filter() {
    grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' || true
}

# save_static_rules <file>: persist only the static ruleset.
save_static_rules() {
    iptables-save 2>/dev/null | nx_static_rules_filter > "$1" || true
}
apply_iptables() {
    info "Applying iptables rules..."

    # BUG-027 (fail closed): with no Cloudflare ranges loaded, every rule
    # below would treat CF IPs as ordinary traffic. Refuse to arm.
    if [ "${#CF_RANGES[@]}" -eq 0 ]; then
        err "Cloudflare range list is empty/missing - refusing to apply iptables rules (CF would lose its exemption)"
        return 1
    fi

    # BUG-063: purge rate rules from any previous run/tier first. The
    # named hashlimit tables are ours by construction; re-applying with
    # different thresholds otherwise APPENDS new rules next to the old
    # ones (same --hashlimit-name), and the old rule - evaluated first -
    # keeps deciding, so a raised limit silently never takes effect.
    # Deletion is by rule number from `iptables -S` (spec deletion breaks
    # on quoted arguments).
    local _pn
    for _pn in $(iptables -S INPUT 2>/dev/null | \
            grep -nE 'hashlimit-name (syn_flood|udp_flood|icmp_flood|rst_flood|bw_per_ip|bw_per_ip_test|new_conn_rate|http_req_rate|udp_reflect_[0-9]+)|nx_connlimit' | \
            cut -d: -f1 | sort -rn); do
        iptables -D INPUT $((_pn - 1)) 2>/dev/null || true
    done

    # Helper: add if not already present
    ipt_add() { iptables -C "$@" 2>/dev/null || iptables -A "$@"; }
    ipt_ins() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }

    # ── Step 0: Loopback ─────────────────────────────
    ipt_ins INPUT -i lo -j ACCEPT

    # ── Step 1: Drop INVALID state ───────────────────
    ipt_ins INPUT   -m conntrack --ctstate INVALID -j DROP
    ipt_ins FORWARD -m conntrack --ctstate INVALID -j DROP
    success "Invalid packet drop: ON"

    # ── Step 2: ESTABLISHED fast path + the two rules that police it ──
    # BUG-002 fix: the ESTABLISHED accept used to sit alone at the top, so
    # the two rules that police ESTABLISHED traffic (bw_per_ip and
    # http_req_rate, appended far below) were unreachable dead code - an
    # established connection was accepted before ever reaching them.
    # Insert order here is deliberate (ipt_ins stacks; last insert = top):
    #   1) ESTABLISHED accept  -> ends up deepest of the three
    #   2) bw_per_ip           -> above the accept, so it can police it
    #   3) http_req_rate       -> above bw_per_ip
    # The whitelist ACCEPTs (Steps 3-4c) are inserted AFTER this step and
    # therefore land ABOVE all three: exempt traffic is never policed,
    # exactly as before. Everything appended later stays below.
    ipt_ins INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ── Step 2a: Per-IP bandwidth cap (polices ESTABLISHED) ──
    # _proc_heavy sends 64MB+ per connection. Byte-mode hashlimit
    # caps per-IP throughput on established flows.
    # Try hashlimit byte-mode (kernel 4.1+), fallback to connlimit
    local BW_APPLIED=0
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        # Test if byte-mode (mbit/s) is supported by this kernel
        if iptables -A INPUT -p tcp \
            -m hashlimit \
            --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
            --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
            --hashlimit-mode srcip \
            --hashlimit-name bw_per_ip_test \
            --hashlimit-htable-expire 5000 \
            -j DROP 2>/dev/null; then
            # Success — remove test rule, add the real one via ipt_ins
            iptables -D INPUT -p tcp \
                -m hashlimit \
                --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
                --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
                --hashlimit-mode srcip \
                --hashlimit-name bw_per_ip_test \
                --hashlimit-htable-expire 5000 \
                -j DROP 2>/dev/null || true
            ipt_ins INPUT -p tcp \
                -m conntrack --ctstate ESTABLISHED,RELATED \
                -m hashlimit \
                --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
                --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
                --hashlimit-mode srcip \
                --hashlimit-name bw_per_ip \
                --hashlimit-htable-expire 5000 \
                -j DROP 2>/dev/null && BW_APPLIED=1
            [ "$BW_APPLIED" -eq 1 ] && \
                success "Per-IP bandwidth cap: ${BW_PER_IP_MBIT}Mbps max per non-CF IP"
        fi
    fi
    if [ "$BW_APPLIED" -eq 0 ]; then
        # Fallback: use connlimit — limit simultaneous connections per IP
        # Each connection ~1-5 Mbps for proxy; 60 conns ≈ 60-300 Mbps cap
        ipt_add INPUT -p tcp \
            -m conntrack --ctstate NEW \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" --connlimit-mask 32 \
            -j DROP 2>/dev/null && \
            success "Per-IP bandwidth cap: connlimit fallback (max $CONN_LIMIT_PER_IP conns/IP — kernel too old for byte-mode)" || \
            warn "Per-IP bandwidth cap: both byte-mode and connlimit fallback failed"
    fi


    # ── Step 2b: HTTP request rate (polices ESTABLISHED) ──
    if [ "$HASHLIMIT_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ]; then
            # ── HTTP request rate (packet rate on established TCP) ────
            # _proc_http_burst sends hundreds of requests on keep-alive.
            # hashlimit on all-TCP-packets (not just NEW) catches this.
            ipt_ins INPUT -p tcp \
                -m conntrack --ctstate ESTABLISHED \
                -m hashlimit \
                --hashlimit-above "$HTTP_REQ_RATE" \
                --hashlimit-burst "$HTTP_REQ_BURST" \
                --hashlimit-mode srcip \
                --hashlimit-name http_req_rate \
                --hashlimit-htable-expire 10000 \
                -j DROP
            success "HTTP burst rate: max $HTTP_REQ_RATE pkt/s per non-CF IP (heavy/http_burst defense)"
    fi

    # ── Step 3: CF IPs → ACCEPT (NO limits ever) ─────
    # This is the MOST CRITICAL rule:
    # CF IPs must be accepted BEFORE any hashlimit/connlimit/rate rule
    # Otherwise, CF tunnel traffic can trigger SYN/UDP limits and kill users
    info "Whitelisting Cloudflare IPs (unlimited, no rate limits)..."
    for CF in "${CF_RANGES[@]}"; do
        ipt_ins INPUT -s "$CF" -m comment --comment "cf_whitelist" -j ACCEPT
    done

    # NAT/cloud public-IP discovery (E-6): on cloud VMs the public
    # address lives only in the provider's NAT - ask the metadata
    # service (echo fallback) and cache it, so the self set below
    # covers it too. A failed discovery keeps the previous cache.
    if nx_refresh_public_ips_cache >/dev/null 2>&1; then
        [ -s "$PUBLIC_IPS_FILE" ] && \
            info "Public-IP discovery: $(tr '\n' ' ' < "$PUBLIC_IPS_FILE")"
    fi

    # ── Step 4: Server own IPs → ACCEPT ──────────────
    # E-4: get_server_ips is display-grade (public only) - private and
    # secondary self addresses were missing here, so traffic from the
    # server's own private IP still hit the flood limits. Enforcement
    # uses the exhaustive list_self_ips (loopback excluded, see above).
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        ipt_ins INPUT -s "$SIP/32" -m comment --comment "self_whitelist" -j ACCEPT
    done < <(list_self_ips_all | grep -v '^127\.0\.0\.1$')

    # ── Step 4b: User whitelist → ACCEPT (before ALL limits) ──
    mkdir -p /etc/antiddos
    touch "$WHITELIST_FILE"
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            ipt_ins INPUT -s "$WIP" -m comment --comment "user_whitelist" -j ACCEPT
        done < "$WHITELIST_FILE"
    fi
    success "CF + self whitelist: added (${#CF_RANGES[@]} CF ranges + own IPs)"

    # ── Step 4c: Canonical exempt-set snapshot (D1) ──
    # One file every layer can consult: CF ranges + ALL self IPs + the
    # admin whitelist. Also snapshot the self IPs on their own (FR-2).
    list_self_ips_all > "$SELF_IPS_FILE" 2>/dev/null || true
    { printf '%s\n' "${CF_RANGES[@]}"
      list_self_ips_all
      if [ -f "$WHITELIST_FILE" ]; then
          while IFS= read -r _EX; do
              _EX="${_EX%%#*}"; _EX="${_EX// /}"
              [ -n "$_EX" ] && printf '%s\n' "$_EX"
          done < "$WHITELIST_FILE"
      fi
    } | grep -v '^$' | sort -u > "$EXEMPT_FILE" || true

    # ── Step 5: SYN Flood protection ─────────────────
    # NOTE: CF IPs already accepted above — these rules only apply to non-CF
    if [ "$SYNPROXY_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ] && \
       [ "$VIRT_TYPE" != "openvz" ]; then
        modprobe xt_SYNPROXY 2>/dev/null || true
        # Whitelist CF IPs in raw PREROUTING so SYNPROXY never touches CF traffic
        for CF in "${CF_RANGES[@]}"; do
            iptables -t raw -C PREROUTING -s "$CF" -j ACCEPT 2>/dev/null || \
            iptables -t raw -A PREROUTING -s "$CF" -j ACCEPT
        done
        # Also whitelist server own IPs in raw (E-4: exhaustive list)
        while IFS= read -r SIP; do
            [ -z "$SIP" ] && continue
            iptables -t raw -C PREROUTING -s "$SIP/32" -j ACCEPT 2>/dev/null || \
            iptables -t raw -A PREROUTING -s "$SIP/32" -j ACCEPT
        done < <(list_self_ips_all | grep -v '^127\.0\.0\.1$')
        # Also whitelist user whitelist in raw (SYNPROXY never touches them)
        if [ -f "$WHITELIST_FILE" ]; then
            while IFS= read -r WIP; do
                WIP="${WIP%%#*}"; WIP="${WIP// /}"
                [ -z "$WIP" ] && continue
                iptables -t raw -C PREROUTING -s "$WIP" -j ACCEPT 2>/dev/null || \
                iptables -t raw -A PREROUTING -s "$WIP" -j ACCEPT
            done < "$WHITELIST_FILE"
        fi
        iptables -t raw -C PREROUTING -p tcp --syn \
            -m conntrack --ctstate NEW -j CT --notrack 2>/dev/null || \
        iptables -t raw -A PREROUTING -p tcp --syn \
            -m conntrack --ctstate NEW -j CT --notrack
        iptables -C INPUT -p tcp --syn \
            -m conntrack --ctstate UNTRACKED,INVALID \
            -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 2>/dev/null || \
        iptables -A INPUT -p tcp --syn \
            -m conntrack --ctstate UNTRACKED,INVALID \
            -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
        iptables -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
        iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
        success "SYN Flood: SYNPROXY kernel-level (CF whitelisted in raw table)"
    elif [ "$HASHLIMIT_OK" -eq 1 ]; then
        # Per-IP SYN limit (catches single-source flood)
        ipt_add INPUT -p tcp --syn \
            -m hashlimit \
            --hashlimit-above "$SYN_LIMIT" \
            --hashlimit-burst "$SYN_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name syn_flood \
            --hashlimit-htable-expire 30000 \
            -j DROP
        # Global SYN rate cap — catches spoofed-IP floods where per-IP limit misses
        # Each spoofed SYN uses a unique fake IP so per-IP hashlimit never triggers.
        # A global cap absorbs the total SYN rate regardless of source.
        # Value: 5× per-IP limit to allow bursts from many legit IPs simultaneously.
        local _GS_LIMIT _GS_BURST
        _GS_LIMIT="${SYN_LIMIT//\/sec/}"
        _GS_LIMIT="${_GS_LIMIT//[^0-9]/}"; _GS_LIMIT="${_GS_LIMIT:-500}"
        _GS_BURST="${SYN_BURST:-1000}"
        _GS_BURST="${_GS_BURST//[^0-9]/}"; _GS_BURST="${_GS_BURST:-1000}"
        ipt_add INPUT -p tcp --syn \
            -m limit \
            --limit "$(( _GS_LIMIT * 5 ))/sec" \
            --limit-burst "$(( _GS_BURST * 5 ))" \
            -j ACCEPT
        ipt_add INPUT -p tcp --syn -j DROP
        success "SYN Flood: per-IP hashlimit ($SYN_LIMIT) + global cap ($(( _GS_LIMIT * 5 ))/s) — spoofed-IP resistant"
    else
        ipt_add INPUT -p tcp --syn -m limit --limit 500/s --limit-burst 1000 -j ACCEPT
        ipt_add INPUT -p tcp --syn -j DROP
        success "SYN Flood: global limit (fallback)"
    fi

    # ── Step 6: UDP Flood ─────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p udp \
            -m hashlimit \
            --hashlimit-above "$UDP_LIMIT" \
            --hashlimit-burst "$UDP_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name udp_flood \
            --hashlimit-htable-expire 10000 \
            -j DROP
        success "UDP Flood: hashlimit ($UDP_LIMIT per IP)"

        # UDP amplification ports
        for REFLECT_PORT in 19 111 137 161 1900 5353 11211; do
            ipt_add INPUT -p udp --sport "$REFLECT_PORT" \
                -m hashlimit \
                --hashlimit-above 10/sec \
                --hashlimit-burst 20 \
                --hashlimit-mode srcip \
                --hashlimit-name "udp_reflect_${REFLECT_PORT}" \
                -j DROP
        done
        success "UDP Amplification (chargen/DNS/rpcbind/NetBIOS/NTP/SNMP/SSDP/memcached/mDNS): blocked"
    else
        warn "UDP Flood: hashlimit unavailable - using global limit"
        ipt_add INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT
        ipt_add INPUT -p udp -j DROP
    fi

    # ── Step 7: ICMP Flood ────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p icmp --icmp-type echo-request \
            -m hashlimit \
            --hashlimit-above "$ICMP_LIMIT" \
            --hashlimit-burst "$ICMP_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name icmp_flood \
            -j DROP
        success "ICMP Flood: rate-limited ($ICMP_LIMIT per IP)"
    else
        ipt_add INPUT -p icmp --icmp-type echo-request -m limit \
            --limit 1/s --limit-burst 10 -j ACCEPT
        ipt_add INPUT -p icmp --icmp-type echo-request -j DROP
        success "ICMP Flood: global limit (fallback)"
    fi

    # ── Step 8: HTTP/HTTPS + ALL TCP Flood (connlimit) ──
    # NOTE: CF IPs accepted before this — connlimit only affects non-CF
    if [ "$CONNLIMIT_OK" -eq 1 ]; then
        # HTTP/HTTPS ports — lower connlimit
        for HTTP_PORT in 80 443 8080 8443; do
            ss -tuln 2>/dev/null | grep -q ":${HTTP_PORT} " || continue
            ipt_add INPUT -p tcp --dport "$HTTP_PORT" \
                -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
                --connlimit-mask 32 -m comment --comment "nx_connlimit" \
                -j REJECT --reject-with tcp-reset
            success "HTTP Flood: connlimit :${HTTP_PORT} (max $CONN_LIMIT_PER_IP per non-CF IP)"
        done

        # ── Slowloris / Hold / Heavy attack defense ───────
        # These attacks use few connections but hold them forever with partial data.
        # connlimit on ALL TCP ports (global per-IP) stops this without affecting tunnels.
        # CF IPs are already accepted above — this only hits real attackers.
        # LOG before DROP so fail2ban conn-flood jail can read it from kern.log
        ipt_add INPUT -p tcp \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
            --connlimit-mask 32 -m comment --comment "nx_connlimit" \
            -m limit --limit 10/min --limit-burst 20 \
            -j LOG --log-prefix "[CONNLIMIT DROP] " --log-level 4 2>/dev/null || true
        ipt_add INPUT -p tcp \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
            --connlimit-mask 32 -m comment --comment "nx_connlimit" \
            -j REJECT --reject-with tcp-reset
        success "Slowloris/Hold/Heavy: global connlimit (max $CONN_LIMIT_PER_IP TCP per non-CF IP) + LOG→fail2ban"

        if [ "$HASHLIMIT_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ]; then
            # ── New connection rate per IP (prevents connect-flood) ──
            ipt_add INPUT -p tcp \
                -m conntrack --ctstate NEW \
                -m hashlimit \
                --hashlimit-above "$NEW_CONN_RATE" \
                --hashlimit-burst "$NEW_CONN_BURST" \
                --hashlimit-mode srcip \
                --hashlimit-name new_conn_rate \
                --hashlimit-htable-expire 60000 \
                -j DROP
            success "New TCP conn rate: $NEW_CONN_RATE per non-CF IP"

        fi
    else
        warn "connlimit unavailable - HTTP flood protection limited"
    fi

    # ── Step 9: RST Flood ─────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p tcp --tcp-flags RST RST \
            -m hashlimit \
            --hashlimit-above 200/sec \
            --hashlimit-burst 400 \
            --hashlimit-mode srcip \
            --hashlimit-name rst_flood \
            -j DROP
        success "RST Flood: rate-limited"
    fi

    # ── Step 10: Port Scan signatures ────────────────
    # LOG first (rate-limited) so the portscan fail2ban jail has lines
    # to match - previously nothing logged these, so it never fired.
    ipt_add INPUT -p tcp --tcp-flags ALL NONE \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt_add INPUT -p tcp --tcp-flags ALL ALL \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt_add INPUT -p tcp --tcp-flags ALL FIN \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt_add INPUT -p tcp --tcp-flags ALL NONE -j DROP  # NULL scan
    ipt_add INPUT -p tcp --tcp-flags ALL ALL  -j DROP  # Xmas scan
    ipt_add INPUT -p tcp --tcp-flags ALL FIN  -j DROP  # FIN scan
    ipt_add INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP  # impossible
    ipt_add INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP  # impossible
    success "Port scans: NULL/XMAS/FIN/bogus flags dropped"

    # ── Step 11: Bogus TCP NEW non-SYN ───────────────
    if [ "$CONNTRACK_OK" -eq 1 ]; then
        ipt_add INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
        success "Bogus TCP NEW non-SYN: dropped"
    fi

    # ── Step 12: Fragmented packets ──────────────────
    ipt_add INPUT -f -j DROP
    success "Fragmented packets: dropped"

    # Save rules (static only - transient bans/f2b chains excluded, BUG-012)
    save_static_rules "$IPTABLES_SAVE_FILE"
    chmod 600 "$IPTABLES_SAVE_FILE"
    success "iptables rules saved"

    # IPv6 mirror of this design (Wave 9)
    apply_ip6tables
}

# ════════════════════════════════════════════════
# IPv6 mirror of the INPUT design (Wave 9). Same layer order as IPv4:
# exempt ACCEPTs -> request policing -> ESTABLISHED -> flood limits ->
# connlimit -> scan drops. Skipped cleanly when no IPv6 stack exists.
# ════════════════════════════════════════════════
apply_ip6tables() {
    command -v ip6tables >/dev/null 2>&1 || { info "ip6tables unavailable - IPv6 rules skipped"; return 0; }
    ip6tables -L INPUT >/dev/null 2>&1 || { info "IPv6 stack unavailable - IPv6 rules skipped"; return 0; }
    info "Applying IPv6 firewall rules (mirror of the IPv4 design)..."
    ipt6_add() { ip6tables -C "$@" 2>/dev/null || ip6tables -A "$@" 2>/dev/null || true; }

    ipt6_add INPUT -i lo -j ACCEPT

    # Exempt set snapshot (CF v6 + self v6 + whitelist v6 entries)
    : > /etc/antiddos/exempt6.list 2>/dev/null || true
    local _r6 _s6 _w6
    for _r6 in "${CF6_RANGES[@]}"; do
        ipt6_add INPUT -s "$_r6" -j ACCEPT
        echo "$_r6" >> /etc/antiddos/exempt6.list
    done
    while IFS= read -r _s6; do
        [ -z "$_s6" ] && continue
        ipt6_add INPUT -s "$_s6/128" -j ACCEPT
        echo "$_s6" >> /etc/antiddos/exempt6.list
    done < <(list_self_ips6)
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _w6; do
            _w6="${_w6%%#*}"; _w6="${_w6// /}"
            case "$_w6" in *:*) : ;; *) continue ;; esac
            [ -z "$_w6" ] && continue
            ipt6_add INPUT -s "$_w6" -j ACCEPT
            echo "$_w6" >> /etc/antiddos/exempt6.list
        done < "$WHITELIST_FILE"
    fi

    # Request-rate policing BEFORE the established accept (same BUG-002
    # lesson as IPv4: below it, this rule could never fire)
    ipt6_add INPUT -p tcp -m multiport --dports 80,443 \
        -m hashlimit --hashlimit-name http_req_rate6 --hashlimit-mode srcip \
        --hashlimit 300/min --hashlimit-burst 100 -j DROP

    ipt6_add INPUT -m conntrack --ctstate INVALID -j DROP
    ipt6_add INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Flood limits
    ipt6_add INPUT -p tcp --syn -m hashlimit --hashlimit-name syn_limit6 \
        --hashlimit-mode srcip --hashlimit 200/sec --hashlimit-burst 400 -j DROP
    ipt6_add INPUT -p udp -m hashlimit --hashlimit-name udp_limit6 \
        --hashlimit-mode srcip --hashlimit 1000/sec --hashlimit-burst 2000 -j DROP
    # ICMPv6: NDP must keep working (it is IPv6's ARP) - accept it,
    # rate-limit echo requests, accept the rest.
    ipt6_add INPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT
    ipt6_add INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT
    ipt6_add INPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT
    ipt6_add INPUT -p icmpv6 --icmpv6-type echo-request \
        -m hashlimit --hashlimit-name icmp_limit6 --hashlimit-mode srcip \
        --hashlimit 50/sec --hashlimit-burst 100 -j DROP
    ipt6_add INPUT -p icmpv6 -j ACCEPT

    # Connection limit per host (mask 128) with the same LOG prefix the
    # conn-flood fail2ban jail matches
    ipt6_add INPUT -p tcp --syn -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
        --connlimit-mask 128 -j LOG --log-prefix "[CONNLIMIT DROP] " --log-level 4
    ipt6_add INPUT -p tcp --syn -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
        --connlimit-mask 128 -m comment --comment "nx_connlimit" -j DROP

    # Scan signatures: LOG ([NX-SCAN], feeds the portscan jail) + DROP
    ipt6_add INPUT -p tcp --tcp-flags ALL NONE \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt6_add INPUT -p tcp --tcp-flags ALL ALL \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt6_add INPUT -p tcp --tcp-flags ALL FIN \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "[NX-SCAN] " --log-level 4
    ipt6_add INPUT -p tcp --tcp-flags ALL NONE -j DROP
    ipt6_add INPUT -p tcp --tcp-flags ALL ALL -j DROP
    ipt6_add INPUT -p tcp --tcp-flags ALL FIN -j DROP
    ipt6_add INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    ipt6_add INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

    ip6tables-save 2>/dev/null | nx_static_rules_filter > /etc/antiddos/ip6tables-antiddos.rules || true
    chmod 600 /etc/antiddos/ip6tables-antiddos.rules 2>/dev/null || true
    success "IPv6 rules applied + saved"
}

# Delete ip6tables rules by pattern (mirror of nx_delete_matching).
nx_delete_matching6() {
    local _c="$1" _p="$2" _n
    command -v ip6tables >/dev/null 2>&1 || return 0
    ip6tables -L "$_c" >/dev/null 2>&1 || return 0
    while true; do
        _n=$(ip6tables -S "$_c" 2>/dev/null | grep -nE "$_p" | head -1 | cut -d: -f1 || true)
        [ -z "$_n" ] && break
        ip6tables -D "$_c" $((_n - 1)) 2>/dev/null || break
    done
}

# ════════════════════════════════════════════════
# LAYER 3: fail2ban jails
# ════════════════════════════════════════════════
