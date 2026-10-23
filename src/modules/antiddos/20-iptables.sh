# @part modules/antiddos/20-iptables.sh - apply_iptables (single cohesive function)
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
apply_iptables() {
    info "Applying iptables rules..."

    # BUG-027 (fail closed): with no Cloudflare ranges loaded, every rule
    # below would treat CF IPs as ordinary traffic. Refuse to arm.
    if [ "${#CF_RANGES[@]}" -eq 0 ]; then
        err "Cloudflare range list is empty/missing - refusing to apply iptables rules (CF would lose its exemption)"
        return 1
    fi

    # Helper: add if not already present
    ipt_add() { iptables -C "$@" 2>/dev/null || iptables -A "$@"; }
    ipt_ins() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }

    # ── Step 0: Loopback ─────────────────────────────
    ipt_ins INPUT -i lo -j ACCEPT

    # ── Step 1: Drop INVALID state ───────────────────
    ipt_ins INPUT   -m conntrack --ctstate INVALID -j DROP
    ipt_ins FORWARD -m conntrack --ctstate INVALID -j DROP
    success "Invalid packet drop: ON"

    # ── Step 2: Fast path for established ────────────
    # Must come BEFORE rate-limit rules so existing CF connections never hit limits
    ipt_ins INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ── Step 3: CF IPs → ACCEPT (NO limits ever) ─────
    # This is the MOST CRITICAL rule:
    # CF IPs must be accepted BEFORE any hashlimit/connlimit/rate rule
    # Otherwise, CF tunnel traffic can trigger SYN/UDP limits and kill users
    info "Whitelisting Cloudflare IPs (unlimited, no rate limits)..."
    for CF in "${CF_RANGES[@]}"; do
        ipt_ins INPUT -s "$CF" -m comment --comment "cf_whitelist" -j ACCEPT
    done

    # ── Step 4: Server own IPs → ACCEPT ──────────────
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        ipt_ins INPUT -s "$SIP/32" -m comment --comment "self_whitelist" -j ACCEPT
    done < <(get_server_ips)

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
    list_self_ips > "$SELF_IPS_FILE" 2>/dev/null || true
    { printf '%s\n' "${CF_RANGES[@]}"
      list_self_ips
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
        # Also whitelist server own IPs in raw
        while IFS= read -r SIP; do
            [ -z "$SIP" ] && continue
            iptables -t raw -C PREROUTING -s "$SIP/32" -j ACCEPT 2>/dev/null || \
            iptables -t raw -A PREROUTING -s "$SIP/32" -j ACCEPT
        done < <(get_server_ips)
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
        _GS_LIMIT=$(echo "$SYN_LIMIT" | sed 's|/sec||')
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
        success "UDP Amplification (DNS/NTP/SSDP/memcached): blocked"
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
                --connlimit-mask 32 \
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
            --connlimit-mask 32 \
            -m limit --limit 10/min --limit-burst 20 \
            -j LOG --log-prefix "[CONNLIMIT DROP] " --log-level 4 2>/dev/null || true
        ipt_add INPUT -p tcp \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
            --connlimit-mask 32 \
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

            # ── HTTP request rate (packet rate on established TCP) ────
            # _proc_http_burst sends hundreds of requests on keep-alive.
            # hashlimit on all-TCP-packets (not just NEW) catches this.
            ipt_add INPUT -p tcp \
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
    else
        warn "connlimit unavailable - HTTP flood protection limited"
    fi

    # ── Step 8b: Per-IP bandwidth limit via tc ──────────
    # _proc_heavy sends 64MB+ per connection. tc limits bandwidth before
    # data reaches xray/kernel, preventing CPU spike from data processing.
    # This adds an iptables MARK for non-CF IPs → tc filters pick it up.
    # ── Step 8: Per-IP bandwidth cap ─────────────────────
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
            # Success — remove test rule, add via ipt_add (idempotent)
            iptables -D INPUT -p tcp \
                -m hashlimit \
                --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
                --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
                --hashlimit-mode srcip \
                --hashlimit-name bw_per_ip_test \
                --hashlimit-htable-expire 5000 \
                -j DROP 2>/dev/null || true
            ipt_add INPUT -p tcp \
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
            -m connlimit --connlimit-above 60 --connlimit-mask 32 \
            -j DROP 2>/dev/null && \
            success "Per-IP bandwidth cap: connlimit fallback (max 60 conns/IP — kernel too old for byte-mode)" || \
            warn "Per-IP bandwidth cap: both byte-mode and connlimit fallback failed"
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

    # Save rules
    iptables-save > "$IPTABLES_SAVE_FILE" 2>/dev/null || true
    chmod 600 "$IPTABLES_SAVE_FILE"
    success "iptables rules saved"
}

# ════════════════════════════════════════════════
# LAYER 3: fail2ban jails
# ════════════════════════════════════════════════
