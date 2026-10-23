# @part modules/3proxy/20-iptables.sh - setup_iptables_for_port
# Assembled into 3proxy-socks5.sh by tools/build.py - not a standalone script.
setup_iptables_for_port() {
    local PORT="$1"
    local MAX_CONN="${2:-20}"

    # Remove old rules for this port
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" \
        -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    iptables -D OUTPUT -p tcp --sport "$PORT" \
        -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    # Remove old CF rules (BUG-013: the delete spec must mirror the
    # create spec EXACTLY, including the comment match - without it the
    # delete never matched and every reinstall duplicated all 753 rules)
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT 2>/dev/null || true
    done
    # Remove old self-IP rules (mirror of Step 2 - previously missing, so
    # these duplicated on every reinstall too)
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
            -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
    done < <(get_server_ips)
    # Remove old rate-limit rules by enumeration (BUG-014: the hitcount
    # depends on MAX_CONN at create time - *3 now, *2 in old versions -
    # so a fixed spec delete can miss the real rule; the recent-rule name
    # is the stable identifier)
    local _rn
    for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_$PORT" | cut -d: -f1 | sort -rn); do
        iptables -D INPUT $((_rn - 1)) 2>/dev/null || true
    done
    # Remove old user-whitelist rules (spec mirrors the create below)
    if [ -f /etc/antiddos/whitelist.list ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$WIP" \
                -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
        done < /etc/antiddos/whitelist.list
    fi

    # ── Step 1: CF IPs → ACCEPT immediately (no limits!) ─
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -A INPUT -p tcp --dport "$PORT" -s "$CF" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT
    done

    # ── Step 2: Server own IPs → ACCEPT (no limits) ──────
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        iptables -A INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
            -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
    done < <(get_server_ips)

    # ── Step 2b: User whitelist → ACCEPT (FR-1: exempt means exempt
    # in EVERY layer, including this port's rate limits) ──────
    if [ -f /etc/antiddos/whitelist.list ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            iptables -A INPUT -p tcp --dport "$PORT" -s "$WIP" \
                -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
        done < /etc/antiddos/whitelist.list
    fi

    # ── Step 3: Non-CF rate-limit (new conns per IP) ──────
    # Only apply to IPs NOT from CF (CF already accepted above)
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --update --seconds 60 \
        --hitcount $((MAX_CONN * 3)) -j DROP
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --set

    # ── Step 4: Allow all remaining ──────────────────────
    iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT

    # Stats counters
    iptables -I INPUT  -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in"
    iptables -I OUTPUT -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out"

    # UFW / firewalld compat
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active" && \
        ufw allow "$PORT"/tcp >/dev/null 2>&1 || true
    command -v firewall-cmd >/dev/null 2>&1 && \
        firewall-cmd --add-port="$PORT"/tcp --permanent >/dev/null 2>&1 && \
        firewall-cmd --reload >/dev/null 2>&1 || true
}

# ── Run a command with visible "working" feedback ──────────
# Prints "<label> ......" and a growing dot animation so the user can see the
# step is still alive. The command itself is NEVER time-limited. Output is
# captured to a temp log so the dots stay clean; on failure the log tail is
# shown so the real error is not hidden.
