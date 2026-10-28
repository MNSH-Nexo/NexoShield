# @part modules/3proxy/20-iptables.sh - setup_iptables_for_port
# Assembled into 3proxy-socks5.sh by tools/build.py - not a standalone script.
# remove_proxy_port_rules: delete-only mirror of the delete half of
# setup_iptables_for_port. Used when an update deliberately moves
# the proxy to a new port, so the vacated port's rules do not
# linger (and the old port does not stay open behind us).
remove_proxy_port_rules() {
    local PORT="$1"
    # Snapshot BEFORE deleting (MED-1): the accumulator runs only
    # every 5 minutes, so deleting the counting rules first would lose
    # all traffic counted since the last tick (up to 5 minutes of
    # proxy traffic). The config port is the vacated port here: this
    # is called from install_proxy before the config is rewritten.
    nx_proxy_traffic_accum 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" \
        -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    iptables -D OUTPUT -p tcp --sport "$PORT" \
        -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT 2>/dev/null || true
    done
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
            -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
    done < <(list_self_ips_all)
    local _rn
    for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_${PORT}[^0-9]" | cut -d: -f1 | sort -rn); do
        iptables -D INPUT $((_rn - 1)) 2>/dev/null || true
    done
    if [ -f /etc/antiddos/whitelist.list ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$WIP" \
                -m comment --comment "3proxy_wl_allow" -j ACCEPT 2>/dev/null || true
        done < /etc/antiddos/whitelist.list
    fi
    # LOW-5: mirror the ufw/firewalld cleanup setup and uninstall
    # already do - a vacated port must not stay open behind us.
    command -v ufw >/dev/null 2>&1 && ufw delete allow "$PORT"/tcp 2>/dev/null || true
    command -v firewall-cmd >/dev/null 2>&1 && {
        firewall-cmd --remove-port="${PORT}/tcp" --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    }
    # MED-3: the ruleset changed - refresh the persistent save so a
    # reboot does not resurrect the vacated port's rules.
    nx_3proxy_save_rules 2>/dev/null || true
}

# nx_3proxy_save_rules — persist the live ruleset (static filter only:
# transient bans/f2b chains are runtime state, never baked into boot
# persistence, BUG-012) so a 3proxy-only install survives a reboot
# (MED-3). The save path is overridable for tests. The restore unit
# itself is managed by install/uninstall, not here.
nx_3proxy_save_rules() {
    local _dir="${NX_3PROXY_SAVE_DIR:-/etc/iptables}"
    command -v iptables-save >/dev/null 2>&1 || return 0
    mkdir -p "$_dir" 2>/dev/null || return 0
    iptables-save 2>/dev/null | grep -v -e '"auto-ban"' -e '"subnet-ban"' -e 'f2b-' -e 'fail2ban-' > "$_dir/rules.v4" 2>/dev/null || true
}

setup_iptables_for_port() {
    local PORT="$1"

    # MED-5 (fail closed, mirroring antiddos BUG-027): with no
    # Cloudflare ranges loaded, every rule below would treat CF IPs
    # as ordinary traffic. Refuse to arm.
    if [ "${#CF_RANGES[@]}" -eq 0 ]; then
        echo -e "  ${RED}✗${NC}  Cloudflare range list is empty/missing - refusing to apply proxy iptables rules (CF would lose its exemption)" >&2
        return 1
    fi

    # Snapshot BEFORE deleting (MED-1, see remove_proxy_port_rules):
    # an Install/Update recreates the counting rules, which zeroes
    # their kernel counters. Without this, traffic since the last
    # 5-minute accumulator tick is lost on every update.
    nx_proxy_traffic_accum 2>/dev/null || true
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
    done < <(list_self_ips_all)
    # Remove old rate-limit rules by enumeration (BUG-014: rules
    # created by older versions carry varying hitcounts, so a fixed
    # spec delete can miss the real rule; the recent-rule name is
    # the stable identifier)
    local _rn
    for _rn in $(iptables -S INPUT 2>/dev/null | grep -n "3proxy_${PORT}[^0-9]" | cut -d: -f1 | sort -rn); do
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
    done < <(list_self_ips_all)

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
    # Per-IP burst guard: 300 NEW hits per 60s window from one IP.
    # This is the port's abuse protection - deliberately per-IP and
    # independent of any service-wide connection ceiling.
    # Only apply to IPs NOT from CF (CF already accepted above)
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --update --seconds 60 \
        --hitcount 300 -j DROP
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --set

    # ── Step 4: Allow all remaining ──────────────────────
    iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT

    # Stats counters, pinned at position 1 (v3.17.0: a target-less
    # counting rule only counts packets that reach it - anything
    # ACCEPTed above it shadows it, so the pin is re-asserted here
    # and after every antiddos apply, never merely appended).
    nx_pin_proxy_stats_rules "$PORT"

    # UFW / firewalld compat
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active" && \
        ufw allow "$PORT"/tcp >/dev/null 2>&1 || true
    command -v firewall-cmd >/dev/null 2>&1 && \
        firewall-cmd --add-port="$PORT"/tcp --permanent >/dev/null 2>&1 && \
        firewall-cmd --reload >/dev/null 2>&1 || true

    # MED-3: the ruleset changed - refresh the persistent save so a
    # reboot does not lose the proxy's rules on a 3proxy-only box.
    nx_3proxy_save_rules 2>/dev/null || true
}

# ── Run a command with visible "working" feedback ──────────
# Prints "<label> ......" and a growing dot animation so the user can see the
# step is still alive. The command itself is NEVER time-limited. Output is
# captured to a temp log so the dots stay clean; on failure the log tail is
# shown so the real error is not hidden.
