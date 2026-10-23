# @part modules/autoban/50-main-loop.sh - unban_expired + sampling/enforcement main loop
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
unban_expired() {
    local NOW; NOW=$(date +%s)
    [ ! -f "$BANNED_LIST" ] && return
    local NEWLIST=""
    while IFS=' ' read -r ip ts duration; do
        [ -z "$ip" ] && continue
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        duration="${duration//[^0-9]/}"; duration="${duration:-14400}"
        local EXPIRE=$(( ts + duration ))
        if [ "$NOW" -gt "$EXPIRE" ]; then
            # Skip subnet bans — handled by unban_subnet_expired
            [[ "$ip" == *"/"* ]] && NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n" && continue
            iptables -D INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP \
                2>/dev/null || true
            log " UNBANNED: $ip (ban expired)"
        else
            NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n"
        fi
    done < "$BANNED_LIST"
    printf "%b" "$NEWLIST" > "$BANNED_LIST" 2>/dev/null || true
}

# FR-2 watchdog (D2): if a DROP rule or throttle entry ever targets one
# of the server's own IPs (our bug, a foreign tool, a manual mistake),
# remove it and log loudly. "Never block our own IPs" is a monitored
# invariant, not a hope.
self_guard() {
    local _sip _esc _rule
    for _sip in "${SELF_IPS[@]}"; do
        [ -z "$_sip" ] && continue
        _esc=$(printf '%s' "$_sip" | sed 's/\./\\./g')
        while IFS= read -r _rule; do
            [ -z "$_rule" ] && continue
            # _rule is an "INPUT ..." spec derived from iptables -S output.
            # shellcheck disable=SC2086  # word splitting IS the mechanism
            iptables -D $_rule 2>/dev/null && \
                log " SELF-GUARD: removed DROP rule hitting own IP $_sip"
        done < <(iptables -S INPUT 2>/dev/null | grep -E -- "-s ${_esc}(/32)?[[:space:]]" | grep -- '-j DROP' | sed 's/^-A /INPUT /')
    done
    if [ -f "$THROTTLE_LIST" ]; then
        for _sip in "${SELF_IPS[@]}"; do
            if grep -q "^${_sip} " "$THROTTLE_LIST" 2>/dev/null; then
                unthrottle_ip "$_sip" hard 2>/dev/null || true
                unthrottle_ip "$_sip" soft 2>/dev/null || true
                log " SELF-GUARD: removed throttle state for own IP $_sip"
            fi
        done
    fi
}

log " Smart throttle+ban started (conn_threshold:${CONN_THRESHOLD} ban_threshold:${BAN_CONN_THRESHOLD} subnet_threshold:${SUBNET_THRESHOLD} observe:${OBSERVE_SECONDS}s throttle:${THROTTLE_MBPS}Mbps ban:${BAN_HOURS}h)"

score_init

# Restore throttle filters recorded before a restart/reboot (the qdisc
# may have been rebuilt without them - see reapply_throttles, BUG-022).
reapply_throttles

CYCLE=0
while true; do
    CYCLE=$((CYCLE + 1))

    # Every ~5 min: unban expired IPs and subnets
    [ $((CYCLE % 75)) -eq 0 ] && unban_expired && unban_subnet_expired

    # Every cycle: enforce self-IP immunity (cheap; iptables -S scan)
    self_guard

    # Measure active connections per IP (accurate, zero CPU overhead)
    # Normal user: 5-20 connections. Attacker: 100s-1000s.
    declare -A CONN_COUNT
    SS_OUT=$(ss -tn 2>/dev/null | awk 'NR>1{print $5}' | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        sort | uniq -c | sort -rn | head -100 || true)
    if [ -n "$SS_OUT" ]; then
        while IFS= read -r line; do
            CNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            [ -n "$IP" ] && [ -n "$CNT" ] && CONN_COUNT["$IP"]="$CNT"
        done <<< "$SS_OUT"
    fi
    sleep "$SAMPLE_INTERVAL"

    # Process results — based on real connection count, not packets
    for ip in "${!CONN_COUNT[@]}"; do
        count="${CONN_COUNT[$ip]}"
        [ "${count:-0}" -lt "$CONN_THRESHOLD" ] && continue

        # Skip exempt IPs (CF + self)
        is_exempt "$ip" && continue

        # Skip already banned
        grep -qF "$ip" "$BANNED_LIST" 2>/dev/null && continue

        # Reputation scoring: adjust score for this sample and enforce band.
        # Uses the connection count and the interval since the last sample.
        update_score "$ip" "$count" "$SAMPLE_INTERVAL"

        # Immediate action if way over limit (≥ BAN_CONN_THRESHOLD conns)
        if [ "${count:-0}" -ge "$BAN_CONN_THRESHOLD" ]; then
            if ! grep -qF "$ip" "$THROTTLE_LIST" 2>/dev/null; then
                throttle_ip "$ip"
            fi
            ban_ip "$ip"
            sed -i "/$ip/d" "$WATCH_LIST" 2>/dev/null || true
            log " INSTANT BAN: $ip | ${count} active connections (>=${BAN_CONN_THRESHOLD})"
            continue
        fi

        if grep -qF "$ip" "$WATCH_LIST" 2>/dev/null; then
            # Was being watched — check if still high
            WATCH_START=$(grep -F "$ip" "$WATCH_LIST" | awk '{print $2}' | head -1)
            WATCH_START="${WATCH_START//[^0-9]/}"
            NOW=$(date +%s)
            ELAPSED=$(( NOW - ${WATCH_START:-$NOW} ))

            if [ "$ELAPSED" -ge "$OBSERVE_SECONDS" ]; then
                # Watched for full period and still high
                if grep -qF "$ip" "$THROTTLE_LIST" 2>/dev/null; then
                    # Already throttled — now ban
                    ban_ip "$ip"
                    sed -i "/$ip/d" "$WATCH_LIST" 2>/dev/null || true
                    sed -i "/$ip/d" "$THROTTLE_LIST" 2>/dev/null || true
                else
                    # Not yet throttled — throttle now
                    throttle_ip "$ip"
                    # Reset watch timer
                    sed -i "/$ip/d" "$WATCH_LIST" 2>/dev/null || true
                    echo "$ip $(date +%s)" >> "$WATCH_LIST"
                fi
            fi
        else
            # Start watching
            echo "$ip $(date +%s)" >> "$WATCH_LIST"
            log " WATCHING: $ip | ${count} active connections (threshold: ${CONN_THRESHOLD})"
        fi
    done

    # Clean watch list: remove IPs that went quiet (dropped below threshold)
    while IFS=' ' read -r ip ts; do
        [ -z "$ip" ] && continue
        # If IP is now below threshold and not being throttled, remove from watch
        if [ "${CONN_COUNT[$ip]:-0}" -lt "$CONN_THRESHOLD" ] && \
           ! grep -qF "$ip" "$THROTTLE_LIST" 2>/dev/null; then
            sed -i "/$ip/d" "$WATCH_LIST" 2>/dev/null || true
        fi
    done < "$WATCH_LIST" 2>/dev/null || true

    # ── Auto-release throttled IPs that have calmed down ──
    # A throttled IP that drops back below the safe threshold (e.g. a legit heavy
    # download that ended) should be released back to the normal class instead of
    # being held forever. This is the "recover reputation" half of scoring.
    # CF + own IPs are always exempt; banned IPs stay banned until expiry.
    while IFS=' ' read -r ip ts; do
        [ -z "$ip" ] && continue
        is_exempt "$ip" && continue
        grep -qF "$ip" "$BANNED_LIST" 2>/dev/null && continue
        # Still hot → keep throttled, let scoring manage it.
        [ "${CONN_COUNT[$ip]:-0}" -ge "$CONN_THRESHOLD" ] && continue
        # Not banned, no longer hot → release to normal class (1:20).
        # Remove THIS IP's throttle filter by its recorded prio (never a bare
        # 'parent 1:' delete, and never a competing add — an added release
        # filter would out-prio the throttle band and permanently defeat
        # re-throttling of this IP, plus it would accumulate on the iface).
        _RELEASE_PRIO=$(grep -F "$ip " "$THROTTLE_LIST" 2>/dev/null | \
                        awk '{print $2}' | head -1 || true)
        [ -n "$_RELEASE_PRIO" ] && \
            tc filter del dev "$IF" parent 1: prio "$_RELEASE_PRIO" 2>/dev/null || true
        sed -i "/^$ip /d" "$THROTTLE_LIST" 2>/dev/null || true
        sed -i "/$ip/d" "$WATCH_LIST" 2>/dev/null || true
        clear_reputation "$ip"
        log " AUTO-RELEASE: $ip (calmed down) → normal class (1:20)"
    done < "$THROTTLE_LIST" 2>/dev/null || true

    # ── Subnet /24 botnet detection ──────────────────────────
    # Aggregate connections by /24 subnet to detect distributed botnets
    # where each attacker IP stays under the per-IP threshold.
    declare -A SUBNET_COUNT
    for ip in "${!CONN_COUNT[@]}"; do
        subnet=$(echo "$ip" | grep -oP '^\d+\.\d+\.\d+')
        [ -z "$subnet" ] && continue
        SUBNET_COUNT["$subnet"]=$(( ${SUBNET_COUNT[$subnet]:-0} + ${CONN_COUNT[$ip]:-0} ))
    done

    for subnet in "${!SUBNET_COUNT[@]}"; do
        total="${SUBNET_COUNT[$subnet]:-0}"
        [ "$total" -lt "$SUBNET_THRESHOLD" ] && continue
        # Skip if CF subnet
        is_cf_ip "${subnet}.1" 2>/dev/null && continue
        # Already banned as subnet?
        iptables -C INPUT -s "${subnet}.0/24" -m comment --comment "subnet-ban" \
            -j DROP 2>/dev/null && continue

        if [ "$total" -ge "$SUBNET_BAN_THRESHOLD" ]; then
            ban_subnet "$subnet"
        else
            # Watch mode: log first sighting
            if ! grep -qF "$subnet" "$SUBNET_WATCH_LIST" 2>/dev/null; then
                echo "$subnet $(date +%s)" >> "$SUBNET_WATCH_LIST"
                log " SUBNET WATCHING: ${subnet}.0/24 | ${total} total conns from subnet"
            else
                SWATCH_START=$(grep -F "$subnet" "$SUBNET_WATCH_LIST" | awk '{print $2}' | head -1)
                SWATCH_START="${SWATCH_START//[^0-9]/}"; SWATCH_START="${SWATCH_START:-$(date +%s)}"
                SELAPSED=$(( $(date +%s) - SWATCH_START ))
                if [ "$SELAPSED" -ge "$OBSERVE_SECONDS" ]; then
                    log " SUBNET HIGH: ${subnet}.0/24 | ${total} conns for ${SELAPSED}s → banning"
                    ban_subnet "$subnet"
                    sed -i "/$subnet/d" "$SUBNET_WATCH_LIST" 2>/dev/null || true
                fi
            fi
        fi
    done

    # Clean subnet watch list: remove subnets that calmed down
    while IFS=' ' read -r subnet ts; do
        [ -z "$subnet" ] && continue
        if [ "${SUBNET_COUNT[$subnet]:-0}" -lt "$SUBNET_THRESHOLD" ]; then
            sed -i "/$subnet/d" "$SUBNET_WATCH_LIST" 2>/dev/null || true
        fi
    done < "$SUBNET_WATCH_LIST" 2>/dev/null || true

    unset CONN_COUNT SUBNET_COUNT
done
