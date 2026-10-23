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
            [[ "$ip" == *":"* ]] && ip6tables -D INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || true
            iptables -D INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP \
                2>/dev/null || true
            # D3 (FR-3): expiry is a probation release, never a return to
            # a stale low score - identical for every ban path.
            rep_on_unban "$ip"
            log " UNBANNED: $ip (ban expired) → probation (score $PROBATION_SCORE, ${PROBATION_SECONDS}s)"
        else
            NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n"
        fi
    done < "$BANNED_LIST"
    printf "%b" "$NEWLIST" > "$BANNED_LIST.tmp.$$" 2>/dev/null && \
        mv "$BANNED_LIST.tmp.$$" "$BANNED_LIST" 2>/dev/null || true
}

# reconcile_bans (BUG-004/D6): state files and the kernel drifted apart
# across reboots - bans were recorded in BANNED_LIST but the iptables
# rules were gone, while the loop skipped those IPs as "already banned".
# At startup, re-apply every unexpired ban to the kernel; expiry (with
# the D3 probation transition) is handled by unban_expired right after.
reconcile_bans() {
    [ -f "$BANNED_LIST" ] || return 0
    local now ip ts duration
    now=$(date +%s)
    while read -r ip ts duration; do
        [ -z "$ip" ] && continue
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        duration="${duration//[^0-9]/}"; duration="${duration:-14400}"
        [ $(( ts + duration )) -le "$now" ] && continue
        case "$ip" in
            *:*) ip6tables -C INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || ip6tables -I INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || true ;;
            */*) iptables -C INPUT -s "$ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || \
                 iptables -I INPUT -s "$ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || true ;;
            *)   iptables -C INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || \
                 iptables -I INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || true ;;
        esac
    done < "$BANNED_LIST"
    unban_expired
    unban_subnet_expired
    log " RECONCILE: unexpired bans re-applied to iptables from state"
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
        state_del_ip "$BANNED_LIST" "$_sip"
    done
    # IPv6 self sweep (Wave 9): the same hard guarantee for v6
    local _sip6
    for _sip6 in "${SELF6_IPS[@]}"; do
        if ip6tables -C INPUT -s "$_sip6" -j DROP 2>/dev/null; then
            ip6tables -D INPUT -s "$_sip6" -j DROP 2>/dev/null || true
            log " SELF-GUARD: removed DROP rule for own IPv6 $_sip6"
        fi
        state_del_ip "$BANNED_LIST" "$_sip6"
    done
    if [ -f "$THROTTLE_LIST" ]; then
        local _prio
        for _sip in "${SELF_IPS[@]}"; do
            if state_has_ip "$THROTTLE_LIST" "$_sip"; then
                _prio=$(state_get_field "$THROTTLE_LIST" "$_sip" 2)
                [ -n "$_prio" ] && tc filter del dev "$IF" parent 1: prio "$_prio" 2>/dev/null || true
                state_del_ip "$THROTTLE_LIST" "$_sip"
                log " SELF-GUARD: removed throttle state for own IP $_sip"
            fi
        done
    fi
}

log " Smart throttle+ban started (conn_threshold:${CONN_THRESHOLD} ban_threshold:${BAN_CONN_THRESHOLD} subnet_threshold:${SUBNET_THRESHOLD} observe:${OBSERVE_SECONDS}s throttle:${THROTTLE_MBPS}Mbps ban:${BAN_HOURS}h)"

score_init

# Restore throttle filters recorded before a restart/reboot (the qdisc
# may have been rebuilt without them - see reapply_throttles, BUG-022).
# After a reboot /tmp is empty: pull the state back from the mirror
# first (U-11), or reapply has nothing to work with.
restore_throttle_state
reapply_throttles

# Re-apply recorded bans to the kernel (BUG-004) and expire the stale
# ones through the D3 transition.
reconcile_bans

CYCLE=0
while true; do
    CYCLE=$((CYCLE + 1))

    # Keep the persistent throttle mirror current (U-11).
    mirror_throttle_state

    # Every ~5 min: pick up any newly assigned own IPs (E-3), then
    # unban expired IPs and subnets
    [ $((CYCLE % 75)) -eq 0 ] && refresh_self_ips && unban_expired && unban_subnet_expired

    # Every cycle: enforce self-IP immunity (cheap; iptables -S scan)
    self_guard

    # Measure active connections per IP. Counting definition (BUG-030):
    # only ESTABLISHED and SYN-RECV sockets count (the old `ss -tn`
    # sample also counted TIME-WAIT/CLOSING states), and flows whose
    # LOCAL port is ephemeral (>=32768) are the server's own OUTBOUND
    # connections - the peer of an outbound flow is not an attacker.
    declare -A CONN_COUNT
    SS_OUT=$({ ss -tnH state established 2>/dev/null; ss -tnH state syn-recv 2>/dev/null; } | \
        awk '{ split($4, L, ":"); lp = L[length(L)];
               if (lp !~ /^[0-9]+$/) next;
               if (lp >= 32768) next;
               print $5 }' | \
        { grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; grep -oE '\[[0-9a-fA-F:]+\]' | tr -d '[]'; } | \
        sort | uniq -c | sort -rn | head -100 || true)
    if [ -n "$SS_OUT" ]; then
        while IFS= read -r line; do
            CNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            [ -n "$IP" ] && [ -n "$CNT" ] && CONN_COUNT["$IP"]="$CNT"
        done <<< "$SS_OUT"
    fi
    # SYN-RECV per IP (scoring v2): half-open sockets are the SYN-flood
    # signature; v1 merged them into the same counter as ESTABLISHED,
    # so scoring could not tell a flood from honest load.
    declare -A SYN_COUNT
    SS_SYN=$(ss -tnH state syn-recv 2>/dev/null | \
        awk '{ split($4, L, ":"); lp = L[length(L)];
               if (lp !~ /^[0-9]+$/) next;
               if (lp >= 32768) next;
               print $5 }' | \
        { grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; grep -oE '\[[0-9a-fA-F:]+\]' | tr -d '[]'; } | \
        sort | uniq -c | sort -rn | head -100 || true)
    if [ -n "$SS_SYN" ]; then
        while IFS= read -r line; do
            CNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            [ -n "$IP" ] && [ -n "$CNT" ] && SYN_COUNT["$IP"]="$CNT"
        done <<< "$SS_SYN"
    fi
    sleep "$SAMPLE_INTERVAL"

    # Process results — based on real connection count, not packets
    for ip in "${!CONN_COUNT[@]}"; do
        count="${CONN_COUNT[$ip]}"
        [ "${count:-0}" -lt "$CONN_THRESHOLD" ] && continue

        # Skip exempt IPs (CF + self)
        is_exempt_any "$ip" && continue

        # Skip already banned
        state_has_ip "$BANNED_LIST" "$ip" && continue

        # Reputation scoring: adjust score for this sample and enforce band.
        # Uses the connection count and the interval since the last sample.
        update_score "$ip" "$count" "${SYN_COUNT[$ip]:-0}" "$SAMPLE_INTERVAL"

        # Immediate action if way over limit (≥ BAN_CONN_THRESHOLD conns)
        if [ "${count:-0}" -ge "$BAN_CONN_THRESHOLD" ]; then
            if ! state_has_ip "$THROTTLE_LIST" "$ip"; then
                nx_throttle "$ip"
            fi
            nx_ban "$ip"
            rep_on_ban "$ip"
            state_del_ip "$WATCH_LIST" "$ip"
            log " INSTANT BAN: $ip | ${count} active connections (>=${BAN_CONN_THRESHOLD})"
            continue
        fi

        if state_has_ip "$WATCH_LIST" "$ip"; then
            # Was being watched — check if still high
            WATCH_START=$(state_get_field "$WATCH_LIST" "$ip" 2)
            WATCH_START="${WATCH_START//[^0-9]/}"
            NOW=$(date +%s)
            ELAPSED=$(( NOW - ${WATCH_START:-$NOW} ))

            if [ "$ELAPSED" -ge "$OBSERVE_SECONDS" ]; then
                # Watched for full period and still high
                if state_has_ip "$THROTTLE_LIST" "$ip"; then
                    # Already throttled — now ban (ban_ip cleans the
                    # throttle filter + its state entry itself)
                    nx_ban "$ip"
                    rep_on_ban "$ip"
                    state_del_ip "$WATCH_LIST" "$ip"
                else
                    # Not yet throttled — throttle now
                    nx_throttle "$ip"
                    # Reset watch timer
                    state_del_ip "$WATCH_LIST" "$ip"
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
           ! state_has_ip "$THROTTLE_LIST" "$ip"; then
            state_del_ip "$WATCH_LIST" "$ip"
        fi
    done < "$WATCH_LIST" 2>/dev/null || true

    # ── Auto-release throttled IPs that have calmed down ──
    # A throttled IP that drops back below the safe threshold (e.g. a legit heavy
    # download that ended) should be released back to the normal class instead of
    # being held forever. This is the "recover reputation" half of scoring.
    # CF + own IPs are always exempt; banned IPs stay banned until expiry.
    while IFS=' ' read -r ip ts; do
        [ -z "$ip" ] && continue
        is_exempt_any "$ip" && continue
        state_has_ip "$BANNED_LIST" "$ip" && continue
        # Still hot → keep throttled, let scoring manage it.
        [ "${CONN_COUNT[$ip]:-0}" -ge "$CONN_THRESHOLD" ] && continue
        # Not banned, no longer hot → release to normal class (1:20).
        # Remove THIS IP's throttle filter by its recorded prio (never a bare
        # 'parent 1:' delete, and never a competing add — an added release
        # filter would out-prio the throttle band and permanently defeat
        # re-throttling of this IP, plus it would accumulate on the iface).
        # R-2 (deep review 2026-10-23): release only once the
        # reputation has genuinely recovered. A single quiet sample
        # used to release the filter AND wipe the score
        # (clear_reputation), so a pulsing source - hot 40s, quiet 3s -
        # erased its history every cycle. Quiet recovery is the
        # sweep's job now; the entry is left for it to finish.
        _REL_SCORE=$(state_get_field "$SCORE_FILE" "$ip" 2)
        _REL_SCORE="${_REL_SCORE//[^0-9]/}"; _REL_SCORE="${_REL_SCORE:-100}"
        [ "$_REL_SCORE" -lt "$SCORE_THROTTLE" ] && continue
        _RELEASE_PRIO=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
        [ -n "$_RELEASE_PRIO" ] && \
            tc filter del dev "$IF" parent 1: prio "$_RELEASE_PRIO" 2>/dev/null || true
        state_del_ip "$THROTTLE_LIST" "$ip"
        state_del_ip "$WATCH_LIST" "$ip"
        log " AUTO-RELEASE: $ip (calmed down, score $_REL_SCORE) → normal class (1:20)"
    done < "$THROTTLE_LIST" 2>/dev/null || true

    # ── Subnet /24 botnet detection ──────────────────────────
    # Aggregate connections by /24 subnet to detect distributed botnets
    # where each attacker IP stays under the per-IP threshold.
    declare -A SUBNET_COUNT
    for ip in "${!CONN_COUNT[@]}"; do
        # BUG-011: exempt traffic (CF/self/whitelist) never counts toward
        # a subnet ban - it used to inflate the totals.
        is_exempt_any "$ip" && continue
        case "$ip" in *:*) continue ;; esac
        subnet=$(echo "$ip" | grep -oP '^\d+\.\d+\.\d+')
        [ -z "$subnet" ] && continue
        SUBNET_COUNT["$subnet"]=$(( ${SUBNET_COUNT[$subnet]:-0} + ${CONN_COUNT[$ip]:-0} ))
    done

    for subnet in "${!SUBNET_COUNT[@]}"; do
        total="${SUBNET_COUNT[$subnet]:-0}"
        [ "$total" -lt "$SUBNET_THRESHOLD" ] && continue
        # Skip if a CF range overlaps this /24 (real overlap test)
        subnet_overlaps_cf "$subnet" && continue
        # Already banned as subnet?
        iptables -C INPUT -s "${subnet}.0/24" -m comment --comment "subnet-ban" \
            -j DROP 2>/dev/null && continue

        if [ "$total" -ge "$SUBNET_BAN_THRESHOLD" ]; then
            ban_subnet "$subnet"
        else
            # Watch mode: log first sighting
            if ! state_has_ip "$SUBNET_WATCH_LIST" "$subnet"; then
                echo "$subnet $(date +%s)" >> "$SUBNET_WATCH_LIST"
                log " SUBNET WATCHING: ${subnet}.0/24 | ${total} total conns from subnet"
            else
                SWATCH_START=$(state_get_field "$SUBNET_WATCH_LIST" "$subnet" 2)
                SWATCH_START="${SWATCH_START//[^0-9]/}"; SWATCH_START="${SWATCH_START:-$(date +%s)}"
                SELAPSED=$(( $(date +%s) - SWATCH_START ))
                # BUG-011: the sustained path may only ban at the BAN
                # threshold. Sustained traffic at the WATCH level (400)
                # for OBSERVE_SECONDS used to ban a /24 the design says
                # to merely watch - the effective trigger was 400/45s,
                # not the documented 1000.
                if [ "$SELAPSED" -ge "$OBSERVE_SECONDS" ] && [ "$total" -ge "$SUBNET_BAN_THRESHOLD" ]; then
                    log " SUBNET HIGH: ${subnet}.0/24 | ${total} conns for ${SELAPSED}s → banning"
                    ban_subnet "$subnet"
                    state_del_ip "$SUBNET_WATCH_LIST" "$subnet"
                fi
            fi
        fi
    done

    # Clean subnet watch list: remove subnets that calmed down
    while IFS=' ' read -r subnet ts; do
        [ -z "$subnet" ] && continue
        if [ "${SUBNET_COUNT[$subnet]:-0}" -lt "$SUBNET_THRESHOLD" ]; then
            state_del_ip "$SUBNET_WATCH_LIST" "$subnet"
        fi
    done < "$SUBNET_WATCH_LIST" 2>/dev/null || true

    # Recovery for quiet IPs (D3): hot IPs were handled by update_score.
    reputation_sweep

    unset CONN_COUNT SUBNET_COUNT SYN_COUNT
done
