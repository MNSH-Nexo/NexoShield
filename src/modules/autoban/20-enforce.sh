# @part modules/autoban/20-enforce.sh - throttle_ip, hard_throttle_ip, ban_ip
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.

# ── tc helpers (Wave 2) ─────────────────────────────
# next_tc_prio: persistent monotonic prio allocator. The old schemes
# collided (soft = 10000 + line count of a file other code also rewrites;
# hard = 20000 + RANDOM%4000), and 'tc filter del prio X' deletes EVERY
# filter at that prio - a collision could wipe a CF whitelist filter.
# Daemon filter prios now come only from this counter (>= 20001), far
# above the setup bands (10..<10000) and never reused.
next_tc_prio() {
    local f v
    f="$(dirname "$THROTTLE_LIST")/tc-prio.seq"
    v=$(cat "$f" 2>/dev/null || echo 20000)
    v="${v//[^0-9]/}"; v="${v:-20000}"
    [ "$v" -lt 20000 ] && v=20000
    v=$(( v + 1 ))
    echo "$v" > "$f" 2>/dev/null || true
    echo "$v"
}

tc_class_exists() {
    tc class show dev "$IF" 2>/dev/null | grep -q "class htb $1[[:space:]]"
}

# reapply_throttles: after a reboot (or any qdisc rebuild that did not go
# through tc-setup.sh), restore the daemon's recorded throttle filters so
# THROTTLE_LIST and the kernel agree again (BUG-022/BUG-004 family).
reapply_throttles() {
    [ -f "$THROTTLE_LIST" ] || return 0
    local ip prio ts band flow
    while read -r ip prio ts band; do
        [ -z "$ip" ] && continue
        case "$prio" in ''|*[!0-9]*) continue ;; esac
        flow=1:30; [ "$band" = "hard" ] && flow=1:40
        tc_class_exists "$flow" || flow=1:30
        tc_class_exists "$flow" || continue
        tc filter del dev "$IF" parent 1: protocol ip prio "$prio" 2>/dev/null || true
        tc filter add dev "$IF" parent 1: protocol ip prio "$prio" \
            u32 match ip dst "$ip/32" flowid $flow 2>/dev/null || true
    done < "$THROTTLE_LIST"
}
throttle_ip() {
    local ip="$1"
    is_exempt "$ip" && return 0
    grep -qF "$ip " "$THROTTLE_LIST" 2>/dev/null && return 0
    # BUG-024: never record state for a throttle that does not exist.
    # In autoban-only mode there are no tc classes at all - say so.
    if ! tc_class_exists 1:30; then
        log " THROTTLE SKIP: $ip - tc class 1:30 missing on $IF (autoban-only mode? run the full antiddos setup to enable bandwidth throttling)"
        return 1
    fi
    local HANDLE; HANDLE=$(next_tc_prio)
    # BUG-001: egress qdisc - the client is the DESTINATION.
    if tc filter add dev "$IF" parent 1: protocol ip prio "$HANDLE" \
        u32 match ip dst "$ip/32" flowid 1:30 2>/dev/null; then
        echo "$ip $HANDLE $(date +%s) soft" >> "$THROTTLE_LIST"
        log " THROTTLE: $ip -> 100Mbps (will ban in ${OBSERVE_SECONDS}s if continues)"
    else
        log " THROTTLE FAIL: $ip - tc filter add failed; state NOT recorded"
        return 1
    fi
}

# Hard-throttle: move an IP to class 1:40 (50Mbps). Used by the reputation
# scoring system when score falls into the worst (pre-ban) band but the IP is
# not yet confirmed as an attack. Keeps the connection open (legit heavy user
# stays online) while crushing throughput so a flood can't starve the box.
# Class 1:40 must exist (added by install alongside 1:30). If it does not,
# fall back to 100Mbps class 1:30 rather than failing.
hard_throttle_ip() {
    local ip="$1"
    is_exempt "$ip" && return 0
    # Drop any earlier throttle entry for this IP so the tc filter list stays
    # consistent and no stale prio is left behind (its filter would still match).
    local _OLD
    _OLD=$(grep -F "$ip " "$THROTTLE_LIST" 2>/dev/null | awk '{print $2}' | head -1 || true)
    [ -n "$_OLD" ] && tc filter del dev "$IF" parent 1: prio "$_OLD" 2>/dev/null || true
    sed -i "/^$ip /d" "$THROTTLE_LIST" 2>/dev/null || true
    # Pick the strongest class that actually exists (BUG-024: state is
    # written only after the filter lands).
    local FLOW=""
    if tc_class_exists 1:40; then FLOW=1:40
    elif tc_class_exists 1:30; then FLOW=1:30
    else
        log " HARD-THROTTLE SKIP: $ip - no tc throttle classes on $IF"
        return 1
    fi
    local HANDLE; HANDLE=$(next_tc_prio)
    if tc filter add dev "$IF" parent 1: protocol ip prio "$HANDLE" \
        u32 match ip dst "$ip/32" flowid $FLOW 2>/dev/null; then
        echo "$ip $HANDLE $(date +%s) hard" >> "$THROTTLE_LIST"
        log " HARD-THROTTLE: $ip -> $FLOW (reputation low)"
    else
        log " HARD-THROTTLE FAIL: $ip - tc filter add failed; state NOT recorded"
        return 1
    fi
}

ban_ip() {
    local ip="$1"
    # FR-2 choke-point guard: ban_ip is the funnel for EVERY ban path
    # (classic, reputation, instant). A self IP must never pass, even if
    # some other check regresses.
    if is_self_ip "$ip"; then
        log " SELF-GUARD: refused to ban the server's own IP $ip"
        return 1
    fi
    is_exempt "$ip" && return 0
    grep -qF "$ip " "$BANNED_LIST" 2>/dev/null && return 0
    local UNBAN_TIME
    UNBAN_TIME=$(date -d "+${BAN_HOURS} hours" '+%H:%M:%S' 2>/dev/null || \
                 date -v "+${BAN_HOURS}H" '+%H:%M:%S' 2>/dev/null || echo "N/A")
    iptables -I INPUT -s "$ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || true
    echo "$ip $(date +%s) $((BAN_HOURS * 3600))" >> "$BANNED_LIST"
    # Remove ONLY this IP's throttle/hard-throttle tc filter.
    # NOTE: never run 'tc filter del dev "$IF" parent 1:' here — that deletes
    # EVERY filter including the Cloudflare + server-own whitelist, which would
    # throttle CF traffic. We remove the one filter recorded for this IP.
    local _PRIO
    _PRIO=$(grep -F "$ip " "$THROTTLE_LIST" 2>/dev/null | awk '{print $2}' | head -1 || true)
    [ -n "$_PRIO" ] && tc filter del dev "$IF" parent 1: prio "$_PRIO" 2>/dev/null || true
    sed -i "/^$ip /d" "$THROTTLE_LIST" 2>/dev/null || true
    log " BANNED: $ip | unban: $UNBAN_TIME"
}

# ════════════════════════════════════════════════════════════
# Reputation scoring — heuristic behavior-based scoring.
# Idea: instead of a hard 80/200 connection cut, score each IP 100..0 and
# escalate gradually. Human/browser traffic opens connections slowly and holds
# them; bots open many new short-lived connections rapidly. We derive the
# new-connection rate from successive connection-count samples (no per-packet
# cost), which is the strongest single discriminator.
#   - well-behaved  → score recovers (auto-release of throttle)
#   - rapid churn   → score drops fast → graduated penalty → ban
# ════════════════════════════════════════════════════════════

# ensure SCORE_DIR exists and SCORE_FILE is readable
