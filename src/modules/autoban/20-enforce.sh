# @part modules/autoban/20-enforce.sh - throttle_ip, hard_throttle_ip, ban_ip
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
throttle_ip() {
    local ip="$1"
    is_exempt "$ip" && return 0
    grep -qF "$ip " "$THROTTLE_LIST" 2>/dev/null && return 0
    # Add to tc class 1:30 (100Mbps)
    local HANDLE
    local _WC; _WC=$(wc -l < "$THROTTLE_LIST" 2>/dev/null || echo 1)
    _WC="${_WC//[^0-9]/}"; _WC="${_WC:-1}"
    HANDLE=$(( 10000 + _WC ))
    echo "$ip $HANDLE $(date +%s)" >> "$THROTTLE_LIST"
    tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
        u32 match ip src "$ip/32" flowid 1:30 2>/dev/null || true
    log " THROTTLE: $ip -> 100Mbps (will ban in ${OBSERVE_SECONDS}s if continues)"
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
    local HANDLE
    HANDLE=$(( 20000 + ( RANDOM % 4000 ) ))
    echo "$ip $HANDLE $(date +%s) hard" >> "$THROTTLE_LIST"
    tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
        u32 match ip src "$ip/32" flowid 1:40 2>/dev/null || \
    tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
        u32 match ip src "$ip/32" flowid 1:30 2>/dev/null || true
    log " HARD-THROTTLE: $ip -> 50Mbps (reputation low)"
}

ban_ip() {
    local ip="$1"
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
