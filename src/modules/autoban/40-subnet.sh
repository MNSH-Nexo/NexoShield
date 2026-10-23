# @part modules/autoban/40-subnet.sh - ban_subnet + unban_subnet_expired
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
ban_subnet() {
    local subnet="$1"   # e.g. "1.2.3"  (first 3 octets)
    local cidr="${subnet}.0/24"
    # Don't ban if any CF range overlaps this /24 (BUG-011: the old
    # check tested only the .1 address and missed ranges starting
    # mid-/24; subnet_overlaps_cf tests real range intersection)
    subnet_overlaps_cf "$subnet" && { log " SUBNET SKIP: $cidr overlaps a Cloudflare range"; return 0; }
    # Don't ban own server subnet - check EVERY local address (BUG-065:
    # the old code compared only the first `ip addr` line via head -1)
    local _sip
    for _sip in "${SELF_IPS[@]}"; do
        [ "${_sip%.*}" = "$subnet" ] && { log " SUBNET SKIP: $cidr contains own IP $_sip"; return 0; }
    done
    if [ -f /etc/antiddos/self-ips.list ]; then
        while IFS= read -r _sip; do
            [ "${_sip%.*}" = "$subnet" ] && { log " SUBNET SKIP: $cidr contains own IP $_sip (snapshot)"; return 0; }
        done < /etc/antiddos/self-ips.list
    fi
    # Don't ban if any user-whitelisted IP/CIDR falls inside this /24 subnet —
    # whitelisted users must never be dropped even under distributed attacks.
    local _ENTRY _EIP
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _ENTRY; do
            _ENTRY="${_ENTRY%%#*}"; _ENTRY="${_ENTRY// /}"
            [ -z "$_ENTRY" ] && continue
            case "$_ENTRY" in
                */*) _EIP="${_ENTRY%%/*}" ;;
                *)   _EIP="$_ENTRY" ;;
            esac
            _ECIDR="$_ENTRY"; case "$_ECIDR" in */*) ;; *) _ECIDR="${_ECIDR}/32" ;; esac
            if ip_in_cidr "${subnet}.0" "$_ECIDR" 2>/dev/null || \
               ip_in_cidr "$_EIP" "${subnet}.0/24" 2>/dev/null; then
                log " SUBNET SKIP: $cidr overlaps whitelisted $_ENTRY"
                return 0
            fi
        done < "$WHITELIST_FILE"
    fi
    # Already banned? (state is the source of truth, Phase 1b)
    state_has_ip "$BANNED_LIST" "$cidr" && return 0
    # Phase 1c: subnet bans are short (guardrail vs shared-egress
    # collateral) and ride the same backend as single-IP bans.
    if ! nx_ban_apply "$cidr" $((${SUBNET_BAN_MINUTES:-60} * 60)) "subnet-ban"; then
        log " SUBNET BAN FAILED: $cidr - backend refused; state NOT recorded"
        return 1
    fi
    echo "$cidr $(date +%s) $((${SUBNET_BAN_MINUTES:-60} * 60))" >> "$BANNED_LIST"
    log " SUBNET BAN: $cidr | botnet distributed attack detected | unban: ${SUBNET_BAN_MINUTES:-60}min"
}

unban_subnet_expired() {
    local NOW; NOW=$(date +%s)
    [ ! -f "$BANNED_LIST" ] && return
    local NEWLIST=""
    while IFS=' ' read -r ip ts duration; do
        [ -z "$ip" ] && continue
        # Only process subnet entries (contain /)
        [[ "$ip" != *"/"* ]] && NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n" && continue
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        duration="${duration//[^0-9]/}"; duration="${duration:-14400}"
        local EXPIRE=$(( ts + duration ))
        if [ "$NOW" -gt "$EXPIRE" ]; then
            nx_ban_remove_fw "$ip"
            iptables -D INPUT -s "$ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || true
            log " SUBNET UNBANNED: $ip (expired)"
        else
            NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n"
        fi
    done < "$BANNED_LIST"
    printf "%b" "$NEWLIST" > "$BANNED_LIST.tmp.$$" 2>/dev/null && \
        mv "$BANNED_LIST.tmp.$$" "$BANNED_LIST" 2>/dev/null || true
}

