# @part modules/autoban/40-subnet.sh - ban_subnet + unban_subnet_expired
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
ban_subnet() {
    local subnet="$1"   # e.g. "1.2.3"  (first 3 octets)
    local cidr="${subnet}.0/24"
    # Don't ban if any CF range overlaps (rough check: skip 103.x, 104.x, 108.x, 141.x, 162.x, 172.x, 173.x, 188.x, 190.x, 197.x, 198.x)
    is_cf_ip "${subnet}.1" 2>/dev/null && return 0
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
            if [ "$(echo "$_EIP" | grep -oP '^\d+\.\d+\.\d+' 2>/dev/null)" = "$subnet" ]; then
                log " SUBNET SKIP: $cidr overlaps whitelisted $_ENTRY"
                return 0
            fi
        done < "$WHITELIST_FILE"
    fi
    # Already banned?
    iptables -C INPUT -s "$cidr" -m comment --comment "subnet-ban" -j DROP 2>/dev/null && return 0
    iptables -I INPUT -s "$cidr" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || true
    echo "$cidr $(date +%s) $((BAN_HOURS * 3600))" >> "$BANNED_LIST"
    log " SUBNET BAN: $cidr | botnet distributed attack detected | unban: ${BAN_HOURS}h"
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
            iptables -D INPUT -s "$ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || true
            log " SUBNET UNBANNED: $ip (expired)"
        else
            NEWLIST="${NEWLIST}${ip} ${ts} ${duration}\n"
        fi
    done < "$BANNED_LIST"
    printf "%b" "$NEWLIST" > "$BANNED_LIST" 2>/dev/null || true
}

