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
        case "$ip" in
            *:*)
                tc filter del dev "$IF" parent 1: protocol ip6 prio "$prio" 2>/dev/null || true
                tc filter add dev "$IF" parent 1: protocol ip6 prio "$prio" \
                    u32 match ip6 dst "$ip" flowid $flow 2>/dev/null || true ;;
            *)
                tc filter del dev "$IF" parent 1: protocol ip prio "$prio" 2>/dev/null || true
                tc filter add dev "$IF" parent 1: protocol ip prio "$prio" \
                    u32 match ip dst "$ip/32" flowid $flow 2>/dev/null || true ;;
        esac
    done < "$THROTTLE_LIST"
}
# U-11: keep the persistent mirror in sync with the live tmp state,
# and restore from it after a reboot (tmp is wiped; the mirror and
# tc-setup.sh's re-apply both read /etc/antiddos/throttled.list).
mirror_throttle_state() {
    [ -f "$THROTTLE_LIST" ] || return 0
    cmp -s "$THROTTLE_LIST" "$THROTTLE_MIRROR" 2>/dev/null && return 0
    cp "$THROTTLE_LIST" "$THROTTLE_MIRROR.tmp.$$" 2>/dev/null && \
        mv "$THROTTLE_MIRROR.tmp.$$" "$THROTTLE_MIRROR" 2>/dev/null || true
}
restore_throttle_state() {
    if [ ! -f "$THROTTLE_LIST" ] && [ -s "$THROTTLE_MIRROR" ]; then
        cp "$THROTTLE_MIRROR" "$THROTTLE_LIST" 2>/dev/null || true
        log " STATE: throttle list restored from persistent mirror"
    fi
}

throttle_ip() {
    local ip="$1"
    is_exempt "$ip" && return 0
    state_has_ip "$THROTTLE_LIST" "$ip" && return 0
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
    # R-7 (deep review): already hard-throttled = nothing to do. The
    # old code deleted + re-added the filter on EVERY scoring cycle -
    # filter churn, a burned prio per cycle, log spam.
    if state_has_ip "$THROTTLE_LIST" "$ip" && \
        [ "$(state_get_field "$THROTTLE_LIST" "$ip" 4)" = "hard" ]; then
        return 0
    fi
    # Drop any earlier throttle entry for this IP so the tc filter list stays
    # consistent and no stale prio is left behind (its filter would still match).
    local _OLD
    _OLD=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
    [ -n "$_OLD" ] && tc filter del dev "$IF" parent 1: prio "$_OLD" 2>/dev/null || true
    state_del_ip "$THROTTLE_LIST" "$ip"
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

# ── Ban backend (Phase 1b): nftables timed sets ──────────────────
# State files stay the source of truth; the kernel side is a projection.
# With the nft backend, bans live in ONE inet table whose sets give
# ~O(1) lookup (vs one iptables rule per ban, scanned per packet) and
# the kernel itself expires elements (timeout = ban duration). The
# chain checks the EXEMPT set before the ban set: defence in depth
# behind the ban-choke guards, so FR-1/FR-2 hold even inside the
# drop path. Backend resolves ONCE at daemon startup (nx_resolve_ban_
# backend); until then, and whenever nft is unusable, the historical
# iptables path applies — a stock install can never get worse.
NX_BAN_BACKEND="${NX_BAN_BACKEND:-iptables}"

nx_nft_ensure() {
    nft list table inet nexoshield >/dev/null 2>&1 && return 0
    nft -f - >/dev/null 2>&1 <<'NXNFT'
table inet nexoshield {
    set ban4 { type ipv4_addr; flags interval, timeout; }
    set ban6 { type ipv6_addr; flags interval, timeout; }
    set exempt4 { type ipv4_addr; flags interval; }
    set exempt6 { type ipv6_addr; flags interval; }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @exempt4 accept
        ip6 saddr @exempt6 accept
        ip saddr @ban4 drop
        ip6 saddr @ban6 drop
      }
    }
NXNFT
}

nx_resolve_ban_backend() {
    if command -v nft >/dev/null 2>&1 && nx_nft_ensure; then
        NX_BAN_BACKEND=nft
        nx_nft_sync_exempt
    else
        NX_BAN_BACKEND=iptables
    fi
    log " BAN BACKEND: $NX_BAN_BACKEND"
}

# Project the exemption universe into the nft exempt sets: self IPs
# (arrays + snapshots + discovered public IPs), the admin whitelist,
# and the Cloudflare ranges — the same sources is_exempt* consult.
nx_nft_sync_exempt() {
    [ "$NX_BAN_BACKEND" = "nft" ] || return 0
    local v4="" v6="" e
    for e in "${SELF_IPS[@]}"; do [ -n "$e" ] && v4="${v4}${e}, "; done
    for e in "${SELF6_IPS[@]}"; do [ -n "$e" ] && v6="${v6}${e}, "; done
    for e in "${CF_RANGES[@]}"; do v4="${v4}${e}, "; done
    for e in "${CF6_RANGES[@]}"; do v6="${v6}${e}, "; done
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r e; do
            e="${e%%#*}"; e="${e// /}"
            [ -z "$e" ] && continue
            case "$e" in *:*) v6="${v6}${e}, " ;; *) v4="${v4}${e}, " ;; esac
        done < "$WHITELIST_FILE"
    fi
    local snap
    for snap in /etc/antiddos/self-ips.list /etc/antiddos/public-ips.list; do
        [ -f "$snap" ] || continue
        while IFS= read -r e; do
            [ -z "$e" ] && continue
            case "$e" in *:*) v6="${v6}${e}, " ;; *) v4="${v4}${e}, " ;; esac
        done < "$snap"
    done
    nft flush set inet nexoshield exempt4 2>/dev/null || true
    nft flush set inet nexoshield exempt6 2>/dev/null || true
    [ -n "$v4" ] && nft add element inet nexoshield exempt4 "{ ${v4%, } }" 2>/dev/null || true
    [ -n "$v6" ] && nft add element inet nexoshield exempt6 "{ ${v6%, } }" 2>/dev/null || true
}

# nx_ban_apply <ip|cidr> <duration-sec> [comment] — enforce one ban in
# the kernel via the active backend. Legacy fallback on any nft error.
nx_ban_apply() {
    local ip="$1" dur="$2" comment="${3:-auto-ban}" set
    if [ "$NX_BAN_BACKEND" = "nft" ]; then
        case "$ip" in *:*) set=ban6 ;; *) set=ban4 ;; esac
        nft delete element inet nexoshield "$set" "{ $ip }" >/dev/null 2>&1 || true
        if nft add element inet nexoshield "$set" "{ $ip timeout ${dur}s }" >/dev/null 2>&1; then
            return 0
        fi
        log " NFT BAN FAILED for $ip - falling back to iptables"
    fi
    case "$ip" in
        *:*) ip6tables -C INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null || \
             ip6tables -I INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null ;;
        *)   iptables -C INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null || \
             iptables -I INPUT -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null ;;
    esac
}

# nx_ban_remove_fw <ip|cidr> — kernel-side removal for the nft backend
# (legacy iptables deletes stay at the call sites as belt-and-braces).
nx_ban_remove_fw() {
    [ "$NX_BAN_BACKEND" = "nft" ] || return 0
    local set
    case "$1" in *:*) set=ban6 ;; *) set=ban4 ;; esac
    nft delete element inet nexoshield "$set" "{ $1 }" >/dev/null 2>&1 || true
}

# ── Host stress (Phase 1d) ────────────────────────────────────────
# nx_update_stress runs once per cycle: it watches the kernel counters
# that stay truthful under syncookies (RFC 4987) — ListenOverflows —
# plus conntrack pressure. nx_host_stressed is the gate's oracle.
NX_STRESSED_UNTIL=0
_NX_OVF_PREV=""
_NX_SYNCOOK_PREV=""
_NX_SYNCOOK_LAST_LOG=0
NX_OVF_DELTA=0
NX_SYNCOOK_DELTA=0
nx_update_stress() {
    local now ovf scook
    now=$(date +%s)
    read -r ovf scook <<< "$(awk '
        /^TcpExt:/ { if (!h) { for (i=2;i<=NF;i++) { if ($i=="ListenOverflows") co=i; if ($i=="SyncookiesSent") cs=i } h=1; next }
                     print $(co), $(cs); exit }' /proc/net/netstat 2>/dev/null)"
    ovf="${ovf//[^0-9]/}"; scook="${scook//[^0-9]/}"
    NX_OVF_DELTA=0
    NX_SYNCOOK_DELTA=0
    if [ -n "$ovf" ]; then
        if [ -n "$_NX_OVF_PREV" ]; then
            NX_OVF_DELTA=$(( ovf - _NX_OVF_PREV ))
            [ "$NX_OVF_DELTA" -lt 0 ] && NX_OVF_DELTA=0
            [ "$ovf" -gt "$_NX_OVF_PREV" ] && NX_STRESSED_UNTIL=$(( now + 60 ))
        fi
        _NX_OVF_PREV="$ovf"
    fi
    if [ -n "$scook" ]; then
        if [ -n "$_NX_SYNCOOK_PREV" ]; then
            NX_SYNCOOK_DELTA=$(( scook - _NX_SYNCOOK_PREV ))
            [ "$NX_SYNCOOK_DELTA" -lt 0 ] && NX_SYNCOOK_DELTA=0
        fi
        if [ -n "$_NX_SYNCOOK_PREV" ] && [ "$scook" -gt "$_NX_SYNCOOK_PREV" ] \
           && [ $(( now - _NX_SYNCOOK_LAST_LOG )) -ge 60 ]; then
            log " SYNPRESSURE: syncookies engaged (+$(( scook - _NX_SYNCOOK_PREV )) since last check) - SYN-RECV state is being absorbed by the kernel"
            _NX_SYNCOOK_LAST_LOG=$now
        fi
        _NX_SYNCOOK_PREV="$scook"
    fi
}
nx_host_stressed() {
    local now; now=$(date +%s)
    [ "$now" -lt "$NX_STRESSED_UNTIL" ] && return 0
    # Load pressure: load1 >= 0.9 * cores
    local l1 nc
    l1=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    nc=$(nproc 2>/dev/null || echo 1)
    if [ -n "$l1" ] && awk -v l="$l1" -v c="$nc" 'BEGIN{ exit !(l >= 0.9*c) }'; then
        return 0
    fi
    # Conntrack pressure: usage >= 80% of the table
    local cc cm
    cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
    cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
    cc="${cc//[^0-9]/}"; cm="${cm//[^0-9]/}"
    if [ -n "$cc" ] && [ -n "$cm" ] && [ "$cm" -gt 0 ] && [ $(( cc * 100 / cm )) -ge 80 ]; then
        return 0
    fi
    return 1
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
    state_has_ip "$BANNED_LIST" "$ip" && return 0
    # Phase 1c: progressive duration (explicit $2 wins - manual paths).
    local DUR="${2:-$(rep_ban_duration_secs "$ip")}"
    local UNBAN_TIME
    UNBAN_TIME=$(date -d "+${DUR} seconds" '+%H:%M:%S' 2>/dev/null || echo "N/A")
    nx_ban_apply "$ip" "$DUR" "auto-ban"
    echo "$ip $(date +%s) $DUR" >> "$BANNED_LIST"
    # Remove ONLY this IP's throttle/hard-throttle tc filter.
    # NOTE: never run 'tc filter del dev "$IF" parent 1:' here — that deletes
    # EVERY filter including the Cloudflare + server-own whitelist, which would
    # throttle CF traffic. We remove the one filter recorded for this IP.
    local _PRIO
    _PRIO=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
    [ -n "$_PRIO" ] && tc filter del dev "$IF" parent 1: prio "$_PRIO" 2>/dev/null || true
    state_del_ip "$THROTTLE_LIST" "$ip"
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

# ── IPv6 enforcers (Wave 9): mirrors of the v4 functions ──
_throttle6() {  # <ip> <soft|hard>
    local ip="$1" band="${2:-soft}" flow="1:30"
    [ "$band" = "hard" ] && flow="1:40"
    is_exempt6 "$ip" && return 0
    # R-7: same-band = no-op; soft->hard upgrades by replacing the
    # filter (the old blanket state check made v6 upgrades impossible).
    if state_has_ip "$THROTTLE_LIST" "$ip"; then
        [ "$(state_get_field "$THROTTLE_LIST" "$ip" 4)" = "$band" ] && return 0
        local _op; _op=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
        [ -n "$_op" ] && tc filter del dev "$IF" parent 1: protocol ip6 prio "$_op" 2>/dev/null || true
        state_del_ip "$THROTTLE_LIST" "$ip"
    fi
    tc_class_exists "$flow" || flow="1:30"
    if ! tc_class_exists "$flow"; then
        log " THROTTLE SKIP (v6): $ip - no tc classes on $IF (autoban-only mode)"
        return 0
    fi
    local prio
    prio=$(next_tc_prio)
    if tc filter add dev "$IF" parent 1: protocol ip6 prio "$prio" \
        u32 match ip6 dst "$ip" flowid $flow 2>/dev/null; then
        echo "$ip $prio $(date +%s) $band" >> "$THROTTLE_LIST"
        log " THROTTLED (v6): $ip -> $flow (prio $prio)"
    else
        log " THROTTLE FAILED (v6): $ip - tc refused the filter; state not recorded"
    fi
}
throttle_ip6() { _throttle6 "$1" soft; }
hard_throttle_ip6() { _throttle6 "$1" hard; }

ban_ip6() {
    local ip="$1" _s6 DUR="${2:-$(rep_ban_duration_secs "$1")}"
    is_exempt6 "$ip" && return 0
    # Self-IP choke guard (FR-2): refuse, always, no exceptions.
    for _s6 in "${SELF6_IPS[@]}"; do
        if ip6_in_cidr "$ip" "$_s6/128"; then
            log " REFUSED: $ip is a server IPv6 address (self-IP immunity)"
            return 0
        fi
    done
    state_has_ip "$BANNED_LIST" "$ip" && return 0
    local _PRIO
    _PRIO=$(state_get_field "$THROTTLE_LIST" "$ip" 2)
    [ -n "$_PRIO" ] && tc filter del dev "$IF" parent 1: protocol ip6 prio "$_PRIO" 2>/dev/null || true
    state_del_ip "$THROTTLE_LIST" "$ip"
    nx_ban_apply "$ip" "$DUR" "auto-ban"
    echo "$ip $(date +%s) $DUR" >> "$BANNED_LIST"
    log " BANNED (v6): $ip for $((DUR / 60))min (progressive)"
}
