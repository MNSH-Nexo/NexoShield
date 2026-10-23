#!/bin/bash
# ============================================================
#  Smart Throttle+Ban — Anti-DDoS Layer 4
#  Pipeline: watch(120 conns) → throttle(100Mbps) → ban(4h) | instant ban: 300 conns
#  CF IPs + server own IPs: ALWAYS exempt
# ============================================================

LOG="/var/log/auto-ban.log"
BANNED_LIST="/etc/antiddos/banned.list"
WATCH_LIST="/tmp/autoban_watch"
THROTTLE_LIST="/tmp/autoban_throttle"
# User whitelist — IPs/CIDRs exempt from ALL anti-DDoS limits.
# Managed by the user via the menu (never auto-modified). One per line.
# Lines starting with # are comments. Server's own IPs + CF IPs are always
# exempt separately (see is_exempt), this file adds MORE whitelisted IPs.
WHITELIST_FILE="/etc/antiddos/whitelist.list"

# ── Reputation scoring state (persistent across cycles) ────
# Each scored IP keeps: score, last connection count, last timestamp.
# Persisted to disk so the value survives the short-lived shell arrays
# and survives service restarts.
SCORE_DIR="/var/lib/antiddos/scores"
SCORE_FILE="$SCORE_DIR/reputation.dat"
# Bands (see research: adaptive/graduated enforcement beats one-shot ban):
#  100-80 NORMAL    no action (only watched if above CONN_THRESHOLD)
#   79-60 SUSPECT   watch only, no penalty
#   59-40 THROTTLED move to class 1:30 (100Mbps)
#   39-20 HARD      move to class 1:40 (50Mbps)
#   <20  BANNED     ban_ip (4h)
SCORE_BAN=20
SCORE_HARD=40
SCORE_THROTTLE=60
SCORE_SUSPECT=80
# Recovery: how fast a well-behaved IP regains reputation (per cycle).
SCORE_RECOVER=3
# When connections are counted we snapshot the previous sample to derive the
# new-connection rate (attacker signature) without per-packet overhead.

# Thresholds
# THRESHOLD: minimum active connections from one IP to start watching.
# Normal user: 5-20 connections (browser + download + streaming).
# Heaviest legitimate user (multiple download managers + several services):
# ~50-60 connections. Attacker: hundreds to thousands.
# Set CONN_THRESHOLD well above ANY legitimate user so normal speed is never
# limited, but far below a flood. OBSERVE allows brief legit spikes (a download
# manager burst) to pass untouched before any action.
CONN_THRESHOLD=120    # active connections from one IP = start watching (safe margin)
BAN_CONN_THRESHOLD=300  # active connections from one IP = immediate throttle+ban
OBSERVE_SECONDS=45    # seconds to watch before throttle (tolerates legit spikes)
THROTTLE_MBPS=100    # throttle bandwidth in Mbps (must match tc class 1:30 = 100mbit)
BAN_HOURS=4          # hours to ban after throttle
# Sample cadence. 2s (was 4s): churn rate is already normalized per-second, so
# scoring bands are unchanged, but short <4s bursts from a 120+ conn IP are now
# caught instead of being averaged out. Recovery of well-behaved IPs is also 2x
# faster. The CONN_THRESHOLD=120 gate means normal users are never touched.
# (One-way bytes tracking was deliberately NOT added: on a SOCKS5/tunnel proxy,
# server→client relay makes "sent>>received" the NORMAL heavy-download pattern,
# so it would false-positive on legitimate heavy users.)
SAMPLE_INTERVAL=2    # seconds per measurement

# ── Subnet /24 botnet detection ──────────────────────────────
# Botnet distributes connections across many IPs in same /24 subnet.
# Each IP stays under single-IP threshold, but total subnet load is high.
# SUBNET_CONN_THRESHOLD: total connections from a /24 subnet = start watching.
# Normal ISP: ~5-10 users behind NAT/CGNAT, each ~20 conns = ~200 total.
# A very heavy CGNAT node (many legit users) could reach ~400.
# Botnet with 50 IPs × 100+ conns = 5000 → way above threshold.
SUBNET_THRESHOLD=400       # total conns from /24 = start watching subnet
SUBNET_BAN_THRESHOLD=1000  # total conns from /24 = block subnet
SUBNET_WATCH_LIST="/tmp/autoban_subnet_watch"
touch "$SUBNET_WATCH_LIST" 2>/dev/null || true

# Detect main interface
IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
IF=${IF:-eth0}

# Cloudflare ranges (NEVER touched)
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi

mkdir -p /etc/antiddos
touch "$LOG" && chmod 600 "$LOG"
touch "$BANNED_LIST" "$WATCH_LIST" "$THROTTLE_LIST" 2>/dev/null || true

# Collect all server IPs at startup (never ban these)
SELF_IPS=()
while IFS= read -r sip; do
    [ -n "$sip" ] && SELF_IPS+=("$sip")
done < <(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+')
while IFS= read -r sip; do
    [ -n "$sip" ] && SELF_IPS+=("$sip")
done < <(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]')

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# Convert IP to integer for CIDR comparison
ip_to_int() {
    local IFS=.
    # shellcheck disable=SC2206
    local -a A=($1)
    echo $(( (A[0]<<24) + (A[1]<<16) + (A[2]<<8) + A[3] ))
}

# Check if IP is inside a CIDR range (e.g. "104.16.0.0/13")
ip_in_cidr() {
    local ip="$1" cidr="$2"
    local base mask_bits ip_int base_int mask
    base="${cidr%/*}"; mask_bits="${cidr#*/}"
    ip_int=$(ip_to_int "$ip")     2>/dev/null || return 1
    base_int=$(ip_to_int "$base") 2>/dev/null || return 1
    mask=$(( 0xFFFFFFFF << (32 - mask_bits) & 0xFFFFFFFF ))
    [ $(( ip_int & mask )) -eq $(( base_int & mask )) ]
}

# Check if IP is in CF ranges (pure bash CIDR match — no ipcalc needed)
is_cf_ip() {
    local ip="$1"
    for CF in "${CF_RANGES[@]}"; do
        ip_in_cidr "$ip" "$CF" 2>/dev/null && return 0
    done
    return 1
}

# Check if IP is server's own IP
is_self_ip() {
    local ip="$1"
    for sip in "${SELF_IPS[@]}"; do
        [ "$sip" = "$ip" ] && return 0
    done
    ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | grep -qxF "$ip" && return 0
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -qxF "$ip" && return 0
    return 1
}

# Check if IP is in the user whitelist (exact or within a listed CIDR)
is_user_whitelisted() {
    local ip="$1" entry
    [ -f "$WHITELIST_FILE" ] || return 1
    while IFS= read -r entry; do
        entry="${entry%%#*}"            # strip comments
        entry="${entry// /}"            # drop spaces
        [ -z "$entry" ] && continue
        case "$entry" in
            */*) ip_in_cidr "$ip" "$entry" 2>/dev/null && return 0 ;;
            *)   [ "$entry" = "$ip" ] && return 0 ;;
        esac
    done < "$WHITELIST_FILE"
    return 1
}

# Check if IP should be exempt (CF or self or user-whitelisted)
is_exempt() {
    local ip="$1"
    is_self_ip "$ip"  && return 0
    is_cf_ip   "$ip"  && return 0
    is_user_whitelisted "$ip" && return 0
    return 1
}

# Reserved tc filter priority bands (must never overlap):
#   whitelist (CF + server-own + user)  : 10 .. <10000  (allocated in tc-setup.sh)
#   throttle (100Mbps class 1:30)       : 10000 ..
#   hard-throttle (50Mbps class 1:40)   : 20000 ..
# This guarantees a throttle filter can NEVER collide with a Cloudflare/server
# whitelist filter, so CF and the server itself stay exempt even at ban time
# (ban_ip deletes only the recorded throttle-band prio).
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
score_init() {
    mkdir -p "$SCORE_DIR" 2>/dev/null || true
    touch "$SCORE_FILE" 2>/dev/null || true
}

# load_reputation <ip> -> sets REP_SCORE, REP_PREV_CNT, REP_TS (or defaults)
load_reputation() {
    local ip="$1"
    REP_SCORE=100
    REP_PREV_CNT=0
    REP_TS=0
    local line prev
    line=$(grep -F "$ip " "$SCORE_FILE" 2>/dev/null | tail -1 || true)
    [ -z "$line" ] && return 0
    # format: IP SCORE PREV_CNT TS
    REP_SCORE=$(echo "$line" | awk '{print $2}')
    prev=$(echo "$line" | awk '{print $3}')
    REP_TS=$(echo "$line" | awk '{print $4}')
    REP_SCORE="${REP_SCORE:-100}"; REP_SCORE="${REP_SCORE//[^0-9]/}"; REP_SCORE="${REP_SCORE:-100}"
    REP_PREV_CNT="${prev:-0}"; REP_PREV_CNT="${REP_PREV_CNT//[^0-9]/}"; REP_PREV_CNT="${REP_PREV_CNT:-0}"
    REP_TS="${REP_TS:-0}"; REP_TS="${REP_TS//[^0-9]/}"; REP_TS="${REP_TS:-0}"
    [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
}

save_reputation() {
    local ip="$1"
    sed -i "/^$ip /d" "$SCORE_FILE" 2>/dev/null || true
    echo "$ip $REP_SCORE $REP_PREV_CNT $(date +%s)" >> "$SCORE_FILE"
}

# clear_reputation <ip> — remove score after ban/unban/cleanup
clear_reputation() {
    local ip="$1"
    sed -i "/^$ip /d" "$SCORE_FILE" 2>/dev/null || true
}

# update_score <ip> <current_conn_count> <elapsed_seconds_since_last>
# Adjusts REP_SCORE based on behavior, then enforces the matching band.
update_score() {
    local ip="$1" cur="$2" dt="$3"
    [ "$dt" -lt 1 ] && dt=1
    is_exempt "$ip" && { clear_reputation "$ip"; return 0; }
    grep -qF "$ip " "$SCORE_FILE" 2>/dev/null || echo "$ip 100 0 0" >> "$SCORE_FILE" 2>/dev/null || true

    load_reputation "$ip"
    local new_rate=0  # new connections per second
    if [ "$REP_PREV_CNT" -gt 0 ] && [ "$cur" -ge "$REP_PREV_CNT" ]; then
        new_rate=$(( (cur - REP_PREV_CNT) / dt ))
    fi

    # ── Score adjustment (deltas per cycle) ──────────────
    local drop=0
    # 1) Connection churn — the attacker signature. Rapid new-connection rate.
    if   [ "$new_rate" -ge 50 ]; then drop=$(( drop + 18 ))
    elif [ "$new_rate" -ge 25 ]; then drop=$(( drop + 12 ))
    elif [ "$new_rate" -ge 10 ]; then drop=$(( drop + 6 ))
    elif [ "$new_rate" -ge 5  ]; then drop=$(( drop + 2 ))
    fi
    # 2) Sustained high concurrent connections (holding many, near-flood)
    if   [ "$cur" -ge 800 ]; then drop=$(( drop + 15 ))
    elif [ "$cur" -ge 400 ]; then drop=$(( drop + 8 ))
    elif [ "$cur" -ge 200 ]; then drop=$(( drop + 4 ))
    elif [ "$cur" -gt "$CONN_THRESHOLD" ]; then drop=$(( drop + 1 ))
    fi
    # 3) Time-based decay: a hot IP that stays hot loses a little each cycle
    #    (prevents an IP hovering at a band boundary forever).
    if [ "$drop" -gt 0 ]; then
        drop=$(( drop + 1 ))
    fi

    # Recover if this cycle was clean (below churn, below flood, low enough)
    if [ "$drop" -eq 0 ]; then
        REP_SCORE=$(( REP_SCORE + SCORE_RECOVER ))
        [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    else
        REP_SCORE=$(( REP_SCORE - drop ))
        [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
    fi
    REP_PREV_CNT="$cur"
    save_reputation "$ip"

    # ── Enforce band (graduated, only escalate; never penalize a NORMAL IP) ──
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ]; then
        if ! grep -qF "$ip" "$BANNED_LIST" 2>/dev/null; then
            log " REP-BAN: $ip | score $REP_SCORE (below $SCORE_BAN) → ban ${BAN_HOURS}h"
            throttle_ip "$ip"
            ban_ip "$ip"
        fi
        clear_reputation "$ip"
    elif [ "$REP_SCORE" -lt "$SCORE_HARD" ]; then
        hard_throttle_ip "$ip"
        log " REP-HARD: $ip | score $REP_SCORE → 50Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_THROTTLE" ]; then
        throttle_ip "$ip"
        log " REP-THROTTLE: $ip | score $REP_SCORE → 100Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_SUSPECT" ]; then
        # SUSPECT band: watch only, no bandwidth penalty. But ensure it is on
        # the watch list so the classic per-IP path can escalate it if it grows.
        if ! grep -qF "$ip" "$WATCH_LIST" 2>/dev/null; then
            echo "$ip $(date +%s)" >> "$WATCH_LIST" 2>/dev/null || true
        fi
    fi
}

# ── Subnet /24 ban — blocks entire /24 CIDR ──────────────────
# Used when a botnet sends many IPs from the same subnet, each under per-IP threshold.
# Exempt: CF ranges and own IPs — checked via is_cf_ip on the subnet base.
ban_subnet() {
    local subnet="$1"   # e.g. "1.2.3"  (first 3 octets)
    local cidr="${subnet}.0/24"
    # Don't ban if any CF range overlaps (rough check: skip 103.x, 104.x, 108.x, 141.x, 162.x, 172.x, 173.x, 188.x, 190.x, 197.x, 198.x)
    is_cf_ip "${subnet}.1" 2>/dev/null && return 0
    # Don't ban own server subnet
    local own_subnet
    own_subnet=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+' | head -1)
    [ "${own_subnet:-x}" = "$subnet" ] && return 0
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

log " Smart throttle+ban started (conn_threshold:${CONN_THRESHOLD} ban_threshold:${BAN_CONN_THRESHOLD} subnet_threshold:${SUBNET_THRESHOLD} observe:${OBSERVE_SECONDS}s throttle:${THROTTLE_MBPS}Mbps ban:${BAN_HOURS}h)"

score_init

CYCLE=0
while true; do
    CYCLE=$((CYCLE + 1))

    # Every ~5 min: unban expired IPs and subnets
    [ $((CYCLE % 75)) -eq 0 ] && unban_expired && unban_subnet_expired

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
