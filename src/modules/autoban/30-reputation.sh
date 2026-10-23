# @part modules/autoban/30-reputation.sh - score persistence + update_score
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
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
