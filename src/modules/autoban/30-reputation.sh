# @part modules/autoban/30-reputation.sh - score persistence + update_score
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
score_init() {
    mkdir -p "$SCORE_DIR" 2>/dev/null || true
    touch "$SCORE_FILE" 2>/dev/null || true
}

# load_reputation <ip> -> sets REP_SCORE, REP_PREV_CNT, REP_TS,
# REP_PROB_UNTIL (or defaults). Exact field-1 match (BUG-003: the old
# grep -F "$ip " also matched 11.2.3.4 when asked for 1.2.3.4).
# Format: IP SCORE PREV_CNT TS PROB_UNTIL   (PROB_UNTIL added by D3;
# older 4-field lines read as 0.)
load_reputation() {
    local ip="$1"
    REP_SCORE=100
    REP_PREV_CNT=0
    REP_TS=0
    REP_PROB_UNTIL=0
    local line prev prob
    line=$(awk -v x="$ip" '$1==x' "$SCORE_FILE" 2>/dev/null | tail -1 || true)
    [ -z "$line" ] && return 0
    REP_SCORE=$(echo "$line" | awk '{print $2}')
    prev=$(echo "$line" | awk '{print $3}')
    REP_TS=$(echo "$line" | awk '{print $4}')
    prob=$(echo "$line" | awk '{print $5}')
    REP_SCORE="${REP_SCORE:-100}"; REP_SCORE="${REP_SCORE//[^0-9]/}"; REP_SCORE="${REP_SCORE:-100}"
    REP_PREV_CNT="${prev:-0}"; REP_PREV_CNT="${REP_PREV_CNT//[^0-9]/}"; REP_PREV_CNT="${REP_PREV_CNT:-0}"
    REP_TS="${REP_TS:-0}"; REP_TS="${REP_TS//[^0-9]/}"; REP_TS="${REP_TS:-0}"
    REP_PROB_UNTIL="${prob:-0}"; REP_PROB_UNTIL="${REP_PROB_UNTIL//[^0-9]/}"; REP_PROB_UNTIL="${REP_PROB_UNTIL:-0}"
    [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
}

# save_reputation: atomic rewrite (tmp + rename, BUG-033) - a crash
# mid-write can no longer corrupt the whole score file.
save_reputation() {
    local ip="$1"
    awk -v x="$ip" '$1!=x' "$SCORE_FILE" > "$SCORE_FILE.tmp.$$" 2>/dev/null || true
    echo "$ip $REP_SCORE $REP_PREV_CNT $(date +%s) ${REP_PROB_UNTIL:-0}" >> "$SCORE_FILE.tmp.$$"
    mv "$SCORE_FILE.tmp.$$" "$SCORE_FILE" 2>/dev/null || true
}

# clear_reputation <ip> — remove score after cleanup
clear_reputation() {
    local ip="$1"
    state_del_ip "$SCORE_FILE" "$ip"
}

# rep_on_unban <ip> — the D3 release transition, identical for EVERY ban
# path: a served ban ends in PROBATION (score PROBATION_SCORE + window),
# never in a stale low score and never wiped to a fresh 100.
rep_on_ban() {
    local ip="$1" now
    now=$(date +%s)
    load_reputation "$ip"
    REP_SCORE="$PROBATION_SCORE"
    REP_PROB_UNTIL=$(( now + BAN_HOURS * 3600 + PROBATION_SECONDS ))
    save_reputation "$ip"
}

rep_on_unban() {
    local ip="$1" now
    now=$(date +%s)
    load_reputation "$ip"
    if state_has_ip "$SCORE_FILE" "$ip"; then
        [ "$REP_SCORE" -lt "$PROBATION_SCORE" ] && REP_SCORE="$PROBATION_SCORE"
        [ "$REP_PROB_UNTIL" -lt $(( now + PROBATION_SECONDS )) ] && \
            REP_PROB_UNTIL=$(( now + PROBATION_SECONDS ))
    else
        REP_SCORE="$PROBATION_SCORE"
        REP_PREV_CNT=0
        REP_PROB_UNTIL=$(( now + PROBATION_SECONDS ))
    fi
    save_reputation "$ip"
}

# reputation_sweep — recovery for QUIET IPs (FR-3/BUG-034: update_score
# only ever ran for hot IPs, so a quiet low score could never recover).
# Runs every cycle over the score file: clean quiet IPs regain points
# (+SCORE_RECOVER, or +PROBATION_RECOVER during probation); banned IPs
# are frozen; fully-recovered stale entries (>24h) are pruned. IPs the
# main loop scored this cycle (hot right now) are left to update_score.
reputation_sweep() {
    [ -f "$SCORE_FILE" ] || return 0
    local now ip score prev ts prob rec ns
    now=$(date +%s)
    local tmp="$SCORE_FILE.sweep.$$"
    : > "$tmp"
    while read -r ip score prev ts prob; do
        [ -z "$ip" ] && continue
        score="${score//[^0-9]/}"; score="${score:-100}"
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        prob="${prob//[^0-9]/}"; prob="${prob:-0}"
        if state_has_ip "$BANNED_LIST" "$ip"; then
            echo "$ip $score $prev $ts $prob" >> "$tmp"; continue
        fi
        if [ "${CONN_COUNT[$ip]:-0}" -ge "$CONN_THRESHOLD" ]; then
            echo "$ip $score $prev $ts $prob" >> "$tmp"; continue
        fi
        if [ "$score" -ge 100 ] && [ "$prob" -le "$now" ] && [ $(( now - ts )) -gt 86400 ]; then
            continue  # prune
        fi
        rec="$SCORE_RECOVER"; [ "$prob" -gt "$now" ] && rec="$PROBATION_RECOVER"
        ns=$(( score + rec )); [ "$ns" -gt 100 ] && ns=100
        echo "$ip $ns $prev $ts $prob" >> "$tmp"
    done < "$SCORE_FILE"
    mv "$tmp" "$SCORE_FILE" 2>/dev/null || true
}

# update_score <ip> <current_conn_count> <elapsed_seconds_since_last>
# Adjusts REP_SCORE based on behavior, then enforces the matching band.
update_score() {
    local ip="$1" cur="$2" dt="$3"
    [ "$dt" -lt 1 ] && dt=1
    is_exempt "$ip" && { clear_reputation "$ip"; return 0; }
    state_has_ip "$SCORE_FILE" "$ip" || echo "$ip 100 0 0 0" >> "$SCORE_FILE" 2>/dev/null || true

    load_reputation "$ip"

    # ── D3: real elapsed time (BUG-020: the caller-supplied dt was a
    # constant; measure from the persisted timestamp instead, clamped)
    local now; now=$(date +%s)
    if [ "$REP_TS" -gt 0 ] && [ "$REP_TS" -le "$now" ]; then
        dt=$(( now - REP_TS ))
        [ "$dt" -lt 1 ] && dt=1
        [ "$dt" -gt 60 ] && dt=60
    fi

    # ── D3 normalization (FR-3): a score in the ban band while the IP is
    # NOT banned is a leftover from a ban that ended outside this path
    # (manual unban, older daemon, expiry race). That state was a
    # de-facto permanent ban. Normalize it to a probation release.
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ] && ! state_has_ip "$BANNED_LIST" "$ip"; then
        REP_SCORE="$PROBATION_SCORE"
        REP_PROB_UNTIL=$(( now + PROBATION_SECONDS ))
        log " REP-PROBATION: $ip | stale post-ban score normalized to $PROBATION_SCORE (probation ${PROBATION_SECONDS}s)"
    fi
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

    # Probation (D3): during the window, drops count double - a real
    # repeat offender returns to the ban band quickly - but a ban still
    # only fires from the band itself, never from a stale state.
    if [ "$drop" -gt 0 ] && [ "$now" -lt "${REP_PROB_UNTIL:-0}" ]; then
        drop=$(( drop * 2 ))
    fi

    # Recover if this cycle was clean (below churn, below flood, low enough)
    if [ "$drop" -eq 0 ]; then
        local _rec="$SCORE_RECOVER"
        [ "$now" -lt "${REP_PROB_UNTIL:-0}" ] && _rec="$PROBATION_RECOVER"
        REP_SCORE=$(( REP_SCORE + _rec ))
        [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    else
        REP_SCORE=$(( REP_SCORE - drop ))
        [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
    fi
    REP_PREV_CNT="$cur"
    save_reputation "$ip"

    # ── Enforce band (graduated, only escalate; never penalize a NORMAL IP) ──
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ]; then
        if ! state_has_ip "$BANNED_LIST" "$ip"; then
            log " REP-BAN: $ip | score $REP_SCORE (below $SCORE_BAN) → ban ${BAN_HOURS}h"
            throttle_ip "$ip"
            ban_ip "$ip"
            # D3: the ban sets up its own release - when it expires, the
            # IP returns in PROBATION at PROBATION_SCORE (rep_on_unban
            # enforces the same transition on the expiry path).
            rep_on_ban "$ip"
        fi
    elif [ "$REP_SCORE" -lt "$SCORE_HARD" ]; then
        hard_throttle_ip "$ip"
        log " REP-HARD: $ip | score $REP_SCORE → 50Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_THROTTLE" ]; then
        throttle_ip "$ip"
        log " REP-THROTTLE: $ip | score $REP_SCORE → 100Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_SUSPECT" ]; then
        # SUSPECT band: watch only, no bandwidth penalty. But ensure it is on
        # the watch list so the classic per-IP path can escalate it if it grows.
        if ! state_has_ip "$WATCH_LIST" "$ip"; then
            echo "$ip $(date +%s)" >> "$WATCH_LIST" 2>/dev/null || true
        fi
    fi
}

# ── Subnet /24 ban — blocks entire /24 CIDR ──────────────────
# Used when a botnet sends many IPs from the same subnet, each under per-IP threshold.
# Exempt: CF ranges and own IPs — checked via is_cf_ip on the subnet base.
