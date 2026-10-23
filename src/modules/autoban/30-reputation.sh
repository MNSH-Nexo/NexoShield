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
    REP_FRAC=0
    REP_RATE=0
    local line prev prob frac rate
    line=$(awk -v x="$ip" '$1==x' "$SCORE_FILE" 2>/dev/null | tail -1 || true)
    [ -z "$line" ] && return 0
    REP_SCORE=$(echo "$line" | awk '{print $2}')
    prev=$(echo "$line" | awk '{print $3}')
    REP_TS=$(echo "$line" | awk '{print $4}')
    prob=$(echo "$line" | awk '{print $5}')
    frac=$(echo "$line" | awk '{print $6}')
    rate=$(echo "$line" | awk '{print $7}')
    REP_SCORE="${REP_SCORE:-100}"; REP_SCORE="${REP_SCORE//[^0-9]/}"; REP_SCORE="${REP_SCORE:-100}"
    REP_PREV_CNT="${prev:-0}"; REP_PREV_CNT="${REP_PREV_CNT//[^0-9]/}"; REP_PREV_CNT="${REP_PREV_CNT:-0}"
    REP_TS="${REP_TS:-0}"; REP_TS="${REP_TS//[^0-9]/}"; REP_TS="${REP_TS:-0}"
    REP_PROB_UNTIL="${prob:-0}"; REP_PROB_UNTIL="${REP_PROB_UNTIL//[^0-9]/}"; REP_PROB_UNTIL="${REP_PROB_UNTIL:-0}"
    REP_FRAC="${frac:-0}"; [[ "$REP_FRAC" =~ ^-?[0-9]+$ ]] || REP_FRAC=0
    REP_RATE="${rate:-0}"; REP_RATE="${REP_RATE//[^0-9]/}"; REP_RATE="${REP_RATE:-0}"
    [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
}

# save_reputation: atomic rewrite (tmp + rename, BUG-033) - a crash
# mid-write can no longer corrupt the whole score file.
save_reputation() {
    local ip="$1"
    awk -v x="$ip" '$1!=x' "$SCORE_FILE" > "$SCORE_FILE.tmp.$$" 2>/dev/null || true
    echo "$ip $REP_SCORE $REP_PREV_CNT $(date +%s) ${REP_PROB_UNTIL:-0} ${REP_FRAC:-0} ${REP_RATE:-0}" >> "$SCORE_FILE.tmp.$$"
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
    REP_FRAC=0
    REP_RATE=0
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
    local now ip score prev ts prob frac rate rec gain acc apply ns elapsed
    now=$(date +%s)
    local tmp="$SCORE_FILE.sweep.$$"
    : > "$tmp"
    while read -r ip score prev ts prob frac rate; do
        [ -z "$ip" ] && continue
        score="${score//[^0-9]/}"; score="${score:-100}"
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        prob="${prob//[^0-9]/}"; prob="${prob:-0}"
        [[ "${frac:-}" =~ ^-?[0-9]+$ ]] || frac=0
        rate="${rate//[^0-9]/}"; rate="${rate:-0}"
        if state_has_ip "$BANNED_LIST" "$ip"; then
            echo "$ip $score $prev $ts $prob $frac $rate" >> "$tmp"; continue
        fi
        if [ "${CONN_COUNT[$ip]:-0}" -ge "$CONN_THRESHOLD" ]; then
            echo "$ip $score $prev $ts $prob $frac $rate" >> "$tmp"; continue
        fi
        if [ "$score" -ge 100 ] && [ "$prob" -le "$now" ] && [ $(( now - ts )) -gt 86400 ]; then
            continue  # prune fully-recovered stale entries
        fi
        if [ "$score" -lt 100 ]; then
            # Scoring v2: recovery is time-based (points per minute of
            # quiet), accumulated through the fractional field - the old
            # flat per-cycle gain made recovery speed depend on how
            # often the daemon happened to loop.
            elapsed=$(( now - ts )); [ "$elapsed" -lt 0 ] && elapsed=0
            [ "$elapsed" -gt 3600 ] && elapsed=3600
            rec="$SCORE_RECOVER_PER_MIN"; [ "$prob" -gt "$now" ] && rec="$PROBATION_RECOVER_PER_MIN"
            gain=$(( rec * 100 * elapsed / 60 ))
            acc=$(( frac + gain ))
            apply=$(( acc / 100 ))
            frac=$(( acc - apply * 100 ))
            ns=$(( score + apply )); [ "$ns" -gt 100 ] && ns=100
            echo "$ip $ns $prev $now $prob $frac $rate" >> "$tmp"
        else
            echo "$ip $score $prev $ts $prob $frac $rate" >> "$tmp"
        fi
    done < "$SCORE_FILE"
    mv "$tmp" "$SCORE_FILE" 2>/dev/null || true
}

# update_score <ip> <current_conn_count> <syn_recv_count> <elapsed_hint>
# Scoring model v2 (docs/SCORING.md): continuous, time-normalized terms
# with fractional accumulation; adjusts REP_SCORE, enforces the band.
update_score() {
    local ip="$1" cur="$2" syn="${3:-0}" dt="${4:-2}"
    [ "$dt" -lt 1 ] && dt=1
    is_exempt_any "$ip" && { clear_reputation "$ip"; return 0; }
    state_has_ip "$SCORE_FILE" "$ip" || echo "$ip 100 0 0 0 0 0" >> "$SCORE_FILE" 2>/dev/null || true

    load_reputation "$ip"

    # Real elapsed time (BUG-020/D3): measured from the persisted
    # timestamp, clamped - the caller value is only a fallback.
    local now; now=$(date +%s)
    if [ "$REP_TS" -gt 0 ] && [ "$REP_TS" -le "$now" ]; then
        dt=$(( now - REP_TS ))
        [ "$dt" -lt 1 ] && dt=1
        [ "$dt" -gt 60 ] && dt=60
    fi

    # D3 normalization (FR-3): a score in the ban band while the IP is
    # NOT banned is a leftover from a ban that ended outside this path.
    # Normalize it to a probation release instead of re-banning.
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ] && ! state_has_ip "$BANNED_LIST" "$ip"; then
        REP_SCORE="$PROBATION_SCORE"
        REP_PROB_UNTIL=$(( now + PROBATION_SECONDS ))
        log " REP-PROBATION: $ip | stale post-ban score normalized to $PROBATION_SCORE (probation ${PROBATION_SECONDS}s)"
    fi

    local old_score="$REP_SCORE"
    local in_prob=0; [ "$now" -lt "${REP_PROB_UNTIL:-0}" ] && in_prob=1

    # ── Scoring v2 terms, all in points per minute (docs/SCORING.md) ──
    # churn: EWMA-smoothed new-connection rate above a 2/s allowance,
    #   continuous (the v1 step table jumped +2 -> +18 between 49 and
    #   50 conn/s); sustained: concurrent-connection excess over the
    #   watch threshold; syn: half-open share of the total (the SYN
    #   flood signature v1 could not see - it merged SYN-RECV into the
    #   same counter as ESTABLISHED). First sample of a tracked IP
    #   (prev=0): every connection is new within the window.
    local CHURN SUST SYNP RS
    read -r CHURN SUST SYNP RS <<< "$(awk \
        -v cur="$cur" -v prev="$REP_PREV_CNT" -v syn="$syn" \
        -v dt="$dt" -v rate_prev="${REP_RATE:-0}" -v thr="$CONN_THRESHOLD" \
        'BEGIN{
            r = (prev > 0) ? ((cur >= prev) ? (cur - prev) / dt : 0) : cur / dt;
            rs = 0.5 * r + 0.5 * (rate_prev / 100);
            churn = (rs <= 2) ? 0 : (rs - 2) * 1.2; if (churn > 30) churn = 30;
            ex = cur - thr; sust = (ex <= 0) ? 0 : ex / 40; if (sust > 20) sust = 20;
            synp = 0;
            if (syn >= 20 && cur > 0) { ratio = syn / cur; if (ratio > 0.5) { synp = (ratio - 0.5) * 40; if (synp > 15) synp = 15; } }
            printf "%.2f %.2f %.2f %.2f", churn, sust, synp, rs;
        }')"
    REP_RATE=$(awk -v rs="$RS" 'BEGIN{ printf "%d", rs * 100 + 0.5 }')

    # Probation: drops count double; the total is capped per minute.
    local total_x100 acc apply
    total_x100=$(awk -v c="$CHURN" -v s="$SUST" -v y="$SYNP" \
        -v prob="$in_prob" -v cap="$SCORE_DROP_CAP_PER_MIN" 'BEGIN{
            t = c + s + y; if (prob) t *= 2; if (t > cap) t = cap;
            printf "%d", t * 100 + 0.5 }')
    if [ "$total_x100" -gt 0 ]; then
        acc=$(( REP_FRAC - total_x100 * dt / 60 ))
    else
        local rec="$SCORE_RECOVER_PER_MIN"
        [ "$in_prob" -eq 1 ] && rec="$PROBATION_RECOVER_PER_MIN"
        acc=$(( REP_FRAC + rec * 100 * dt / 60 ))
    fi
    apply=$(( acc / 100 ))
    REP_FRAC=$(( acc - apply * 100 ))
    REP_SCORE=$(( REP_SCORE + apply ))
    [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
    REP_PREV_CNT="$cur"
    save_reputation "$ip"

    # Structured, explainable logging: every material score change is
    # recorded with the exact terms that produced it.
    if [ "$apply" -ne 0 ]; then
        local dstr; [ "$apply" -ge 0 ] && dstr="+$apply" || dstr="$apply"
        log " SCORE: $ip | $old_score->$REP_SCORE (d$dstr) | churn=${CHURN}/min sust=${SUST}/min syn=${SYNP}/min rate=${RS}/s syn_n=$syn dt=${dt}s prob=$in_prob"
    fi

    # ── Enforce band (graduated, only escalate) ──
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ]; then
        if ! state_has_ip "$BANNED_LIST" "$ip"; then
            log " REP-BAN: $ip | score $REP_SCORE (below $SCORE_BAN) -> ban ${BAN_HOURS}h"
            nx_throttle "$ip"
            nx_ban "$ip"
            rep_on_ban "$ip"
        fi
    elif [ "$REP_SCORE" -lt "$SCORE_HARD" ]; then
        nx_hard_throttle "$ip"
        log " REP-HARD: $ip | score $REP_SCORE -> 50Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_THROTTLE" ]; then
        nx_throttle "$ip"
        log " REP-THROTTLE: $ip | score $REP_SCORE -> 100Mbps"
    elif [ "$REP_SCORE" -lt "$SCORE_SUSPECT" ]; then
        if ! state_has_ip "$WATCH_LIST" "$ip"; then
            echo "$ip $(date +%s)" >> "$WATCH_LIST" 2>/dev/null || true
        fi
    fi
}

# ── Subnet /24 ban — blocks entire /24 CIDR ──────────────────
# Used when a botnet sends many IPs from the same subnet, each under per-IP threshold.
# Exempt: CF ranges and own IPs — checked via is_cf_ip on the subnet base.
