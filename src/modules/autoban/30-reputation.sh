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
    REP_STRIKES=0
    REP_LAST_BAN=0
    REP_CUSUM_ARR=0
    REP_CUSUM_SYN=0
    local line prev prob frac rate strikes lastban
    line=$(awk -v x="$ip" '$1==x' "$SCORE_FILE" 2>/dev/null | tail -1 || true)
    [ -z "$line" ] && return 0
    REP_SCORE=$(echo "$line" | awk '{print $2}')
    prev=$(echo "$line" | awk '{print $3}')
    REP_TS=$(echo "$line" | awk '{print $4}')
    prob=$(echo "$line" | awk '{print $5}')
    frac=$(echo "$line" | awk '{print $6}')
    rate=$(echo "$line" | awk '{print $7}')
    strikes=$(echo "$line" | awk '{print $8}')
    lastban=$(echo "$line" | awk '{print $9}')
    REP_SCORE="${REP_SCORE:-100}"; REP_SCORE="${REP_SCORE//[^0-9]/}"; REP_SCORE="${REP_SCORE:-100}"
    REP_PREV_CNT="${prev:-0}"; REP_PREV_CNT="${REP_PREV_CNT//[^0-9]/}"; REP_PREV_CNT="${REP_PREV_CNT:-0}"
    REP_TS="${REP_TS:-0}"; REP_TS="${REP_TS//[^0-9]/}"; REP_TS="${REP_TS:-0}"
    REP_PROB_UNTIL="${prob:-0}"; REP_PROB_UNTIL="${REP_PROB_UNTIL//[^0-9]/}"; REP_PROB_UNTIL="${REP_PROB_UNTIL:-0}"
    REP_FRAC="${frac:-0}"; [[ "$REP_FRAC" =~ ^-?[0-9]+$ ]] || REP_FRAC=0
    REP_RATE="${rate:-0}"; REP_RATE="${REP_RATE//[^0-9]/}"; REP_RATE="${REP_RATE:-0}"
    REP_STRIKES="${strikes:-0}"; REP_STRIKES="${REP_STRIKES//[^0-9]/}"; REP_STRIKES="${REP_STRIKES:-0}"
    REP_LAST_BAN="${lastban:-0}"; REP_LAST_BAN="${REP_LAST_BAN//[^0-9]/}"; REP_LAST_BAN="${REP_LAST_BAN:-0}"
    local cusarr cussyn
    cusarr=$(echo "$line" | awk '{print $10}')
    cussyn=$(echo "$line" | awk '{print $11}')
    REP_CUSUM_ARR="${cusarr:-0}"; REP_CUSUM_ARR="${REP_CUSUM_ARR//[^0-9]/}"; REP_CUSUM_ARR="${REP_CUSUM_ARR:-0}"
    REP_CUSUM_SYN="${cussyn:-0}"; REP_CUSUM_SYN="${REP_CUSUM_SYN//[^0-9]/}"; REP_CUSUM_SYN="${REP_CUSUM_SYN:-0}"
    [ "$REP_SCORE" -gt 100 ] && REP_SCORE=100
    [ "$REP_SCORE" -lt 0 ] && REP_SCORE=0
}

# save_reputation: atomic rewrite (tmp + rename, BUG-033) - a crash
# mid-write can no longer corrupt the whole score file.
save_reputation() {
    local ip="$1"
    awk -v x="$ip" '$1!=x' "$SCORE_FILE" > "$SCORE_FILE.tmp.$$" 2>/dev/null || true
    echo "$ip $REP_SCORE $REP_PREV_CNT $(date +%s) ${REP_PROB_UNTIL:-0} ${REP_FRAC:-0} ${REP_RATE:-0} ${REP_STRIKES:-0} ${REP_LAST_BAN:-0} ${REP_CUSUM_ARR:-0} ${REP_CUSUM_SYN:-0}" >> "$SCORE_FILE.tmp.$$"
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
    local ip="$1" now dur
    now=$(date +%s)
    load_reputation "$ip"
    REP_SCORE="$PROBATION_SCORE"
    REP_FRAC=0
    REP_RATE=0
    # Phase 1c: probation starts when the ACTUAL ban (progressive
    # duration recorded in the state file) ends, not a flat BAN_HOURS.
    dur=$(state_get_field "$BANNED_LIST" "$ip" 3)
    dur="${dur//[^0-9]/}"; [ -n "$dur" ] && [ "$dur" -gt 0 ] || dur=$((BAN_HOURS * 3600))
    REP_PROB_UNTIL=$(( now + dur + PROBATION_SECONDS ))
    # Strike bookkeeping: a ban older than 7 days stops counting.
    if [ "$REP_LAST_BAN" -gt 0 ] && [ $(( now - REP_LAST_BAN )) -gt 604800 ]; then
        REP_STRIKES=0
    fi
    REP_STRIKES=$(( REP_STRIKES + 1 ))
    REP_LAST_BAN=$now
    save_reputation "$ip"
}

# rep_ban_duration_secs <ip> - progressive ban length (Phase 1c):
# ban_base_minutes doubling per strike, capped at ban_max_minutes.
# Reads the reputation record directly (never disturbs REP_* state).
rep_ban_duration_secs() {
    local ip="$1" now strikes=0 lastban=0 mins i
    now=$(date +%s)
    if [ -f "$SCORE_FILE" ]; then
        strikes=$(awk -v x="$ip" '$1==x{print $8}' "$SCORE_FILE" 2>/dev/null | tail -1)
        lastban=$(awk -v x="$ip" '$1==x{print $9}' "$SCORE_FILE" 2>/dev/null | tail -1)
    fi
    strikes="${strikes//[^0-9]/}"; strikes="${strikes:-0}"
    lastban="${lastban//[^0-9]/}"; lastban="${lastban:-0}"
    if [ "$lastban" -gt 0 ] && [ $(( now - lastban )) -gt 604800 ]; then strikes=0; fi
    [ "$strikes" -gt 10 ] && strikes=10
    mins=${BAN_BASE_MINUTES:-30}
    for (( i=0; i<strikes; i++ )); do mins=$(( mins * 2 )); done
    [ "$mins" -gt "${BAN_MAX_MINUTES:-10080}" ] && mins=${BAN_MAX_MINUTES:-10080}
    echo $(( mins * 60 ))
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
    while read -r ip score prev ts prob frac rate strikes lastban cusarr cussyn; do
        [ -z "$ip" ] && continue
        score="${score//[^0-9]/}"; score="${score:-100}"
        ts="${ts//[^0-9]/}"; ts="${ts:-0}"
        prob="${prob//[^0-9]/}"; prob="${prob:-0}"
        [[ "${frac:-}" =~ ^-?[0-9]+$ ]] || frac=0
        rate="${rate//[^0-9]/}"; rate="${rate:-0}"
        strikes="${strikes//[^0-9]/}"; strikes="${strikes:-0}"
        lastban="${lastban//[^0-9]/}"; lastban="${lastban:-0}"
        cusarr="${cusarr//[^0-9]/}"; cusarr="${cusarr:-0}"
        cussyn="${cussyn//[^0-9]/}"; cussyn="${cussyn:-0}"
        if state_has_ip "$BANNED_LIST" "$ip"; then
            echo "$ip $score $prev $ts $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"; continue
        fi
        if [ "${CONN_COUNT[$ip]:-0}" -ge "${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" ]; then
            echo "$ip $score $prev $ts $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"; continue
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
            echo "$ip $ns $prev $now $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"
        else
            echo "$ip $score $prev $ts $prob $frac $rate $strikes $lastban $cusarr $cussyn" >> "$tmp"
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
    # ── Phase 2 event terms: armed only with a fresh nxcountd snapshot.
    # Completion ratio (2b) and slow-attack features (2e) feed the awk
    # below; CUSUM accumulators (2c) update here from this cycle's exact
    # arrival deltas, paired with the true inter-snapshot interval.
    local EVOK=0 S60=0 E60=0 AGES=0 BPC=0 CLOSEDN=0 CUSUM_PTS=0 R60="0.00" CRT=0 SLOW=0
    if [ "${NX_EV_OK:-0}" = "1" ]; then
        EVOK=1
        S60="${EV_SYN60[$ip]:-0}"; E60="${EV_EST60[$ip]:-0}"
        CLOSEDN="${EV_CLOSED[$ip]:-0}"
        if [ "$CLOSEDN" -gt 0 ]; then
            AGES=$(( ${EV_AGE[$ip]:-0} / CLOSEDN / 1000 ))
            BPC=$(( ${EV_BYTES[$ip]:-0} / CLOSEDN ))
        fi
        [ "$S60" -gt 0 ] && R60=$(awk -v e="$E60" -v s="$S60" 'BEGIN{ printf "%.2f", e / s }')
        local _a="${EV_DSYN[$ip]:-0}" _d="${EV_DEST[$ip]:-0}" _inc=0 _edt="${NX_EV_DT:-2}"
        [ "$_a" -gt "$_d" ] && _inc=$(( _a - _d ))
        REP_CUSUM_ARR=$(( ${REP_CUSUM_ARR:-0} + _a * 100 - 200 * _edt ))
        [ "$REP_CUSUM_ARR" -lt 0 ] && REP_CUSUM_ARR=0
        REP_CUSUM_SYN=$(( ${REP_CUSUM_SYN:-0} + _inc * 100 - 25 * _edt ))
        [ "$REP_CUSUM_SYN" -lt 0 ] && REP_CUSUM_SYN=0
        [ "$REP_CUSUM_ARR" -ge 12000 ] && CUSUM_PTS=$(( CUSUM_PTS + 8 ))
        [ "$REP_CUSUM_SYN" -ge 6000 ] && CUSUM_PTS=$(( CUSUM_PTS + 8 ))
    fi

    local CHURN SUST SYNP RS
    read -r CHURN SUST SYNP RS CRT SLOW <<< "$(awk \
        -v cur="$cur" -v prev="$REP_PREV_CNT" -v syn="$syn" \
        -v dt="$dt" -v rate_prev="${REP_RATE:-0}" -v thr="${EFF_CONN_THRESHOLD:-$CONN_THRESHOLD}" \
        -v evok="$EVOK" -v s60="$S60" -v e60="$E60" -v ages="$AGES" -v bpc="$BPC" -v cln="$CLOSEDN" \
        -v ca="${CHURN_ALLOW:-2}" -v cw="${CHURN_WEIGHT:-1.2}" -v ccap="${CHURN_CAP:-30}" \
        -v sdiv="${SUST_DIV:-40}" -v scap="${SUST_CAP:-20}" \
        -v smin="${SYN_MIN:-20}" -v srat="${SYN_RATIO:-0.5}" -v sw="${SYN_WEIGHT:-40}" -v sycap="${SYN_CAP:-15}" \
        'BEGIN{
            r = (prev > 0) ? ((cur >= prev) ? (cur - prev) / dt : 0) : cur / dt;
            rs = 0.5 * r + 0.5 * (rate_prev / 100);
            churn = (rs <= ca) ? 0 : (rs - ca) * cw; if (churn > ccap) churn = ccap;
            ex = cur - thr; sust = (ex <= 0) ? 0 : ex / sdiv; if (sust > scap) sust = scap;
            synp = 0;
            if (syn >= smin && cur > 0) { ratio = syn / cur; if (ratio > srat) { synp = (ratio - srat) * sw; if (synp > sycap) synp = sycap; } }
            crt = 0;
            if (evok && s60 >= smin) { rr = e60 / s60; if (rr < srat) { crt = (srat - rr) * sw; if (crt > sycap) crt = sycap; } }
            if (crt > synp) synp = crt;
            slow = 0;
            if (evok && cln >= 10 && ages >= 120 && bpc <= 2000 && cur >= 30) { slow = (cur - 30) / 10; if (slow > 10) slow = 10; }
            printf "%.2f %.2f %.2f %.2f %.2f %.2f", churn, sust, synp, rs, crt, slow;
        }')"
    REP_RATE=$(awk -v rs="$RS" 'BEGIN{ printf "%d", rs * 100 + 0.5 }')

    # Probation: drops count double; the total is capped per minute.
    local total_x100 acc apply
    total_x100=$(awk -v c="$CHURN" -v s="$SUST" -v y="$SYNP" \
        -v cu="$CUSUM_PTS" -v sl="$SLOW" \
        -v prob="$in_prob" -v cap="$SCORE_DROP_CAP_PER_MIN" 'BEGIN{
            t = c + s + y + cu + sl; if (prob) t *= 2; if (t > cap) t = cap;
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
        local evlog=""
        [ "$EVOK" = "1" ] && evlog=" | ev comp=${CRT}/min cusum=${CUSUM_PTS}/min slow=${SLOW}/min r=$R60"
        log " SCORE: $ip | $old_score->$REP_SCORE (d$dstr) | churn=${CHURN}/min sust=${SUST}/min syn=${SYNP}/min rate=${RS}/s syn_n=$syn dt=${dt}s prob=$in_prob$evlog"
    fi

    # ── Enforce band (graduated, only escalate) ──
    if [ "$REP_SCORE" -lt "$SCORE_BAN" ]; then
        if ! state_has_ip "$BANNED_LIST" "$ip"; then
            # Stress gate (Phase 1d, F5 pattern): on a host that is NOT
            # under stress, a first offence in the shallow ban band is
            # a throttle, not a ban — anomalies alone do not prove the
            # host needs relief. Deep scores (<10) and repeat offenders
            # (strikes > 0) always ban.
            if [ "${STRESS_GATE:-1}" = "1" ] && [ "$REP_SCORE" -ge 10 ] \
               && [ "${REP_STRIKES:-0}" -eq 0 ] && ! nx_host_stressed; then
                nx_hard_throttle "$ip"
                log " GATE: $ip | score $REP_SCORE - ban deferred (host not stressed) -> hard throttle"
            else
                log " REP-BAN: $ip | score $REP_SCORE (below $SCORE_BAN) -> ban (progressive)"
                nx_throttle "$ip"
                nx_ban "$ip"
                rep_on_ban "$ip"
            fi
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
