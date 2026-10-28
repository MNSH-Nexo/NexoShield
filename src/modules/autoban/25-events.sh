# @part modules/autoban/25-events.sh - nxcountd snapshot loader + adaptive thresholds (Phase 2)
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
#
# Phase 2 measurement core. nxcountd publishes exact conntrack event
# aggregates every second; this loader diffs consecutive snapshots
# into per-cycle arrival deltas and 60 s window sums. When the
# snapshot is missing or stale, NX_EV_OK=0 and EVERY Phase-2 term
# disarms — behaviour is then exactly the pre-Phase-2 daemon.

NX_COUNTERS_FILE="${NX_COUNTERS_FILE:-/run/nexoshield/counters.dat}"
declare -A EV_SYN60 EV_EST60 EV_CLOSED EV_BYTES EV_AGE
declare -A EV_DSYN EV_DEST EV_PSYN EV_PEST
NX_EV_OK=0
NX_EV_BASE=""
NX_EV_TOT_DSYN=0
NX_EV_TOT_DEST=0
# L4: nxcountd's own loss counters (emitted in the header since
# Phase 2 but never read). NX_EV_DROPPED is the cumulative count of
# netlink messages the helper dropped (ENOBUFS) and
# NX_EV_FLOWS_DROPPED the flows lost with them; NX_EV_DROP_DELTA is
# the increase since the previous cycle. A nonzero delta is logged
# so a lossy cycle is never silently read as "low arrivals".
NX_EV_DROPPED=0
NX_EV_FLOWS_DROPPED=0
NX_EV_DROP_DELTA=0
NX_EV_DT=2
_NX_EV_PREV_TS=""
_NX_EV_PREV_TOTSYN=""
_NX_EV_PREV_TOTEST=""
_NX_EV_PREV_DROPPED=""
_NX_EV_PREV_FLOWS_DROPPED=""

nx_load_event_counters() {
    NX_EV_OK=0
    NX_EV_TOT_DSYN=0
    NX_EV_TOT_DEST=0
    [ -f "$NX_COUNTERS_FILE" ] || return 0
    local hdr kv ts="" base="" totsyn="" totest="" now dropped="" flows_dropped=""
    hdr=$(head -n 1 "$NX_COUNTERS_FILE" 2>/dev/null) || return 0
    case "$hdr" in "# nxcountd 1 "*) ;; *) return 0 ;; esac
    for kv in $hdr; do
        case "$kv" in
            ts=*) ts="${kv#ts=}" ;;
            base=*) base="${kv#base=}" ;;
            totalsyn=*) totsyn="${kv#totalsyn=}" ;;
            totalest=*) totest="${kv#totalest=}" ;;
            dropped=*) dropped="${kv#dropped=}" ;;
            flows_dropped=*) flows_dropped="${kv#flows_dropped=}" ;;
        esac
    done
    ts="${ts//[^0-9]/}"; [ -n "$ts" ] || return 0
    now=$(date +%s)
    # Fresh = published within the last 5 s (clock skew tolerated).
    [ $(( now - ts )) -gt 5 ] && return 0
    [ $(( ts - now )) -gt 5 ] && return 0
    if [ "$base" != "$NX_EV_BASE" ]; then
        # Helper (re)started: cumulative counters reset — re-base the
        # delta windows instead of diffing across the restart.
        NX_EV_BASE="$base"
        EV_PSYN=(); EV_PEST=()
        _NX_EV_PREV_TOTSYN=""
        _NX_EV_PREV_DROPPED=""
        _NX_EV_PREV_FLOWS_DROPPED=""
        log " EVENTS: nxcountd counters (re)based - arrival windows re-arming"
    fi
    totsyn="${totsyn//[^0-9]/}"; totest="${totest//[^0-9]/}"
    if [ -n "$_NX_EV_PREV_TOTSYN" ] && [ -n "$totsyn" ]; then
        NX_EV_TOT_DSYN=$(( totsyn - _NX_EV_PREV_TOTSYN ))
        [ "$NX_EV_TOT_DSYN" -lt 0 ] && NX_EV_TOT_DSYN=0
        NX_EV_TOT_DEST=$(( totest - _NX_EV_PREV_TOTEST ))
        [ "$NX_EV_TOT_DEST" -lt 0 ] && NX_EV_TOT_DEST=0
    fi
    _NX_EV_PREV_TOTSYN="${totsyn:-}"
    _NX_EV_PREV_TOTEST="${totest:-}"
    # L4: surface the helper's loss counters (same delta discipline
    # as the arrival totals - clamped, re-based on restart).
    dropped="${dropped//[^0-9]/}"; flows_dropped="${flows_dropped//[^0-9]/}"
    NX_EV_DROPPED="${dropped:-0}"; NX_EV_FLOWS_DROPPED="${flows_dropped:-0}"
    NX_EV_DROP_DELTA=0
    if [ -n "$_NX_EV_PREV_DROPPED" ] && [ -n "$dropped" ]; then
        NX_EV_DROP_DELTA=$(( dropped - _NX_EV_PREV_DROPPED ))
        [ "$NX_EV_DROP_DELTA" -lt 0 ] && NX_EV_DROP_DELTA=0
        if [ "$NX_EV_DROP_DELTA" -gt 0 ]; then
            local _fd=$(( ${flows_dropped:-0} - ${_NX_EV_PREV_FLOWS_DROPPED:-0} ))
            [ "$_fd" -lt 0 ] && _fd=0
            log " EVENTS: nxcountd lost $NX_EV_DROP_DELTA netlink messages ($_fd flows) since last cycle - arrival counts are a lower bound (cumulative: $NX_EV_DROPPED messages, $NX_EV_FLOWS_DROPPED flows)"
        fi
    fi
    _NX_EV_PREV_DROPPED="${dropped:-}"
    _NX_EV_PREV_FLOWS_DROPPED="${flows_dropped:-}"
    if [ -n "$_NX_EV_PREV_TS" ]; then
        local _ddt=$(( ts - _NX_EV_PREV_TS ))
        [ "$_ddt" -ge 1 ] && [ "$_ddt" -le 30 ] && NX_EV_DT="$_ddt"
    fi
    _NX_EV_PREV_TS="$ts"
    EV_SYN60=(); EV_EST60=(); EV_CLOSED=(); EV_BYTES=(); EV_AGE=(); EV_DSYN=(); EV_DEST=()
    local ip s e s60 e60 cl b a ps pe d
    while read -r ip s e s60 e60 _ _ cl b a; do
        case "$ip" in \#*|"") continue ;; esac
        EV_SYN60["$ip"]="$s60"; EV_EST60["$ip"]="$e60"
        EV_CLOSED["$ip"]="$cl"; EV_BYTES["$ip"]="$b"; EV_AGE["$ip"]="$a"
        ps="${EV_PSYN[$ip]:-}"; pe="${EV_PEST[$ip]:-}"
        if [ -n "$ps" ]; then
            d=$(( s - ps )); [ "$d" -lt 0 ] && d=0; EV_DSYN["$ip"]="$d"
            d=$(( e - pe )); [ "$d" -lt 0 ] && d=0; EV_DEST["$ip"]="$d"
        else
            EV_DSYN["$ip"]=0; EV_DEST["$ip"]=0
        fi
        EV_PSYN["$ip"]="$s"; EV_PEST["$ip"]="$e"
    done < <(tail -n +2 "$NX_COUNTERS_FILE" 2>/dev/null)
    NX_EV_OK=1
}

# ── Adaptive global thresholds (Phase 2d) ────────────────────────
# EWMA mean/deviation of total SYN arrivals per cycle. ATTACK state
# (z >= 4 sustained 3 cycles) tightens the gates and FREEZES the
# baseline — attack traffic must never train its own threshold
# (F5's rule; Wang et al.'s 3-sigma stage is the same shape).
# Calm resumes after z < 2 for 30 cycles (hysteresis). Without event
# data the adaptive layer simply does not move: EFF_* stay at the
# configured values.
NX_ADAPT_FILE="${NX_ADAPT_FILE:-/etc/antiddos/adaptive.dat}"
NX_MU=""
NX_SIG=""
NX_ATTACK=0
_NX_AD_HI=0
_NX_AD_LO=0
_NX_AD_INIT=0
_NX_AD_CYC=0
_NX_AD_PREV=0
EFF_CONN_THRESHOLD=120
EFF_OBSERVE=45

nx_update_adaptive() {
    EFF_CONN_THRESHOLD="$CONN_THRESHOLD"
    EFF_OBSERVE="$OBSERVE_SECONDS"
    [ "${ADAPTIVE_ENABLED:-1}" = "1" ] || return 0
    [ "$NX_EV_OK" = "1" ] || return 0
    if [ "$_NX_AD_INIT" -eq 0 ]; then
        _NX_AD_INIT=1
        if [ -f "$NX_ADAPT_FILE" ]; then
            read -r NX_MU NX_SIG NX_ATTACK < "$NX_ADAPT_FILE" || true
            [[ "${NX_MU:-}" =~ ^[0-9.]+$ ]] || NX_MU=""
            [[ "${NX_SIG:-}" =~ ^[0-9.]+$ ]] || NX_SIG=""
            [ "${NX_ATTACK:-0}" = "1" ] || NX_ATTACK=0
        fi
    fi
    read -r NX_MU NX_SIG NX_ATTACK _NX_AD_HI _NX_AD_LO <<< "$(awk \
        -v A="$NX_EV_TOT_DSYN" -v mu="${NX_MU:-0}" -v sig="${NX_SIG:-0}" \
        -v atk="$NX_ATTACK" -v hi="$_NX_AD_HI" -v lo="$_NX_AD_LO" 'BEGIN{
            if (mu == 0 && sig == 0) { mu = A; sig = (A > 0 ? A * 0.25 : 1); }
            z = (sig > 0.5) ? (A - mu) / sig : ((A > mu * 3 && A > 50) ? 99 : 0);
            if (!atk) {
                if (z >= 4) { hi++; lo = 0; } else { hi = 0; }
                if (hi >= 3) { atk = 1; hi = 0; lo = 0; }
                else {
                    d = A - mu; mu += 0.02 * d;
                    ad = (d < 0 ? -d : d) * 1.2533; sig += 0.02 * (ad - sig);
                    if (sig < 0.5) sig = 0.5;
                }
            } else {
                if (z < 2) { lo++; } else { lo = 0; }
                if (lo >= 30) { atk = 0; lo = 0; hi = 0; }
            }
            printf "%.4f %.4f %d %d %d", mu, sig, atk, hi, lo;
        }')"
    if [ "$NX_ATTACK" = "1" ]; then
        EFF_CONN_THRESHOLD=$(awk -v t="$CONN_THRESHOLD" 'BEGIN{ v = int(t * 0.6); if (v < 40) v = 40; if (v > 400) v = 400; print v }')
        EFF_OBSERVE=$(awk -v o="$OBSERVE_SECONDS" 'BEGIN{ v = int(o * 0.5); if (v < 10) v = 10; print v }')
    fi
    _NX_AD_CYC=$(( _NX_AD_CYC + 1 ))
    if [ $(( _NX_AD_CYC % 30 )) -eq 0 ]; then
        printf '%s %s %s\n' "$NX_MU" "$NX_SIG" "$NX_ATTACK" > "$NX_ADAPT_FILE.tmp.$$" 2>/dev/null && \
            mv "$NX_ADAPT_FILE.tmp.$$" "$NX_ADAPT_FILE" 2>/dev/null || true
    fi
    if [ "$NX_ATTACK" != "$_NX_AD_PREV" ]; then
        if [ "$NX_ATTACK" = "1" ]; then
            log " ADAPTIVE: ATTACK state - gates tightened (conn=$EFF_CONN_THRESHOLD observe=${EFF_OBSERVE}s), baseline frozen"
        else
            log " ADAPTIVE: calm - baseline learning resumed (mu=$NX_MU sig=$NX_SIG)"
        fi
        _NX_AD_PREV="$NX_ATTACK"
    fi
}
