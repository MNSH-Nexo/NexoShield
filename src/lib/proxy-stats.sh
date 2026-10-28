# nx_proxy_stats_* - shared traffic-counting helpers (v3.17.0).
# Included at build time into BOTH 3proxy-socks5.sh and antiddos.sh,
# because both programs can reorder the chains the counters live in.
# @lib-body
# A counting rule has no -j target: it counts only packets that
# REACH it. Any ACCEPT above it (an antiddos -I insert, or a
# third-party firewall's blanket rule) shadows it, so a counter
# that is merely inserted once silently undercounts. Field report
# v3.16.3: stats_in buried at INPUT #811 below the ESTABLISHED
# accept counted SYNs only (282 pkts / 14 KB while the interface
# moved ~515 MB); stats_out below a blanket OUTPUT accept counted
# exactly zero. The pin below re-asserts the rules at position 1,
# and only moves them when they are NOT already on top, so a
# re-pin never destroys a healthy counter. Moving a target-less
# rule changes no allow/block behaviour - it only counts.
nx_proxy_stats_top() {
    # nx_proxy_stats_top CHAIN COMMENT [PORT] -> 0 if the chain's
    # first rule carries COMMENT (and, when PORT is given, the
    # matching --dport/--sport PORT). LOW-2: a stale other-port
    # rule at position 1 used to satisfy the comment-only check, so
    # the pin became a no-op and the accumulator read the wrong
    # counter. The trailing-space/EOL alternatives keep port 1080
    # from matching 10801.
    local _first
    _first=$(iptables -S "$1" 2>/dev/null | grep -m1 '^-A' || true)
    case "$_first" in *"$2"*) ;; *) return 1 ;; esac
    if [ -n "${3:-}" ]; then
        case "$_first" in
            *"--dport ${3} "*|*"--dport ${3}"|*"--sport ${3} "*|*"--sport ${3}") ;;
            *) return 1 ;;
        esac
    fi
    return 0
}

nx_pin_proxy_stats_rules() {
    # nx_pin_proxy_stats_rules PORT: re-assert both counting rules
    # at position 1. No-op (counter preserved) when already pinned.
    local PORT="$1"
    [ -n "$PORT" ] || return 0
    if ! nx_proxy_stats_top INPUT "3proxy_stats_in" "$PORT"; then
        iptables -D INPUT -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in" 2>/dev/null || true
        iptables -I INPUT 1 -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    fi
    if ! nx_proxy_stats_top OUTPUT "3proxy_stats_out" "$PORT"; then
        iptables -D OUTPUT -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out" 2>/dev/null || true
        iptables -I OUTPUT 1 -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    fi
}

nx_proxy_stats_bytes() {
    # nx_proxy_stats_bytes CHAIN COMMENT [PORT] -> counter bytes
    # (or empty). Same parse as show_stats: the bytes column of
    # `iptables -L`. With PORT, the row must also carry dpt:/spt:
    # PORT (the [^0-9] guard keeps 1080 from matching 10801).
    if [ -n "${3:-}" ]; then
        iptables -L "$1" -v -n -x 2>/dev/null | grep "$2" | grep -E "(dpt|spt):${3}([^0-9]|$)" | awk '{print $2}' | head -1
    else
        iptables -L "$1" -v -n -x 2>/dev/null | grep "$2" | awk '{print $2}' | head -1
    fi
}

nx_proxy_port_from_config() {
    # Live port from the 3proxy config (source of truth, not install.info).
    grep -oP '(?<=socks -p)\s*\K\d+' /etc/3proxy/3proxy.cfg 2>/dev/null | head -1 || true
}

# State file format (one line): LAST_IN LAST_OUT TOTAL_IN TOTAL_OUT.
# Written atomically (tmp + rename). Totals survive reboots and rule
# recreations: a counter that went BACKWARDS means its rule was
# recreated, so the delta is the new counter itself, never negative.
# A missing rule (proxy removed, rules wiped) leaves totals untouched.
nx_proxy_traffic_accum() {
    # LOW-3: the timer, the pin callers and a manual run can overlap
    # (two writers interleaving read-compute-write would lose a
    # delta). A non-blocking lock defers a contended run to the
    # next 5-minute tick instead of blocking the caller - the
    # snapshot is periodic, never urgent. No flock binary: proceed
    # unlocked (the old behaviour), never fail the caller.
    local PORT STATE CUR_IN CUR_OUT LAST_IN LAST_OUT TOT_IN TOT_OUT _lock_fd _rc
    PORT=$(nx_proxy_port_from_config)
    [ -n "$PORT" ] || return 0
    STATE="${NX_PROXY_TRAFFIC_STATE:-/etc/3proxy/traffic-total.state}"
    if command -v flock >/dev/null 2>&1; then
        exec {_lock_fd}>"${STATE}.lock" 2>/dev/null || _lock_fd=""
        if [ -n "$_lock_fd" ]; then
            flock -n "$_lock_fd" 2>/dev/null || { exec {_lock_fd}>&- 2>/dev/null || true; return 0; }
        fi
    fi
    CUR_IN=$(nx_proxy_stats_bytes INPUT "3proxy_stats_in" "$PORT")
    CUR_OUT=$(nx_proxy_stats_bytes OUTPUT "3proxy_stats_out" "$PORT")
    # Release the lock on every exit path: a leaked fd would hold
    # the lock in a long-lived caller (the menu process, the test
    # harness) and starve every later run.
    if [ -z "$CUR_IN" ] || [ -z "$CUR_OUT" ]; then
        [ -n "${_lock_fd:-}" ] && exec {_lock_fd}>&- 2>/dev/null || true
        return 0
    fi
    LAST_IN=""; LAST_OUT=""; TOT_IN=""; TOT_OUT=""
    if [ -f "$STATE" ]; then
        read -r LAST_IN LAST_OUT TOT_IN TOT_OUT < "$STATE" 2>/dev/null || true
    fi
    LAST_IN="${LAST_IN//[^0-9]/}"; LAST_OUT="${LAST_OUT//[^0-9]/}"
    TOT_IN="${TOT_IN//[^0-9]/}"; TOT_OUT="${TOT_OUT//[^0-9]/}"
    LAST_IN="${LAST_IN:-0}"; LAST_OUT="${LAST_OUT:-0}"
    TOT_IN="${TOT_IN:-0}"; TOT_OUT="${TOT_OUT:-0}"
    if [ "$CUR_IN" -ge "$LAST_IN" ] 2>/dev/null; then TOT_IN=$((TOT_IN + CUR_IN - LAST_IN)); else TOT_IN=$((TOT_IN + CUR_IN)); fi
    if [ "$CUR_OUT" -ge "$LAST_OUT" ] 2>/dev/null; then TOT_OUT=$((TOT_OUT + CUR_OUT - LAST_OUT)); else TOT_OUT=$((TOT_OUT + CUR_OUT)); fi
    printf '%s %s %s %s\n' "$CUR_IN" "$CUR_OUT" "$TOT_IN" "$TOT_OUT" > "${STATE}.tmp.$$" 2>/dev/null && mv -f "${STATE}.tmp.$$" "$STATE" 2>/dev/null || true
    # Self-heal shadowing AFTER the snapshot, so a re-pin never
    # destroys counts it has not yet recorded.
    nx_pin_proxy_stats_rules "$PORT"
    _rc=$?
    [ -n "${_lock_fd:-}" ] && exec {_lock_fd}>&- 2>/dev/null || true
    return "$_rc"
}
