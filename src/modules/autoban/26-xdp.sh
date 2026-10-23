# @part modules/autoban/26-xdp.sh - XDP emergency shield control (Phase 3)
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
#
# The shield is DORMANT: the daemon attaches it only while kernel
# distress signals say the netfilter path is drowning (syncookie
# storms, listen-backlog overflows, or an extreme sustained SYN
# arrival rate from nxcountd), syncs the SAME ban/exempt state the
# nft backend enforces, and detaches after a sustained calm. If the
# loader/object were never built (no clang/libbpf at install time)
# every function here is a no-op.

NX_XDP_BIN="${NX_XDP_BIN:-/usr/local/bin/nx-xdp}"
NX_XDP_OBJ="${NX_XDP_OBJ:-/usr/local/lib/nx_xdp.o}"
NX_XDP_DIR="${NX_XDP_DIR:-/run/nexoshield}"
NX_XDP_BANS_FILE="$NX_XDP_DIR/xdp-bans.list"
NX_XDP_EXEMPT_FILE="$NX_XDP_DIR/xdp-exempt.list"
NX_XDP_AVAILABLE=0
NX_XDP_ATTACHED=""
NX_XDP_IFACE=""
_NX_XDP_HOT=0
_NX_XDP_CALM_SINCE=0
_NX_XDP_WIN_START=0
_NX_XDP_OVF_WIN=0
_NX_XDP_SCOOK_WIN=0
_NX_XDP_BANS_MT=0

nx_xdp_init() {
    if [ -x "$NX_XDP_BIN" ] && [ -f "$NX_XDP_OBJ" ]; then
        NX_XDP_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
        [ -n "$NX_XDP_IFACE" ] && NX_XDP_AVAILABLE=1
    fi
    [ "$NX_XDP_AVAILABLE" = "1" ] && \
        log " XDP: emergency shield available on $NX_XDP_IFACE (dormant)"
    return 0
}

nx_xdp_build_files() {
    mkdir -p "$NX_XDP_DIR" || return 1
    local now ip ts dur rem e f
    now=$(date +%s)
    : > "$NX_XDP_BANS_FILE.tmp"
    while read -r ip ts dur; do
        [ -n "$ip" ] || continue
        dur="${dur:-$(( ${BAN_HOURS:-4} * 3600 ))}"
        rem=$(( ts + dur - now ))
        [ "$rem" -gt 0 ] && printf '%s %s\n' "$ip" "$rem" >> "$NX_XDP_BANS_FILE.tmp"
    done < "$BANNED_LIST"
    mv "$NX_XDP_BANS_FILE.tmp" "$NX_XDP_BANS_FILE"
    {
        for e in "${SELF_IPS[@]}" "${SELF6_IPS[@]}"; do [ -n "$e" ] && printf '%s\n' "$e"; done
        for e in "${CF_RANGES[@]}" "${CF6_RANGES[@]}"; do [ -n "$e" ] && printf '%s\n' "$e"; done
        for f in "$WHITELIST_FILE" /etc/antiddos/self-ips.list /etc/antiddos/public-ips.list /etc/antiddos/exempt.list; do
            [ -f "$f" ] && cat "$f"
        done
    } | grep -E '^[0-9a-fA-F:./]+$' | sort -u > "$NX_XDP_EXEMPT_FILE.tmp"
    mv "$NX_XDP_EXEMPT_FILE.tmp" "$NX_XDP_EXEMPT_FILE"
}

nx_xdp_attach() {
    local reason="$1"
    nx_xdp_build_files || return 1
    if ! "$NX_XDP_BIN" check "$NX_XDP_BANS_FILE" "$NX_XDP_EXEMPT_FILE" >/dev/null 2>&1; then
        log " XDP: sync files failed validation - NOT attaching"
        return 1
    fi
    if "$NX_XDP_BIN" load "$NX_XDP_IFACE" "$NX_XDP_OBJ" >> "${LOG_FILE:-/dev/null}" 2>&1; then
        "$NX_XDP_BIN" sync-bans "$NX_XDP_BANS_FILE" >/dev/null 2>&1 || true
        "$NX_XDP_BIN" sync-exempt "$NX_XDP_EXEMPT_FILE" >/dev/null 2>&1 || true
        NX_XDP_ATTACHED="$NX_XDP_IFACE"
        _NX_XDP_CALM_SINCE=0
        _NX_XDP_BANS_MT=$(stat -c %Y "$BANNED_LIST" 2>/dev/null || echo 0)
        log " XDP: emergency shield ATTACHED on $NX_XDP_IFACE ($reason) - line-rate SYN relief active"
    else
        log " XDP: attach FAILED on $NX_XDP_IFACE - continuing with nft/iptables only"
        return 1
    fi
}

nx_xdp_detach() {
    "$NX_XDP_BIN" unload "$NX_XDP_ATTACHED" >> "${LOG_FILE:-/dev/null}" 2>&1 || true
    log " XDP: shield detached from $NX_XDP_ATTACHED ($1)"
    NX_XDP_ATTACHED=""
    _NX_XDP_HOT=0
    _NX_XDP_CALM_SINCE=0
}

nx_xdp_tick() {
    [ "$NX_XDP_AVAILABLE" = "1" ] || return 0
    local now rate=0 mt
    now=$(date +%s)
    [ "$_NX_XDP_WIN_START" -eq 0 ] && _NX_XDP_WIN_START=$now
    _NX_XDP_OVF_WIN=$(( _NX_XDP_OVF_WIN + ${NX_OVF_DELTA:-0} ))
    _NX_XDP_SCOOK_WIN=$(( _NX_XDP_SCOOK_WIN + ${NX_SYNCOOK_DELTA:-0} ))
    if [ "${NX_EV_OK:-0}" = "1" ] && [ "${NX_EV_DT:-0}" -gt 0 ]; then
        rate=$(( NX_EV_TOT_DSYN / NX_EV_DT ))
    fi
    if [ -z "$NX_XDP_ATTACHED" ]; then
        if [ "$rate" -gt "${XDP_SYN_RATE:-3000}" ]; then
            _NX_XDP_HOT=$(( _NX_XDP_HOT + 1 ))
        else
            _NX_XDP_HOT=0
        fi
        if [ "$_NX_XDP_HOT" -ge 15 ]; then
            nx_xdp_attach "SYN arrival rate ${rate}/s sustained" || true
            return 0
        fi
        if [ $(( now - _NX_XDP_WIN_START )) -ge 60 ]; then
            if [ "$_NX_XDP_OVF_WIN" -gt "${XDP_OVERFLOW_RATE:-1000}" ]; then
                nx_xdp_attach "listen overflows ${_NX_XDP_OVF_WIN}/min" || true
            elif [ "$_NX_XDP_SCOOK_WIN" -gt "${XDP_SYNCOOKIE_RATE:-500}" ]; then
                nx_xdp_attach "syncookies ${_NX_XDP_SCOOK_WIN}/min" || true
            fi
            _NX_XDP_WIN_START=$now; _NX_XDP_OVF_WIN=0; _NX_XDP_SCOOK_WIN=0
        fi
    else
        mt=$(stat -c %Y "$BANNED_LIST" 2>/dev/null || echo 0)
        if [ "$mt" != "$_NX_XDP_BANS_MT" ]; then
            _NX_XDP_BANS_MT="$mt"
            if nx_xdp_build_files; then
                "$NX_XDP_BIN" sync-bans "$NX_XDP_BANS_FILE" >/dev/null 2>&1 || true
                "$NX_XDP_BIN" sync-exempt "$NX_XDP_EXEMPT_FILE" >/dev/null 2>&1 || true
            fi
        fi
        if [ "${NX_OVF_DELTA:-0}" -eq 0 ] && [ "${NX_SYNCOOK_DELTA:-0}" -eq 0 ] && [ "$rate" -lt 500 ]; then
            [ "$_NX_XDP_CALM_SINCE" -eq 0 ] && _NX_XDP_CALM_SINCE=$now
            if [ $(( now - _NX_XDP_CALM_SINCE )) -ge "${XDP_CALM_SECONDS:-600}" ]; then
                nx_xdp_detach "calm for ${XDP_CALM_SECONDS:-600}s"
            fi
        else
            _NX_XDP_CALM_SINCE=0
        fi
        if [ $(( now - _NX_XDP_WIN_START )) -ge 60 ]; then
            _NX_XDP_WIN_START=$now; _NX_XDP_OVF_WIN=0; _NX_XDP_SCOOK_WIN=0
        fi
    fi
}
