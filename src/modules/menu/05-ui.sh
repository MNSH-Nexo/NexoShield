# @part modules/menu/05-ui.sh - UI framework (v3.7 redesign)
# Assembled into proxy-menu.sh by tools/build.py - not a standalone script.
#
# Before v3.7 every screen hand-rolled its own loop: 21 separate
# printf/read pairs against /dev/tty, four different confirmation
# idioms, headers drawn ad hoc, and no fallback when /dev/tty was
# unavailable (ssh without -t meant an infinite empty-read redraw).
# All screens now share this small framework:
#   ui_input VAR "prompt"  - one read idiom (tty, stdin fallback)
#   ui_confirm "question"  - the single (y/N) idiom
#   ui_title "A › B"       - header + breadcrumb title
#   ui_options "n|label|status" ... - aligned menu rows
#   ui_home_panel          - the dashboard summary on the main menu
# State locations are overridable for tests (NX_STATE_DIR,
# NX_SCORE_FILE); production defaults are the real paths.
NX_STATE_DIR="${NX_STATE_DIR:-/etc/antiddos}"
NX_SCORE_FILE="${NX_SCORE_FILE:-/var/lib/antiddos/scores/reputation.dat}"
# The daemon's LIVE throttle state is /tmp/autoban_throttle; the
# persistent mirror (U-11) is /etc/antiddos/throttled.list. Displays
# read the live file, falling back to the mirror right after a
# reboot before the daemon has restored its state.
NX_THROTTLE_LIST="${NX_THROTTLE_LIST:-/tmp/autoban_throttle}"
NX_THROTTLE_MIRROR="${NX_THROTTLE_MIRROR:-/etc/antiddos/throttled.list}"
nx_throttle_file() {
    if [ -f "$NX_THROTTLE_LIST" ]; then echo "$NX_THROTTLE_LIST";
    elif [ -f "$NX_THROTTLE_MIRROR" ]; then echo "$NX_THROTTLE_MIRROR"; fi
}

# nx_unban_ip <ip> - the ONE unban path (U-2). The Security screen's
# old inline version deleted an untagged rule spec the daemon never
# creates, edited the dead /tmp mirror by hand and never touched
# banned.list - so the "unbanned" IP was re-banned at the next
# daemon reconcile. Exact tagged deletes, exact state edits,
# throttle-filter cleanup, fail2ban unban - shared by every screen.
nx_unban_ip() {
    local _ip="$1" _tf _prio _if _j
    # Phase 1b: if the daemon's nft backend holds this ban, remove the
    # set element too (the iptables deletes below stay as belt-and-braces).
    if command -v nft >/dev/null 2>&1; then
        case "$_ip" in
            *:*) nft delete element inet nexoshield ban6 "{ $_ip }" >/dev/null 2>&1 || true ;;
            *)   nft delete element inet nexoshield ban4 "{ $_ip }" >/dev/null 2>&1 || true ;;
        esac
    fi
    case "$_ip" in
        *:*)
            ip6tables -D INPUT -s "$_ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || true ;;
        *)
            iptables -D INPUT -s "$_ip" -m comment --comment "auto-ban" -j DROP 2>/dev/null || \
            iptables -D INPUT -s "$_ip" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || \
            iptables -D INPUT -s "$_ip" -j DROP 2>/dev/null || true ;;
    esac
    for _tf in "$NX_THROTTLE_LIST" "$NX_THROTTLE_MIRROR"; do
        [ -f "$_tf" ] || continue
        _prio=$(awk -v x="$_ip" '$1==x{print $2}' "$_tf" 2>/dev/null | head -1)
        if [ -n "$_prio" ]; then
            _if=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
            [ -n "$_if" ] && tc filter del dev "$_if" parent 1: prio "$_prio" 2>/dev/null || true
        fi
        awk -v x="$_ip" '$1!=x' "$_tf" > "$_tf.nxtmp" 2>/dev/null && mv "$_tf.nxtmp" "$_tf"
    done
    if [ -f "$NX_STATE_DIR/banned.list" ]; then
        awk -v x="$_ip" '$1!=x' "$NX_STATE_DIR/banned.list" > "$NX_STATE_DIR/banned.list.nxtmp" 2>/dev/null && \
            mv "$NX_STATE_DIR/banned.list.nxtmp" "$NX_STATE_DIR/banned.list"
    fi
    fail2ban-client status 2>/dev/null | grep "Jail list" | \
        sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r _j; do
        [ -z "$_j" ] && continue
        fail2ban-client set "$_j" unbanip "$_ip" 2>/dev/null || true
    done
}

ui_input() {
    local _var="$1" _prompt="$2" _val=""
    if [ -n "${NX_UI_STDIN:-}" ]; then
        printf '%s' "$_prompt"; read -r _val || _val=""
    elif (exec </dev/tty) 2>/dev/null; then
        printf '%s' "$_prompt" >/dev/tty; read -r _val </dev/tty || _val=""
    else
        printf '%s' "$_prompt"; read -r _val || _val=""
    fi
    printf -v "$_var" '%s' "$_val"
}

ui_confirm() {
    local _a
    ui_input _a "  $1 (y/N): "
    [ "$_a" = "y" ] || [ "$_a" = "Y" ]
}

ui_title() {
    draw_header
    echo -e "  ${C}${BOLD}$1${NC}"; echo ""
}

ui_options() {
    local _spec _n _label _status
    for _spec in "$@"; do
        _n="${_spec%%|*}"; _label="${_spec#*|}"; _status=""
        case "$_label" in *\|*) _status="${_label#*|}"; _label="${_label%%|*}" ;; esac
        if [ -n "$_status" ]; then
            echo -e "  ${C}${_n}.${NC}  $_label  $_status"
        else
            echo -e "  ${C}${_n}.${NC}  $_label"
        fi
    done
    echo ""
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
}

# press_enter predates the framework (00-header); redefine it on top
# of ui_input so every "go back" pause shares the same input path.
press_enter() {
    echo ""
    local _pe
    ui_input _pe "  Press Enter to go back..."
}

# ── Dashboard summary for the main menu ────────────────────
ui_home_panel() {
    local _nb _nt _nw
    _nb=$(cnt . "$NX_STATE_DIR/banned.list")
    _nt=$(cnt . "$(nx_throttle_file)")
    _nw=$(cnt . "$NX_STATE_DIR/whitelist.list")
    echo -e "  ${BOLD}Overview${NC}"
    echo -e "  ${DIM}Banned now:${NC} ${W}${_nb}${NC}    ${DIM}Throttled:${NC} ${W}${_nt}${NC}    ${DIM}Whitelist entries:${NC} ${W}${_nw}${NC}"
    if [ -s "$NX_SCORE_FILE" ]; then
        echo -e "  ${DIM}Lowest reputation:${NC}"
        sort -k2 -n "$NX_SCORE_FILE" 2>/dev/null | head -3 | while read -r _ip _sc _rest; do
            [ -z "${_ip:-}" ] && continue
            local _col="$DIM"
            [ "${_sc:-100}" -lt 40 ] 2>/dev/null && _col="$R"
            [ "${_sc:-100}" -ge 40 ] && [ "${_sc:-100}" -lt 60 ] 2>/dev/null && _col="$Y"
            echo -e "    ${_col}${_ip} — score ${_sc}${NC}"
        done
    fi
    if [ -s /var/log/auto-ban.log ]; then
        echo -e "  ${DIM}Recent auto-ban events:${NC}"
        tail -3 /var/log/auto-ban.log 2>/dev/null | sed 's/^/    /'
    fi
    echo ""
}

# ── Plain-text CLI views (scriptable; no colours) ─────────
nx_status_plain() {
    echo "NexoShield v$VERSION"
    echo "3proxy:    $(systemctl is-active 3proxy 2>/dev/null || echo unknown) (port: $(get_proxy_port || echo -))"
    echo "auto-ban:  $(systemctl is-active auto-ban 2>/dev/null || echo unknown)"
    echo "fail2ban:  $(systemctl is-active fail2ban 2>/dev/null || echo unknown)"
    [ -f "$NX_STATE_DIR/state.conf" ] && echo "antiddos:  installed" || echo "antiddos:  not installed"
    echo "banned:    $(cnt . "$NX_STATE_DIR/banned.list")"
    echo "throttled: $(cnt . "$(nx_throttle_file)")"
}

nx_bans_plain() {
    [ -s "$NX_STATE_DIR/banned.list" ] || { echo "(no active bans)"; return 0; }
    local _ip _ts _dur
    while read -r _ip _ts _dur; do
        [ -z "$_ip" ] && continue
        _ts="${_ts//[^0-9]/}"; _dur="${_dur//[^0-9]/}"
        echo "$_ip  since $(date -d "@${_ts:-0}" '+%F %T' 2>/dev/null || echo '?')  expires $(date -d "@$(( ${_ts:-0} + ${_dur:-0} ))" '+%F %T' 2>/dev/null || echo '?')"
    done < "$NX_STATE_DIR/banned.list"
}
