# @part modules/antiddos/70-whitelist-main.sh - show_thresholds, manage_whitelist, apply_tc_runtime, main loop
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
show_thresholds() {
    sep; echo -e "  ${CYAN}${BOLD}Current Thresholds${NC}"; sep
    printf "  %-35s ${WHITE}%s${NC}\n" "SYN rate limit:"        "$SYN_LIMIT (burst: $SYN_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "UDP rate limit:"        "$UDP_LIMIT (burst: $UDP_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "ICMP rate limit:"       "$ICMP_LIMIT (burst: $ICMP_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "HTTP req rate limit:"   "${HTTP_REQ_RATE:-N/A} (burst: ${HTTP_REQ_BURST:-N/A})"
    printf "  %-35s ${WHITE}%s${NC}\n" "New conn rate limit:"   "${NEW_CONN_RATE:-N/A} (burst: ${NEW_CONN_BURST:-N/A})"
    printf "  %-35s ${WHITE}%s${NC}\n" "Per-IP bandwidth cap:"  "${BW_PER_IP_MBIT:-N/A} Mbps"
    printf "  %-35s ${WHITE}%s${NC}\n" "HTTP conns/non-CF IP:"  "$CONN_LIMIT_PER_IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban watch threshold:"   "120 active conns/IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban instant-ban:"       "300 active conns/IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban subnet watch:"      "400 total conns from /24"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban subnet ban:"        "1000 total conns from /24"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban observe:"           "45s watch before throttle"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban throttle:"          "100Mbps"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban duration:"          "Progressive: 30 min, doubling to 7 days"
    printf "  %-35s ${WHITE}%s${NC}\n" "Reputation scoring:"         "ON (100→0, human-vs-bot)"
    printf "  %-35s ${WHITE}%s${NC}\n" "  bands:"                    "80+normal 60+watch 40+100M 20+50M <20 ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "  auto-release:"             "ON (throttled→normal when calmed)"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban 3proxy:"       "100 req/60s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban HTTP burst:"    "200 req/30s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban conn-flood:"    "20 drops/10s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban SSH:"          "3 fails/30s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "Cloudflare IPs:"        "UNLIMITED at all layers"
    sep
}

# Validate an IPv4 address or CIDR (e.g. 1.2.3.4 or 5.6.7.0/24).
# Returns 0 when valid, 1 otherwise. Guards the whitelist manager so a
# typo can't silently add a non-address that iptables then ignores.
valid_ip_or_cidr() {
    local input="${1:-}" addr mask o slashed=0
    case "$input" in
        */*) addr="${input%%/*}"; mask="${input#*/}"; slashed=1 ;;
        *)   addr="$input"; mask="" ;;
    esac
    case "$addr" in
        ""|.*|*.|*..*|*[!0-9.]*) return 1 ;;
    esac
    local o1 o2 o3 o4 extra
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$addr"
    [ -z "${extra:-}" ] || return 1
    for o in "$o1" "$o2" "$o3" "$o4"; do
        case "$o" in
            ""|*[!0-9]*) return 1 ;;
        esac
        [ "${#o}" -le 3 ] || return 1
        (( 10#$o <= 255 )) || return 1
    done
    if [ "$slashed" = 1 ]; then
        case "$mask" in
            ""|*[!0-9]*) return 1 ;;
        esac
        [ "${#mask}" -le 2 ] || return 1
        (( 10#$mask <= 32 )) || return 1
    fi
    return 0
}

# ── Exempt-set membership (D1) ─────────────────────────────
nx_ip_to_int() {
    local IFS=. a b c d
    read -r a b c d <<< "$1"
    echo $(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))
}

nx_ip_in_cidr() {
    local ip="$1" cidr="$2" net mask ni ii sh
    net="${cidr%%/*}"; mask="${cidr#*/}"
    case "$mask" in ''|*[!0-9]*) return 1 ;; esac
    (( 10#$mask <= 32 )) || return 1
    ni=$(nx_ip_to_int "$net"); ii=$(nx_ip_to_int "$ip")
    [ "$mask" -eq 0 ] && return 0
    sh=$(( 32 - 10#$mask ))
    [ $(( ii >> sh )) -eq $(( ni >> sh )) ]
}

# exempt_check <ip> — per-layer exemption status for one IP.
# Exit: 0 = member of the exempt set (CF / self / whitelist), 1 = not
# exempt, 2 = invalid input. Manual block flows MUST refuse on 0 (FR-1/2).
# flush_autobans — remove every auto-ban/subnet-ban rule and clear the
# daemon's ban/throttle/watch state. Backs the menu's "Flush all
# auto-bans" (BUG-008): the old menu implementation grepped
# `iptables -L` output for the comment text - comments never appear in
# -L listings, so it flushed nothing while reporting success. Rules
# are deleted by number from `iptables -S` (nx_delete_matching) and
# recorded tc throttle filters are removed by their prios.
flush_autobans() {
    nx_delete_matching INPUT '--comment "auto-ban"'
    nx_delete_matching INPUT '--comment "subnet-ban"'
    local _iface _f _ip _prio _rest
    _iface=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    for _f in /tmp/autoban_throttle /etc/antiddos/throttled.list; do
        [ -f "$_f" ] || continue
        while read -r _ip _prio _rest; do
            if [ -n "${_prio:-}" ] && [ -n "$_iface" ]; then
                tc filter del dev "$_iface" parent 1: prio "$_prio" 2>/dev/null || true
            fi
        done < "$_f"
        : > "$_f" 2>/dev/null || true
    done
    : > /etc/antiddos/banned.list 2>/dev/null || true
    : > /tmp/autoban_watch 2>/dev/null || true
    success "All auto-bans flushed (iptables rules + daemon state)"
}

# valid_ip6_or_cidr - IPv6 counterpart of valid_ip_or_cidr (E-5).
# The whitelist was v4-only end to end: every layer HONOURS v6
# entries (daemon is_exempt6, ip6tables, fail2ban ignoreip) but the
# admin could never add one, and --exempt-check rejected v6 targets
# as "invalid". Charset + group-count validation; embedded-IPv4
# forms are rejected (whitelist the v4 form instead).
valid_ip6_or_cidr() {
    local input="${1:-}" addr mask
    case "$input" in
        */*) addr="${input%%/*}"; mask="${input#*/}"
             case "$mask" in ''|*[!0-9]*) return 1 ;; esac
             [ "${#mask}" -le 3 ] || return 1
             (( 10#$mask <= 128 )) || return 1 ;;
        *)   addr="$input" ;;
    esac
    case "$addr" in
        *[!0-9a-fA-F:]*) return 1 ;;
        *:::*) return 1 ;;
    esac
    case "$addr" in
        *::*) case "${addr#*::}" in *::*) return 1 ;; esac ;;
    esac
    [ "$addr" = "::" ] && return 0
    local _groups=0 _g
    local _oldIFS="$IFS"; IFS=':'
    # shellcheck disable=SC2086
    set -- $addr
    IFS="$_oldIFS"
    for _g in "$@"; do
        [ -z "$_g" ] && continue
        [ "${#_g}" -le 4 ] || return 1
        _groups=$((_groups + 1))
    done
    case "$addr" in
        *::*) [ "$_groups" -le 7 ] || return 1 ;;
        *)    [ "$_groups" -eq 8 ] || return 1 ;;
    esac
    return 0
}

# nx_ip6_in_cidr - the antiddos-side twin of the daemon's ip6_in_cidr
# (same awk nibble-compare; a missing mask means /128).
nx_ip6_in_cidr() {
    awk -v ip="$1" -v cidr="$2" '
    function hv(c) { return index("0123456789abcdef", c) - 1 }
    function pad(h) { while (length(h) < 4) h = "0" h; return h }
    function expand(a,    k,lp,rp,ln,rn,out,i) {
        a = tolower(a)
        k = index(a, "::")
        if (k > 0) {
            lp = substr(a, 1, k - 1); rp = substr(a, k + 2)
            ln = (lp == "") ? 0 : split(lp, L, ":")
            rn = (rp == "") ? 0 : split(rp, G, ":")
            out = ""
            for (i = 1; i <= ln; i++) out = out pad(L[i])
            for (i = 1; i <= 8 - ln - rn; i++) out = out "0000"
            for (i = 1; i <= rn; i++) out = out pad(G[i])
            return out
        }
        split(a, P, ":"); out = ""
        for (i = 1; i <= 8; i++) out = out pad(P[i])
        return out
    }
    BEGIN {
        np = split(cidr, C, "/"); pfx = (np < 2 || C[2] == "") ? 128 : C[2] + 0
        e1 = expand(ip); e2 = expand(C[1])
        full = int(pfx / 4)
        if (substr(e1, 1, full) != substr(e2, 1, full)) exit 1
        rem = pfx % 4
        if (rem > 0) {
            keep = 2 ^ (4 - rem)
            if (int(hv(substr(e1, full + 1, 1)) / keep) != int(hv(substr(e2, full + 1, 1)) / keep)) exit 1
        }
        exit 0
    }'
}

exempt_check() {
    local ip="${1:-}" rc=1 _e
    [ -n "$ip" ] || { echo "usage: --exempt-check <ip>"; return 2; }
    case "$ip" in
        *:*)
            valid_ip6_or_cidr "$ip" || { echo "invalid IPv6/CIDR: $ip"; return 2; }
            ip="${ip%%/*}"
            echo "Exemption check for $ip (IPv6):"
            local cf=no self=no wl=no
            for _e in "${CF6_RANGES[@]}"; do nx_ip6_in_cidr "$ip" "$_e" && { cf=yes; break; }; done
            list_self_ips6 2>/dev/null | grep -qxF "$ip" && self=yes
            if [ -f "$WHITELIST_FILE" ]; then
                while IFS= read -r _e; do
                    _e="${_e%%#*}"; _e="${_e// /}"
                    case "$_e" in *:*) : ;; *) continue ;; esac
                    [ -n "$_e" ] && nx_ip6_in_cidr "$ip" "$_e" && { wl=yes; break; }
                done < "$WHITELIST_FILE"
            fi
            echo "  cloudflare ranges : $cf"
            echo "  server own IP     : $self"
            echo "  admin whitelist   : $wl"
            { [ "$cf" = yes ] || [ "$self" = yes ] || [ "$wl" = yes ]; } && rc=0
            [ "$rc" -eq 0 ] && echo "  VERDICT: EXEMPT" || echo "  VERDICT: not exempt"
            return $rc ;;
    esac
    valid_ip_or_cidr "$ip" || { echo "invalid IP/CIDR: $ip"; return 2; }
    ip="${ip%%/*}"
    echo "Exemption check for $ip:"
    local cf=no self=no wl=no
    for _e in "${CF_RANGES[@]}"; do nx_ip_in_cidr "$ip" "$_e" && { cf=yes; break; }; done
    list_self_ips_all 2>/dev/null | grep -qxF "$ip" && self=yes
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _e; do
            _e="${_e%%#*}"; _e="${_e// /}"
            [ -z "$_e" ] && continue
            case "$_e" in
                */*) nx_ip_in_cidr "$ip" "$_e" && { wl=yes; break; } ;;
                *)   [ "$_e" = "$ip" ] && { wl=yes; break; } ;;
            esac
        done < "$WHITELIST_FILE"
    fi
    echo "  cloudflare ranges : $cf"
    echo "  server own IP     : $self"
    echo "  admin whitelist   : $wl"
    { [ "$cf" = yes ] || [ "$self" = yes ] || [ "$wl" = yes ]; } && rc=0
    if [ -f "$F2B_JAIL_DIR/antiddos.conf" ]; then
        if grep -qw "$ip" "$F2B_JAIL_DIR/antiddos.conf" 2>/dev/null; then
            echo "  fail2ban ignoreip : listed"
        else
            echo "  fail2ban ignoreip : NOT listed by exact IP (CIDR entries may still cover it)"
        fi
    fi
    if iptables -S INPUT 2>/dev/null | grep -F -- "-s $ip" | grep -q -- '-j ACCEPT'; then
        echo "  iptables INPUT    : ACCEPT rule present for this exact IP"
    fi
    [ "$rc" -eq 0 ] && echo "  VERDICT: EXEMPT" || echo "  VERDICT: not exempt"
    return $rc
}

# ── Whitelist manager ──────────────────────────────────────
manage_whitelist() {
    local WL="$WHITELIST_FILE"
    mkdir -p /etc/antiddos
    [ -f "$WL" ] || touch "$WL"

    while true; do
        clear; sep
        echo -e "  ${CYAN}${BOLD}Whitelist Manager${NC}"
        echo -e "  ${DIM}IPs/CIDRs here are exempt from ALL anti-DDoS limits:${NC}"
        echo -e "  ${DIM}iptables rate-limit, connlimit, SYNPROXY, tc bandwidth, auto-ban.${NC}"
        sep
        if [ -s "$WL" ]; then
            echo -e "  ${CYAN}Current whitelist:${NC}"
            local N=0
            while IFS= read -r E; do
                [ -z "${E%%#*}" ] && continue
                E="${E// /}"
                [ -z "$E" ] && continue
                N=$((N + 1))
                printf "    ${GREEN}%s.${NC} %s\n" "$N" "$E"
            done < "$WL"
            echo ""
        else
            echo -e "  ${YELLOW}Whitelist is empty.${NC} (Server's own IPs + Cloudflare are always exempt automatically.)"
            echo ""
        fi
        echo -e "  ${CYAN}a.${NC} Add IP/CIDR"
        echo -e "  ${CYAN}d.${NC} Remove entry"
        echo -e "  ${CYAN}c.${NC} Check an IP (is it exempt from all layers?)"
        echo -e "  ${CYAN}0.${NC} Back"
        sep
        printf '%s' "  Enter choice: " >/dev/tty; read -r WCH </dev/tty || WCH=""
        case "$WCH" in
            a|A)
                printf '%s' "  IP or CIDR to whitelist (e.g. 1.2.3.4 or 5.6.7.0/24): " >/dev/tty
                read -r WIP </dev/tty || WIP=""
                WIP="${WIP// /}"
                if [ -z "$WIP" ]; then
                    echo -e "  ${YELLOW}No input.${NC}"
                elif ! valid_ip_or_cidr "$WIP" && ! valid_ip6_or_cidr "$WIP"; then
                    echo -e "  ${RED}Invalid IP/CIDR: $WIP${NC}"
                elif grep -qF "$WIP" "$WL" 2>/dev/null; then
                    echo -e "  ${YELLOW}Already in whitelist.${NC}"
                else
                    echo "$WIP" >> "$WL"
                    echo -e "  ${GREEN}✓ Added: $WIP${NC}"
                    # Apply to iptables + tc immediately (re-apply both)
                    apply_iptables >/dev/null 2>&1 || true
                    apply_tc_runtime "$MAIN_IF" >/dev/null 2>&1 || true
                    update_f2b_ignoreip || true
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            c|C)
                printf '%s' "  IP to check: " >/dev/tty
                read -r CIP </dev/tty || CIP=""
                CIP="${CIP// /}"
                if [ -n "$CIP" ]; then
                    exempt_check "$CIP"
                else
                    echo -e "  ${YELLOW}No input.${NC}"
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            d|D)
                printf '%s' "  Entry to remove (paste the exact IP/CIDR): " >/dev/tty
                read -r RIP </dev/tty || RIP=""
                RIP="${RIP// /}"
                if [ -n "$RIP" ] && grep -qF "$RIP" "$WL" 2>/dev/null; then
                    grep -vxF "$RIP" "$WL" > "$WL.tmp" && mv "$WL.tmp" "$WL"
                    # Clean the empty case
                    sed -i '/^[[:space:]]*$/d' "$WL" 2>/dev/null || true
                    echo -e "  ${GREEN}✓ Removed: $RIP${NC}"
                    apply_iptables >/dev/null 2>&1 || true
                    apply_tc_runtime "$MAIN_IF" >/dev/null 2>&1 || true
                    update_f2b_ignoreip || true
                else
                    echo -e "  ${YELLOW}Not found.${NC}"
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            0) return 0 ;;
            *) echo -e "  ${YELLOW}Invalid choice.${NC}"; sleep 1 ;;
        esac
    done
}

# Runtime tc re-apply for a single interface (used by whitelist manager)
apply_tc_runtime() {
    local IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
    [ -z "$IF" ] && IF="eth0"
    # Only re-run if tc is already configured
    tc qdisc show dev "$IF" 2>/dev/null | grep -q htb || return 0
    setup_tc "$IF" >/dev/null 2>&1 || true
    # BUG-036: verify the rebuild actually produced the throttle classes
    # instead of reporting success on faith.
    tc class show dev "$IF" 2>/dev/null | grep -q 'class htb 1:30' || \
        warn "tc re-apply: class 1:30 missing on $IF after rebuild - throttling unavailable"
}

# CLI args
case "${1:-}" in
    --install|-i)    detect_env; do_install; exit 0 ;;
    --remove|-r)     detect_env; remove_rules; exit 0 ;;
    --remove-force)  detect_env; CONF_R="y"; remove_rules; exit 0 ;;
    --status|-s)     detect_env; show_status; exit 0 ;;
    --exempt-check)  exempt_check "${2:-}"; exit $? ;;
    --flush-autobans) flush_autobans; exit $? ;;
    --thresholds|-t) detect_env; show_thresholds; exit 0 ;;
    --sysctl)        detect_env; apply_sysctl_hardening; exit 0 ;;
    --iptables)      detect_env; apply_iptables; exit 0 ;;
    --fail2ban)      detect_env; apply_fail2ban; exit 0 ;;
    --autoban)       detect_env; setup_autoban; exit 0 ;;
    --whitelist|-w)  detect_env; manage_whitelist; exit 0 ;;
    --tc)            detect_env; setup_tc; exit 0 ;;
    --auto|-y)
        detect_env
        sep
        echo -e "  ${CYAN}${BOLD}Anti-DDoS Full Install v${SCRIPT_VERSION}${NC}"; sep
        echo -e "  ${DIM}RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | Virt: ${VIRT_TYPE} | IF: ${MAIN_IF}${NC}"
        echo ""
        apply_sysctl_hardening; apply_iptables; apply_fail2ban
        setup_autoban; setup_tc; setup_persistence
        cat > "$STATE_FILE" << EOF
DATE=$(date)
VERSION=${SCRIPT_VERSION}
VIRT_TYPE=${VIRT_TYPE}
RAM_MB=${RAM_MB}
SYNPROXY=${SYNPROXY_OK}
HASHLIMIT=${HASHLIMIT_OK}
MAIN_IF=${MAIN_IF}
EOF
        sep
        success "Anti-DDoS installation complete!"
        exit 0 ;;
esac

# Interactive menu
detect_env

while true; do
    clear; sep
    echo -e "  ${CYAN}${BOLD}Anti-DDoS Manager v${SCRIPT_VERSION}${NC}"; sep
    [ -f "$STATE_FILE" ] && \
        echo -e "  Status: ${GREEN}✓ Installed${NC}" || \
        echo -e "  Status: ${YELLOW}○ Not installed${NC}"
    _AB_ST=$(systemctl is-active auto-ban 2>/dev/null || echo "inactive")
    [ "$_AB_ST" = "active" ] && \
        echo -e "  auto-ban: \033[0;32mRunning\033[0m" || \
        echo -e "  auto-ban: \033[0;31mStopped\033[0m"
    echo ""
    echo -e "  ${CYAN}1.${NC}  Full install (all layers)"
    echo -e "  ${CYAN}2.${NC}  Status & active bans"
    echo -e "  ${CYAN}3.${NC}  View thresholds"
    echo -e "  ${CYAN}4.${NC}  Kernel sysctl only"
    echo -e "  ${CYAN}5.${NC}  iptables only"
    echo -e "  ${CYAN}6.${NC}  fail2ban only"
    echo -e "  ${CYAN}7.${NC}  Smart ban only"
    echo -e "  ${CYAN}8.${NC}  tc bandwidth only"
    echo -e "  ${CYAN}9.${NC}  Unban IP (all layers)"
    echo -e "  ${CYAN}w.${NC}  Manage whitelist (IPs exempt from ALL limits)"
    echo -e "  ${CYAN}r.${NC}  Remove all rules"
    echo -e "  ${CYAN}0.${NC}  Back"
    sep
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) do_install; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) show_status; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        3) show_thresholds; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        4) apply_sysctl_hardening; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        5) apply_iptables; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        6) apply_fail2ban; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        7) setup_autoban; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        8) setup_tc; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        9) echo -e "  ${CYAN}Unban IP${NC}"; echo ""
           printf '%s' "  Enter IP to unban (iptables + fail2ban): " >/dev/tty; read -r UIP </dev/tty || UIP=""
           if [ -n "$UIP" ] && ! valid_ip_or_cidr "$UIP"; then
               echo -e "  ${RED}✗ Invalid IP/CIDR: $UIP${NC}"
               UIP=""
           fi
           [ -n "$UIP" ] && {
               # Exact deletes (BUG-038): the daemon's rules carry the
               # auto-ban/subnet-ban comments, so the old bare-spec
               # delete never matched them; and the state edit was a
               # substring sed - unbanning 1.2.3.4 also dropped
               # 11.2.3.4's entry. Match field 1 exactly instead.
               iptables -D INPUT -s "$UIP" -m comment --comment "auto-ban" -j DROP 2>/dev/null || \
               iptables -D INPUT -s "$UIP" -m comment --comment "subnet-ban" -j DROP 2>/dev/null || \
               iptables -D INPUT -s "$UIP" -j DROP 2>/dev/null || true
               echo -e "  ${GREEN}✓ iptables unblocked${NC}"
               if [ -f "$BANNED_LIST" ]; then
                   awk -v x="$UIP" '$1!=x' "$BANNED_LIST" > "$BANNED_LIST.tmp" 2>/dev/null && \
                       mv "$BANNED_LIST.tmp" "$BANNED_LIST"
               fi
               fail2ban-client status 2>/dev/null | grep "Jail list" | \
                   sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r jail; do
                   [ -z "$jail" ] && continue
                   fail2ban-client set "$jail" unbanip "$UIP" 2>/dev/null && \
                       echo -e "  ${GREEN}✓ fail2ban $jail unblocked${NC}" || true
               done
               echo -e "  ${GREEN}✓ $UIP fully unblocked${NC}"
           }
           printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        w|W) manage_whitelist ;;
        r) remove_rules; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
