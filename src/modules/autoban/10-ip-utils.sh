# @part modules/autoban/10-ip-utils.sh - log, ip helpers, Cloudflare/self/whitelist exemption checks
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
# BUG-019: every iptables call in this script takes the xtables lock with
# a 5s wait. The daemon, fail2ban and the menus mutate rules concurrently;
# without -w a contended call fails with "Resource temporarily
# unavailable" and the failure is usually swallowed by || true - rules
# silently never landed. (iptables-save/-restore are separate binaries
# and are not affected by this wrapper.)
iptables() { command iptables -w 5 "$@"; }

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# ── Exact state-file matching (BUG-003) ─────────────
# State files are "IP field field..." per line. The ONLY correct match
# is field 1 == IP, exactly. The old grep -qF "$ip" / sed "/$ip/d"
# substring+regex patterns made 1.2.3.4 match 11.2.3.4 and 1.2.3.45,
# corrupting other IPs' watch/ban/throttle state.
state_has_ip() {  # <file> <ip>
    [ -f "$1" ] || return 1
    awk -v x="$2" '$1==x{f=1} END{exit !f}' "$1" 2>/dev/null
}
state_get_field() {  # <file> <ip> <field#> -> prints the field (or empty)
    [ -f "$1" ] || return 0
    awk -v x="$2" -v n="$3" '$1==x{print $n; exit}' "$1" 2>/dev/null
}
state_del_ip() {  # <file> <ip>  (atomic rewrite)
    [ -f "$1" ] || return 0
    awk -v x="$2" '$1!=x' "$1" > "$1.tmp.$$" 2>/dev/null && mv "$1.tmp.$$" "$1"
}

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
    # Fast path (BUG-020): precomputed network integers, zero forks.
    local _i
    ip_int "$1"
    for _i in "${!CF_NET_INT[@]}"; do
        [ $(( IP_INT >> CF_SHIFT[_i] )) -eq $(( CF_NET_INT[_i] >> CF_SHIFT[_i] )) ] && return 0
    done
    return 1
}

# ── IPv6 (Wave 9) ───────────────────────────────────
ip6tables() { command ip6tables -w 5 "$@"; }

# ip6_in_cidr <ip> <cidr> — pure-awk membership test (no strtonum, so
# it works under mawk too). Handles "::" compression, mixed case and
# fully-expanded forms on either side.
ip6_in_cidr() {
    awk -v ip="$1" -v cidr="$2" '
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
    function hv(c) { return index("0123456789abcdef", c) - 1 }
    BEGIN {
        split(cidr, C, "/"); pfx = C[2] + 0
        e1 = expand(ip); e2 = expand(C[1])
        full = int(pfx / 4)
        if (substr(e1, 1, full) != substr(e2, 1, full)) exit 1
        rem = pfx % 4
        if (rem > 0) {
            # keep the top `rem` bits of the nibble (arithmetic, since
            # mawk has no bitwise and() builtin)
            keep = 2 ^ (4 - rem)
            if (int(hv(substr(e1, full + 1, 1)) / keep) != int(hv(substr(e2, full + 1, 1)) / keep)) exit 1
        }
        exit 0
    }' 2>/dev/null
}

is_cf6_ip() {
    local _r6
    for _r6 in "${CF6_RANGES[@]}"; do
        ip6_in_cidr "$1" "$_r6" && return 0
    done
    return 1
}

is_exempt6() {
    local ip="$1" _s6 _w6
    is_cf6_ip "$ip" && return 0
    for _s6 in "${SELF6_IPS[@]}"; do
        ip6_in_cidr "$ip" "$_s6/128" && return 0
    done
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _w6; do
            _w6="${_w6%%#*}"; _w6="${_w6// /}"
            case "$_w6" in *:*) : ;; *) continue ;; esac
            [ -n "$_w6" ] && ip6_in_cidr "$ip" "$_w6" && return 0
        done < "$WHITELIST_FILE"
    fi
    return 1
}

# Family-dispatching wrappers: the pipeline below speaks v4 names;
# these route IPv6 peers to the v6 enforcers.
is_exempt_any() { case "$1" in *:*) is_exempt6 "$1" ;; *) is_exempt "$1" ;; esac; }
nx_ban() { case "$1" in *:*) ban_ip6 "$1" ;; *) ban_ip "$1" ;; esac; }
nx_throttle() { case "$1" in *:*) throttle_ip6 "$1" ;; *) throttle_ip "$1" ;; esac; }
nx_hard_throttle() { case "$1" in *:*) hard_throttle_ip6 "$1" ;; *) hard_throttle_ip "$1" ;; esac; }

# subnet_overlaps_cf <a.b.c> — TRUE range-overlap test between a /24 and
# every CF range (BUG-011: the old check tested only the .1 address, so
# a CF range starting mid-/24 was missed).
subnet_overlaps_cf() {
    local subnet="$1" CF
    for CF in "${CF_RANGES[@]}"; do
        ip_in_cidr "${subnet}.0" "$CF" 2>/dev/null && return 0
        ip_in_cidr "${CF%%/*}" "${subnet}.0/24" 2>/dev/null && return 0
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
    # Freshness fallback: the installer's self-IP snapshot (FR-2)
    [ -f /etc/antiddos/self-ips.list ] && \
        grep -qxF "$ip" /etc/antiddos/self-ips.list 2>/dev/null && return 0
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
            */*)
                # BUG-029 (daemon half): a malformed mask must NEVER widen
                # the match (arithmetic on garbage treated it as a number).
                # Invalid entries are skipped, never "close enough".
                _m="${entry#*/}"
                case "$_m" in ''|*[!0-9]*) continue ;; esac
                [ "${#_m}" -le 2 ] || continue
                (( 10#$_m <= 32 )) || continue
                ip_in_cidr "$ip" "$entry" 2>/dev/null && return 0 ;;
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
