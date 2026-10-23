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
    local ip="$1"
    for CF in "${CF_RANGES[@]}"; do
        ip_in_cidr "$ip" "$CF" 2>/dev/null && return 0
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
