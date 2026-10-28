# list_self_ips - the ONLY copy in the repository (included at build time).
# Echoes EVERY local IPv4 address of this server (all interfaces, incl.
# loopback and private addresses), one per line, deduplicated.
# Used for self-IP immunity (FR-2): an address the server owns must never
# be rate-limited, throttled or banned by any layer. Unlike a
# public-address display lookup, this list is deliberately exhaustive.
# @lib-body
list_self_ips() {
    { ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+'
      hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    } | sort -u | grep -v '^$'
}

# list_self_ips6 - every local IPv6 address (incl. ::1), one per line.
list_self_ips6() {
    { ip -6 addr show 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+'
      echo "::1"
    } | sort -u | grep -v '^$'
}

# ── Public-IP discovery for NAT / cloud servers ─────────────────
# On cloud VMs (Azure, most NAT setups) the server's public IPv4
# exists only in the provider's NAT - it is on NO interface, so
# list_self_ips can never see it, yet it is unmistakably one of the
# server's own addresses (FR-2). Discovery asks the cloud metadata
# service (link-local, no internet involved); only when no metadata
# service answers does it fall back to an external echo service.
# Every candidate passes nx_is_public_ipv4: metadata/echo replies
# are untrusted input, and a private/documentation/garbage answer
# must never widen the immune set.
NX_PUBLIC_IPS_FILE="${NX_PUBLIC_IPS_FILE:-/etc/antiddos/public-ips.list}"

nx_is_public_ipv4() {
    local ip="${1:-}" o1 o2 o3 o4 extra _o
    case "$ip" in *[!0-9.]*) return 1 ;; esac
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for _o in "$o1" "$o2" "$o3" "$o4"; do
        case "$_o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_o}" -le 3 ] || return 1
        (( 10#$_o <= 255 )) || return 1
    done
    case "$o1" in
        0|10|127) return 1 ;;
        100) [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 1 ;;
        169) [ "$o2" = 254 ] && return 1 ;;
        172) [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 1 ;;
        192) [ "$o2" = 168 ] && return 1
             { [ "$o2" = 0 ] && { [ "$o3" = 0 ] || [ "$o3" = 2 ]; }; } && return 1 ;;
        198) case "$o2" in 18|19|51) return 1 ;; esac ;;
        203) { [ "$o2" = 0 ] && [ "$o3" = 113 ]; } && return 1 ;;
    esac
    [ "$o1" -ge 224 ] && return 1
    return 0
}

nx_metadata_public_ips() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _tok _base="http://169.254.169.254"
    # Azure IMDS (first two addresses on the primary NIC)
    for _idx in 0 1; do
        _ip=$(curl -s -m 2 -H "Metadata: true" \
            "$_base/metadata/instance/network/interface/0/ipv4/ipAddress/$_idx/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
        nx_is_public_ipv4 "$_ip" && echo "$_ip"
    done
    # AWS EC2 IMDS (token first, plain fallback)
    _tok=$(curl -s -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "$_base/latest/api/token" 2>/dev/null)
    if [ -n "$_tok" ]; then
        _ip=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $_tok" \
            "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    else
        _ip=$(curl -s -m 2 "$_base/latest/meta-data/public-ipv4" 2>/dev/null)
    fi
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # GCP
    _ip=$(curl -s -m 2 -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # DigitalOcean
    _ip=$(curl -s -m 2 "$_base/metadata/v1/interfaces/public/0/ipv4/address" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    # Hetzner Cloud
    _ip=$(curl -s -m 2 "$_base/hetzner/v1/metadata/public-ipv4" 2>/dev/null)
    nx_is_public_ipv4 "$_ip" && echo "$_ip"
    return 0
}

nx_external_public_ip() {
    command -v curl >/dev/null 2>&1 || return 0
    local _ip _url
    for _url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me/ip"; do
        _ip=$(curl -s -m 3 "$_url" 2>/dev/null | tr -d ' \r\n')
        nx_is_public_ipv4 "$_ip" && { echo "$_ip"; return 0; }
    done
    return 0
}

# Echo the server's public IPv4s that are NOT on any interface
# (metadata first; external echo only as a last resort).
discover_public_ips() {
    local _found _ip
    _found=$(nx_metadata_public_ips | sort -u)
    [ -z "$_found" ] && _found=$(nx_external_public_ip)
    for _ip in $_found; do
        list_self_ips | grep -qxF "$_ip" || echo "$_ip"
    done
}

# Refresh the cache file; a failed/empty discovery NEVER wipes a
# previously discovered set (an offline reinstall must not disarm
# the immunity). Prints the discovered addresses when any exist.
nx_refresh_public_ips_cache() {
    local _found
    _found=$(discover_public_ips)
    if [ -n "$_found" ]; then
        mkdir -p "$(dirname "$NX_PUBLIC_IPS_FILE")" 2>/dev/null || true
        printf '%s\n' "$_found" > "$NX_PUBLIC_IPS_FILE.tmp" 2>/dev/null && \
            mv "$NX_PUBLIC_IPS_FILE.tmp" "$NX_PUBLIC_IPS_FILE" 2>/dev/null || true
        printf '%s\n' "$_found"
    elif [ -f "$NX_PUBLIC_IPS_FILE" ]; then
        cat "$NX_PUBLIC_IPS_FILE"
    fi
}

# list_self_ips_all - interface addresses PLUS the cached
# discovered public IPs. This is the feed every enforcement layer
# uses for "the server's own addresses" (FR-2 complete: local,
# private, secondary AND NAT-public).
list_self_ips_all() {
    { list_self_ips
      if [ -r "$NX_PUBLIC_IPS_FILE" ]; then
          grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$NX_PUBLIC_IPS_FILE" 2>/dev/null
      fi
    } | sort -u | grep -v '^$'
}
