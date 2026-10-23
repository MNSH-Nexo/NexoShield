# list_self_ips - the ONLY copy in the repository (included at build time).
# Echoes EVERY local IPv4 address of this server (all interfaces, incl.
# loopback and private addresses), one per line, deduplicated.
# Used for self-IP immunity (FR-2): an address the server owns must never
# be rate-limited, throttled or banned by any layer. Unlike get_server_ips
# (public addresses only, for display/whitelist display purposes), this
# list is deliberately exhaustive.
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
