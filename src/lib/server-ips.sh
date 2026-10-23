# get_server_ips - the ONLY copy in the repository (included at build time).
# @lib-body
get_server_ips() {
    # All public IPs of this server (for auto-whitelist)
    ip -4 addr show 2>/dev/null | grep 'inet ' | \
        grep -v '127\.\|10\.\|192\.168\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.' | \
        awk '{print $2}' | cut -d/ -f1
}
