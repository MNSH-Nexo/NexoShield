# Cloudflare IPv4 ranges loader - the ONLY copy in the repository.
# Included at build time wherever CF_RANGES must be populated from
# /etc/antiddos/cloudflare-ipv4.list (the installer writes that file
# from src/data/cloudflare-ipv4.list).
# @lib-body
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi
