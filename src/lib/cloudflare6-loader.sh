# Cloudflare IPv6 ranges loader - the ONLY copy in the repository.
# Included at build time wherever CF6_RANGES must be populated from
# /etc/antiddos/cloudflare-ipv6.list (the installer writes that file
# from src/data/cloudflare-ipv6.list). Added in Wave 9 (IPv6 parity).
# @lib-body
# ── Cloudflare IPv6 ranges (loaded from shared data file) ──
CF6_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv6.list ]; then
    while IFS= read -r _cfl6; do
        _cfl6="${_cfl6//[[:space:]]/}"
        [ -n "$_cfl6" ] && CF6_RANGES+=("$_cfl6")
    done < /etc/antiddos/cloudflare-ipv6.list
fi
