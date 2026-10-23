#!/usr/bin/env bash
# E-6: NAT/cloud public-IP discovery. On cloud VMs the public IPv4
# lives only in the provider NAT (no interface carries it), so the
# self set must be completed from the metadata service (external
# echo as last resort) - with hard validation, because a metadata
# or echo answer is untrusted input and must never widen immunity
# to private/documentation/garbage addresses.
set -uo pipefail
cd "$(dirname "$0")/../.."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# source the real lib (it is a plain function library)
. src/lib/self-ips.sh
export NX_PUBLIC_IPS_FILE="$TMP/public-ips.list"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }

# ── validator truth table ──
for good in 65.52.200.121 8.8.8.8 1.1.1.1 203.0.178.9 192.0.178.1 45.33.32.1; do
    nx_is_public_ipv4 "$good" && ok || bad "validator rejected legit public $good"
done
for badip in 10.0.0.5 172.16.0.4 172.31.255.1 192.168.1.1 100.64.0.1 127.0.0.1 \
             169.254.1.1 203.0.113.9 198.51.100.2 192.0.2.1 192.0.0.7 198.18.0.1 \
             224.0.0.1 0.1.2.3 1.2.3 1.2.3.4.5 256.1.1.1 "" "hello" "1.2.3.x"; do
    nx_is_public_ipv4 "$badip" && bad "validator accepted '$badip'" || ok
done

# ── metadata-first discovery (Azure answers) ──
curl() {
    case "$*" in
        *publicIpAddress*) echo "65.52.200.121" ;;
        *) return 1 ;;
    esac
}
list_self_ips() { printf '%s\n' "127.0.0.1" "172.16.0.4"; }
OUT=$(discover_public_ips)
[ "$OUT" = "65.52.200.121" ] && ok || bad "azure metadata discovery: got '$OUT'"

# metadata answer that is private must be rejected; echo takes over
curl() {
    case "$*" in
        *publicIpAddress*) echo "10.99.0.50" ;;          # bogus/private - reject
        *api.ipify.org*) echo "203.0.178.9" ;;
        *) return 1 ;;
    esac
}
OUT=$(discover_public_ips)
[ "$OUT" = "203.0.178.9" ] && ok || bad "private metadata answer not rejected / echo fallback: '$OUT'"

# everything dead -> empty (never garbage)
curl() { return 1; }
OUT=$(discover_public_ips)
[ -z "$OUT" ] && ok || bad "dead discovery returned '$OUT'"

# discovered address already on an interface is not duplicated
curl() {
    case "$*" in
        *publicIpAddress*) echo "172.16.0.4" ;;
        *) return 1 ;;
    esac
}
nx_is_public_ipv4 "172.16.0.4" && bad "172.16.0.4 passed the public validator" || ok

# ── cache semantics: refresh writes; failure keeps the old cache ──
curl() {
    case "$*" in
        *publicIpAddress*) echo "65.52.200.121" ;;
        *) return 1 ;;
    esac
}
nx_refresh_public_ips_cache >/dev/null
grep -qx "65.52.200.121" "$NX_PUBLIC_IPS_FILE" && ok || bad "cache not written"
curl() { return 1; }
nx_refresh_public_ips_cache >/dev/null
grep -qx "65.52.200.121" "$NX_PUBLIC_IPS_FILE" && ok || bad "cache wiped by a failed discovery"

# ── merged feed: interfaces + cache ──
OUT=$(list_self_ips_all | sort | tr '\n' ' ')
case "$OUT" in *"172.16.0.4"*"65.52.200.121"*) ok ;; *) bad "merged self feed wrong: $OUT" ;; esac

echo "public-ip discovery (E-6): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
