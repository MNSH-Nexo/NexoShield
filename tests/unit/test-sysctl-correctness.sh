#!/usr/bin/env bash
# Sysctl correctness tests (Wave 7): BUG-007 value parsing, BUG-009
# snapshot set covers write set, BUG-010 tcp_mem page math.
set -uo pipefail
cd "$(dirname "$0")/../.."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

extract_fn() {
    local start end
    start=$(grep -n "^$2() {" "$1" | head -1 | cut -d: -f1)
    [ -n "$start" ] || return 1
    end=$(tail -n +"$start" "$1" | grep -n '^}' | head -1 | cut -d: -f1)
    sed -n "${start},$((start + end - 1))p" "$1" >> "$3"
}
: > "$TMP/fns.sh"
extract_fn src/modules/sysctl/30-apply-rollback.sh nx_sysctl_parse "$TMP/fns.sh" || { echo "FAIL extract parser"; exit 1; }
extract_fn src/modules/sysctl/10-detect.sh calculate_values "$TMP/fns.sh" || { echo "FAIL extract calc"; exit 1; }
# shellcheck disable=SC1091
. "$TMP/fns.sh"

# ── BUG-007: multi-token values survive parsing ──
nx_sysctl_parse "net.ipv4.tcp_rmem = 32768 262144 67108864"
[ "$NX_KEY" = "net.ipv4.tcp_rmem" ] && [ "$NX_VAL" = "32768 262144 67108864" ] && ok || bad "tcp_rmem parse: [$NX_KEY]=[$NX_VAL]"
nx_sysctl_parse "$(printf 'net.ipv4.tcp_mem = 65536\t786432\t6291456')"
[ "$NX_VAL" = "65536 786432 6291456" ] && ok || bad "tab-separated parse: [$NX_VAL]"
nx_sysctl_parse "vm.swappiness = 10"
[ "$NX_KEY" = "vm.swappiness" ] && [ "$NX_VAL" = "10" ] && ok || bad "single value parse"

# ── BUG-010: tcp_mem derived in pages from RAM ──
sysctl() { echo 0; }
RAM_MB=16384; BBR_AVAILABLE=0; PUBLIC_IP_COUNT=1; HAS_SWAP=0
VIRT_TYPE=kvm; CONNTRACK_AVAILABLE=1
calculate_values
# 16 GiB RAM = 4,194,304 pages: pressure 50% = 2,097,152; max 75% = 3,145,728
[ "$TCP_MEM_PRESSURE" = "2097152" ] && ok || bad "pressure pages: $TCP_MEM_PRESSURE"
[ "$TCP_MEM_MAX" = "3145728" ] && ok || bad "max pages: $TCP_MEM_MAX"
RAM_MB=512; calculate_values
[ "$TCP_MEM_MAX" -ge 262144 ] && [ "$TCP_MEM_PRESSURE" -ge 131072 ] && ok || bad "floors on small RAM"

# ── BUG-009: every key write_config writes is in the snapshot set ──
python3 - << 'PYEOF' && ok || bad "snapshot set does not cover write set"
import re, sys
src = open('src/modules/sysctl/20-snapshot-config.sh').read()
snap_block = src.split('for KEY in', 1)[1].split('; do', 1)[0]
snap = set(re.findall(r'[a-z][a-z0-9_.]+', snap_block))
write_fn = src.split('write_config() {', 1)[1]
written = set(re.findall(r'^((?:net|vm|fs)\.[a-z0-9_.]+) =', write_fn, re.M))
missing = written - snap
if missing:
    print("  missing from snapshot:", sorted(missing))
    sys.exit(1)
PYEOF

echo "sysctl correctness: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
