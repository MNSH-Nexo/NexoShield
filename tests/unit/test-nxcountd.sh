#!/usr/bin/env bash
# Phase 2a: nxcountd compiles clean and its parser/aggregator —
# exercised through --selftest with synthetic conntrack messages —
# produces exact aggregates: handshake completion, destroy-time
# age/bytes accounting, the local-source (outbound) filter, v6.
set -uo pipefail
cd "$(dirname "$0")/../.."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }

if ! command -v cc >/dev/null 2>&1; then
    echo "nxcountd (Phase 2a): SKIPPED (no C compiler)"; exit 0
fi
if ! cc -O2 -Wall -Wextra -o "$TMP/nxcountd" src/native/nxcountd.c 2>"$TMP/cc.log"; then
    cat "$TMP/cc.log"
    bad "nxcountd must compile warning-free"
    echo "nxcountd (Phase 2a): $pass passed, $fail failed"; exit 1
fi
ok
[ -s "$TMP/cc.log" ] && { cat "$TMP/cc.log"; bad "compiler warnings present"; } || ok

OUT="$("$TMP/nxcountd" --selftest)"
echo "$OUT" | grep -q '^# nxcountd 1 ts=1700000000 base=42 dropped=0 flows_dropped=0 totalsyn=3 totalest=1$' \
    && ok || { bad "header/totals wrong"; echo "$OUT"; }
# 203.0.113.7: 2 SYNs, 1 completion, 1 closed (4000 bytes, 5 s age), 1 still established
echo "$OUT" | grep -qx '203.0.113.7 2 1 2 1 0 1 1 4000 5000' \
    && ok || { bad "v4 aggregate wrong"; echo "$OUT"; }
# 2001:db8::1: 1 SYN, never completed, destroyed with 500 bytes after 5 s
echo "$OUT" | grep -qx '2001:db8::1 1 0 1 0 0 0 1 500 5000' \
    && ok || { bad "v6 aggregate wrong"; echo "$OUT"; }
# the local-source flow must not exist at all
echo "$OUT" | grep -q '10.0.0.5' && bad "local/outbound flow leaked into aggregates" || ok

echo "nxcountd (Phase 2a): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
