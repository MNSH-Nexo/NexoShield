#!/usr/bin/env bash
# Test runner: every tests/unit/test-*.sh must pass.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
for t in tests/unit/test-*.sh; do
    [ -f "$t" ] || continue
    echo "== $t"
    bash "$t" || fail=1
done
[ "$fail" -eq 0 ] && echo "ALL TESTS PASSED" || { echo "TESTS FAILED"; exit 1; }
