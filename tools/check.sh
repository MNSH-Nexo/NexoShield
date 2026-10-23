#!/usr/bin/env bash
# Full local quality gate: syntax, lint (warning level), and build integrity.
# Run before every commit:   ./tools/check.sh    (or: make check)
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0

echo "== bash -n (syntax) =="
for f in src/modules/*.sh src/installer/*.sh tools/check.sh build.sh; do
    [ -f "$f" ] || continue
    if bash -n "$f"; then echo "  ok   $f"; else echo "  FAIL $f"; fail=1; fi
done

echo "== shellcheck (modules, warning level) =="
if command -v shellcheck >/dev/null 2>&1; then
    # Installer fragments are two halves of one script: they are linted as
    # part of the built file, not standalone. Modules must be warning-clean.
    if shellcheck -S warning src/modules/*.sh; then
        echo "  ok   modules are warning-clean"
    else
        echo "  FAIL shellcheck reported warnings"; fail=1
    fi
else
    echo "  skip shellcheck not installed (apt install shellcheck)"
fi

echo "== build verification =="
if python3 tools/verify.py; then
    echo "  ok   verify"
else
    fail=1
fi

[ "$fail" -eq 0 ] && echo "ALL CHECKS PASSED" || { echo "CHECKS FAILED"; exit 1; }
