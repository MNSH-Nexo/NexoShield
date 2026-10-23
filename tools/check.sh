#!/usr/bin/env bash
# Full local quality gate: syntax, lint (warning level), and build integrity.
# Run before every commit:   ./tools/check.sh    (or: make check)
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

echo "== bash -n (syntax: parts, lib, installer fragments) =="
for f in src/modules/*/*.sh src/lib/*.sh src/installer/*.sh tools/check.sh build.sh; do
    if bash -n "$f" 2>"$TMPD/err"; then
        echo "  ok   $f"
    else
        echo "  FAIL $f"; cat "$TMPD/err"; fail=1
    fi
done

echo "== assemble modules =="
python3 tools/build.py --emit-modules "$TMPD/modules" || fail=1
for f in "$TMPD"/modules/*.sh; do
    if bash -n "$f"; then echo "  ok   assembled $(basename "$f")"; else echo "  FAIL assembled $f"; fail=1; fi
done

echo "== shellcheck (assembled modules, warning level) =="
if command -v shellcheck >/dev/null 2>&1; then
    # Parts are fragments; lint runs on the assembled runtime modules,
    # which is also what ships. Modules must be warning-clean.
    if shellcheck -S warning "$TMPD"/modules/*.sh; then
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
