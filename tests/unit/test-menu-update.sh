#!/bin/bash
# Self-update suite: nx_update_nexoshield against file:// fixtures.
# Cases: newer version installs (verified installer runs), same
# version is a no-op, unreachable server changes nothing, a
# declined confirm changes nothing, and an installer whose
# embedded version disagrees with the advertised one is refused.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
python3 "$ROOT/tools/build.py" --emit-modules "$W/mod" >/dev/null 2>&1 || { echo "  FAIL: emit"; exit 1; }
extract_fn() {
    awk -v n="$1" 'BEGIN{p=0} $0 ~ "^" n "\\(\\) \\{" {p=1} p{print} p && /^\}/{exit}' "$2"
}
{ extract_fn ui_input "$W/mod/proxy-menu.sh"
  extract_fn ui_confirm "$W/mod/proxy-menu.sh"
  extract_fn nx_update_nexoshield "$W/mod/proxy-menu.sh"
} > "$W/fn.sh"
grep -q 'nx_update_nexoshield' "$W/fn.sh" || { echo "  FAIL: function not found"; exit 1; }

C=""; Y=""; G=""; DIM=""; NC=""
VERSION="3.11.0"
SCRIPT_DIR="$W"
ok()   { echo "  OK: $*"; }
warn() { echo "  WARN: $*"; }
# pass/fail counters belong to the suite; the product's ok/warn
# helpers print only. Rebind the suite counters under other names.
pok()  { pass=$((pass+1)); }
pbad() { fail=$((fail+1)); echo "  FAIL: $*"; }
# shellcheck disable=SC1091
. "$W/fn.sh"

mk_fixture() {  # $1=dir $2=advertised VERSION $3=embedded VERSION
    mkdir -p "$1"
    printf '%s\n' "$2" > "$1/VERSION"
    cat > "$1/install.sh" <<EOF
#!/bin/bash
# NexoShield fake installer (test fixture)
VERSION="$3"
echo ran >> "$1/ran.marker"
EOF
    chmod +x "$1/install.sh"
}

# (a) newer version + confirm y -> installer runs
F="$W/a"; mk_fixture "$F" 9.9.9 9.9.9
OUT=$(NX_UI_STDIN=1 NX_UPDATE_BASE="file://$F" nx_update_nexoshield <<< "y" 2>&1); RC=$?
[ "$RC" -eq 0 ] && [ -f "$F/ran.marker" ] && pok || pbad "newer-version install (rc=$RC)"
echo "$OUT" | grep -q 'Updated to NexoShield v9.9.9' && pok || pbad "success message missing"

# (b) same version -> no-op
F="$W/b"; mk_fixture "$F" 3.11.0 3.11.0
OUT=$(NX_UI_STDIN=1 NX_UPDATE_BASE="file://$F" nx_update_nexoshield <<< "y" 2>&1); RC=$?
[ "$RC" -eq 0 ] && [ ! -f "$F/ran.marker" ] && pok || pbad "same-version no-op (rc=$RC)"
echo "$OUT" | grep -q 'up to date' && pok || pbad "up-to-date message missing"

# (c) unreachable server -> rc 1, nothing runs
OUT=$(NX_UI_STDIN=1 NX_UPDATE_BASE="file://$W/does-not-exist" nx_update_nexoshield <<< "y" 2>&1); RC=$?
[ "$RC" -eq 1 ] && pok || pbad "unreachable rc=$RC (want 1)"
echo "$OUT" | grep -q 'nothing was changed' && pok || pbad "unreachable message missing"

# (d) newer version + confirm n -> cancelled, nothing runs
F="$W/d"; mk_fixture "$F" 9.9.9 9.9.9
OUT=$(NX_UI_STDIN=1 NX_UPDATE_BASE="file://$F" nx_update_nexoshield <<< "n" 2>&1); RC=$?
[ "$RC" -eq 0 ] && [ ! -f "$F/ran.marker" ] && pok || pbad "declined confirm (rc=$RC)"

# (e) embedded version disagrees -> verification refuses to run it
F="$W/e"; mk_fixture "$F" 9.9.9 9.9.8
OUT=$(NX_UI_STDIN=1 NX_UPDATE_BASE="file://$F" nx_update_nexoshield <<< "y" 2>&1); RC=$?
[ "$RC" -eq 1 ] && [ ! -f "$F/ran.marker" ] && pok || pbad "version mismatch refused (rc=$RC)"
echo "$OUT" | grep -q 'failed verification' && pok || pbad "verification message missing"

# (f) older remote -> not newer, no-op
F="$W/f"; mk_fixture "$F" 3.10.0 3.10.0
OUT=$(NX_UI_STDIN=1 NX_UPDATE_BASE="file://$F" nx_update_nexoshield <<< "y" 2>&1); RC=$?
[ "$RC" -eq 0 ] && [ ! -f "$F/ran.marker" ] && pok || pbad "older remote no-op (rc=$RC)"

echo "menu update: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
