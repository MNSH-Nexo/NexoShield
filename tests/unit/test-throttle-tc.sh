#!/usr/bin/env bash
# Stub-bin integration tests for the auto-ban throttle path (Wave 2):
#   - filters classify by ip DST on the egress qdisc (BUG-001)
#   - prios come from a persistent monotonic counter, never reused (BUG-021)
#   - state is written ONLY after tc succeeds (BUG-024)
#   - a missing tc class is a loud skip, not a fake throttle (BUG-024)
# A fake `tc` on PATH records every invocation; the shipped functions are
# extracted verbatim from src/modules/autoban/20-enforce.sh.
set -uo pipefail
cd "$(dirname "$0")/../.."

SRC="src/modules/autoban/20-enforce.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

# ── fake tc ──
cat > "$TMP/bin/tc" << 'STUB'
#!/usr/bin/env bash
echo "tc $*" >> "$TC_LOG"
if [ "${1:-}" = "class" ] && [ "${2:-}" = "show" ]; then
    cat "$TC_CLASSES" 2>/dev/null || true
    exit 0
fi
if [ "${1:-}" = "filter" ] && [ "${2:-}" = "add" ]; then
    exit "${TC_ADD_RC:-0}"
fi
exit 0
STUB
chmod +x "$TMP/bin/tc"
export PATH="$TMP/bin:$PATH"
export TC_LOG="$TMP/tc.log"
export TC_CLASSES="$TMP/classes.txt"
export TC_ADD_RC=0
printf '%s\n' "class htb 1:30 parent 1:1 rate 100Mbit" "class htb 1:40 parent 1:1 rate 50Mbit" > "$TC_CLASSES"
: > "$TC_LOG"

extract_fn() {
    local start end
    start=$(grep -n "^$2() {" "$1" | head -1 | cut -d: -f1)
    [ -n "$start" ] || return 1
    end=$(tail -n +"$start" "$1" | grep -n '^}' | head -1 | cut -d: -f1)
    sed -n "${start},$((start + end - 1))p" "$1" >> "$3"
}
: > "$TMP/fns.sh"
for fn in next_tc_prio tc_class_exists throttle_ip hard_throttle_ip; do
    extract_fn "$SRC" "$fn" "$TMP/fns.sh" || { echo "FAIL: cannot extract $fn"; exit 1; }
done

# Daemon environment fixtures
IF="eth0"
THROTTLE_LIST="$TMP/throttled.list"
OBSERVE_SECONDS=45
: > "$THROTTLE_LIST"
log() { echo "$*" >> "$TMP/daemon.log"; }
is_exempt() { return 1; }

# shellcheck disable=SC1091
. "$TMP/fns.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

# 1) soft throttle: dst filter, state recorded with band, prio >= 20001
throttle_ip 5.5.5.5 || bad "throttle_ip rc"
grep -q "match ip dst 5.5.5.5/32 flowid 1:30" "$TC_LOG" && ok || bad "dst filter to 1:30"
grep -q "^5.5.5.5 [0-9]* [0-9]* soft$" "$THROTTLE_LIST" && ok || bad "state entry with soft band"
P1=$(awk '$1=="5.5.5.5"{print $2}' "$THROTTLE_LIST")
[ "${P1:-0}" -ge 20001 ] && ok || bad "prio >= 20001 (got ${P1:-none})"

# 2) second throttle: different prio (no reuse)
throttle_ip 6.6.6.6 || bad "throttle_ip 2 rc"
P2=$(awk '$1=="6.6.6.6"{print $2}' "$THROTTLE_LIST")
[ -n "$P2" ] && [ "$P2" != "$P1" ] && ok || bad "unique prio (P1=$P1 P2=${P2:-none})"

# 3) tc failure: no state written, non-zero rc (BUG-024)
export TC_ADD_RC=1
if throttle_ip 7.7.7.7; then bad "failing tc must make throttle_ip fail"; else ok; fi
grep -q "^7.7.7.7 " "$THROTTLE_LIST" && bad "state written despite tc failure" || ok
export TC_ADD_RC=0

# 4) hard throttle: dst filter to 1:40, old soft entry replaced, band=hard
hard_throttle_ip 5.5.5.5 || bad "hard_throttle_ip rc"
grep -q "match ip dst 5.5.5.5/32 flowid 1:40" "$TC_LOG" && ok || bad "dst filter to 1:40"
[ "$(grep -c '^5.5.5.5 ' "$THROTTLE_LIST")" -eq 1 ] && ok || bad "exactly one state entry after hard"
grep -q "^5.5.5.5 [0-9]* [0-9]* hard$" "$THROTTLE_LIST" && ok || bad "state entry with hard band"

# 5) no tc classes at all: loud skip, no state (autoban-only mode)
: > "$TC_CLASSES"
if throttle_ip 8.8.8.8; then bad "missing class must make throttle_ip fail"; else ok; fi
grep -q "^8.8.8.8 " "$THROTTLE_LIST" && bad "state written without tc class" || ok

# 6) prio counter persists across a fresh shell (monotonic, never reused)
P_NEXT=$(bash -c 'THROTTLE_LIST="'"$THROTTLE_LIST"'"; . "'"$TMP"'/fns.sh" >/dev/null 2>&1; next_tc_prio')
P_LAST=$(awk '{print $2}' "$THROTTLE_LIST" | sort -n | tail -1)
[ "${P_NEXT:-0}" -gt "${P_LAST:-0}" ] && ok || bad "counter monotonic across shells (next=${P_NEXT:-?} last=${P_LAST:-?})"

echo "throttle/tc: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
