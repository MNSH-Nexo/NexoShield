#!/bin/bash
# Regression suite for the v3.19.0 fix round (lab Round 2 findings):
# - nft /24 overlap: ban_subnet supersedes individually-banned members
# - REP-BAN without ban verification: a refused ban records no strike
# - covering-/24 short-circuit: ban_ip treats a range-blocked IP as done
# - L5 race: concurrent ban_ip + nx_release_ban cannot diverge state
# Functions are extracted verbatim from the assembled modules and run
# against a file-backed nft stub and recording iptables/tc stubs.
# The state lock is REAL flock on a tmp lock file (not stubbed).
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

MOD=$(mktemp -d)
T=$(mktemp -d)
cleanup() { rm -rf "$MOD" "$T"; }
trap cleanup EXIT
mkdir -p "$T/v4" "$T/v6"

if [ -e /etc/antiddos ]; then
    echo "  FAIL: refusing to run - /etc/antiddos exists (live install?); run on a clean sandbox"
    exit 1
fi

python3 "$ROOT/tools/build.py" --emit-modules "$MOD" >/dev/null 2>&1 || { echo "  FAIL: emit"; exit 1; }
extract_fn() {
    # Like the other suites' helper, but one-liner functions (e.g. the
    # nx_ban dispatcher) must stop on their own line: the naive
    # "exit at the next ^}" swallows the following definitions
    # (nx_throttle/nx_hard_throttle) and silently overrides stubs.
    awk -v n="$1" 'BEGIN{p=0} $0 ~ "^" n "\\(\\) \\{" {p=1; print; if ($0 ~ /}/) exit; next} p{print} p && /^}/{exit}' "$2"
}

# ── Fake iptables: chain files hold -S-style rule lines ─────
iptables() {
    echo "iptables $*" >> "$T/iptables.log"
    local cmd="$1" chain
    [ "$1" = "-t" ] && shift 2
    cmd="$1"; chain="$2"; shift 2
    local file="$T/v4/$chain" line prev="" a
    [ -f "$file" ] || : > "$file"
    case "$cmd" in
        -C) return 1 ;;
        -I) [ "${IPT_FAIL:-0}" = "1" ] && return 1
            line="-A $chain"
            for a in "$@"; do
                if [ "$prev" = "--comment" ]; then line="$line \"$a\""; else line="$line $a"; fi
                prev="$a"
            done
            printf '%s\n' "$line" >> "$file"; return 0 ;;
        -D) line="-A $chain"
            for a in "$@"; do
                if [ "$prev" = "--comment" ]; then line="$line \"$a\""; else line="$line $a"; fi
                prev="$a"
            done
            if grep -Fxq -- "$line" "$file"; then
                grep -Fxv -- "$line" "$file" > "$file.tmp" || true
                mv "$file.tmp" "$file"
                return 0
            fi
            return 1 ;;
    esac
    return 0
}
ip6tables() { echo "ip6tables $*" >> "$T/iptables.log"; return 1; }

# ── Fake nft: set files, one element per line; NFT_FAIL=1 makes
# every add fail (degraded-backend simulation for the REP-BAN test).
nft() {
    echo "nft $*" >> "$T/nft.log"
    case "$1 $2" in
        "list table") return 0 ;;
        "delete element")
            local _ip _f
            _ip=$(printf '%s' "$6" | tr -d '{}' | awk '{print $1}')
            _f="$T/nft_$5"
            if [ -f "$_f" ] && grep -Fxq -- "$_ip" "$_f"; then
                grep -Fxv -- "$_ip" "$_f" > "$_f.tmp" || true
                mv "$_f.tmp" "$_f"
            fi
            return 0 ;;
        "add element")
            if [ "${NFT_FAIL:-0}" = "1" ]; then return 1; fi
            local _ip _f
            _ip=$(printf '%s' "$6" | tr -d '{}' | awk '{print $1}')
            _f="$T/nft_$5"
            grep -Fxq -- "$_ip" "$_f" 2>/dev/null || printf '%s\n' "$_ip" >> "$_f"
            return 0 ;;
    esac
    return 0
}
tc()  { echo "tc $*" >> "$T/tc.log"; return 0; }
ip()  { return 0; }
fail2ban-client() { return 0; }

log()     { echo "LOG: $*" >> "$T/calls.log"; }
info()    { echo "INFO: $*" >> "$T/calls.log"; }
success() { echo "SUCCESS: $*" >> "$T/calls.log"; }
warn()    { echo "WARN: $*" >> "$T/calls.log"; }
err()     { echo "ERR: $*" >> "$T/calls.log"; }

# Stubs for exemption/throttle helpers (their own suites cover them).
is_self_ip()      { return 1; }
is_exempt()       { return 1; }
is_exempt_any()   { return 1; }
nx_host_stressed() { return 1; }
nx_throttle()     { echo "throttle $1" >> "$T/calls.log"; }
nx_hard_throttle() { echo "hard $1" >> "$T/calls.log"; }

# ── Extract the real functions ───────────────────────────────
for fn in state_has_ip state_get_field state_del_ip ip_to_int ip_in_cidr subnet_overlaps_cf nx_state_lock nx_state_unlock nx_ban_apply nx_ban_remove_fw nx_ban ban_ip load_reputation save_reputation rep_on_ban rep_ban_duration_secs update_score ban_subnet; do
    extract_fn "$fn" "$MOD/auto-ban.sh"
done > "$MOD/fns.sh"
for fn in nx_release_ban; do
    extract_fn "$fn" "$MOD/antiddos.sh"
done >> "$MOD/fns.sh"
# shellcheck disable=SC1091
. "$MOD/fns.sh"

# ── Environment ──────────────────────────────────────────────
export NX_BAN_BACKEND=nft NX_STATE_LOCK_FILE="$T/state.lock"
export BANNED_LIST="$T/banned.list" THROTTLE_LIST="$T/throttled.list" WATCH_LIST="$T/watch.list"
export SCORE_FILE="$T/scores/reputation.dat" WHITELIST_FILE="$T/whitelist"
export SUBNET_BAN_MINUTES=60 BAN_HOURS=4 BAN_BASE_MINUTES=30 BAN_MAX_MINUTES=10080
export SCORE_BAN=20 SCORE_HARD=40 SCORE_THROTTLE=60 SCORE_SUSPECT=80
export PROBATION_SCORE=50 PROBATION_SECONDS=1800
export SCORE_RECOVER_PER_MIN=6 PROBATION_RECOVER_PER_MIN=10 SCORE_DROP_CAP_PER_MIN=45
export CONN_THRESHOLD=120
SELF_IPS=(); SELF6_IPS=(); CF_NET_INT=(); CF_SHIFT=()
mkdir -p "$T/scores"
: > "$T/banned.list"; : > "$T/throttled.list"; : > "$T/watch.list"; : > "$T/whitelist"; : > "$T/calls.log"
: > "$T/nft_ban4"; : > "$T/nft_ban6"; : > "$T/iptables.log"; : > "$T/nft.log"
field() { awk -v x="$1" -v n="$2" '$1==x{print $n}' "$3"; }

# ── 1) nft /24 overlap: members are superseded, range lands ──
NOW=$(date +%s)
printf '%s\n' "198.51.100.5 $NOW 1800" > "$T/banned.list"
printf '%s\n' "198.51.100.5" > "$T/nft_ban4"
printf '%s\n' "-A INPUT -s 198.51.100.5 -m comment --comment \"auto-ban\" -j DROP" > "$T/v4/INPUT"
: > "$T/calls.log"
ban_subnet 198.51.100
grep -q "^198.51.100.0/24 " "$T/banned.list" && ! grep -q "^198.51.100.5 " "$T/banned.list" && ok || bad "overlap: banned.list should hold the /24, not the member: [$(tr '\n' ' ' < "$T/banned.list")]"
grep -q "^198.51.100.0/24$" "$T/nft_ban4" && ! grep -q "^198.51.100.5$" "$T/nft_ban4" && ok || bad "overlap: nft ban4 should hold the /24, not the member: [$(tr '\n' ' ' < "$T/nft_ban4")]"
grep -q "SUBNET BAN: 198.51.100.0/24" "$T/calls.log" && ok || bad "overlap: no SUBNET BAN log"
grep -q "iptables -D INPUT -s 198.51.100.5" "$T/iptables.log" && ok || bad "overlap: member iptables rule was not deleted"

# ── 2) REP-BAN without ban verification ──────────────────────
# 2a) Backend refuses: no strike, no probation, no state, loud log.
NFT_FAIL=1 IPT_FAIL=1
printf '%s\n' "198.51.100.9 5 100 $((NOW - 60)) 0 0 0 0 0" > "$T/scores/reputation.dat"
: > "$T/banned.list"; : > "$T/nft_ban4"; : > "$T/calls.log"
update_score 198.51.100.9 4000 0 2
grep -q "REP-BAN FAILED: 198.51.100.9" "$T/calls.log" && ok || bad "rep-ban-fail: no REP-BAN FAILED log: [$(cat "$T/calls.log")]"
grep -q "REP-BAN: 198.51.100.9" "$T/calls.log" && bad "rep-ban-fail: success REP-BAN logged despite refused ban" || ok
[ "$(field 198.51.100.9 8 "$T/scores/reputation.dat")" = "0" ] && ok || bad "rep-ban-fail: strike recorded despite refused ban"
[ ! -s "$T/banned.list" ] && ! grep -q "198.51.100.9" "$T/nft_ban4" && ok || bad "rep-ban-fail: state recorded despite refused ban"
# 2b) Control: working backend bans + strikes + probations.
NFT_FAIL=0 IPT_FAIL=0
printf '%s\n' "198.51.100.9 5 100 $((NOW - 60)) 0 0 0 0 0" > "$T/scores/reputation.dat"
: > "$T/banned.list"; : > "$T/nft_ban4"; : > "$T/calls.log"
update_score 198.51.100.9 4000 0 2
grep -q "REP-BAN: 198.51.100.9" "$T/calls.log" && ok || bad "rep-ban-ok: no REP-BAN log: [$(cat "$T/calls.log")]"
[ "$(field 198.51.100.9 8 "$T/scores/reputation.dat")" = "1" ] && ok || bad "rep-ban-ok: strike not recorded"
grep -q "^198.51.100.9 " "$T/banned.list" && grep -q "^198.51.100.9$" "$T/nft_ban4" && ok || bad "rep-ban-ok: ban not recorded in state + nft"
[ "$(field 198.51.100.9 2 "$T/scores/reputation.dat")" = "50" ] && ok || bad "rep-ban-ok: score not moved to probation (50)"

# ── 3) Covering-/24 short-circuit ────────────────────────────
printf '%s\n' "198.51.100.0/24 $NOW 3600" > "$T/banned.list"
printf '%s\n' "198.51.100.0/24" > "$T/nft_ban4"
: > "$T/calls.log"
ban_ip 198.51.100.5 && ok || bad "covering: ban_ip of a range-blocked IP returned nonzero"
[ "$(cat "$T/banned.list")" = "198.51.100.0/24 $NOW 3600" ] && [ "$(cat "$T/nft_ban4")" = "198.51.100.0/24" ] && ok || bad "covering: state changed for a range-blocked IP"
grep -q "BAN FAILED" "$T/calls.log" && bad "covering: BAN FAILED logged for an already-blocked IP" || ok
grep -q "BANNED: 198.51.100.5" "$T/calls.log" && bad "covering: duplicate BANNED log for a range-blocked IP" || ok

# ── 4) L5: concurrent ban + release cannot diverge state ────
: > "$T/banned.list"; : > "$T/nft_ban4"
for w in 0 1 2 3 4 5 6 7; do
    printf '%s\n' "192.0.2.$((30 + w)) $NOW 1800" >> "$T/banned.list"
    printf '%s\n' "192.0.2.$((30 + w))" >> "$T/nft_ban4"
done
for w in 0 1 2 3 4 5 6 7; do
    (
        for _ in $(seq 1 20); do
            ban_ip "192.0.2.$((20 + w))" >/dev/null 2>&1 || true
            nx_release_ban "192.0.2.$((30 + w))" >/dev/null 2>&1 || true
        done
    ) &
done
wait
for w in 0 1 2 3 4 5 6 7; do
    [ "$(grep -c "^192.0.2.$((20 + w)) " "$T/banned.list")" = "1" ] && ok || bad "l5: 192.0.2.$((20 + w)) not exactly once in banned.list: [$(tr '\n' ' ' < "$T/banned.list")]"
    grep -q "^192.0.2.$((30 + w)) " "$T/banned.list" && bad "l5: released 192.0.2.$((30 + w)) still in banned.list" || ok
done
[ "$(sort "$T/banned.list" | awk '{print $1}' | tr '\n' ' ')" = "192.0.2.20 192.0.2.21 192.0.2.22 192.0.2.23 192.0.2.24 192.0.2.25 192.0.2.26 192.0.2.27 " ] && ok || bad "l5: final banned.list wrong: [$(tr '\n' ' ' < "$T/banned.list")]"
[ "$(sort "$T/nft_ban4" | tr '\n' ' ')" = "192.0.2.20 192.0.2.21 192.0.2.22 192.0.2.23 192.0.2.24 192.0.2.25 192.0.2.26 192.0.2.27 " ] && ok || bad "l5: final nft ban4 wrong: [$(tr '\n' ' ' < "$T/nft_ban4")]"

echo "fix round 3.19.0: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
