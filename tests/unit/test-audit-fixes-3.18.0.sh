#!/bin/bash
# Regression suite for the v3.18.0 audit fixes (Highs + Mediums).
# Fresh-process execution tests: functions are extracted verbatim
# from the assembled modules and run against fake iptables /
# ip6tables / nft / tc binaries - never grep-only assertions (the
# wave8 style that let F1 through). Two items are structural by
# necessity and say so: the HIGH-1 failure path (install_proxy is
# not executable standalone) and M1 (the full daemon loop is not
# executable standalone); both carry ordering assertions on the
# assembled code instead of a faked execution test.
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

# Fail closed: two functions under test write absolute paths
# (flush truncates /etc/antiddos/banned.list, apply_ip6tables
# writes the exempt/rules files). On a sandbox those writes fail
# harmlessly because the directory is absent; on a live install
# they would destroy real state. Refuse instead of risking it -
# this suite is for CI/sandbox only, like every other suite here.
if [ -e /etc/antiddos ]; then
    echo "  FAIL: refusing to run - /etc/antiddos exists (live install?); run on a clean sandbox"
    exit 1
fi

python3 "$ROOT/tools/build.py" --emit-modules "$MOD" >/dev/null 2>&1 || { echo "  FAIL: emit"; exit 1; }
extract_fn() {
    awk -v n="$1" 'BEGIN{p=0} $0 ~ "^" n "\\(\\) \\{" {p=1} p{print} p && /^}/{exit}' "$2"
}

# ── Fake netfilter: chain files hold -S-style rule lines ─────
# -S prints a policy line first (rule number = line - 1, exactly
# like nx_delete_matching / self_guard assume); -D takes a rule
# number or a full spec (rebuilt with the comment value quoted,
# matching the -S rendering the functions grep for).
_fake_chain() {
    local dir="$1"; shift
    [ "$1" = "-t" ] && shift 2
    local cmd="$1" chain="$2"; shift 2
    local file="$dir/$chain" line prev="" a
    [ -f "$file" ] || : > "$file"
    case "$cmd" in
        -S) printf -- '-P %s ACCEPT\n' "$chain"; cat "$file" ;;
        -L) return 0 ;;
        -C) return 1 ;;
        -A) line="-A $chain"
            for a in "$@"; do
                if [ "$prev" = "--comment" ]; then line="$line \"$a\""; else line="$line $a"; fi
                prev="$a"
            done
            printf '%s\n' "$line" >> "$file" ;;
        -D) if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
                sed -i "${1}d" "$file" 2>/dev/null || true
            else
                line="-A $chain"
                for a in "$@"; do
                    if [ "$prev" = "--comment" ]; then line="$line \"$a\""; else line="$line $a"; fi
                    prev="$a"
                done
                if grep -Fxq -- "$line" "$file"; then
                    # grep -Fxv exits 1 when it filters EVERY line -
                    # do not let that skip the mv (the single-rule
                    # case is exactly the common one).
                    grep -Fxv -- "$line" "$file" > "$file.tmp" || true
                    mv "$file.tmp" "$file"
                    return 0
                fi
                return 1
            fi ;;
    esac
}
iptables()   { _fake_chain "$T/v4" "$@"; }
ip6tables()  { _fake_chain "$T/v6" "$@"; }

# ── Fake nft: set files, one element per line ─────────────────
nft() {
    echo "nft $*" >> "$T/nft.log"
    case "$1 $2" in
        "list table") return 0 ;;
        "flush set")
            : > "$T/nft_$5" 2>/dev/null || true
            return 0 ;;
        "delete element")
            local _ip _f
            _ip=$(printf '%s' "$6" | tr -d '{} ')
            _f="$T/nft_$5"
            if [ -f "$_f" ] && grep -Fxq -- "$_ip" "$_f"; then
                grep -Fxv -- "$_ip" "$_f" > "$_f.tmp" || true
                mv "$_f.tmp" "$_f"
                return 0
            fi
            return 1 ;;
        "add element")
            local _ip _f
            _ip=$(printf '%s' "$6" | tr -d '{} ')
            _f="$T/nft_$5"
            grep -Fxq -- "$_ip" "$_f" 2>/dev/null || printf '%s\n' "$_ip" >> "$_f"
            return 0 ;;
    esac
    return 0
}
tc()  { echo "tc $*" >> "$T/tc.log"; return 0; }
ip()  { if [ "${1:-}" = "route" ]; then echo "default via 10.0.0.1 dev eth0"; fi; return 0; }
fail2ban-client() { echo "f2b $*" >> "$T/f2b.log"; if [ "${1:-}" = "status" ]; then echo "Jail list: sshd, nginx"; fi; return 0; }

# Stubs for the programs' print helpers (extracted functions call
# these; the test asserts behaviour, not log text).
log()     { echo "LOG: $*" >> "$T/calls.log"; }
info()    { echo "INFO: $*" >> "$T/calls.log"; }
success() { echo "SUCCESS: $*" >> "$T/calls.log"; }
warn()    { echo "WARN: $*" >> "$T/calls.log"; }
err()     { echo "ERR: $*" >> "$T/calls.log"; }

# ── H1: daemon sees IPv6 peers ───────────────────────────────
for fn in nx_extract_peer_ips; do extract_fn "$fn" "$MOD/auto-ban.sh"; done > "$MOD/h1.sh"
# shellcheck disable=SC1091
. "$MOD/h1.sh"
_H1_OUT=$(printf '%s\n' "1.2.3.4:443" "[2001:db8::1]:443" "[2001:db8::1]:80" "[::ffff:5.6.7.8]:1080" "9.9.9.9:80" | nx_extract_peer_ips | sort | uniq -c | awk '{print $2":"$1}' | tr '\n' ' ')
[ "$_H1_OUT" = "1.2.3.4:1 2001:db8::1:2 5.6.7.8:1 9.9.9.9:1 " ] && ok || bad "H1 peer extraction wrong: [$_H1_OUT]"

# ── F1/H2/H3: flush_autobans in a fresh process ──────────────
for fn in nx_delete_matching nx_delete_matching6 flush_autobans; do
    extract_fn "$fn" "$MOD/antiddos.sh"
done > "$MOD/flush.sh"
# shellcheck disable=SC1091
. "$MOD/flush.sh"
export THROTTLE_LIST="$T/throttle.live" WATCH_LIST="$T/watch" SUBNET_WATCH_LIST="$T/subnet_watch" BANNED_LIST="$T/banned.list"
printf '%s\n' "-A INPUT -s 1.2.3.4 -m comment --comment \"auto-ban\" -j DROP" "-A INPUT -s 5.6.7.8 -m comment --comment \"subnet-ban\" -j DROP" "-A INPUT -s 9.9.9.9 -j ACCEPT" > "$T/v4/INPUT"
printf '%s\n' "-A INPUT -s 2001:db8::1 -m comment --comment \"auto-ban\" -j DROP" "-A INPUT -s 2001:db8::2 -j ACCEPT" > "$T/v6/INPUT"
printf '%s\n' "1.2.3.4" "2001:db8::5" > "$T/nft_ban4"
printf '%s\n' "2001:db8::5" > "$T/nft_ban6"
printf '%s\n' "1.2.3.4 10000 1700000000 soft" > "$T/throttle.live"
printf 'x\n' > "$T/watch"; printf 'x\n' > "$T/subnet_watch"
: > "$T/nft.log"; : > "$T/tc.log"
flush_autobans
[ "$(cat "$T/v4/INPUT")" = "-A INPUT -s 9.9.9.9 -j ACCEPT" ] && ok || bad "F1 flush left v4 rules: [$(cat "$T/v4/INPUT" | tr '\n' ' ')]"
[ "$(cat "$T/v6/INPUT")" = "-A INPUT -s 2001:db8::2 -j ACCEPT" ] && ok || bad "H3 flush left v6 rules: [$(cat "$T/v6/INPUT" | tr '\n' ' ')]"
[ ! -s "$T/nft_ban4" ] && [ ! -s "$T/nft_ban6" ] && ok || bad "H2 flush left nft elements"
grep -q "filter del dev eth0 parent 1: prio 10000" "$T/tc.log" && [ ! -s "$T/throttle.live" ] && ok || bad "flush did not remove throttle filter/state"
[ ! -s "$T/watch" ] && [ ! -s "$T/subnet_watch" ] && ok || bad "flush did not truncate watch files"
grep -q "SUCCESS: All auto-bans flushed" "$T/calls.log" && ok || bad "flush printed no success"

# ── nx_release_ban: honest 0/1 + both families ───────────────
for fn in nx_release_ban; do extract_fn "$fn" "$MOD/antiddos.sh"; done > "$MOD/rel.sh"
# shellcheck disable=SC1091
. "$MOD/rel.sh"
printf '%s\n' "-A INPUT -s 1.2.3.4 -m comment --comment \"auto-ban\" -j DROP" > "$T/v4/INPUT"
printf '%s\n' "-A INPUT -s 2001:db8::1 -m comment --comment \"auto-ban\" -j DROP" > "$T/v6/INPUT"
printf '%s\n' "1.2.3.4 1700000000 1800" "5.6.7.8 1700000000 1800" > "$T/banned.list"
printf '%s\n' "1.2.3.4" > "$T/nft_ban4"; printf '%s\n' "2001:db8::1" > "$T/nft_ban6"
: > "$T/tc.log"
nx_release_ban 1.2.3.4 && ok || bad "release of a banned v4 IP returned nonzero"
[ "$(cat "$T/v4/INPUT")" = "" ] && ! grep -q "1.2.3.4" "$T/banned.list" && ! grep -q "1.2.3.4" "$T/nft_ban4" && ok || bad "release did not remove v4 ban everywhere"
nx_release_ban 9.9.9.9 && bad "release of an unbanned IP returned zero" || ok
nx_release_ban 2001:db8::1 && ok || bad "release of a banned v6 IP returned nonzero"
[ "$(cat "$T/v6/INPUT")" = "" ] && ! grep -q "2001:db8::1" "$T/nft_ban6" && ok || bad "release did not remove v6 ban everywhere"

# ── M2: whitelisting releases covered bans ───────────────────
for fn in nx_ip_to_int nx_ip_in_cidr nx_ip6_in_cidr _wl_covered wl_release_bans_for; do
    extract_fn "$fn" "$MOD/antiddos.sh"
done > "$MOD/wl.sh"
# shellcheck disable=SC1091
. "$MOD/wl.sh"
printf '%s\n' "1.2.3.4 1700000000 1800" "1.2.3.99 1700000000 1800" "5.6.7.0/24 1700000000 3600" > "$T/banned.list"
printf '%s\n' "-A INPUT -s 1.2.3.4 -m comment --comment \"auto-ban\" -j DROP" > "$T/v4/INPUT"
printf '%s\n' "1.2.3.4" "1.2.3.99" > "$T/nft_ban4"
: > "$T/nft_exempt4"
wl_release_bans_for 1.2.3.0/24
! grep -q "1.2.3.4" "$T/banned.list" && ! grep -q "1.2.3.99" "$T/banned.list" && ok || bad "M2 whitelist did not release covered IPs"
grep -q "1.2.3.0/24" "$T/nft_exempt4" && ok || bad "M2 whitelist did not join the nft exempt set"
printf '%s\n' "5.6.7.0/24 1700000000 3600" > "$T/banned.list"
wl_release_bans_for 5.6.7.8
grep -q "5.6.7.0/24" "$T/banned.list" && ok || bad "M2 single IP wrongly lifted a subnet ban"
wl_release_bans_for 5.6.7.0/24
! grep -q "5.6.7.0/24" "$T/banned.list" && ok || bad "M2 same-CIDR whitelist did not release the subnet ban"

# ── HIGH-2/M4: live tc rebuild re-applies throttles ──────────
# The full setup_tc is not executed standalone: it writes absolute
# paths (/opt/proxy-manager/tc-setup.sh, a systemd unit) that no
# test may touch. Instead the loop itself is extracted VERBATIM
# from the assembled module and executed, plus a structural check
# that it sits inside the live setup_tc (not only the boot script).
sed -n '/HIGH-2: re-apply live daemon throttles/,/done < /p' "$MOD/antiddos.sh" > "$MOD/h2.sh"
grep -q 'TFLOW=1:30' "$MOD/h2.sh" || { echo "  FAIL: HIGH-2 loop not found in assembled antiddos.sh"; fail=$((fail+1)); }
MAIN_IF=eth0 IF=eth0
export THROTTLE_LIST="$T/throttle.live"
printf '%s\n' "1.2.3.4 10000 1700000000 soft" "2001:db8::9 10001 1700000000 hard" > "$T/throttle.live"
: > "$T/tc.log"
# shellcheck disable=SC1091
. "$MOD/h2.sh"
grep -q "filter add dev eth0 parent 1: protocol ip prio 10000.*flowid 1:30" "$T/tc.log" && ok || bad "HIGH-2 soft v4 filter not re-applied: [$(cat "$T/tc.log" | tr '\n' ' ')]"
grep -q "filter add dev eth0 parent 1: protocol ip6 prio 10001.*flowid 1:40" "$T/tc.log" && ok || bad "HIGH-2 hard v6 filter not re-applied"
# Structural: the loop lives inside the LIVE setup_tc, before WARP.
_S_TC=$(grep -n '^setup_tc() {' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
_S_H2=$(grep -n 'HIGH-2: re-apply live daemon throttles' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
_S_WARP=$(grep -n 'WARP / WireGuard awareness' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
[ -n "$_S_TC" ] && [ -n "$_S_H2" ] && [ -n "$_S_WARP" ] && [ "$_S_TC" -lt "$_S_H2" ] && [ "$_S_H2" -lt "$_S_WARP" ] && ok || bad "HIGH-2 loop not inside live setup_tc (tc=$_S_TC h2=$_S_H2 warp=$_S_WARP)"
# Live-wins dedup: only when /etc/antiddos does not already exist
# (never touch a real install's state). A stale mirror entry for
# the same IP must not resurrect the replaced filter.
if [ ! -e /etc/antiddos ]; then
    mkdir -p /etc/antiddos
    printf '%s\n' "1.2.3.4 9999 1700000000 soft" > /etc/antiddos/throttled.list
    trap 'rm -rf /etc/antiddos; rm -rf "$MOD" "$T"' EXIT
    : > "$T/tc.log"
    # shellcheck disable=SC1091
    . "$MOD/h2.sh"
    grep -q "prio 10000" "$T/tc.log" && ! grep -q "prio 9999" "$T/tc.log" && ok || bad "HIGH-2 stale mirror entry resurrected: [$(cat "$T/tc.log" | tr '\n' ' ')]"
    rm -rf /etc/antiddos
    trap 'rm -rf "$MOD" "$T"' EXIT
else
    echo "  SKIP: HIGH-2 mirror-priority check (/etc/antiddos already exists)"
fi

# ── M3: self_guard deletes comment-tagged rules by number ───
for fn in state_has_ip state_get_field state_del_ip self_guard; do
    if fn_text=$(extract_fn "$fn" "$MOD/auto-ban.sh"); [ -n "$fn_text" ]; then printf '%s\n' "$fn_text"; fi
done > "$MOD/sg.sh"
# nx_ban_remove_fw is nft-only and lives in 20-enforce.sh; stub it.
nx_ban_remove_fw() { echo "ban_remove_fw $*" >> "$T/calls.log"; return 0; }
# shellcheck disable=SC1091
. "$MOD/sg.sh"
export BANNED_LIST="$T/banned.list" THROTTLE_LIST="$T/throttle.live" IF=eth0
SELF_IPS=("10.0.0.5"); SELF6_IPS=("2001:db8::5")
printf '%s\n' "10.0.0.5 1700000000 1800" > "$T/banned.list"
printf '%s\n' "10.0.0.5 10002 1700000000 soft" > "$T/throttle.live"
printf '%s\n' "-A INPUT -s 10.0.0.5 -m comment --comment \"auto-ban\" -j DROP" "-A INPUT -s 1.2.3.4 -m comment --comment \"auto-ban\" -j DROP" "-A INPUT -s 10.0.0.5 -m comment --comment \"says -j DROP here\" -j ACCEPT" > "$T/v4/INPUT"
printf '%s\n' "-A INPUT -s 2001:db8::5 -m comment --comment \"auto-ban\" -j DROP" > "$T/v6/INPUT"
: > "$T/f2b.log"; : > "$T/tc.log"
self_guard
! grep -q '10.0.0.5.*auto-ban' "$T/v4/INPUT" && grep -q "1.2.3.4" "$T/v4/INPUT" && ok || bad "M3 self v4 rule not removed: [$(cat "$T/v4/INPUT" | tr '\n' ' ')]"
grep -q "says -j DROP here" "$T/v4/INPUT" && ok || bad "M3 removed a rule it must not touch"
[ ! -s "$T/v6/INPUT" ] && ok || bad "M3 self v6 rule not removed"
! grep -q "10.0.0.5" "$T/banned.list" && ! grep -q "10.0.0.5" "$T/throttle.live" && ok || bad "M3 self state not cleaned"
grep -q "unbanip 10.0.0.5" "$T/f2b.log" && ok || bad "M3 fail2ban sweep did not run after a removal"
: > "$T/f2b.log"
self_guard
[ ! -s "$T/f2b.log" ] && ok || bad "M3 fail2ban sweep ran with nothing removed (L8)"

# ── M5/L11: no state for a refused ban ───────────────────────
for fn in state_has_ip state_get_field state_del_ip ban_ip ban_ip6; do
    extract_fn "$fn" "$MOD/auto-ban.sh"
done > "$MOD/ban.sh"
is_self_ip() { return 1; }
is_exempt() { return 1; }
is_exempt6() { return 1; }
ip6_in_cidr() { local _b="${2%%/*}"; [ "$1" = "$_b" ]; }
rep_ban_duration_secs() { echo 1800; }
NX_BAN_APPLY_RC=0
nx_ban_apply() { return "$NX_BAN_APPLY_RC"; }
# shellcheck disable=SC1091
. "$MOD/ban.sh"
export BANNED_LIST="$T/banned.list" THROTTLE_LIST="$T/throttle.live" IF=eth0
SELF6_IPS=()
: > "$T/banned.list"; : > "$T/throttle.live"
NX_BAN_APPLY_RC=1
ban_ip 1.2.3.4; [ "$?" -eq 1 ] && [ ! -s "$T/banned.list" ] && ok || bad "M5 failed v4 ban recorded state or returned 0"
NX_BAN_APPLY_RC=0
ban_ip 1.2.3.4; [ "$?" -eq 0 ] && grep -q "^1.2.3.4 " "$T/banned.list" && ok || bad "M5 successful v4 ban not recorded"
NX_BAN_APPLY_RC=1
ban_ip6 2001:db8::7; [ "$?" -eq 1 ] && ! grep -q "2001:db8::7" "$T/banned.list" && ok || bad "M5 failed v6 ban recorded state or returned 0"
SELF6_IPS=("2001:db8::7")
NX_BAN_APPLY_RC=0
ban_ip6 2001:db8::7; [ "$?" -eq 1 ] && ! grep -q "2001:db8::7" "$T/banned.list" && ok || bad "L11 v6 self-refusal did not return 1 (or recorded state)"

# ── M6/L16: drops-aware detach, fail-closed ──────────────────
cat > "$T/nx-xdp" << 'XDP_EOF'
#!/bin/bash
case "$1" in
    stats) echo "syn=0 drops=$(cat "$NX_XDP_DROPS_FILE" 2>/dev/null || echo 0) exempt_pass=0" ;;
    unload) exit "$(cat "$NX_XDP_UNLOAD_RC" 2>/dev/null || echo 0)" ;;
    *) exit 0 ;;
esac
XDP_EOF
chmod +x "$T/nx-xdp"
for fn in nx_xdp_tick nx_xdp_detach; do extract_fn "$fn" "$MOD/auto-ban.sh"; done > "$MOD/xdp.sh"
# shellcheck disable=SC1091
. "$MOD/xdp.sh"
export NX_XDP_BIN="$T/nx-xdp" NX_XDP_DROPS_FILE="$T/drops" NX_XDP_UNLOAD_RC="$T/unload_rc"
export BANNED_LIST="$T/banned.list"
touch "$T/banned.list"
NX_XDP_AVAILABLE=1; NX_XDP_ATTACHED="eth0"; NX_XDP_IFACE="eth0"
NX_OVF_DELTA=0; NX_SYNCOOK_DELTA=0; NX_EV_OK=0; NX_EV_DT=2
XDP_CALM_SECONDS=600; _NX_XDP_WIN_START=0; _NX_XDP_OVF_WIN=0; _NX_XDP_SCOOK_WIN=0
_NX_XDP_BANS_MT=$(stat -c %Y "$T/banned.list")
echo 0 > "$T/unload_rc"
# Rising drops with an already-expired calm window must NOT detach
# (old code detached here: it never looked at the counter).
_NOW=$(date +%s); _NX_XDP_CALM_SINCE=$((_NOW - 700)); _NX_XDP_LAST_DROPS="50"
echo 100 > "$T/drops"
nx_xdp_tick
[ "$NX_XDP_ATTACHED" = "eth0" ] && ok || bad "M6 rising drops did not prevent the detach"
# Stable drops + expired calm window DOES detach.
_NOW=$(date +%s); _NX_XDP_CALM_SINCE=$((_NOW - 700)); _NX_XDP_LAST_DROPS="100"
nx_xdp_tick
[ -z "$NX_XDP_ATTACHED" ] && ok || bad "M6 stable-drops calm window did not detach"
# L16: a failed unload keeps the shield attached.
NX_XDP_ATTACHED="eth0"; echo 1 > "$T/unload_rc"
nx_xdp_detach "test"
[ "$NX_XDP_ATTACHED" = "eth0" ] && [ "$_NX_XDP_CALM_SINCE" -gt 0 ] && ok || bad "L16 failed detach cleared attached state"
echo 0 > "$T/unload_rc"
nx_xdp_detach "test"
[ -z "$NX_XDP_ATTACHED" ] && ok || bad "L16 successful detach did not clear attached state"

# ── M8/M9 + v6 inversion: apply_ip6tables ────────────────────
extract_fn apply_ip6tables "$MOD/antiddos.sh" > "$MOD/v6.sh"
# shellcheck disable=SC1091
. "$MOD/v6.sh"
list_self_ips6() { echo "2001:db8::5"; }
CF6_RANGES=("2001:db8::/32")
export WHITELIST_FILE="$T/whitelist.list"
printf '%s\n' "2001:db8::99" "1.2.3.4" > "$T/whitelist.list"
export SYN_LIMIT="1000/sec" SYN_BURST=2000 UDP_LIMIT="300/sec" UDP_BURST=600 \
       ICMP_LIMIT="50/sec" ICMP_BURST=100 HTTP_REQ_RATE="1000/sec" HTTP_REQ_BURST=2000 \
       NEW_CONN_RATE="200/sec" NEW_CONN_BURST=400 BW_PER_IP_MBIT=250 CONN_LIMIT_PER_IP=300
# Seed an old-form (bare --hashlimit) rule and a new-form rule.
printf '%s\n' "-A INPUT -p tcp --syn -m hashlimit --hashlimit-name syn_limit6 --hashlimit-mode srcip --hashlimit 200/sec --hashlimit-burst 400 -j DROP" "-A INPUT -p tcp --syn -m hashlimit --hashlimit-name syn_limit6 --hashlimit-mode srcip --hashlimit-above 200/sec --hashlimit-burst 999 -j DROP" > "$T/v6/INPUT"
apply_ip6tables
_V6_OUT=$(cat "$T/v6/INPUT")
! printf '%s\n' "$_V6_OUT" | grep -E 'hashlimit-name (syn_limit6|udp_limit6|http_req_rate6|icmp_limit6)' | grep -v 'hashlimit-above' | grep -q . && ok || bad "M8 old-form bare---hashlimit DROP rule survived"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name syn_limit6 --hashlimit-mode srcip --hashlimit-above 200/sec --hashlimit-burst 999' && ok || bad "M8 migration purge removed a new-form rule"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name syn_limit6 --hashlimit-mode srcip --hashlimit-above 1000/sec --hashlimit-burst 2000' && ok || bad "M8 SYN rule not tiered"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name udp_limit6 --hashlimit-mode srcip --hashlimit-above 300/sec --hashlimit-burst 600' && ok || bad "M8 UDP rule not tiered"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name icmp_limit6 --hashlimit-mode srcip --hashlimit-above 50/sec --hashlimit-burst 100' && ok || bad "M8 ICMP rule not tiered"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name bw_per_ip6 ' && printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-above 250mbit/s' && ok || bad "M8 per-IP BW cap missing"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name http_req_est6' && ok || bad "M8 HTTP established cap missing"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name new_conn_rate6' && ok || bad "M8 new-conn rate missing"
printf '%s\n' "$_V6_OUT" | grep -q 'hashlimit-name rst_flood6' && ok || bad "M8 RST flood rule missing"
printf '%s\n' "$_V6_OUT" | grep -q 'tcp ! --syn -m conntrack --ctstate NEW -j DROP' && ok || bad "M8 bogus NEW non-SYN rule missing"
printf '%s\n' "$_V6_OUT" | grep -q 'frag ! --fragfirst -j DROP' && ok || bad "M8 fragment rule missing"
printf '%s\n' "$_V6_OUT" | grep -q 'udp_reflect6_1900' && ok || bad "M8 UDP amplification rules missing"
printf '%s\n' "$_V6_OUT" | grep -q 'connlimit-above 300.*-m limit --limit 10/min --limit-burst 20' && ok || bad "M9 connlimit LOG lacks -m limit"
printf '%s\n' "$_V6_OUT" | grep -q 'cf_whitelist' && printf '%s\n' "$_V6_OUT" | grep -q 'self_whitelist' && printf '%s\n' "$_V6_OUT" | grep -q 'user_whitelist' && ok || bad "M8 exempt ACCEPTs lack v4-identical comments"
! printf '%s\n' "$_V6_OUT" | grep -E '\-j DROP' | grep -E '\-\-hashlimit [0-9]' | grep -q . && ok || bad "bare --hashlimit DROP rule remains somewhere in v6"

# ── L4: nxcountd loss counters surfaced ──────────────────────
extract_fn nx_load_event_counters "$MOD/auto-ban.sh" > "$MOD/ev.sh"
# The loader's globals live outside the function; initialise them
# (the daemon header normally does this).
NX_EV_OK=0; NX_EV_BASE=""; NX_EV_TOT_DSYN=0; NX_EV_TOT_DEST=0
NX_EV_DROPPED=0; NX_EV_FLOWS_DROPPED=0; NX_EV_DROP_DELTA=0; NX_EV_DT=2
_NX_EV_PREV_TS=""; _NX_EV_PREV_TOTSYN=""; _NX_EV_PREV_TOTEST=""
_NX_EV_PREV_DROPPED=""; _NX_EV_PREV_FLOWS_DROPPED=""
declare -A EV_SYN60 EV_EST60 EV_CLOSED EV_BYTES EV_AGE EV_DSYN EV_DEST EV_PSYN EV_PEST
# shellcheck disable=SC1091
. "$MOD/ev.sh"
export NX_COUNTERS_FILE="$T/counters.dat"
_TS=$(date +%s)
printf '%s\n' "# nxcountd 1 ts=$_TS base=1 dropped=5 flows_dropped=2 totalsyn=100 totalest=50" "1.2.3.4 10 8 5 4 x x 1 1000 60" > "$T/counters.dat"
nx_load_event_counters
[ "$NX_EV_OK" = "1" ] && [ "$NX_EV_DROPPED" = "5" ] && [ "$NX_EV_DROP_DELTA" = "0" ] && ok || bad "L4 first load wrong (ok=$NX_EV_OK dropped=$NX_EV_DROPPED delta=$NX_EV_DROP_DELTA)"
_TS=$(date +%s)
printf '%s\n' "# nxcountd 1 ts=$_TS base=1 dropped=8 flows_dropped=4 totalsyn=150 totalest=70" "1.2.3.4 20 15 9 7 x x 2 2000 60" > "$T/counters.dat"
: > "$T/calls.log"
nx_load_event_counters
[ "$NX_EV_DROP_DELTA" = "3" ] && grep -q "lost 3 netlink messages (2 flows)" "$T/calls.log" && ok || bad "L4 drop delta not surfaced (delta=$NX_EV_DROP_DELTA)"
_TS=$(date +%s)
printf '%s\n' "# nxcountd 1 ts=$_TS base=2 dropped=0 flows_dropped=0 totalsyn=10 totalest=5" "1.2.3.4 2 1 1 1 x x 0 100 60" > "$T/counters.dat"
nx_load_event_counters
[ "$NX_EV_DROP_DELTA" = "0" ] && [ "$NX_EV_DROPPED" = "0" ] && ok || bad "L4 rebase did not reset drop delta"

# ── L7: nx_cfg range validation ──────────────────────────────
export NX_CONFIG_FILE="$T/scoring.conf"
printf '%s\n' "score_ban=999" "conn_threshold=-5" "probation_seconds=900" "churn_weight=1.2" "syn_ratio=1.5" "sust_divisor=0" > "$T/scoring.conf"
# shellcheck disable=SC1091
. "$ROOT/src/lib/config.sh"
[ "$(nx_cfg score_ban 20)" = "20" ] && ok || bad "L7 out-of-range score_ban accepted"
[ "$(nx_cfg conn_threshold 120)" = "120" ] && ok || bad "L7 negative conn_threshold accepted"
[ "$(nx_cfg probation_seconds 1800)" = "900" ] && ok || bad "L7 valid probation_seconds rejected"
[ "$(nx_cfg churn_weight 1.0)" = "1.2" ] && ok || bad "L7 valid float churn_weight rejected"
[ "$(nx_cfg syn_ratio 0.5)" = "0.5" ] && ok || bad "L7 out-of-range float syn_ratio accepted"
[ "$(nx_cfg sust_divisor 10)" = "10" ] && ok || bad "L7 zero sust_divisor accepted (division by zero)"

# ── L1: loader prefix validation (compile when cc exists) ───
if command -v cc >/dev/null 2>&1; then
    sed -n '/^static int parse_cidr/,/^}/p' "$ROOT/src/native/nx-xdp-loader.c" > "$T/parse_cidr.c"
    cat >> "$T/parse_cidr.c" << 'C_EOF'
#include <stdio.h>
int main(void) {
    int fam, pfx; uint8_t addr[16]; int rc = 0;
    if (parse_cidr("10.0.0.0/24", &fam, &pfx, addr) != 0 || pfx != 24) rc = 1;
    if (parse_cidr("10.0.0.1", &fam, &pfx, addr) != 0 || pfx != 32) rc = 1;
    if (parse_cidr("2001:db8::/32", &fam, &pfx, addr) != 0 || pfx != 32) rc = 1;
    if (parse_cidr("10.0.0.0/abc", &fam, &pfx, addr) == 0) rc = 1;
    if (parse_cidr("10.0.0.0/-1", &fam, &pfx, addr) == 0) rc = 1;
    if (parse_cidr("10.0.0.0/32junk", &fam, &pfx, addr) == 0) rc = 1;
    if (parse_cidr("10.0.0.0/33", &fam, &pfx, addr) == 0) rc = 1;
    if (parse_cidr("2001:db8::/129", &fam, &pfx, addr) == 0) rc = 1;
    if (parse_cidr("not-an-ip/24", &fam, &pfx, addr) == 0) rc = 1;
    return rc;
}
C_EOF
    sed -i '1i #include <arpa/inet.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>' "$T/parse_cidr.c"
    if cc -o "$T/parse_cidr" "$T/parse_cidr.c" 2>/dev/null && "$T/parse_cidr"; then ok; else bad "L1 parse_cidr rejects/accepts wrong"; fi
else
    echo "  SKIP: L1 parse_cidr test (no cc)"
fi

# ── Structural pins (documented as such) ─────────────────────
# HIGH-1: backup before config rewrite; restore inside the failure
# path; install.info written only after the is-active check.
_H_BK=$(grep -nF '_ROLLBACK_DIR=$(mktemp' "$MOD/3proxy-socks5.sh" | head -1 | cut -d: -f1)
_H_CFG=$(grep -nF 'cat > "$PROXY_CONF"' "$MOD/3proxy-socks5.sh" | head -1 | cut -d: -f1)
_H_ACT=$(grep -nF 'systemctl is-active 3proxy' "$MOD/3proxy-socks5.sh" | head -1 | cut -d: -f1)
_H_RS=$(grep -nF 'cp -a "$_ROLLBACK_DIR/3proxy.cfg" "$PROXY_CONF"' "$MOD/3proxy-socks5.sh" | head -1 | cut -d: -f1)
_H_INFO=$(grep -nF 'cat > /etc/3proxy/install.info' "$MOD/3proxy-socks5.sh" | head -1 | cut -d: -f1)
[ -n "$_H_BK" ] && [ -n "$_H_CFG" ] && [ -n "$_H_ACT" ] && [ -n "$_H_RS" ] && [ -n "$_H_INFO" ] && \
[ "$_H_BK" -lt "$_H_CFG" ] && [ "$_H_CFG" -lt "$_H_ACT" ] && [ "$_H_ACT" -lt "$_H_RS" ] && [ "$_H_RS" -lt "$_H_INFO" ] && ok || \
bad "HIGH-1 ordering broken (bk=$_H_BK cfg=$_H_CFG act=$_H_ACT rs=$_H_RS info=$_H_INFO)"
# M7: remove_rules clears the nft table + ban memory.
_R_START=$(grep -nF 'remove_rules() {' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
_R_NFT=$(grep -nF 'nft delete table inet nexoshield' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
_R_BAN=$(grep -nF ': > "$BANNED_LIST"' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
[ -n "$_R_START" ] && [ -n "$_R_NFT" ] && [ -n "$_R_BAN" ] && [ "$_R_START" -lt "$_R_NFT" ] && [ "$_R_NFT" -lt "$_R_BAN" ] && ok || \
bad "M7 remove_rules does not clear nft + ban memory (start=$_R_START nft=$_R_NFT ban=$_R_BAN)"
# F5: no /tmp/autoban literals left in src; assembled defaults /run.
! grep -rn '/tmp/autoban' "$ROOT/src/" | grep -q . && ok || bad "F5 /tmp/autoban literal remains in src/"
grep -q 'WATCH_LIST="/run/nexoshield/autoban_watch"' "$MOD/auto-ban.sh" && ok || bad "F5 daemon watch default not /run"

# ── F11: menu unban validator ────────────────────────────────
extract_fn nx_valid_ip_or_cidr "$MOD/proxy-menu.sh" > "$MOD/valid.sh"
# shellcheck disable=SC1091
. "$MOD/valid.sh"
nx_valid_ip_or_cidr 1.2.3.4 && nx_valid_ip_or_cidr 10.0.0.0/24 && nx_valid_ip_or_cidr 2001:db8::1 && nx_valid_ip_or_cidr 2001:db8::/32 && ok || bad "F11 validator rejects valid input"
nx_valid_ip_or_cidr 010.0.0.1 && bad "F11 validator accepts leading-zero octet" || ok
nx_valid_ip_or_cidr 999.1.1.1 && bad "F11 validator accepts out-of-range octet" || ok
nx_valid_ip_or_cidr 1.2.3.4/33 && bad "F11 validator accepts /33" || ok
nx_valid_ip_or_cidr "not-an-ip" && bad "F11 validator accepts garbage" || ok

# ── MED-6/F6: dispatch exit codes (verbatim case blocks) ─────
# run_dispatch prints the subshell's stdout, then a final "rc=N"
# line. A bare invocation falls through the case and prints
# FELL-THROUGH (the menu still opens with no flags - that path is
# preserved by the non-empty-$1 guard).
run_dispatch() { # PROG STARTLINE ENDLINE -- ARGS...
    local prog="$1" start="$2" end="$3"; shift 3
    [ "$1" = "--" ] && shift
    sed -n "${start},${end}p" "$MOD/$prog" > "$T/case.sh"
    bash -c ". \"$T/stubs.sh\"; set -- \"\$@\"; . \"$T/case.sh\"; echo FELL-THROUGH" _ "$@" 2>/dev/null
    echo "rc=$?"
}
# Stubs for every action the dispatch blocks can call.
cat > "$T/stubs.sh" << 'STUB_EOF'
detect_env() { return 0; }
do_install() { return "${ACTION_RC:-0}"; }
remove_rules() { return "${ACTION_RC:-0}"; }
show_status() { return 0; }
exempt_check() { return 0; }
flush_autobans() { return 0; }
show_thresholds() { return 0; }
apply_sysctl_hardening() { return 0; }
apply_iptables() { return 0; }
apply_fail2ban() { return 0; }
setup_autoban() { return 0; }
manage_whitelist() { return 0; }
setup_tc() { return 0; }
install_proxy() { return "${ACTION_RC:-0}"; }
uninstall_proxy() { return "${ACTION_RC:-0}"; }
show_stats() { return "${ACTION_RC:-0}"; }
show_info() { return "${ACTION_RC:-0}"; }
delete_proxy_user() { return "${ACTION_RC:-0}"; }
set_proxy_password() { return "${ACTION_RC:-0}"; }
regen_proxy_traffic_accum() { return 0; }
nx_status_plain() { return 0; }
nx_bans_plain() { return 0; }
systemctl() { return "${SYSTEMCTL_RC:-0}"; }
tail() { return 0; }
journalctl() { return 0; }
tc() { return 0; }
ip() { if [ "${1:-}" = "route" ]; then echo "default via 10.0.0.1 dev eth0"; fi; return 0; }
VERSION="3.18.0"
PROXY_LOG_DIR="$T/logs"
STATE_FILE="$T/state.conf"
SCRIPT_VERSION="3.18.0"
STUB_EOF
# Antiddos dispatch bounds (comment line -> esac).
_A_START=$(($(grep -n '^# CLI args' "$MOD/antiddos.sh" | head -1 | cut -d: -f1) + 1))
_A_END=$(awk -v s="$_A_START" 'NR>=s && /^esac/{print NR; exit}' "$MOD/antiddos.sh")
ACTION_RC=0; export ACTION_RC
[ "$(run_dispatch antiddos.sh "$_A_START" "$_A_END" -- --bogus | tail -1)" = "rc=2" ] && ok || bad "F6 antiddos unknown flag did not exit 2"
ACTION_RC=1; export ACTION_RC
[ "$(run_dispatch antiddos.sh "$_A_START" "$_A_END" -- --install | tail -1)" = "rc=1" ] && ok || bad "MED-6 antiddos --install did not propagate failure"
ACTION_RC=0; export ACTION_RC
run_dispatch antiddos.sh "$_A_START" "$_A_END" -- | grep -q FELL-THROUGH && ok || bad "antiddos bare invocation must still fall through to the menu"
# 3proxy dispatch bounds.
_P_START=$(($(grep -n 'CLI flags (called from proxy-menu' "$MOD/3proxy-socks5.sh" | head -1 | cut -d: -f1) + 1))
_P_END=$(awk -v s="$_P_START" 'NR>=s && /^esac/{print NR; exit}' "$MOD/3proxy-socks5.sh")
ACTION_RC=0; export ACTION_RC
[ "$(run_dispatch 3proxy-socks5.sh "$_P_START" "$_P_END" -- --bogus | tail -1)" = "rc=2" ] && ok || bad "F6 3proxy unknown flag did not exit 2"
ACTION_RC=1; export ACTION_RC
[ "$(run_dispatch 3proxy-socks5.sh "$_P_START" "$_P_END" -- --install | tail -1)" = "rc=1" ] && ok || bad "MED-6 3proxy --install did not propagate failure"
SYSTEMCTL_RC=1; export SYSTEMCTL_RC
[ "$(run_dispatch 3proxy-socks5.sh "$_P_START" "$_P_END" -- --restart | tail -1)" = "rc=1" ] && ok || bad "MED-6 3proxy --restart did not propagate systemctl failure"
SYSTEMCTL_RC=0; export SYSTEMCTL_RC
# Menu dispatch bounds.
_M_START=$(($(grep -n 'CLI (v3.7)' "$MOD/proxy-menu.sh" | head -1 | cut -d: -f1) + 1))
_M_END=$(awk -v s="$_M_START" 'NR>=s && /^esac/{print NR; exit}' "$MOD/proxy-menu.sh")
[ "$(run_dispatch proxy-menu.sh "$_M_START" "$_M_END" -- --bogus | tail -1)" = "rc=2" ] && ok || bad "F6 menu unknown flag did not exit 2"
run_dispatch proxy-menu.sh "$_M_START" "$_M_END" -- --help | grep -q "Usage: shield" && ok || bad "F13 menu --help still says proxy-menu.sh"

echo "audit fixes 3.18.0: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
