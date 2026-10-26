#!/bin/bash
# Proxy traffic-counting suite (v3.17.0): the stats rules are
# target-less, so they only count packets that REACH them. Field
# report: stats_in buried at INPUT #811 below the ESTABLISHED
# accept counted SYNs only (282 pkts / 14 KB while the interface
# moved ~515 MB); stats_out below a blanket OUTPUT accept counted
# exactly zero. The pin must move shadowed rules to position 1
# AND must not touch counters that are already pinned; the
# accumulator must record cumulative totals across rule
# recreations and reboots, and never lose totals when rules vanish.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

MOD=$(mktemp -d)
RULES_DIR=$(mktemp -d)
STATE_DIR=$(mktemp -d)
cleanup() { rm -rf "$MOD" "$RULES_DIR" "$STATE_DIR"; }
trap cleanup EXIT
touch "$RULES_DIR/INPUT" "$RULES_DIR/OUTPUT"

python3 "$ROOT/tools/build.py" --emit-modules "$MOD" >/dev/null 2>&1 || { echo "  FAIL: emit"; exit 1; }
extract_fn() {
    awk -v n="$1" 'BEGIN{p=0} $0 ~ "^" n "\\(\\) \\{" {p=1} p{print} p && /^\}/{exit}' "$2"
}
for fn in nx_proxy_stats_top nx_pin_proxy_stats_rules nx_proxy_stats_bytes nx_proxy_traffic_accum; do
    extract_fn "$fn" "$MOD/3proxy-socks5.sh" >> "$MOD/fn.sh"
done
grep -q 'nx_proxy_traffic_accum' "$MOD/fn.sh" || { echo "  FAIL: lib functions not found in assembled 3proxy-socks5.sh"; exit 1; }

# ── Fake iptables: ordered rule lists with counters ──────────
# File per chain; each line: KIND|PKTS|BYTES (KIND: in/out/other).
iptables() {
    local cmd="$1" chain="$2" kind
    case "$cmd" in
        -S)
            printf -- '-P %s ACCEPT\n' "$chain"
            while IFS='|' read -r kind _pkts _bytes; do
                case "$kind" in
                    in)  printf -- '-A %s -p tcp --dport 1080 -m comment --comment 3proxy_stats_in\n' "$chain" ;;
                    out) printf -- '-A %s -p tcp --sport 1080 -m comment --comment 3proxy_stats_out\n' "$chain" ;;
                    *)   printf -- '-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n' "$chain" ;;
                esac
            done < "$RULES_DIR/$chain" 2>/dev/null || true
            ;;
        -L)
            printf 'Chain %s (policy ACCEPT 0 packets, 0 bytes)\n' "$chain"
            printf '    pkts      bytes target     prot opt in     out     source               destination\n'
            while IFS='|' read -r kind pkts bytes; do
                case "$kind" in
                    in)  printf '  %s %s            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:1080 /* 3proxy_stats_in */\n' "$pkts" "$bytes" ;;
                    out) printf '  %s %s            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:1080 /* 3proxy_stats_out */\n' "$pkts" "$bytes" ;;
                    *)   printf '  %s %s            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp /* generic */\n' "$pkts" "$bytes" ;;
                esac
            done < "$RULES_DIR/$chain" 2>/dev/null || true
            ;;
        -I)
            kind=other
            case "$*" in *3proxy_stats_in*) kind=in ;; *3proxy_stats_out*) kind=out ;; esac
            { printf '%s|0|0\n' "$kind"; cat "$RULES_DIR/$chain" 2>/dev/null; } > "$RULES_DIR/$chain.tmp" && mv "$RULES_DIR/$chain.tmp" "$RULES_DIR/$chain"
            ;;
        -D)
            kind=other
            case "$*" in *3proxy_stats_in*) kind=in ;; *3proxy_stats_out*) kind=out ;; esac
            awk -F'|' -v k="$kind" 'BEGIN{d=0} $1==k && !d {d=1; next} {print}' "$RULES_DIR/$chain" > "$RULES_DIR/$chain.tmp" && mv "$RULES_DIR/$chain.tmp" "$RULES_DIR/$chain"
            ;;
    esac
}
add_rule() { printf '%s|%s|%s\n' "$2" "$3" "$4" >> "$RULES_DIR/$1"; }
first_kind() { head -1 "$RULES_DIR/$1" 2>/dev/null | cut -d'|' -f1; }
kind_counters() { grep "^$2|" "$RULES_DIR/$1" 2>/dev/null | head -1 | cut -d'|' -f2- | tr '|' ' '; }
set_counters() {
    awk -F'|' -v k="$2" -v p="$3" -v b="$4" 'BEGIN{d=0} $1==k && !d {$2=p; $3=b; d=1} {print $1"|"$2"|"$3}' "$RULES_DIR/$1" > "$RULES_DIR/$1.tmp" && mv "$RULES_DIR/$1.tmp" "$RULES_DIR/$1"
}
reset_chains() { : > "$RULES_DIR/INPUT"; : > "$RULES_DIR/OUTPUT"; }

# The accumulator reads the port from the config; stub it (the real
# one reads /etc/3proxy/3proxy.cfg, which tests must not touch).
nx_proxy_port_from_config() { echo 1080; }
export NX_PROXY_TRAFFIC_STATE="$STATE_DIR/traffic-total.state"
# shellcheck disable=SC1091
. "$MOD/fn.sh"

# (a) Shadowed rules move to position 1 (the v3.16.3 field shape).
reset_chains
add_rule INPUT other 0 0; add_rule INPUT in 282 14490
add_rule OUTPUT other 0 0; add_rule OUTPUT out 0 0
nx_pin_proxy_stats_rules 1080
[ "$(first_kind INPUT)" = "in" ] && [ "$(first_kind OUTPUT)" = "out" ] && ok || bad "shadowed rules not pinned to top"

# (b) Already-pinned rules are a NO-OP: counters preserved.
reset_chains
add_rule INPUT in 282 14490; add_rule OUTPUT out 500 9000
nx_pin_proxy_stats_rules 1080
[ "$(kind_counters INPUT in)" = "282 14490" ] && [ "$(kind_counters OUTPUT out)" = "500 9000" ] && ok || bad "re-pin destroyed healthy counters"

# (c) Missing rules are created at position 1.
reset_chains
nx_pin_proxy_stats_rules 1080
[ "$(first_kind INPUT)" = "in" ] && [ "$(first_kind OUTPUT)" = "out" ] && ok || bad "missing rules not created on top"

# (d) Accumulator lifecycle: first run, growth, rule recreation.
# add_rule args are KIND PKTS BYTES; the accumulator tracks BYTES.
reset_chains
add_rule INPUT in 1000 2000; add_rule OUTPUT out 1000 2000
nx_proxy_traffic_accum
[ "$(cat "$STATE_DIR/traffic-total.state")" = "2000 2000 2000 2000" ] && ok || bad "first accum run wrong: $(cat "$STATE_DIR/traffic-total.state" 2>/dev/null)"
set_counters INPUT in 1500 2600; set_counters OUTPUT out 1500 2600
nx_proxy_traffic_accum
[ "$(cat "$STATE_DIR/traffic-total.state")" = "2600 2600 2600 2600" ] && ok || bad "growth accum wrong: $(cat "$STATE_DIR/traffic-total.state" 2>/dev/null)"
# Rule recreation: counters restart at 0 and grow a little.
reset_chains
add_rule INPUT in 100 50; add_rule OUTPUT out 100 50
nx_proxy_traffic_accum
[ "$(cat "$STATE_DIR/traffic-total.state")" = "50 50 2650 2650" ] && ok || bad "recreation accum wrong: $(cat "$STATE_DIR/traffic-total.state" 2>/dev/null)"

# (e) Missing rules leave totals untouched.
reset_chains
nx_proxy_traffic_accum
[ "$(cat "$STATE_DIR/traffic-total.state")" = "50 50 2650 2650" ] && ok || bad "missing rules changed totals"

# (f) Accumulator self-heals shadowing (after the snapshot).
reset_chains
add_rule INPUT other 0 0; add_rule INPUT in 10 20
add_rule OUTPUT out 10 20
nx_proxy_traffic_accum
[ "$(first_kind INPUT)" = "in" ] && ok || bad "accumulator did not re-pin shadowed INPUT"

# (g) Static wiring: pin + accumulator shipped in both programs.
grep -q 'nx_pin_proxy_stats_rules "$PORT"' "$MOD/3proxy-socks5.sh" && ok || bad "3proxy setup does not pin stats"
grep -q 'nx_pin_proxy_stats_rules "$(nx_proxy_port_from_config)"' "$MOD/antiddos.sh" && ok || bad "antiddos apply does not re-pin stats"
_PIN_LINE=$(grep -n 'nx_pin_proxy_stats_rules "$(nx_proxy_port_from_config)"' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
_SAVE_LINE=$(grep -n 'save_static_rules "$IPTABLES_SAVE_FILE"' "$MOD/antiddos.sh" | head -1 | cut -d: -f1)
[ -n "$_PIN_LINE" ] && [ -n "$_SAVE_LINE" ] && [ "$_PIN_LINE" -lt "$_SAVE_LINE" ] && ok || bad "pin does not run before static save (pin=$_PIN_LINE save=$_SAVE_LINE)"
grep -q 'nx-proxy-traffic-accum.timer' "$MOD/3proxy-socks5.sh" && ok || bad "accumulator timer not installed by install_proxy"
grep -q 'Total recorded (cumulative)' "$MOD/3proxy-socks5.sh" && ok || bad "show_stats has no cumulative display"
grep -q 'nx-proxy-traffic-accum' "$MOD/3proxy-socks5.sh" && grep -q 'systemctl disable nx-proxy-traffic-accum.timer' "$MOD/3proxy-socks5.sh" && ok || bad "uninstall does not remove accumulator"

echo "proxy stats: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
