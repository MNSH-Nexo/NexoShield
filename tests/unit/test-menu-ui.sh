#!/usr/bin/env bash
# UI framework render/navigation test (v3.7 redesign): assembles
# proxy-menu.sh from its parts exactly like tools/build.py, stubs the
# system surface, and drives the menus with scripted input.
set -uo pipefail
cd "$(dirname "$0")/../.."
[ "$(id -u)" = "0" ] || { echo "menu ui: skipped (needs root for the menu's own guard)"; exit 0; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state"

cat > "$TMP/bin/systemctl" <<'EOF'
#!/bin/bash
case "$1" in
    is-active) echo active ;;
    is-enabled) echo enabled ;;
esac
exit 0
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/bash
echo 203.0.113.10
EOF
cat > "$TMP/bin/ip" <<'EOF'
#!/bin/bash
case "$*" in
    *route*) echo "default via 203.0.113.1 dev eth0 proto static" ;;
    *addr*) echo "    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0" ;;
esac
exit 0
EOF
for c in tc iptables ip6tables fail2ban-client; do
    printf '#!/bin/bash\nexit 0\n' > "$TMP/bin/$c"
done
chmod +x "$TMP/bin/"*

printf '%s\n' "1.2.3.4 1700000000 14400" "5.6.7.8 1700000000 14400" > "$TMP/state/banned.list"
printf '%s\n' "9.9.9.8 20001 1700000000 soft" > "$TMP/state/throttled.list"
printf '%s\n' "203.0.113.7" "198.51.100.0/24" "# comment" > "$TMP/state/whitelist.list"
touch "$TMP/state/state.conf"
printf '%s\n' "9.9.9.9 35 0 1700000000 0 0 0" "8.8.8.8 90 0 1700000000 0 0 0" > "$TMP/rep.dat"

VER="$(cat VERSION)"
cat src/modules/menu/00-header.sh src/modules/menu/05-ui.sh \
    src/modules/menu/10-proxy-menu.sh src/modules/menu/20-sysctl-monitor-menus.sh \
    src/modules/menu/30-monitor-dashboard.sh src/modules/menu/40-security-services-system.sh \
    src/modules/menu/50-antiddos-menu.sh src/modules/menu/60-autoban-main.sh \
    | sed "s/@@VERSION@@/$VER/g" > "$TMP/proxy-menu.sh"

export PATH="$TMP/bin:$PATH" NX_UI_STDIN=1 NX_STATE_DIR="$TMP/state" NX_SCORE_FILE="$TMP/rep.dat"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
run_menu() { printf '%b' "$1" | timeout 20 bash "$TMP/proxy-menu.sh" 2>/dev/null; }

OUT=$(run_menu '0\n')
echo "$OUT" | grep -q "NexoShield" && ok || bad "home: banner missing"
echo "$OUT" | grep -q "Overview" && ok || bad "home: dashboard panel missing"
echo "$OUT" | grep -q "9.9.9.9 — score 35" && ok || bad "home: lowest-reputation row missing"
echo "$OUT" | grep -q "SOCKS5 Proxy" && ok || bad "home: menu entries missing"

OUT=$(run_menu '3\n0\n0\n')
echo "$OUT" | grep -q "Anti-DDoS Protection" && ok || bad "nav: antiddos screen missing"
echo "$OUT" | grep -q "Auto-ban control" && ok || bad "nav: antiddos entries missing"

OUT=$(run_menu '1\n0\n0\n')
echo "$OUT" | grep -q "SOCKS5 Proxy (3proxy)" && ok || bad "nav: proxy screen missing"
echo "$OUT" | grep -q "Suspicious IPs" && ok || bad "nav: proxy entries missing"

OUT=$(bash "$TMP/proxy-menu.sh" --status 2>/dev/null)
echo "$OUT" | grep -q "banned:    2" && ok || bad "--status: ban count wrong: $OUT"
echo "$OUT" | grep -q "antiddos:  installed" && ok || bad "--status: install state wrong"

OUT=$(bash "$TMP/proxy-menu.sh" --bans 2>/dev/null)
echo "$OUT" | grep -q "1.2.3.4" && ok || bad "--bans: seeded ban missing"

OUT=$(bash "$TMP/proxy-menu.sh" --version 2>/dev/null)
[ "$OUT" = "NexoShield v$VER" ] && ok || bad "--version: got '$OUT'"

echo "menu ui: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
