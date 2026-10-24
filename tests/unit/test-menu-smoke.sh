#!/bin/bash
# Menu smoke suite: walks the REAL assembled proxy-menu.sh through
# every top-level section and every Monitoring sub-screen with
# scripted input (NX_UI_STDIN=1) and stubbed system services, and
# asserts the screens render and the process exits cleanly.
# This is the end-to-end guard for "the menu sections work".
set -u

# This suite exercises root-only paths (the menu refuses non-root;
# the delete fixture lives in /etc). CI runners are unprivileged
# but carry passwordless sudo: re-exec once as root, else skip.
if [ "$(id -u)" -ne 0 ]; then
    if [ -z "${NX_SUDOED:-}" ] && sudo -n true 2>/dev/null; then
        NX_SUDOED=1 exec sudo -n bash "$0" "$@"
    fi
    echo "  SKIP: requires root (no passwordless sudo available)"
    exit 0
fi
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
python3 "$ROOT/tools/build.py" --emit-modules "$W/mod" >/dev/null 2>&1 || { echo "  FAIL: emit"; exit 1; }

# ── Stubs ────────────────────────────────────────────────────
mkdir -p "$W/bin" "$W/state"
cat > "$W/bin/systemctl" <<'EOF'
#!/bin/bash
case "$1" in
    is-active) echo inactive; exit 3 ;;
    is-enabled) echo disabled; exit 1 ;;
    list-unit-files) exit 0 ;;
    status) echo "stub status for $2"; exit 0 ;;
    *) echo "systemctl $*" >> "$STUB_LOG"; exit 0 ;;
esac
EOF
cat > "$W/bin/fail2ban-client" <<'EOF'
#!/bin/bash
if [ "${2:-}" = "" ]; then echo "Status: x"; echo "Jail list: sshd, 3proxy-ddos"; exit 0; fi
echo "Status for the jail: $2"; echo "Currently banned: 0"; echo "Banned IP list:"; exit 0
EOF
cat > "$W/bin/iptables" <<'EOF'
#!/bin/bash
case " $* " in
    *" -S "*) echo "-P INPUT ACCEPT"; echo "-A INPUT -j DROP -m comment --comment x" ;;
    *" -L "*) echo "Chain INPUT (policy ACCEPT)"; echo "target prot opt source destination" ;;
    *) : ;;
esac
exit 0
EOF
cat > "$W/bin/ip6tables" <<'EOF'
#!/bin/bash
exit 0
EOF
cat > "$W/bin/tc" <<'EOF'
#!/bin/bash
echo "class htb 1:10 root rate 1000Mbit"
exit 0
EOF
cat > "$W/bin/ip" <<'EOF'
#!/bin/bash
case " $* " in
    *"route show default"*) echo "default via 10.0.0.1 dev eth0 proto static" ;;
    *"addr show"*) echo "2: eth0: <UP>"; echo "    inet 10.0.0.5/24 scope global eth0" ;;
    *) : ;;
esac
exit 0
EOF
cat > "$W/bin/curl" <<'EOF'
#!/bin/bash
exit 1
EOF
cat > "$W/bin/journalctl" <<'EOF'
#!/bin/bash
echo "stub journal line"
exit 0
EOF
cat > "$W/bin/less" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod +x "$W/bin/"*
export STUB_LOG="$W/stub.log"; : > "$STUB_LOG"

# ── Fixtures ─────────────────────────────────────────────────
printf '203.0.113.9 1761300000 1761307200 autoban\n' > "$W/state/banned.list"
printf '198.51.100.7 9001\n' > "$W/state/throttled.list"
printf '192.0.2.55|55|1761300000|1761300000|130|0|0|0|0|0|0\n' > "$W/state/reputation.dat"

# ── Scripted walk ────────────────────────────────────────────
# Monitoring: 2 Connections, 3 CPU&RAM, 4 Disk, 6 autoban log,
# 7 top IPs, 1 live dashboard (q + sacrificial blank), 5 Logs > 4
# journal, 0 back. Then Proxy > 10 Suspicious > skip, Security >
# 1 blocked + 6 autoban status, Anti-DDoS > 5 whitelist note, Sysctl > 3
# values, Services in/out, System > 1 info, Exit.
cat > "$W/input.txt" <<'EOF'
4
2

3

4

6

7

1
x
q

5
4
0
0
1
10

0
5
1

6

0
3
5

0
2
3

0
6
0
7
1

0
8

0
EOF

OUT="$W/out.txt"
NX_UI_STDIN=1 NX_STATE_DIR="$W/state" NX_SCORE_FILE="$W/state/reputation.dat" \
NX_THROTTLE_LIST="$W/state/throttled.list" NX_THROTTLE_MIRROR="$W/state/throttled.list" \
TERM=xterm PATH="$W/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
timeout 60 bash "$W/mod/proxy-menu.sh" < "$W/input.txt" > "$OUT" 2>&1
RC=$?
[ "$RC" -eq 0 ] && ok || bad "menu walk exit code $RC"
for marker in "Monitoring" "LIVE THREAT MONITOR" "Could not reach the update server" "SOCKS5 Proxy (3proxy)" \
              "Threat IPs" "Security" "Anti-DDoS Protection" "Whitelist — exempt an IP from ALL layers" "exempt from every layer" \
              "Network Optimization" "Services" "System" "Hostname:"; do
    grep -q -- "$marker" "$OUT" && ok || bad "screen marker missing: $marker"
done
grep -q 'command not found' "$OUT" && bad "command-not-found in walk output" || ok
grep -q 'syntax error' "$OUT" && bad "syntax error in walk output" || ok
grep -q 'unbound variable' "$OUT" && bad "unbound variable in walk output" || ok

# ── CLI views ────────────────────────────────────────────────
for flag in --version --help --status --bans; do
    NX_STATE_DIR="$W/state" NX_SCORE_FILE="$W/state/reputation.dat" \
    PATH="$W/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    timeout 20 bash "$W/mod/proxy-menu.sh" "$flag" > "$W/cli.txt" 2>&1
    [ $? -eq 0 ] && ok || bad "CLI $flag exit code"
done
NX_STATE_DIR="$W/state" PATH="$W/bin:/usr/bin:/bin" \
    timeout 20 bash "$W/mod/proxy-menu.sh" --version 2>/dev/null | grep -q 'NexoShield v' && ok || bad "--version output"

echo "menu smoke: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
