# @part modules/antiddos/30-fail2ban.sh - apply_fail2ban
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
apply_fail2ban() {
    command -v fail2ban-client >/dev/null 2>&1 || {
        warn "fail2ban not installed - installing..."
        if command -v apt-get >/dev/null 2>&1; then
            info "Running apt-get update first..."
            DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban 2>/dev/null || {
                warn "fail2ban install failed - skipping Layer-3"
                return
            }
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q fail2ban 2>/dev/null || {
                warn "fail2ban install failed - skipping Layer-3"
                return
            }
        else
            warn "Cannot install fail2ban - skipping Layer-3"
            return
        fi
    }
    info "Configuring fail2ban jails..."

    # ── Filter: 3proxy abuse ──────────────────────────
    cat > "$F2B_FILTER_DIR/3proxy-ddos.conf" << 'EOF'
[Definition]
# Our 3proxy logformat: L<date> <time> %U %C:%c %R:%r %O %I %E %T
# %E is the error code: 0 = success. The old regex matched EVERY
# connection line, so a legitimate heavy user (100 conns/60s) earned a
# 24h ban (BUG-017). Only lines with a NON-ZERO error code count now:
# fields after <HOST>:port are remote, bytes-out, bytes-in, then %E.
failregex = ^L\d+-\d+-\d+ \d+:\d+:\d+ \S+ <HOST>:\d+ \S+ \d+ \d+ [1-9][0-9]*\s
ignoreregex =
EOF

    # ── Filter: HTTP flood ────────────────────────────
    # Catches HTTP BURST mode (pipeline=500 requests per connection from same IP)
    cat > "$F2B_FILTER_DIR/http-flood.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s
ignoreregex = \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf)
EOF

    # ── Filter: connection flood (any TCP) ────────────
    # Catches slow-trickle and conn-hold modes: many connections from same IP
    # detected via kernel log (connlimit drop messages with [CONNLIMIT DROP] prefix)
    cat > "$F2B_FILTER_DIR/conn-flood.conf" << 'EOF'
[Definition]
# Matches [CONNLIMIT DROP] log lines written by our iptables LOG rule
failregex = \[CONNLIMIT DROP\].*SRC=<HOST>
ignoreregex =
EOF

    # ── Filter: port scan ─────────────────────────────
    cat > "$F2B_FILTER_DIR/portscan.conf" << 'EOF'
[Definition]
# Matches the [NX-SCAN] LOG rules in apply_iptables (Step 10). The old
# patterns waited for UFW blocks or a fantasy "iptables DROP" log format
# that nothing on this system emits, so the jail could never fire.
failregex = \[NX-SCAN\].*SRC=<HOST>
            kernel.*\[UFW BLOCK\].*SRC=<HOST>
ignoreregex =
EOF

    # ── Filter: xray/proxy logs ───────────────────────
    cat > "$F2B_FILTER_DIR/xray-proxy.conf" << 'EOF'
[Definition]
# Matches: failed handshake, timeout, connection reset from same IP
failregex = \[Warning\].*failed to read.*<HOST>
            \[Warning\].*timeout.*<HOST>
            rejected.*<HOST>
ignoreregex =
EOF

    # ── Jails ─────────────────────────────────────────
    # Build ignoreip from the FULL CF range list (753 ranges), chunked 6 per
    # line, so fail2ban NEVER bans a Cloudflare IP. Previously only 16 legacy
    # ranges were listed here, so CF IPs from newer ranges could get false bans.
    _F2B_IGNORE="127.0.0.1/8 ::1"
    # FR-1/FR-2 (BUG-028): fail2ban must ignore the WHOLE exempt set, not
    # just Cloudflare - the server's own IPs and the admin whitelist too.
    while IFS= read -r _F2B_SELF; do
        [ -n "$_F2B_SELF" ] && _F2B_IGNORE="$_F2B_IGNORE $_F2B_SELF/32"
    done < <(list_self_ips)
    # E-1 (exemption audit): the server's own IPv6 addresses belong in
    # ignoreip too - only ::1 was covered, so fail2ban could ban the
    # server's own global v6 (e.g. via the sshd jail).
    while IFS= read -r _F2B_SELF6; do
        [ -n "$_F2B_SELF6" ] && _F2B_IGNORE="$_F2B_IGNORE $_F2B_SELF6"
    done < <(list_self_ips6)
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r _F2B_WL; do
            _F2B_WL="${_F2B_WL%%#*}"; _F2B_WL="${_F2B_WL// /}"
            [ -n "$_F2B_WL" ] && _F2B_IGNORE="$_F2B_IGNORE $_F2B_WL"
        done < "$WHITELIST_FILE"
    fi
    # IPv6 (Wave 9): CF's v6 ranges join ignoreip too (they are few).
    for _F2B_CF6 in "${CF6_RANGES[@]}"; do
        _F2B_IGNORE="$_F2B_IGNORE $_F2B_CF6"
    done
    _F2B_CF_N=0
    for _F2B_CF in "${CF_RANGES[@]}"; do
        _F2B_CF_N=$((_F2B_CF_N + 1))
        if [ $((_F2B_CF_N % 6)) -eq 1 ]; then
            _F2B_IGNORE="$(printf '%s\n            %s' "$_F2B_IGNORE" "$_F2B_CF")"
        else
            _F2B_IGNORE="$(printf '%s %s' "$_F2B_IGNORE" "$_F2B_CF")"
        fi
    done

    # Field finding T-1 (live test, 2026-10-23): on journal-only images
    # (Debian 12 cloud ships without rsyslog) the classic log files do
    # not exist, and fail2ban refuses to start when ANY enabled jail
    # has no log file at all - the whole service died while the
    # installer reported success. Ensure the syslog-family files exist
    # (empty is fine; rsyslog fills them when present). With no rsyslog
    # at all, kernel/auth jails read the systemd journal instead -
    # otherwise they would run but stay blind forever.
    local _lf
    for _lf in /var/log/kern.log /var/log/auth.log /var/log/secure; do
        [ -e "$_lf" ] || touch "$_lf" 2>/dev/null || true
    done
    local KERN_BACKEND="" SSH_BACKEND="" HTTP_ENABLED="true"
    if ! command -v rsyslogd >/dev/null 2>&1 && command -v journalctl >/dev/null 2>&1; then
        KERN_BACKEND='backend   = systemd
journalmatch = _TRANSPORT=kernel'
        SSH_BACKEND='backend   = systemd'
    fi
    if [ ! -f /var/log/nginx/access.log ] && [ ! -f /var/log/apache2/access.log ]; then
        HTTP_ENABLED="false"
        info "http-flood jail disabled: no nginx/apache access log on this server"
    fi

    cat > "$F2B_JAIL_DIR/antiddos.conf" << EOF
# Anti-DDoS fail2ban jails — generated $(date)
# CF IPs are ignored via ignoreip (no false bans)

[DEFAULT]
# ignoreip built from the full CF range list (${#CF_RANGES[@]} ranges)
ignoreip = ${_F2B_IGNORE}

[3proxy-ddos]
enabled   = true
filter    = 3proxy-ddos
# 3proxy rotates daily: the live file is access.log.YYYY.MM.DD (T-2).
logpath   = /var/log/3proxy/access.log.*
maxretry  = 100
findtime  = 60
bantime   = 86400
action    = iptables-allports[name=3proxy-ddos, protocol=all]

[http-flood]
enabled   = ${HTTP_ENABLED}
filter    = http-flood
# Combined-log-format web servers only. 3proxy's access.log is NOT an
# HTTP access log; its floods are covered by the daemon and 3proxy-ddos.
logpath   = /var/log/nginx/access.log
            /var/log/apache2/access.log
# 200 requests in 30s = flood (normal user: <50 req/30s)
# HTTP BURST mode sends 500 pipelined reqs per conn → caught immediately
maxretry  = 200
findtime  = 30
bantime   = 86400
action    = iptables-allports[name=http-flood, protocol=all]

[conn-flood]
enabled   = true
filter    = conn-flood
logpath   = /var/log/kern.log
            /var/log/syslog
${KERN_BACKEND}
# 20 iptables DROP events from same IP in 10s = flood
# connlimit DROP fires when IP exceeds CONN_LIMIT_PER_IP connections
maxretry  = 20
findtime  = 10
bantime   = 86400
action    = iptables-allports[name=conn-flood, protocol=all]

[portscan]
enabled   = true
filter    = portscan
logpath   = /var/log/kern.log
            /var/log/syslog
${KERN_BACKEND}
maxretry  = 5
findtime  = 30
bantime   = 86400
action    = iptables-allports[name=portscan, protocol=all]

[sshd-aggressive]
enabled   = true
filter    = sshd
logpath   = /var/log/auth.log
            /var/log/secure
${SSH_BACKEND}
maxretry  = 3
findtime  = 30
bantime   = 86400
action    = iptables-allports[name=sshd-aggressive, protocol=all]

[xray-proxy]
enabled   = false
filter    = xray-proxy
logpath   = /var/log/xray/error.log
            /var/log/xray/access.log
maxretry  = 20
findtime  = 60
bantime   = 3600
action    = iptables-allports[name=xray-proxy, protocol=all]
EOF

    # Verify, never assume (T-1): a written config is not a running
    # jail set. Test the configuration, then check the real service.
    if command -v fail2ban-client >/dev/null 2>&1 && \
        ! fail2ban-client -t >/dev/null 2>&1; then
        warn "fail2ban: configuration test FAILED - jails not applied (diagnose: fail2ban-client -t)"
        return 1
    fi
    systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        ACTIVE_JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | \
            sed 's/.*://;s/,/ /g' | wc -w || echo 0)
        success "fail2ban: $ACTIVE_JAILS jails active"
    else
        warn "fail2ban: service is NOT running after apply (diagnose: systemctl status fail2ban)"
        return 1
    fi
}

# Regenerate the jail file (its ignoreip is built from the live exempt
# set) and reload fail2ban. Called by the whitelist manager after every
# add/remove so a whitelisted IP is exempt in fail2ban immediately (FR-1).
update_f2b_ignoreip() {
    [ -f "$F2B_JAIL_DIR/antiddos.conf" ] || return 0
    apply_fail2ban >/dev/null 2>&1 || true
    fail2ban-client reload >/dev/null 2>&1 || \
        systemctl reload fail2ban >/dev/null 2>&1 || true
}

# ════════════════════════════════════════════════
# LAYER 4: Smart throttle+ban (auto-ban.sh)
# Pipeline: watch (45s) → throttle 100Mbps → ban 4h
# CF IPs: ALWAYS exempt
# ════════════════════════════════════════════════
