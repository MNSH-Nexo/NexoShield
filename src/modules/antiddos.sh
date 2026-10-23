#!/bin/bash
# ============================================================
#  Anti-DDoS Protection Manager v@@VERSION@@
#
#  Layers:
#    1. Kernel (sysctl hardening + tight conntrack timeouts)
#    2. iptables (SYNPROXY / hashlimit / connlimit / scans)
#       *** CF IPs ALWAYS whitelisted — NO limits ***
#    3. fail2ban (3proxy-ddos / portscan / sshd / xray)
#    4. Smart throttle+ban (watch → throttle → ban pipeline)
#    5. tc bandwidth control (CF=unlimited, others=500Mbps)
#
#  Key lessons from production:
#    - CF IPs must be whitelisted BEFORE any rate-limit rule
#    - rp_filter=0 for servers with multiple public IPs
#    - SYN hashlimit must NOT apply to CF IPs
#    - tc must work on SRC IP (not DST), else tunnel breaks
#    - keepalive_time=30s detects dead connections fast (Slowloris)
#    - conntrack established=120s cleans dead conns quickly
#    - auto-ban: 120 active conns = watch, 300 conns = instant ban (4h)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_VERSION="@@VERSION@@"
LOG_FILE="/var/log/antiddos.log"
STATE_FILE="/etc/antiddos/state.conf"
BANNED_LIST="/etc/antiddos/banned.list"
F2B_FILTER_DIR="/etc/fail2ban/filter.d"
F2B_JAIL_DIR="/etc/fail2ban/jail.d"
SYSCTL_FILE="/etc/sysctl.d/98-antiddos-hardening.conf"
IPTABLES_SAVE_FILE="/etc/antiddos/iptables-antiddos.rules"
AUTOBAN_SCRIPT="/opt/proxy-manager/auto-ban.sh"
AUTOBAN_SERVICE="/etc/systemd/system/auto-ban.service"
WHITELIST_FILE="/etc/antiddos/whitelist.list"

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1

mkdir -p /etc/antiddos
touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
touch "$BANNED_LIST" && chmod 600 "$BANNED_LIST"

log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
info()    { echo -e "  ${CYAN}->${NC}  $*"; log "INFO: $*"; }
success() { echo -e "  ${GREEN}✓${NC}  $*"; log "OK: $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; log "WARN: $*"; }
err()     { echo -e "  ${RED}✗${NC}  $*"; log "ERR: $*"; }
sep()     { echo -e "${CYAN}════════════════════════════════════════════════${NC}"; }

# ── Cloudflare IP ranges (NEVER rate-limited) ─────────────
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi

# Get all server's own public IPs (auto-whitelist)
get_server_ips() {
    ip -4 addr show 2>/dev/null | grep 'inet ' | \
        grep -v '127\.\|10\.\|192\.168\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.' | \
        awk '{print $2}' | cut -d/ -f1
}

# Detect environment
detect_env() {
    RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 512)
    RAM_MB="${RAM_MB//[^0-9]/}"; RAM_MB="${RAM_MB:-512}"
    CPU_CORES=$(nproc 2>/dev/null || echo 1)
    CPU_CORES="${CPU_CORES//[^0-9]/}"; CPU_CORES="${CPU_CORES:-1}"
    VIRT_TYPE="bare-metal"
    systemd-detect-virt 2>/dev/null | grep -qi kvm    && VIRT_TYPE="kvm"    || true
    systemd-detect-virt 2>/dev/null | grep -qi lxc    && VIRT_TYPE="lxc"    || true
    [ -f /proc/vz/version ]                            && VIRT_TYPE="openvz" || true

    SYNPROXY_OK=0;  modprobe xt_SYNPROXY  2>/dev/null && SYNPROXY_OK=1  || true
    HASHLIMIT_OK=0; modprobe xt_hashlimit 2>/dev/null && HASHLIMIT_OK=1 || true
    CONNLIMIT_OK=0; modprobe xt_connlimit 2>/dev/null && CONNLIMIT_OK=1 || true
    CONNTRACK_OK=0; modprobe nf_conntrack 2>/dev/null && CONNTRACK_OK=1 || true

    # Detect main network interface
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    MAIN_IF=${MAIN_IF:-eth0}

    # Count public IPs (for rp_filter decision)
    PUBLIC_IP_COUNT=$(ip -4 addr show 2>/dev/null | grep 'inet ' | \
        grep -v '127\.\|10\.\|192\.168\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.' | wc -l || echo 0)

    # Scale rate limits by RAM
    if [ "$RAM_MB" -ge 4096 ]; then
        SYN_LIMIT="2000/sec"; SYN_BURST="4000"
        UDP_LIMIT="500/sec";  UDP_BURST="1000"
        ICMP_LIMIT="100/sec"; ICMP_BURST="200"
        CONN_LIMIT_PER_IP="200"
        NEW_CONN_RATE="200/sec"; NEW_CONN_BURST="400"
        # HTTP_REQ_RATE: packets on ESTABLISHED TCP per IP
        # A heavy download = ~1500byte packets = ~800 pkt/s per Gbps
        # Normal user with 100Mbps fiber download = ~80 pkt/s — set 2000 to be safe
        HTTP_REQ_RATE="2000/sec"; HTTP_REQ_BURST="4000"
        BW_PER_IP_MBIT="200"
    elif [ "$RAM_MB" -ge 2048 ]; then
        SYN_LIMIT="1000/sec"; SYN_BURST="2000"
        UDP_LIMIT="300/sec";  UDP_BURST="600"
        ICMP_LIMIT="50/sec";  ICMP_BURST="100"
        CONN_LIMIT_PER_IP="100"
        NEW_CONN_RATE="100/sec"; NEW_CONN_BURST="200"
        HTTP_REQ_RATE="1000/sec"; HTTP_REQ_BURST="2000"
        BW_PER_IP_MBIT="100"
    else
        SYN_LIMIT="500/sec";  SYN_BURST="1000"
        UDP_LIMIT="150/sec";  UDP_BURST="300"
        ICMP_LIMIT="25/sec";  ICMP_BURST="50"
        CONN_LIMIT_PER_IP="50"
        NEW_CONN_RATE="50/sec"; NEW_CONN_BURST="100"
        HTTP_REQ_RATE="500/sec"; HTTP_REQ_BURST="1000"
        BW_PER_IP_MBIT="50"
    fi
}

# ════════════════════════════════════════════════
# LAYER 1: Kernel hardening (sysctl)
# ════════════════════════════════════════════════
apply_sysctl_hardening() {
    info "Applying kernel hardening (sysctl)..."

    # Decide rp_filter: multi-IP servers must use 0
    # (rp_filter=1 breaks asymmetric routing on servers with multiple public IPs)
    RP_FILTER=1
    [ "${PUBLIC_IP_COUNT:-0}" -gt 1 ] && RP_FILTER=0

    cat > "$SYSCTL_FILE" << EOF
# Anti-DDoS Kernel Hardening — $(date)
# Generated by antiddos.sh v${SCRIPT_VERSION}
# rp_filter=$RP_FILTER (multi-IP detection: $PUBLIC_IP_COUNT public IPs)

# ── SYN Flood ─────────────────────────────────
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# ── Connection & TIME_WAIT ────────────────────
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_max_tw_buckets = 400000
# tcp_max_orphans: limits half-open connections (Hold/Heavy attack defense)
net.ipv4.tcp_max_orphans = 4096
# Keepalive 30s: detect dead connections fast (Slowloris mitigation)
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 3

# ── IP Spoofing & Redirects ───────────────────
net.ipv4.conf.all.rp_filter = $RP_FILTER
net.ipv4.conf.default.rp_filter = $RP_FILTER
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── ICMP ─────────────────────────────────────
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089

# ── conntrack — TIGHT timeouts ────────────────
# syn_recv=8s: attacker's half-open connections expire fast
# established=120s: dead tunnels cleared quickly
# udp=15s, icmp=5s: flood states expire fast
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 8
net.netfilter.nf_conntrack_tcp_timeout_established = 120
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_udp_timeout = 15
# stream=120: WARP/WireGuard keepalive (25s) must never expire the tunnel.
# 120 = ~5x keepalive — absorbs packet-loss/jitter, still < kernel default (180).
# UDP-flood protection comes from hashlimit, not this timeout, so it's safe.
net.netfilter.nf_conntrack_udp_timeout_stream = 120
net.netfilter.nf_conntrack_icmp_timeout = 5
net.netfilter.nf_conntrack_generic_timeout = 60

# ── ARP ──────────────────────────────────────
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192
EOF
    chmod 644 "$SYSCTL_FILE"

    APPLIED=0; SKIPPED=0
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# || -z "${line// }" ]] && continue
        KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
        VAL=$(echo "$line" | cut -d= -f2- | tr -d ' ')
        [ -z "$KEY" ] || [ -z "$VAL" ] && continue
        if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
            APPLIED=$((APPLIED+1))
        else
            SKIPPED=$((SKIPPED+1))
            sed -i "s|^${KEY} =|# [N/A] ${KEY} =|" "$SYSCTL_FILE" 2>/dev/null || true
        fi
    done < "$SYSCTL_FILE"
    success "Kernel: $APPLIED params applied${SKIPPED:+, $SKIPPED skipped}"
}

# ════════════════════════════════════════════════
# LAYER 2: iptables rules
# CRITICAL: CF IPs whitelisted BEFORE any rate-limit
# ════════════════════════════════════════════════
apply_iptables() {
    info "Applying iptables rules..."

    # Helper: add if not already present
    ipt_add() { iptables -C "$@" 2>/dev/null || iptables -A "$@"; }
    ipt_ins() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }

    # ── Step 0: Loopback ─────────────────────────────
    ipt_ins INPUT -i lo -j ACCEPT

    # ── Step 1: Drop INVALID state ───────────────────
    ipt_ins INPUT   -m conntrack --ctstate INVALID -j DROP
    ipt_ins FORWARD -m conntrack --ctstate INVALID -j DROP
    success "Invalid packet drop: ON"

    # ── Step 2: Fast path for established ────────────
    # Must come BEFORE rate-limit rules so existing CF connections never hit limits
    ipt_ins INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ── Step 3: CF IPs → ACCEPT (NO limits ever) ─────
    # This is the MOST CRITICAL rule:
    # CF IPs must be accepted BEFORE any hashlimit/connlimit/rate rule
    # Otherwise, CF tunnel traffic can trigger SYN/UDP limits and kill users
    info "Whitelisting Cloudflare IPs (unlimited, no rate limits)..."
    for CF in "${CF_RANGES[@]}"; do
        ipt_ins INPUT -s "$CF" -m comment --comment "cf_whitelist" -j ACCEPT
    done

    # ── Step 4: Server own IPs → ACCEPT ──────────────
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        ipt_ins INPUT -s "$SIP/32" -m comment --comment "self_whitelist" -j ACCEPT
    done < <(get_server_ips)

    # ── Step 4b: User whitelist → ACCEPT (before ALL limits) ──
    mkdir -p /etc/antiddos
    touch "$WHITELIST_FILE"
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            ipt_ins INPUT -s "$WIP" -m comment --comment "user_whitelist" -j ACCEPT
        done < "$WHITELIST_FILE"
    fi
    success "CF + self whitelist: added (${#CF_RANGES[@]} CF ranges + own IPs)"

    # ── Step 5: SYN Flood protection ─────────────────
    # NOTE: CF IPs already accepted above — these rules only apply to non-CF
    if [ "$SYNPROXY_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ] && \
       [ "$VIRT_TYPE" != "openvz" ]; then
        modprobe xt_SYNPROXY 2>/dev/null || true
        # Whitelist CF IPs in raw PREROUTING so SYNPROXY never touches CF traffic
        for CF in "${CF_RANGES[@]}"; do
            iptables -t raw -C PREROUTING -s "$CF" -j ACCEPT 2>/dev/null || \
            iptables -t raw -A PREROUTING -s "$CF" -j ACCEPT
        done
        # Also whitelist server own IPs in raw
        while IFS= read -r SIP; do
            [ -z "$SIP" ] && continue
            iptables -t raw -C PREROUTING -s "$SIP/32" -j ACCEPT 2>/dev/null || \
            iptables -t raw -A PREROUTING -s "$SIP/32" -j ACCEPT
        done < <(get_server_ips)
        # Also whitelist user whitelist in raw (SYNPROXY never touches them)
        if [ -f "$WHITELIST_FILE" ]; then
            while IFS= read -r WIP; do
                WIP="${WIP%%#*}"; WIP="${WIP// /}"
                [ -z "$WIP" ] && continue
                iptables -t raw -C PREROUTING -s "$WIP" -j ACCEPT 2>/dev/null || \
                iptables -t raw -A PREROUTING -s "$WIP" -j ACCEPT
            done < "$WHITELIST_FILE"
        fi
        iptables -t raw -C PREROUTING -p tcp --syn \
            -m conntrack --ctstate NEW -j CT --notrack 2>/dev/null || \
        iptables -t raw -A PREROUTING -p tcp --syn \
            -m conntrack --ctstate NEW -j CT --notrack
        iptables -C INPUT -p tcp --syn \
            -m conntrack --ctstate UNTRACKED,INVALID \
            -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 2>/dev/null || \
        iptables -A INPUT -p tcp --syn \
            -m conntrack --ctstate UNTRACKED,INVALID \
            -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
        iptables -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
        iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
        success "SYN Flood: SYNPROXY kernel-level (CF whitelisted in raw table)"
    elif [ "$HASHLIMIT_OK" -eq 1 ]; then
        # Per-IP SYN limit (catches single-source flood)
        ipt_add INPUT -p tcp --syn \
            -m hashlimit \
            --hashlimit-above "$SYN_LIMIT" \
            --hashlimit-burst "$SYN_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name syn_flood \
            --hashlimit-htable-expire 30000 \
            -j DROP
        # Global SYN rate cap — catches spoofed-IP floods where per-IP limit misses
        # Each spoofed SYN uses a unique fake IP so per-IP hashlimit never triggers.
        # A global cap absorbs the total SYN rate regardless of source.
        # Value: 5× per-IP limit to allow bursts from many legit IPs simultaneously.
        local _GS_LIMIT _GS_BURST
        _GS_LIMIT=$(echo "$SYN_LIMIT" | sed 's|/sec||')
        _GS_LIMIT="${_GS_LIMIT//[^0-9]/}"; _GS_LIMIT="${_GS_LIMIT:-500}"
        _GS_BURST="${SYN_BURST:-1000}"
        _GS_BURST="${_GS_BURST//[^0-9]/}"; _GS_BURST="${_GS_BURST:-1000}"
        ipt_add INPUT -p tcp --syn \
            -m limit \
            --limit "$(( _GS_LIMIT * 5 ))/sec" \
            --limit-burst "$(( _GS_BURST * 5 ))" \
            -j ACCEPT
        ipt_add INPUT -p tcp --syn -j DROP
        success "SYN Flood: per-IP hashlimit ($SYN_LIMIT) + global cap ($(( _GS_LIMIT * 5 ))/s) — spoofed-IP resistant"
    else
        ipt_add INPUT -p tcp --syn -m limit --limit 500/s --limit-burst 1000 -j ACCEPT
        ipt_add INPUT -p tcp --syn -j DROP
        success "SYN Flood: global limit (fallback)"
    fi

    # ── Step 6: UDP Flood ─────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p udp \
            -m hashlimit \
            --hashlimit-above "$UDP_LIMIT" \
            --hashlimit-burst "$UDP_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name udp_flood \
            --hashlimit-htable-expire 10000 \
            -j DROP
        success "UDP Flood: hashlimit ($UDP_LIMIT per IP)"

        # UDP amplification ports
        for REFLECT_PORT in 19 111 137 161 1900 5353 11211; do
            ipt_add INPUT -p udp --sport "$REFLECT_PORT" \
                -m hashlimit \
                --hashlimit-above 10/sec \
                --hashlimit-burst 20 \
                --hashlimit-mode srcip \
                --hashlimit-name "udp_reflect_${REFLECT_PORT}" \
                -j DROP
        done
        success "UDP Amplification (DNS/NTP/SSDP/memcached): blocked"
    else
        warn "UDP Flood: hashlimit unavailable - using global limit"
        ipt_add INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT
        ipt_add INPUT -p udp -j DROP
    fi

    # ── Step 7: ICMP Flood ────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p icmp --icmp-type echo-request \
            -m hashlimit \
            --hashlimit-above "$ICMP_LIMIT" \
            --hashlimit-burst "$ICMP_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name icmp_flood \
            -j DROP
        success "ICMP Flood: rate-limited ($ICMP_LIMIT per IP)"
    else
        ipt_add INPUT -p icmp --icmp-type echo-request -m limit \
            --limit 1/s --limit-burst 10 -j ACCEPT
        ipt_add INPUT -p icmp --icmp-type echo-request -j DROP
        success "ICMP Flood: global limit (fallback)"
    fi

    # ── Step 8: HTTP/HTTPS + ALL TCP Flood (connlimit) ──
    # NOTE: CF IPs accepted before this — connlimit only affects non-CF
    if [ "$CONNLIMIT_OK" -eq 1 ]; then
        # HTTP/HTTPS ports — lower connlimit
        for HTTP_PORT in 80 443 8080 8443; do
            ss -tuln 2>/dev/null | grep -q ":${HTTP_PORT} " || continue
            ipt_add INPUT -p tcp --dport "$HTTP_PORT" \
                -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
                --connlimit-mask 32 \
                -j REJECT --reject-with tcp-reset
            success "HTTP Flood: connlimit :${HTTP_PORT} (max $CONN_LIMIT_PER_IP per non-CF IP)"
        done

        # ── Slowloris / Hold / Heavy attack defense ───────
        # These attacks use few connections but hold them forever with partial data.
        # connlimit on ALL TCP ports (global per-IP) stops this without affecting tunnels.
        # CF IPs are already accepted above — this only hits real attackers.
        # LOG before DROP so fail2ban conn-flood jail can read it from kern.log
        ipt_add INPUT -p tcp \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
            --connlimit-mask 32 \
            -m limit --limit 10/min --limit-burst 20 \
            -j LOG --log-prefix "[CONNLIMIT DROP] " --log-level 4 2>/dev/null || true
        ipt_add INPUT -p tcp \
            -m connlimit --connlimit-above "$CONN_LIMIT_PER_IP" \
            --connlimit-mask 32 \
            -j REJECT --reject-with tcp-reset
        success "Slowloris/Hold/Heavy: global connlimit (max $CONN_LIMIT_PER_IP TCP per non-CF IP) + LOG→fail2ban"

        if [ "$HASHLIMIT_OK" -eq 1 ] && [ "$CONNTRACK_OK" -eq 1 ]; then
            # ── New connection rate per IP (prevents connect-flood) ──
            ipt_add INPUT -p tcp \
                -m conntrack --ctstate NEW \
                -m hashlimit \
                --hashlimit-above "$NEW_CONN_RATE" \
                --hashlimit-burst "$NEW_CONN_BURST" \
                --hashlimit-mode srcip \
                --hashlimit-name new_conn_rate \
                --hashlimit-htable-expire 60000 \
                -j DROP
            success "New TCP conn rate: $NEW_CONN_RATE per non-CF IP"

            # ── HTTP request rate (packet rate on established TCP) ────
            # _proc_http_burst sends hundreds of requests on keep-alive.
            # hashlimit on all-TCP-packets (not just NEW) catches this.
            ipt_add INPUT -p tcp \
                -m conntrack --ctstate ESTABLISHED \
                -m hashlimit \
                --hashlimit-above "$HTTP_REQ_RATE" \
                --hashlimit-burst "$HTTP_REQ_BURST" \
                --hashlimit-mode srcip \
                --hashlimit-name http_req_rate \
                --hashlimit-htable-expire 10000 \
                -j DROP
            success "HTTP burst rate: max $HTTP_REQ_RATE pkt/s per non-CF IP (heavy/http_burst defense)"
        fi
    else
        warn "connlimit unavailable - HTTP flood protection limited"
    fi

    # ── Step 8b: Per-IP bandwidth limit via tc ──────────
    # _proc_heavy sends 64MB+ per connection. tc limits bandwidth before
    # data reaches xray/kernel, preventing CPU spike from data processing.
    # This adds an iptables MARK for non-CF IPs → tc filters pick it up.
    # ── Step 8: Per-IP bandwidth cap ─────────────────────
    # Try hashlimit byte-mode (kernel 4.1+), fallback to connlimit
    local BW_APPLIED=0
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        # Test if byte-mode (mbit/s) is supported by this kernel
        if iptables -A INPUT -p tcp \
            -m hashlimit \
            --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
            --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
            --hashlimit-mode srcip \
            --hashlimit-name bw_per_ip_test \
            --hashlimit-htable-expire 5000 \
            -j DROP 2>/dev/null; then
            # Success — remove test rule, add via ipt_add (idempotent)
            iptables -D INPUT -p tcp \
                -m hashlimit \
                --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
                --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
                --hashlimit-mode srcip \
                --hashlimit-name bw_per_ip_test \
                --hashlimit-htable-expire 5000 \
                -j DROP 2>/dev/null || true
            ipt_add INPUT -p tcp \
                -m conntrack --ctstate ESTABLISHED,RELATED \
                -m hashlimit \
                --hashlimit-above "${BW_PER_IP_MBIT}mbit/s" \
                --hashlimit-burst "$((BW_PER_IP_MBIT * 2))mbit" \
                --hashlimit-mode srcip \
                --hashlimit-name bw_per_ip \
                --hashlimit-htable-expire 5000 \
                -j DROP 2>/dev/null && BW_APPLIED=1
            [ "$BW_APPLIED" -eq 1 ] && \
                success "Per-IP bandwidth cap: ${BW_PER_IP_MBIT}Mbps max per non-CF IP"
        fi
    fi
    if [ "$BW_APPLIED" -eq 0 ]; then
        # Fallback: use connlimit — limit simultaneous connections per IP
        # Each connection ~1-5 Mbps for proxy; 60 conns ≈ 60-300 Mbps cap
        ipt_add INPUT -p tcp \
            -m conntrack --ctstate NEW \
            -m connlimit --connlimit-above 60 --connlimit-mask 32 \
            -j DROP 2>/dev/null && \
            success "Per-IP bandwidth cap: connlimit fallback (max 60 conns/IP — kernel too old for byte-mode)" || \
            warn "Per-IP bandwidth cap: both byte-mode and connlimit fallback failed"
    fi

    # ── Step 9: RST Flood ─────────────────────────────
    if [ "$HASHLIMIT_OK" -eq 1 ]; then
        ipt_add INPUT -p tcp --tcp-flags RST RST \
            -m hashlimit \
            --hashlimit-above 200/sec \
            --hashlimit-burst 400 \
            --hashlimit-mode srcip \
            --hashlimit-name rst_flood \
            -j DROP
        success "RST Flood: rate-limited"
    fi

    # ── Step 10: Port Scan signatures ────────────────
    ipt_add INPUT -p tcp --tcp-flags ALL NONE -j DROP  # NULL scan
    ipt_add INPUT -p tcp --tcp-flags ALL ALL  -j DROP  # Xmas scan
    ipt_add INPUT -p tcp --tcp-flags ALL FIN  -j DROP  # FIN scan
    ipt_add INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP  # impossible
    ipt_add INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP  # impossible
    success "Port scans: NULL/XMAS/FIN/bogus flags dropped"

    # ── Step 11: Bogus TCP NEW non-SYN ───────────────
    if [ "$CONNTRACK_OK" -eq 1 ]; then
        ipt_add INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
        success "Bogus TCP NEW non-SYN: dropped"
    fi

    # ── Step 12: Fragmented packets ──────────────────
    ipt_add INPUT -f -j DROP
    success "Fragmented packets: dropped"

    # Save rules
    iptables-save > "$IPTABLES_SAVE_FILE" 2>/dev/null || true
    chmod 600 "$IPTABLES_SAVE_FILE"
    success "iptables rules saved"
}

# ════════════════════════════════════════════════
# LAYER 3: fail2ban jails
# ════════════════════════════════════════════════
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
failregex = ^.*\s<HOST>:\d+\s.*\s(CONNECT|SOCKS5)\s.*$
            ^L\d+-\d+-\d+ \d+:\d+:\d+ \S+ <HOST>:\d+.*$
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
failregex = kernel.*\[UFW BLOCK\].*SRC=<HOST>
            kernel.*iptables.*DROP.*SRC=<HOST>
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
    _F2B_CF_N=0
    for _F2B_CF in "${CF_RANGES[@]}"; do
        _F2B_CF_N=$((_F2B_CF_N + 1))
        if [ $((_F2B_CF_N % 6)) -eq 1 ]; then
            _F2B_IGNORE="$(printf '%s\n            %s' "$_F2B_IGNORE" "$_F2B_CF")"
        else
            _F2B_IGNORE="$(printf '%s %s' "$_F2B_IGNORE" "$_F2B_CF")"
        fi
    done

    cat > "$F2B_JAIL_DIR/antiddos.conf" << EOF
# Anti-DDoS fail2ban jails — generated $(date)
# CF IPs are ignored via ignoreip (no false bans)

[DEFAULT]
# ignoreip built from the full CF range list (${#CF_RANGES[@]} ranges)
ignoreip = ${_F2B_IGNORE}

[3proxy-ddos]
enabled   = true
filter    = 3proxy-ddos
logpath   = /var/log/3proxy/access.log
maxretry  = 100
findtime  = 60
bantime   = 86400
action    = iptables-allports[name=3proxy-ddos, protocol=all]

[http-flood]
enabled   = true
filter    = http-flood
logpath   = /var/log/nginx/access.log
            /var/log/apache2/access.log
            /var/log/3proxy/access.log
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
maxretry  = 5
findtime  = 30
bantime   = 86400
action    = iptables-allports[name=portscan, protocol=all]

[sshd-aggressive]
enabled   = true
filter    = sshd
logpath   = /var/log/auth.log
            /var/log/secure
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

    systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
    sleep 2
    ACTIVE_JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | \
        sed 's/.*://;s/,/ /g' | wc -w || echo 0)
    success "fail2ban: $ACTIVE_JAILS jails active"
}

# ════════════════════════════════════════════════
# LAYER 4: Smart throttle+ban (auto-ban.sh)
# Pipeline: watch (45s) → throttle 100Mbps → ban 4h
# CF IPs: ALWAYS exempt
# ════════════════════════════════════════════════
setup_autoban() {
    info "Setting up smart throttle+ban..."

    # Require tcpdump
    if ! command -v tcpdump >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump 2>/dev/null || true
        fi
    fi

    cat > "$AUTOBAN_SCRIPT" << 'AUTOBAN_EOF'
@@AUTOBAN_BODY@@
AUTOBAN_EOF

    chmod +x "$AUTOBAN_SCRIPT"

    # Create systemd service
    cat > "$AUTOBAN_SERVICE" << EOF
[Unit]
Description=Auto-ban DDoS detection (smart throttle+ban)
After=network.target iptables.service

[Service]
Type=simple
ExecStart=$AUTOBAN_SCRIPT
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable auto-ban.service >/dev/null 2>&1
    systemctl restart auto-ban.service 2>/dev/null || true
    sleep 2

    if systemctl is-active auto-ban >/dev/null 2>&1; then
        success "Auto-ban service: running (watch:${CONN_THRESHOLD:-80} conns, ban:${BAN_CONN_THRESHOLD:-200} conns, duration:4h)"
    else
        warn "Auto-ban service failed to start - check: journalctl -u auto-ban"
    fi
}

# ════════════════════════════════════════════════
# LAYER 5: tc bandwidth control
# CF=unlimited, others=500Mbps, throttled=100Mbps
# Uses SRC IP (not DST) to avoid breaking tunnels
# ════════════════════════════════════════════════
setup_tc() {
    command -v tc >/dev/null 2>&1 || {
        warn "tc (iproute2) not installed - skipping bandwidth control"
        return
    }
    info "Configuring tc bandwidth control..."

    # Remove old config
    tc qdisc del dev "$MAIN_IF" root 2>/dev/null || true

    # HTB root — default class 1:20 (normal non-CF)
    tc qdisc add dev "$MAIN_IF" root handle 1: htb default 20
    tc class add dev "$MAIN_IF" parent 1: classid 1:1  htb rate 1gbit ceil 1gbit
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:10 htb rate 1gbit  ceil 1gbit  burst 25Mb    # CF unlimited
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:20 htb rate 500mbit ceil 500mbit burst 6400Kb # normal
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:30 htb rate 100mbit ceil 100mbit burst 1280Kb # throttled
    tc class add dev "$MAIN_IF" parent 1:1 classid 1:40 htb rate 50mbit  ceil 50mbit  burst 640Kb  # hard-throttled

    # CF IPs → class 1:10 (match by SRC IP)
    local HANDLE=10
    for CF in "${CF_RANGES[@]}"; do
        tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip src "$CF" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done

    # Server own IPs → class 1:10
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip src "$SIP/32" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done < <(get_server_ips)

    # User whitelist → class 1:10 (unlimited, same as CF/self)
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            tc filter add dev "$MAIN_IF" parent 1: protocol ip prio $HANDLE \
                u32 match ip src "$WIP" flowid 1:10 2>/dev/null || true
            HANDLE=$((HANDLE + 1))
        done < "$WHITELIST_FILE"
    fi

    # ── WARP / WireGuard awareness ──────────────────────────
    if ip link show 2>/dev/null | grep -qE '^\s*[0-9]+:\s+(wg|utm|warp)[0-9]*[:@]'; then
        warn "WARP/WireGuard tunnel detected — tc shapes '${MAIN_IF}' (default route)."
        warn "Tunneled (WARP) traffic egresses via the tunnel device and is NOT shaped; inbound anti-DDoS (iptables) still applies."
    fi

    success "tc: CF=unlimited, others=500Mbps, throttled=100Mbps"

    # Save to persistent script
    cat > /opt/proxy-manager/tc-setup.sh << 'TCEOF'
#!/bin/bash
# TC persistent setup — auto-generated
IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
IF="${IF:-eth0}"
# ── Cloudflare IP ranges (loaded from shared data file) ──
CF_RANGES=()
if [ -f /etc/antiddos/cloudflare-ipv4.list ]; then
    # Load CF ranges, skipping blank/whitespace-only lines. A stray blank line
    # in the file would otherwise become an empty array entry, and feeding an
    # empty source to iptables ("host/network '' not found") aborts the whole
    # install — which previously left auto-ban uninstalled.
    while IFS= read -r _cfl; do
        _cfl="${_cfl//[[:space:]]/}"
        [ -n "$_cfl" ] && CF_RANGES+=("$_cfl")
    done < /etc/antiddos/cloudflare-ipv4.list
else
    echo "WARN: /etc/antiddos/cloudflare-ipv4.list missing - CF whitelist empty" >&2
fi
tc qdisc del dev "$IF" root 2>/dev/null || true
tc qdisc add dev "$IF" root handle 1: htb default 20
tc class add dev "$IF" parent 1: classid 1:1  htb rate 1gbit ceil 1gbit
tc class add dev "$IF" parent 1:1 classid 1:10 htb rate 1gbit  ceil 1gbit  burst 25Mb
tc class add dev "$IF" parent 1:1 classid 1:20 htb rate 500mbit ceil 500mbit burst 6400Kb
tc class add dev "$IF" parent 1:1 classid 1:30 htb rate 100mbit ceil 100mbit burst 1280Kb
tc class add dev "$IF" parent 1:1 classid 1:40 htb rate 50mbit  ceil 50mbit  burst 640Kb
H=10
for CF in "${CF_RANGES[@]}"; do
    tc filter add dev "$IF" parent 1: protocol ip prio $H \
        u32 match ip src "$CF" flowid 1:10 2>/dev/null || true; H=$((H+1))
done
for SIP in $(ip -4 addr show 2>/dev/null | grep 'inet ' | \
    grep -v '127\.\|10\.\|192\.168\.' | awk '{print $2}' | cut -d/ -f1); do
    tc filter add dev "$IF" parent 1: protocol ip prio $H \
        u32 match ip src "$SIP/32" flowid 1:10 2>/dev/null || true; H=$((H+1))
done
if [ -f /etc/antiddos/whitelist.list ]; then
    while IFS= read -r WIP; do
        WIP="${WIP%%#*}"; WIP="${WIP// /}"
        [ -z "$WIP" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $H \
            u32 match ip src "$WIP" flowid 1:10 2>/dev/null || true; H=$((H+1))
    done < /etc/antiddos/whitelist.list
fi
TCEOF
    chmod +x /opt/proxy-manager/tc-setup.sh

    # systemd service for tc persistence
    cat > /etc/systemd/system/tc-proxy-limit.service << EOF
[Unit]
Description=TC bandwidth shaping (proxy server)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/proxy-manager/tc-setup.sh $MAIN_IF
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    # if-up.d for NetworkManager
    mkdir -p /etc/network/if-up.d
    ln -sf /opt/proxy-manager/tc-setup.sh /etc/network/if-up.d/tc-proxy-limit 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable tc-proxy-limit.service >/dev/null 2>&1 || true
    success "tc persistence: systemd + if-up.d configured"
}

# ════════════════════════════════════════════════
# Persist iptables on reboot
# ════════════════════════════════════════════════
setup_persistence() {
    info "Setting up iptables persistence..."

    # Debian/Ubuntu: iptables-persistent
    if command -v apt-get >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent 2>/dev/null || true
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    # Restore script
    RESTORE_SCRIPT="/etc/antiddos/restore-rules.sh"
    cat > "$RESTORE_SCRIPT" << 'EOF'
#!/bin/bash
RULES="/etc/antiddos/iptables-antiddos.rules"
[ -f "$RULES" ] && iptables-restore < "$RULES" 2>/dev/null || true
[ -f /etc/sysctl.d/98-antiddos-hardening.conf ] && \
    sysctl -p /etc/sysctl.d/98-antiddos-hardening.conf >/dev/null 2>&1 || true
EOF
    chmod +x "$RESTORE_SCRIPT"

    # systemd service
    cat > /etc/systemd/system/antiddos-restore.service << EOF
[Unit]
Description=Restore Anti-DDoS iptables rules on boot
After=network.target
Before=3proxy.service auto-ban.service

[Service]
Type=oneshot
ExecStart=$RESTORE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable antiddos-restore.service >/dev/null 2>&1
    success "iptables persistence: enabled (antiddos-restore)"
}

# ════════════════════════════════════════════════
# Status
# ════════════════════════════════════════════════
show_status() {
    sep; echo -e "  ${CYAN}${BOLD}Anti-DDoS Status${NC}"; sep

    echo -e "  ${DIM}iptables:${NC}"
    INPUT_RULES=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep -c "^[0-9]" || echo 0)
    CF_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "cf_whitelist" || echo 0)
    BANNED_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "auto-ban" || echo 0)
    echo -e "    INPUT rules  : ${WHITE}$INPUT_RULES${NC}  (CF whitelist: $CF_RULES, auto-ban: $BANNED_RULES)"

    if [ -d /proc/net/ipt_hashlimit ]; then
        echo -e "  ${DIM}hashlimit tables:${NC}"
        ls /proc/net/ipt_hashlimit 2>/dev/null | while read -r t; do
            COUNT=$(wc -l < "/proc/net/ipt_hashlimit/$t" 2>/dev/null || echo 0)
            echo -e "    ${CYAN}$t${NC}: ${WHITE}$COUNT IPs${NC}"
        done
    fi

    if [ -f /proc/net/nf_conntrack ]; then
        CURR=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo 0)
        CURR="${CURR//[^0-9]/}"; CURR="${CURR:-0}"
        MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 1)
        MAX="${MAX//[^0-9]/}"; MAX="${MAX:-1}"
        if [ "$MAX" -gt 0 ]; then
            PCT=$(awk "BEGIN{printf \"%.0f\", ${CURR}*100/${MAX}}")
        else
            PCT="?"
        fi
        echo -e "  ${DIM}conntrack:${NC} ${WHITE}$CURR${NC} / ${WHITE}$MAX${NC} (${PCT}%)"
    fi

    if command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "  ${DIM}fail2ban:${NC}"
        fail2ban-client status 2>/dev/null | grep "Jail list" | \
            sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r jail; do
            [ -z "$jail" ] && continue
            BANNED=$(fail2ban-client status "$jail" 2>/dev/null | \
                grep "Banned IP list" | sed 's/.*://;s/^ *//')
            COUNT=$(echo "$BANNED" | tr ' ' '\n' | grep -c '\.' 2>/dev/null | tr -d '\n' || echo 0)
            printf "    %-25s %s\n" "$jail:" "$COUNT IPs banned"
        done
    fi

    echo -e "  ${DIM}auto-ban service:${NC}"
    if systemctl is-active auto-ban >/dev/null 2>&1; then
        echo -e "    ${GREEN}● Running${NC}"
        BANS=$(grep -c "BANNED:" /var/log/auto-ban.log 2>/dev/null || echo 0)
        echo -e "    Total bans: $BANS"
        echo -e "    ${DIM}Last entries:${NC}"
        tail -5 /var/log/auto-ban.log 2>/dev/null | while read -r line; do
            echo "    $line"
        done
    else
        echo -e "    ${RED}○ Not running${NC}"
    fi

    echo -e "  ${DIM}tc bandwidth:${NC}"
    IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -n "$IF" ] && tc class show dev "$IF" 2>/dev/null | grep -q "1:10"; then
        echo -e "    ${GREEN}● Active${NC} (CF=unlimited, others=500Mbps, throttled=100Mbps)"
    else
        echo -e "    ${YELLOW}○ Not configured${NC}"
    fi

    echo -e "  ${DIM}kernel key params:${NC}"
    for P in net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter \
              net.ipv4.tcp_keepalive_time \
              net.netfilter.nf_conntrack_tcp_timeout_established \
              net.netfilter.nf_conntrack_tcp_timeout_syn_recv; do
        V=$(sysctl -n "$P" 2>/dev/null || echo "N/A")
        printf "    ${DIM}%-52s${NC} %s\n" "$P" "$V"
    done

    sep
    # shellcheck disable=SC1090  # STATE_FILE is a fixed path held in a variable
    [ -f "$STATE_FILE" ] && . "$STATE_FILE" 2>/dev/null && \
        echo -e "  ${GREEN}✓ Installed${NC} - $(grep '^DATE=' "$STATE_FILE" | cut -d= -f2-)" || \
        echo -e "  ${YELLOW}○ Not installed${NC}"
    sep
}

# ════════════════════════════════════════════════
# Remove all rules
# ════════════════════════════════════════════════
remove_rules() {
    sep; echo -e "  ${RED}Removing Anti-DDoS rules...${NC}"
    # CONF_R can be pre-set by --remove-force to skip prompt
    if [[ "${CONF_R:-}" != "y" && "${CONF_R:-}" != "Y" ]]; then
        printf '%s' "  Are you sure? This will remove ALL protection. (y/N): " >/dev/tty; read -r CONF_R </dev/tty || CONF_R=""
    fi
    [[ "$CONF_R" != "y" && "$CONF_R" != "Y" ]] && echo -e "  ${DIM}Cancelled.${NC}" && return

    # Sysctl
    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true
    success "Kernel hardening: removed"

    # iptables — delete by content match (line numbers shift after each delete, so loop)
    MATCH_PAT="hashlimit\|SYNPROXY\|connlimit\|cf_whitelist\|auto-ban\|self_whitelist\|user_whitelist\|syn_flood\|udp_flood\|icmp_flood\|rst_flood\|bw_per_ip\|new_conn_rate\|http_req_rate"
    for TABLE in INPUT FORWARD; do
        while iptables -L "$TABLE" -n 2>/dev/null | grep -qE "$MATCH_PAT"; do
            RNUM=$(iptables -L "$TABLE" -n --line-numbers 2>/dev/null | \
                  grep -E "$MATCH_PAT" | awk '{print $1}' | head -1 || true)
            [ -z "$RNUM" ] && break
            iptables -D "$TABLE" "$RNUM" 2>/dev/null || break
        done
    done
    # raw table
    while iptables -t raw -L PREROUTING -n 2>/dev/null | grep -qE "CT|notrack|cf_whitelist|self_whitelist|user_whitelist"; do
        RNUM=$(iptables -t raw -L PREROUTING -n --line-numbers 2>/dev/null | \
              grep -E "CT|notrack|ACCEPT" | awk '{print $1}' | head -1 || true)
        [ -z "$RNUM" ] && break
        iptables -t raw -D PREROUTING "$RNUM" 2>/dev/null || break
    done
    success "iptables rules: removed"

    # fail2ban
    rm -f "$F2B_JAIL_DIR/antiddos.conf"
    rm -f "$F2B_FILTER_DIR/3proxy-ddos.conf" \
          "$F2B_FILTER_DIR/http-flood.conf" \
          "$F2B_FILTER_DIR/conn-flood.conf" \
          "$F2B_FILTER_DIR/portscan.conf" \
          "$F2B_FILTER_DIR/xray-proxy.conf"
    systemctl reload fail2ban 2>/dev/null || true
    success "fail2ban jails: removed"

    # Auto-ban
    systemctl stop auto-ban.service 2>/dev/null || true
    systemctl disable auto-ban.service 2>/dev/null || true
    rm -f "$AUTOBAN_SERVICE"
    systemctl daemon-reload
    # Remove subnet-ban iptables rules
    iptables-save 2>/dev/null | grep '"subnet-ban"' | \
        sed 's/^-A/iptables -D/' | bash 2>/dev/null || true
    # Clean temp files
    rm -f /tmp/autoban_watch /tmp/autoban_throttle /tmp/autoban_subnet_watch 2>/dev/null || true
    success "Auto-ban service: removed"

    # tc
    IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    [ -n "$IF" ] && tc qdisc del dev "$IF" root 2>/dev/null || true
    systemctl disable tc-proxy-limit.service 2>/dev/null || true
    rm -f /etc/systemd/system/tc-proxy-limit.service
    rm -f /etc/network/if-up.d/tc-proxy-limit
    success "tc bandwidth control: removed"

    # Persistence
    systemctl disable antiddos-restore.service 2>/dev/null || true
    rm -f /etc/systemd/system/antiddos-restore.service
    systemctl daemon-reload
    rm -f "$STATE_FILE"
    success "All Anti-DDoS rules removed."
}

# ════════════════════════════════════════════════
# Full install
# ════════════════════════════════════════════════
do_install() {
    sep; echo -e "  ${CYAN}${BOLD}Anti-DDoS Full Install v${SCRIPT_VERSION}${NC}"; sep
    echo -e "  ${DIM}RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | Virt: ${VIRT_TYPE} | IF: ${MAIN_IF}${NC}"
    echo -e "  ${DIM}SYNPROXY: $([ $SYNPROXY_OK -eq 1 ] && echo 'YES' || echo 'NO')  hashlimit: $([ $HASHLIMIT_OK -eq 1 ] && echo 'YES' || echo 'NO')  conntrack: $([ $CONNTRACK_OK -eq 1 ] && echo 'YES' || echo 'NO')${NC}"
    echo -e "  ${DIM}Public IPs: $PUBLIC_IP_COUNT  (rp_filter: $([ "${PUBLIC_IP_COUNT:-0}" -gt 1 ] && echo '0' || echo '1'))${NC}"
    echo ""
    echo -e "  Layers to install:"
    echo -e "    ${CYAN}1.${NC} Kernel sysctl  (keepalive=30s, conntrack tight timeouts)"
    echo -e "    ${CYAN}2.${NC} iptables       (CF whitelist first, then rate-limits)"
    echo -e "    ${CYAN}3.${NC} fail2ban       (3proxy-ddos/portscan/sshd/xray)"
    echo -e "    ${CYAN}4.${NC} Smart ban      (watch->throttle->ban pipeline)"
    echo -e "    ${CYAN}5.${NC} tc bandwidth   (CF=unlimited, others=500Mbps)"
    echo -e "    ${CYAN}6.${NC} Boot persist   (systemd + iptables-persistent)"
    echo ""
    printf '%s' "  Continue? (y/N): " >/dev/tty
    read -r CF_I </dev/tty || CF_I=""
    [[ "$CF_I" != "y" && "$CF_I" != "Y" ]] && return

    apply_sysctl_hardening
    apply_iptables
    apply_fail2ban
    setup_autoban
    setup_tc
    setup_persistence

    cat > "$STATE_FILE" << EOF
DATE=$(date)
VERSION=${SCRIPT_VERSION}
VIRT_TYPE=${VIRT_TYPE}
RAM_MB=${RAM_MB}
SYNPROXY=${SYNPROXY_OK}
HASHLIMIT=${HASHLIMIT_OK}
MAIN_IF=${MAIN_IF}
EOF

    sep
    success "Anti-DDoS installation complete!"
    echo ""
    echo -e "  ${CYAN}Protection summary:${NC}"
    echo -e "    ${GREEN}✓${NC}  SYN Flood   - $([ $SYNPROXY_OK -eq 1 ] && echo 'SYNPROXY (kernel)' || echo 'hashlimit')"
    echo -e "    ${GREEN}✓${NC}  UDP Flood   - hashlimit per-IP + amplification blocked"
    echo -e "    ${GREEN}✓${NC}  ICMP Flood  - rate-limited per source"
    echo -e "    ${GREEN}✓${NC}  Port Scans  - NULL/XMAS/FIN/bogus dropped"
    echo -e "    ${GREEN}✓${NC}  RST Flood   - rate-limited"
    echo -e "    ${GREEN}✓${NC}  Smart Ban   - watch(45s)->throttle(100M)->ban(4h)"
    echo -e "    ${GREEN}✓${NC}  CF Users    - ALWAYS unlimited, never throttled/banned"
    echo -e "    ${GREEN}✓${NC}  Bandwidth   - CF=unlimited, non-CF=500Mbps max"
    echo -e "    ${GREEN}✓${NC}  Slowloris   - keepalive_time=30s"
    echo -e "    ${GREEN}✓${NC}  fail2ban    - 3proxy/portscan/sshd/xray jails"
    sep
}

show_thresholds() {
    sep; echo -e "  ${CYAN}${BOLD}Current Thresholds${NC}"; sep
    printf "  %-35s ${WHITE}%s${NC}\n" "SYN rate limit:"        "$SYN_LIMIT (burst: $SYN_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "UDP rate limit:"        "$UDP_LIMIT (burst: $UDP_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "ICMP rate limit:"       "$ICMP_LIMIT (burst: $ICMP_BURST)"
    printf "  %-35s ${WHITE}%s${NC}\n" "HTTP req rate limit:"   "${HTTP_REQ_RATE:-N/A} (burst: ${HTTP_REQ_BURST:-N/A})"
    printf "  %-35s ${WHITE}%s${NC}\n" "New conn rate limit:"   "${NEW_CONN_RATE:-N/A} (burst: ${NEW_CONN_BURST:-N/A})"
    printf "  %-35s ${WHITE}%s${NC}\n" "Per-IP bandwidth cap:"  "${BW_PER_IP_MBIT:-N/A} Mbps"
    printf "  %-35s ${WHITE}%s${NC}\n" "HTTP conns/non-CF IP:"  "$CONN_LIMIT_PER_IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban watch threshold:"   "120 active conns/IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban instant-ban:"       "300 active conns/IP"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban subnet watch:"      "400 total conns from /24"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban subnet ban:"        "1000 total conns from /24"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban observe:"           "45s watch before throttle"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban throttle:"          "100Mbps"
    printf "  %-35s ${WHITE}%s${NC}\n" "Auto-ban duration:"          "4 hours"
    printf "  %-35s ${WHITE}%s${NC}\n" "Reputation scoring:"         "ON (100→0, human-vs-bot)"
    printf "  %-35s ${WHITE}%s${NC}\n" "  bands:"                    "80+normal 60+watch 40+100M 20+50M <20 ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "  auto-release:"             "ON (throttled→normal when calmed)"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban 3proxy:"       "100 req/60s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban HTTP burst:"    "200 req/30s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban conn-flood:"    "20 drops/10s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "fail2ban SSH:"          "3 fails/30s -> 24h ban"
    printf "  %-35s ${WHITE}%s${NC}\n" "Cloudflare IPs:"        "UNLIMITED at all layers"
    sep
}

# ── Whitelist manager ──────────────────────────────────────
manage_whitelist() {
    local WL="$WHITELIST_FILE"
    mkdir -p /etc/antiddos
    [ -f "$WL" ] || touch "$WL"

    while true; do
        clear; sep
        echo -e "  ${CYAN}${BOLD}Whitelist Manager${NC}"
        echo -e "  ${DIM}IPs/CIDRs here are exempt from ALL anti-DDoS limits:${NC}"
        echo -e "  ${DIM}iptables rate-limit, connlimit, SYNPROXY, tc bandwidth, auto-ban.${NC}"
        sep
        if [ -s "$WL" ]; then
            echo -e "  ${CYAN}Current whitelist:${NC}"
            local N=0
            while IFS= read -r E; do
                [ -z "${E%%#*}" ] && continue
                E="${E// /}"
                [ -z "$E" ] && continue
                N=$((N + 1))
                printf "    ${GREEN}%s.${NC} %s\n" "$N" "$E"
            done < "$WL"
            echo ""
        else
            echo -e "  ${YELLOW}Whitelist is empty.${NC} (Server's own IPs + Cloudflare are always exempt automatically.)"
            echo ""
        fi
        echo -e "  ${CYAN}a.${NC} Add IP/CIDR"
        echo -e "  ${CYAN}d.${NC} Remove entry"
        echo -e "  ${CYAN}0.${NC} Back"
        sep
        printf '%s' "  Enter choice: " >/dev/tty; read -r WCH </dev/tty || WCH=""
        case "$WCH" in
            a|A)
                printf '%s' "  IP or CIDR to whitelist (e.g. 1.2.3.4 or 5.6.7.0/24): " >/dev/tty
                read -r WIP </dev/tty || WIP=""
                WIP="${WIP// /}"
                if [ -z "$WIP" ]; then
                    echo -e "  ${YELLOW}No input.${NC}"
                elif grep -qF "$WIP" "$WL" 2>/dev/null; then
                    echo -e "  ${YELLOW}Already in whitelist.${NC}"
                else
                    echo "$WIP" >> "$WL"
                    echo -e "  ${GREEN}✓ Added: $WIP${NC}"
                    # Apply to iptables + tc immediately (re-apply both)
                    apply_iptables >/dev/null 2>&1 || true
                    apply_tc_runtime "$MAIN_IF" >/dev/null 2>&1 || true
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            d|D)
                printf '%s' "  Entry to remove (paste the exact IP/CIDR): " >/dev/tty
                read -r RIP </dev/tty || RIP=""
                RIP="${RIP// /}"
                if [ -n "$RIP" ] && grep -qF "$RIP" "$WL" 2>/dev/null; then
                    grep -vxF "$RIP" "$WL" > "$WL.tmp" && mv "$WL.tmp" "$WL"
                    # Clean the empty case
                    sed -i '/^[[:space:]]*$/d' "$WL" 2>/dev/null || true
                    echo -e "  ${GREEN}✓ Removed: $RIP${NC}"
                    apply_iptables >/dev/null 2>&1 || true
                    apply_tc_runtime "$MAIN_IF" >/dev/null 2>&1 || true
                else
                    echo -e "  ${YELLOW}Not found.${NC}"
                fi
                printf '%s\n' "  Press Enter..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
            0) return 0 ;;
            *) echo -e "  ${YELLOW}Invalid choice.${NC}"; sleep 1 ;;
        esac
    done
}

# Runtime tc re-apply for a single interface (used by whitelist manager)
apply_tc_runtime() {
    local IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
    [ -z "$IF" ] && IF="eth0"
    # Only re-run if tc is already configured
    tc qdisc show dev "$IF" 2>/dev/null | grep -q htb || return 0
    setup_tc "$IF" >/dev/null 2>&1 || true
}

# CLI args
case "${1:-}" in
    --install|-i)    detect_env; do_install; exit 0 ;;
    --remove|-r)     detect_env; remove_rules; exit 0 ;;
    --remove-force)  detect_env; CONF_R="y"; remove_rules; exit 0 ;;
    --status|-s)     detect_env; show_status; exit 0 ;;
    --thresholds|-t) detect_env; show_thresholds; exit 0 ;;
    --sysctl)        detect_env; apply_sysctl_hardening; exit 0 ;;
    --iptables)      detect_env; apply_iptables; exit 0 ;;
    --fail2ban)      detect_env; apply_fail2ban; exit 0 ;;
    --autoban)       detect_env; setup_autoban; exit 0 ;;
    --whitelist|-w)  detect_env; manage_whitelist; exit 0 ;;
    --tc)            detect_env; setup_tc; exit 0 ;;
    --auto|-y)
        detect_env
        sep
        echo -e "  ${CYAN}${BOLD}Anti-DDoS Full Install v${SCRIPT_VERSION}${NC}"; sep
        echo -e "  ${DIM}RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | Virt: ${VIRT_TYPE} | IF: ${MAIN_IF}${NC}"
        echo ""
        apply_sysctl_hardening; apply_iptables; apply_fail2ban
        setup_autoban; setup_tc; setup_persistence
        cat > "$STATE_FILE" << EOF
DATE=$(date)
VERSION=${SCRIPT_VERSION}
VIRT_TYPE=${VIRT_TYPE}
RAM_MB=${RAM_MB}
SYNPROXY=${SYNPROXY_OK}
HASHLIMIT=${HASHLIMIT_OK}
MAIN_IF=${MAIN_IF}
EOF
        sep
        success "Anti-DDoS installation complete!"
        exit 0 ;;
esac

# Interactive menu
detect_env

while true; do
    clear; sep
    echo -e "  ${CYAN}${BOLD}Anti-DDoS Manager v${SCRIPT_VERSION}${NC}"; sep
    [ -f "$STATE_FILE" ] && \
        echo -e "  Status: ${GREEN}✓ Installed${NC}" || \
        echo -e "  Status: ${YELLOW}○ Not installed${NC}"
    _AB_ST=$(systemctl is-active auto-ban 2>/dev/null || echo "inactive")
    [ "$_AB_ST" = "active" ] && \
        echo -e "  auto-ban: \033[0;32mRunning\033[0m" || \
        echo -e "  auto-ban: \033[0;31mStopped\033[0m"
    echo ""
    echo -e "  ${CYAN}1.${NC}  Full install (all layers)"
    echo -e "  ${CYAN}2.${NC}  Status & active bans"
    echo -e "  ${CYAN}3.${NC}  View thresholds"
    echo -e "  ${CYAN}4.${NC}  Kernel sysctl only"
    echo -e "  ${CYAN}5.${NC}  iptables only"
    echo -e "  ${CYAN}6.${NC}  fail2ban only"
    echo -e "  ${CYAN}7.${NC}  Smart ban only"
    echo -e "  ${CYAN}8.${NC}  tc bandwidth only"
    echo -e "  ${CYAN}9.${NC}  Unban IP (all layers)"
    echo -e "  ${CYAN}w.${NC}  Manage whitelist (IPs exempt from ALL limits)"
    echo -e "  ${CYAN}r.${NC}  Remove all rules"
    echo -e "  ${CYAN}0.${NC}  Back"
    sep
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) do_install; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) show_status; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        3) show_thresholds; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        4) apply_sysctl_hardening; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        5) apply_iptables; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        6) apply_fail2ban; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        7) setup_autoban; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        8) setup_tc; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        9) echo -e "  ${CYAN}Unban IP${NC}"; echo ""
           printf '%s' "  Enter IP to unban (iptables + fail2ban): " >/dev/tty; read -r UIP </dev/tty || UIP=""
           [ -n "$UIP" ] && {
               iptables -D INPUT -s "$UIP" -j DROP 2>/dev/null && \
                   echo -e "  ${GREEN}✓ iptables unblocked${NC}" || true
               [ -f "$BANNED_LIST" ] && \
                   sed -i "/${UIP}/d" "$BANNED_LIST" 2>/dev/null || true
               fail2ban-client status 2>/dev/null | grep "Jail list" | \
                   sed 's/.*://;s/,/\n/g' | tr -d ' ' | while read -r jail; do
                   [ -z "$jail" ] && continue
                   fail2ban-client set "$jail" unbanip "$UIP" 2>/dev/null && \
                       echo -e "  ${GREEN}✓ fail2ban $jail unblocked${NC}" || true
               done
               echo -e "  ${GREEN}✓ $UIP fully unblocked${NC}"
           }
           printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        w|W) manage_whitelist ;;
        r) remove_rules; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
