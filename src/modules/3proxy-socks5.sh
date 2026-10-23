#!/bin/bash
# ============================================================
#  3proxy SOCKS5 Manager
#  - Cloudflare IPs: ALWAYS unlimited (no connlimit, no rate)
#  - tc bandwidth: CF=unlimited, others=500Mbps
#  - Per-IP connlimit only for non-CF IPs
# ============================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
PROXY_BIN="/usr/local/bin/3proxy"
PROXY_CONF="/etc/3proxy/3proxy.cfg"
PROXY_USERS="/etc/3proxy/users.cfg"
PROXY_LOG_DIR="/var/log/3proxy"
SERVICE_FILE="/etc/systemd/system/3proxy.service"

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1

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

get_server_ips() {
    # All public IPs of this server (for auto-whitelist)
    ip -4 addr show 2>/dev/null | grep 'inet ' | \
        grep -v '127\.\|10\.\|192\.168\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.' | \
        awk '{print $2}' | cut -d/ -f1
}

get_server_ip() {
    curl -s -4 --max-time 5 https://api.ipify.org 2>/dev/null || \
    curl -s -4 --max-time 5 https://ifconfig.me 2>/dev/null || \
    hostname -I 2>/dev/null | awk '{print $1}'
}

get_server_ipv6() { curl -s -6 --max-time 5 https://api64.ipify.org 2>/dev/null || true; }
get_current_port() { grep -oP '(?<=socks -p)\s*\K\d+' "$PROXY_CONF" 2>/dev/null | head -1 || true; }
is_installed() { [ -f "$PROXY_BIN" ] && [ -f "$SERVICE_FILE" ]; }
sep() { echo -e "${CYAN}════════════════════════════════════════════════${NC}"; }

# ── tc bandwidth control ─────────────────────────────────
# CF IPs → class 1:10 (unlimited)
# non-CF normal → class 1:20 (500Mbps)
# throttled IPs → class 1:30 (100Mbps)
setup_tc() {
    local IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
    [ -z "$IF" ] && IF="eth0"

    # Get total bandwidth (try to detect, fallback 1Gbps)
    local BW="1gbit"
    command -v ethtool >/dev/null 2>&1 && {
        local SPEED; SPEED=$(ethtool "$IF" 2>/dev/null | grep Speed | awk '{print $2}' | grep -oP '\d+' | head -1)
        [ -n "$SPEED" ] && BW="${SPEED}mbit"
    }

    # Remove old tc config
    tc qdisc del dev "$IF" root 2>/dev/null || true

    # HTB root
    tc qdisc add dev "$IF" root handle 1: htb default 20
    tc class add dev "$IF" parent 1: classid 1:1  htb rate "$BW"  ceil "$BW"
    tc class add dev "$IF" parent 1:1 classid 1:10 htb rate "$BW"  ceil "$BW"   burst 25Mb  # CF: unlimited
    tc class add dev "$IF" parent 1:1 classid 1:20 htb rate 500mbit ceil 500mbit burst 6400Kb  # normal
    tc class add dev "$IF" parent 1:1 classid 1:30 htb rate 100mbit ceil 100mbit burst 1280Kb  # throttled
    tc class add dev "$IF" parent 1:1 classid 1:40 htb rate 50mbit  ceil 50mbit  burst 640Kb   # hard-throttled

    # Cloudflare IPs → class 1:10 (unlimited)
    local HANDLE=10
    for CF in "${CF_RANGES[@]}"; do
        # skip IPv6 if kernel doesn't support tc ip6
        [[ "$CF" == *":"* ]] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip src "$CF" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done

    # Server own IPs → class 1:10 (unlimited)
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip src "$SIP/32" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done < <(get_server_ips)

    # User whitelist → class 1:10 (unlimited, same as CF/self)
    if [ -f "/etc/antiddos/whitelist.list" ]; then
        while IFS= read -r WIP; do
            WIP="${WIP%%#*}"; WIP="${WIP// /}"
            [ -z "$WIP" ] && continue
            tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
                u32 match ip src "$WIP" flowid 1:10 2>/dev/null || true
            HANDLE=$((HANDLE + 1))
        done < /etc/antiddos/whitelist.list
    fi

    # ── WARP / WireGuard awareness ──────────────────────────
    # tc shapes the default-route interface. If a WireGuard/WARP tunnel is
    # present, its traffic egresses on a wg* device, so these filters would
    # NOT shape tunneled traffic — warn the user (conditional, non-intrusive).
    if ip link show 2>/dev/null | grep -qE '^\s*[0-9]+:\s+(wg|utm|warp)[0-9]*[:@]'; then
        echo -e "${YELLOW}⚠ WARP/WireGuard tunnel detected on a different interface.${NC}"
        echo -e "   tc is applied to '${IF}' (default route). Tunneled (WARP) traffic"
        echo -e "   leaves via the tunnel device and is NOT shaped by these limits."
        echo -e "   This is intentional & safe — inbound anti-DDoS (iptables) still applies."
    fi

    echo -e "${GREEN}✓ tc bandwidth control configured (CF=unlimited, others=500Mbps)${NC}"
}

# ── Save tc config for persistence ──────────────────────
save_tc_persistent() {
    local IF="${1:-$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)}"
    [ -z "$IF" ] && IF="eth0"

    # systemd service for tc restore after reboot
    cat > /etc/systemd/system/tc-proxy-limit.service << EOF
[Unit]
Description=TC bandwidth shaping for proxy server
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/proxy-manager/tc-setup.sh $IF
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Write tc-setup.sh
    cat > /opt/proxy-manager/tc-setup.sh << 'TCEOF'
#!/bin/bash
# Auto-generated by proxy-manager — do not edit manually
IF="${1:-eth0}"
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
HANDLE=10
for CF in "${CF_RANGES[@]}"; do
    tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
        u32 match ip src "$CF" flowid 1:10 2>/dev/null || true
    HANDLE=$((HANDLE + 1))
done
# Add server own IPs
for SIP in $(ip -4 addr show 2>/dev/null | grep 'inet ' | \
    grep -v '127\.\|10\.\|192\.168\.' | awk '{print $2}' | cut -d/ -f1); do
    tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
        u32 match ip src "$SIP/32" flowid 1:10 2>/dev/null || true
    HANDLE=$((HANDLE + 1))
done
# Add user whitelist (unlimited)
if [ -f /etc/antiddos/whitelist.list ]; then
    while IFS= read -r WIP; do
        WIP="${WIP%%#*}"; WIP="${WIP// /}"
        [ -z "$WIP" ] && continue
        tc filter add dev "$IF" parent 1: protocol ip prio $HANDLE \
            u32 match ip src "$WIP" flowid 1:10 2>/dev/null || true
        HANDLE=$((HANDLE + 1))
    done < /etc/antiddos/whitelist.list
fi
TCEOF
    chmod +x /opt/proxy-manager/tc-setup.sh

    # Also add to if-up.d for NetworkManager
    mkdir -p /etc/network/if-up.d
    ln -sf /opt/proxy-manager/tc-setup.sh /etc/network/if-up.d/tc-proxy-limit 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable tc-proxy-limit.service >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ tc persistence configured (reboot-safe)${NC}"
}

# ── iptables rules for proxy port (CF unlimited) ─────────
setup_iptables_for_port() {
    local PORT="$1"
    local MAX_CONN="${2:-20}"

    # Remove old rules for this port
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" \
        -m comment --comment "3proxy_stats_in" 2>/dev/null || true
    iptables -D OUTPUT -p tcp --sport "$PORT" \
        -m comment --comment "3proxy_stats_out" 2>/dev/null || true
    # Remove old CF rules
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" -j ACCEPT 2>/dev/null || true
    done
    # Remove old rate-limit rules
    iptables -D INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --update --seconds 60 \
        --hitcount $((MAX_CONN * 2)) -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --set 2>/dev/null || true

    # ── Step 1: CF IPs → ACCEPT immediately (no limits!) ─
    for CF in "${CF_RANGES[@]}"; do
        [[ "$CF" == *":"* ]] && continue
        iptables -A INPUT -p tcp --dport "$PORT" -s "$CF" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT
    done

    # ── Step 2: Server own IPs → ACCEPT (no limits) ──────
    while IFS= read -r SIP; do
        [ -z "$SIP" ] && continue
        iptables -A INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
            -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
    done < <(get_server_ips)

    # ── Step 3: Non-CF rate-limit (new conns per IP) ──────
    # Only apply to IPs NOT from CF (CF already accepted above)
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --update --seconds 60 \
        --hitcount $((MAX_CONN * 3)) -j DROP
    iptables -A INPUT -p tcp --dport "$PORT" -m state --state NEW \
        -m recent --name "3proxy_$PORT" --set

    # ── Step 4: Allow all remaining ──────────────────────
    iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT

    # Stats counters
    iptables -I INPUT  -p tcp --dport "$PORT" -m comment --comment "3proxy_stats_in"
    iptables -I OUTPUT -p tcp --sport "$PORT" -m comment --comment "3proxy_stats_out"

    # UFW / firewalld compat
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active" && \
        ufw allow "$PORT"/tcp >/dev/null 2>&1 || true
    command -v firewall-cmd >/dev/null 2>&1 && \
        firewall-cmd --add-port="$PORT"/tcp --permanent >/dev/null 2>&1 && \
        firewall-cmd --reload >/dev/null 2>&1 || true
}

# ── Run a command with visible "working" feedback ──────────
# Prints "<label> ......" and a growing dot animation so the user can see the
# step is still alive. The command itself is NEVER time-limited. Output is
# captured to a temp log so the dots stay clean; on failure the log tail is
# shown so the real error is not hidden.
run_spinner() {
    local label="$1"; shift
    local log _spin _rc
    log=$(mktemp)
    printf '  %s ' "$label"
    ( while :; do printf '.'; sleep 1; done ) &
    _spin=$!
    "$@" >"$log" 2>&1
    _rc=$?
    kill "$_spin" 2>/dev/null; wait "$_spin" 2>/dev/null
    if [ "$_rc" -eq 0 ]; then
        printf ' done\n'
    else
        printf ' FAILED\n'
        tail -n 15 "$log" >&2
    fi
    rm -f "$log"
    return "$_rc"
}

# Standalone script helpers (not inherited from install.sh).
info() { echo -e "  ${CYAN}->${NC}  $*"; }
ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }

# ── Pick the fastest reachable apt mirror ──────────────────
# Tests a set of candidate mirrors with a SHORT per-mirror timeout (this is a
# probe only) and echoes the URL of the fastest responsive one. The later
# apt-get update/install runs WITHOUT any timeout. Returns empty if none work.
pick_apt_mirror() {
    local os="$1" code="$2"
    local -a cands=()
    if [ "$os" = ubuntu ]; then
        cands=( "http://archive.ubuntu.com/ubuntu" "http://mirrors.aliyun.com/ubuntu" \
                "https://mirrors.tuna.tsinghua.edu.cn/ubuntu" "http://mirrors.ustc.edu.cn/ubuntu" \
                "http://mirrors.cloud.aliyuncs.com/ubuntu" "https://mirrors.huaweicloud.com/ubuntu" \
                "http://mirrors.zju.edu.cn/ubuntu" )
    else
        cands=( "http://deb.debian.org/debian" "http://mirrors.aliyun.com/debian" \
                "https://mirrors.tuna.tsinghua.edu.cn/debian" "http://mirrors.ustc.edu.cn/debian" \
                "https://mirrors.huaweicloud.com/debian" "http://mirrors.cloud.aliyuncs.com/debian" )
    fi
    local best="" best_ms=99999 m t0 ms
    for m in "${cands[@]}"; do
        t0=$(date +%s%N 2>/dev/null || echo 0)
        if curl -fsS --max-time 4 -o /dev/null "$m/dists/$code/InRelease" 2>/dev/null || \
           curl -fsS --max-time 4 -o /dev/null "$m/dists/$code/Release" 2>/dev/null; then
            ms=$(( ( $(date +%s%N 2>/dev/null || echo 0) - t0 ) / 1000000 ))
            [ "$ms" -lt 0 ] && ms=0
            if [ "$ms" -lt "$best_ms" ]; then best_ms=$ms; best=$m; fi
        fi
    done
    printf '%s' "$best"
}

# ── Point apt at the chosen mirror (with backup) ───────────
# Backs up existing apt sources, then writes a minimal sources.list using the
# selected mirror. The original config is kept as *.bak so nothing is lost.
configure_apt_mirror() {
    local os="$1" code="$2" mirror="$3"
    [ -f /etc/apt/sources.list ] && cp -a /etc/apt/sources.list /etc/apt/sources.list.bak 2>/dev/null || true
    for _f in /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
        [ -e "$_f" ] && cp -a "$_f" "$_f.bak" 2>/dev/null || true
    done
    # On modern Ubuntu the default is deb822 (ubuntu.sources); use classic list.
    rm -f /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
    printf 'deb %s %s main restricted universe multiverse\n' "$mirror" "$code" > /etc/apt/sources.list
    printf 'deb %s %s-updates main restricted universe multiverse\n' "$mirror" "$code" >> /etc/apt/sources.list
    printf 'deb %s %s-security main restricted universe multiverse\n' "$mirror" "$code" >> /etc/apt/sources.list
}

install_proxy() {
    sep; echo -e "${YELLOW}Installing 3proxy SOCKS5...${NC}"; sep

    echo -e "${YELLOW}[1/7] Installing dependencies...${NC}"
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=${ID:-unknown}; CODENAME=${VERSION_CODENAME:-}; fi
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        # Prefer a fast reachable mirror so `apt-get update` doesn't stall on a
        # slow one. Probe is quick (timeout on the test only); the install
        # itself below is NEVER time-limited. If no mirror responds, keep the
        # system's existing apt sources.
        MIRROR=""
        [ -n "$CODENAME" ] && MIRROR=$(pick_apt_mirror "$OS" "$CODENAME")
        if [ -n "$MIRROR" ]; then
            info "Using apt mirror: $MIRROR"
            configure_apt_mirror "$OS" "$CODENAME" "$MIRROR"
        else
            info "No faster mirror reachable - using system apt sources"
        fi
        run_spinner "Updating package lists" apt-get update -y || true
        run_spinner "Installing dependencies" apt-get install -y \
            wget curl iptables iproute2 logrotate build-essential tcpdump || {
            echo -e "${YELLOW}Some packages failed, continuing...${NC}"
        }
    elif [[ "$OS" == "centos" || "$OS" == "rhel" || \
            "$OS" == "rocky" || "$OS" == "almalinux" || \
            "$OS" == "fedora" ]]; then
        run_spinner "Installing dependencies" yum install -y \
            wget curl iptables iproute logrotate gcc make iproute-tc tcpdump || {
            echo -e "${YELLOW}Some packages failed, continuing...${NC}"
        }
    fi

    echo -e "${YELLOW}[2/7] Installing 3proxy...${NC}"
    TMPDIR_BUILD=$(mktemp -d)
    cd "$TMPDIR_BUILD" || return 1
    if run_spinner "Installing 3proxy via apt" apt-get install -y 3proxy; then
        PROXY_BIN_PATH=$(command -v 3proxy 2>/dev/null || echo "/usr/bin/3proxy")
        [ "$PROXY_BIN_PATH" != "$PROXY_BIN" ] && ln -sf "$PROXY_BIN_PATH" "$PROXY_BIN"
        echo -e "${GREEN}3proxy installed from apt.${NC}"
    else
        echo -e "${YELLOW}Compiling 3proxy from source...${NC}"
        if run_spinner "Downloading 3proxy source" wget -O 3proxy.tar.gz \
            https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz; then
            run_spinner "Extracting source" tar -xzf 3proxy.tar.gz
            cd 3proxy-0.9.4 || { cd /; rm -rf "$TMPDIR_BUILD"; return 1; }
            if run_spinner "Compiling (this can take a while)" \
                make -f Makefile.Linux -j"$(nproc)"; then
                cp bin/3proxy "$PROXY_BIN" && chmod +x "$PROXY_BIN" && \
                    echo -e "${GREEN}3proxy compiled from source.${NC}" || {
                    echo -e "${RED}Copy failed!${NC}"; cd /; rm -rf "$TMPDIR_BUILD"; return 1
                }
            else
                echo -e "${RED}Compilation failed!${NC}"; cd /; rm -rf "$TMPDIR_BUILD"; return 1
            fi
        else
            echo -e "${RED}Cannot download 3proxy! Check internet connection.${NC}"
            cd /; rm -rf "$TMPDIR_BUILD"; return 1
        fi
    fi
    cd /; rm -rf "$TMPDIR_BUILD"

    echo -e "${YELLOW}[3/7] Port configuration...${NC}"
    DEFAULT_PORT=1080
    read -t 30 -rp "Port (default: $DEFAULT_PORT): " INPUT_PORT < /dev/tty 2>/dev/null || INPUT_PORT=""
    PORT=${INPUT_PORT:-$DEFAULT_PORT}
    # Validate port number
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || PORT=$DEFAULT_PORT
    # Find free port if occupied
    TRIED=0
    while ss -tuln 2>/dev/null | grep -qE ":$PORT\b" && [ "$TRIED" -lt 20 ]; do
        echo -e "${YELLOW}Port $PORT is in use.${NC}"
        PORT=$((PORT + 1))
        TRIED=$((TRIED + 1))
        echo -e "Trying: ${CYAN}$PORT${NC}"
    done

    echo -e "${YELLOW}[4/7] Security settings...${NC}"
    read -t 30 -rp "Max connections per IP (default: 20): " MAX_CONN < /dev/tty 2>/dev/null || MAX_CONN=""
    MAX_CONN=${MAX_CONN:-20}
    [[ "$MAX_CONN" =~ ^[0-9]+$ ]] || MAX_CONN=20

    read -t 30 -rp "Max total connections (default: 10000): " MAX_TOTAL_CONN < /dev/tty 2>/dev/null || MAX_TOTAL_CONN=""
    MAX_TOTAL_CONN=${MAX_TOTAL_CONN:-10000}
    [[ "$MAX_TOTAL_CONN" =~ ^[0-9]+$ ]] || MAX_TOTAL_CONN=10000

    read -t 30 -rp "Idle timeout in seconds (default: 60): " CONN_TIMEOUT < /dev/tty 2>/dev/null || CONN_TIMEOUT=""
    CONN_TIMEOUT=${CONN_TIMEOUT:-60}
    [[ "$CONN_TIMEOUT" =~ ^[0-9]+$ ]] || CONN_TIMEOUT=60

    PROXY_USER=$(tr -dc 'a-z' </dev/urandom 2>/dev/null | head -c 8 || echo "proxyuser")
    PROXY_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16 || echo "proxy$(date +%s)")

    mkdir -p /etc/3proxy "$PROXY_LOG_DIR"
    chmod 750 "$PROXY_LOG_DIR"
    echo "users $PROXY_USER:CL:$PROXY_PASS" > "$PROXY_USERS"
    chmod 600 "$PROXY_USERS"

    echo -e "${YELLOW}[5/7] Writing config...${NC}"
    cat > "$PROXY_CONF" << EOF
# 3proxy SOCKS5 — Generated: $(date)
# Cloudflare users: unlimited (no connlimit applied)
log $PROXY_LOG_DIR/access.log D
logformat "L%d-%m-%Y %H:%M:%S %U %C:%c %R:%r %O %I %E %T"
rotate 1
include $PROXY_USERS
nserver 8.8.8.8
nserver 1.1.1.1
nscache 65536
timeouts 1 5 30 $CONN_TIMEOUT 180 1800 15 60
maxconn $MAX_TOTAL_CONN
# Block private ranges (prevent SSRF)
deny * * 127.0.0.0/8
deny * * 10.0.0.0/8
deny * * 172.16.0.0/12
deny * * 192.168.0.0/16
deny * * 169.254.0.0/16
deny * * 100.64.0.0/10
auth strong
allow $PROXY_USER
socks -p$PORT -i0.0.0.0 -e0.0.0.0 -n$MAX_CONN
EOF
    chmod 600 "$PROXY_CONF"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=3proxy SOCKS5 Proxy Server
After=network.target
[Service]
Type=simple
User=root
LimitNOFILE=65535
LimitNPROC=65535
ExecStart=$PROXY_BIN $PROXY_CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/logrotate.d/3proxy << EOF
$PROXY_LOG_DIR/*.log {
    daily
    rotate 7
    maxsize 100M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    dateext
}
EOF

    echo -e "${YELLOW}[6/7] Firewall rules (CF=unlimited)...${NC}"
    setup_iptables_for_port "$PORT" "$MAX_CONN"

    echo -e "${YELLOW}[7/7] Bandwidth control...${NC}"
    # Detect main interface
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    MAIN_IF=${MAIN_IF:-eth0}
    if command -v tc >/dev/null 2>&1; then
        setup_tc "$MAIN_IF"
        save_tc_persistent "$MAIN_IF"
    else
        echo -e "${YELLOW}tc not available - bandwidth shaping skipped${NC}"
    fi

    # Save install info
    mkdir -p /etc/3proxy
    cat > /etc/3proxy/install.info << EOF
PORT=$PORT
USER=$PROXY_USER
PASS=$PROXY_PASS
MAX_CONN=$MAX_CONN
MAX_TOTAL_CONN=$MAX_TOTAL_CONN
INSTALL_DATE=$(date)
MAIN_IF=$MAIN_IF
EOF
    chmod 600 /etc/3proxy/install.info

    systemctl daemon-reload
    systemctl enable 3proxy >/dev/null 2>&1
    systemctl restart 3proxy
    sleep 2

    SERVER_IP=$(get_server_ip)
    SERVER_IPV6=$(get_server_ipv6)

    # Verify service started
    if ! systemctl is-active 3proxy >/dev/null 2>&1; then
        echo -e "${RED}⚠ 3proxy failed to start! Checking logs...${NC}"
        journalctl -u 3proxy -n 20 --no-pager 2>/dev/null || true
        return 1
    fi

    sep
    echo -e "${GREEN}✓ 3proxy SOCKS5 installed!${NC}"; sep
    echo -e "  Protocol : SOCKS5"
    echo -e "  Address  : ${GREEN}$SERVER_IP${NC}"
    echo -e "  Port     : ${GREEN}$PORT${NC}"
    echo -e "  User     : ${GREEN}$PROXY_USER${NC}"
    echo -e "  Password : ${GREEN}$PROXY_PASS${NC}"
    echo ""
    echo -e "  ${CYAN}Ready-to-use format:${NC}"
    echo -e "  ${GREEN}socks5://$PROXY_USER:$PROXY_PASS@$SERVER_IP:$PORT${NC}"
    [ -n "$SERVER_IPV6" ] && echo -e "  ${GREEN}socks5://$PROXY_USER:$PROXY_PASS@[$SERVER_IPV6]:$PORT${NC}"
    echo ""
    echo -e "  ${CYAN}Bandwidth control:${NC}"
    echo -e "  ${GREEN}CF IPs -> unlimited  |  Others -> 500Mbps${NC}"
    sep
    echo -e "  Status: ${GREEN}● Running${NC}"
    sep
}

uninstall_proxy() {
    sep; echo -e "${RED}Removing 3proxy...${NC}"; sep

    echo -e "${YELLOW}Stopping services...${NC}"

    # ── Stop & disable 3proxy ─────────────────────────────
    systemctl stop    3proxy 2>/dev/null || true
    systemctl disable 3proxy 2>/dev/null || true
    # Also stop any apt-installed 3proxy
    systemctl stop    3proxy.service 2>/dev/null || true

    # ── Stop & disable autoban ────────────────────────────
    systemctl stop    auto-ban  2>/dev/null || true
    systemctl disable auto-ban  2>/dev/null || true
    systemctl stop    auto-ban.service 2>/dev/null || true
    pkill -f "auto-ban.sh" 2>/dev/null || true

    # ── Stop & disable tc service ─────────────────────────
    systemctl stop    tc-proxy-limit  2>/dev/null || true
    systemctl disable tc-proxy-limit  2>/dev/null || true

    # ── Detect port before removing config ────────────────
    PORT=$(get_current_port 2>/dev/null || true)
    # Fallback: read from install.info
    if [ -z "$PORT" ] && [ -f /etc/3proxy/install.info ]; then
        PORT=$(grep -oP '(?<=^PORT=)\d+' /etc/3proxy/install.info 2>/dev/null | head -1 || true)
    fi

    # ── Remove iptables rules ─────────────────────────────
    if [ -n "$PORT" ]; then
        echo -e "${YELLOW}Cleaning iptables rules for port $PORT...${NC}"
        # CF-specific port rules
        for CF in "${CF_RANGES[@]}"; do
            [[ "$CF" == *":"* ]] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$CF" -j ACCEPT 2>/dev/null || true
        done
        # Self-IP rules for this port
        while IFS= read -r SIP; do
            [ -z "$SIP" ] && continue
            iptables -D INPUT -p tcp --dport "$PORT" -s "$SIP/32" \
                -m comment --comment "3proxy_self_allow" -j ACCEPT 2>/dev/null || true
        done < <(get_server_ips)
        # Rate-limit rules for this port
        iptables -D INPUT -p tcp --dport "$PORT" -m state --state NEW \
            -m recent --name "3proxy_${PORT}" --update \
            --seconds 60 --hitcount 60 -j DROP 2>/dev/null || true
        iptables -D INPUT -p tcp --dport "$PORT" -m state --state NEW \
            -m recent --name "3proxy_${PORT}" --set 2>/dev/null || true
        # connlimit rule for this port
        iptables -D INPUT -p tcp --dport "$PORT" \
            -m connlimit --connlimit-above 30 --connlimit-mask 32 \
            -j REJECT --reject-with tcp-reset 2>/dev/null || true
        # hashlimit rules for this port
        iptables -D INPUT -p tcp --dport "$PORT" \
            -m conntrack --ctstate NEW \
            -m hashlimit --hashlimit-above 200/min --hashlimit-burst 50 \
            --hashlimit-mode srcip --hashlimit-name "proxy_${PORT}" -j DROP 2>/dev/null || true
        # Stats counters
        iptables -D INPUT  -p tcp --dport "$PORT" \
            -m comment --comment "3proxy_stats_in"  2>/dev/null || true
        iptables -D OUTPUT -p tcp --sport "$PORT" \
            -m comment --comment "3proxy_stats_out" 2>/dev/null || true
        # Plain ACCEPT rule
        iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p tcp --dport "$PORT" \
            -m comment --comment "3proxy_cf_allow" -j ACCEPT 2>/dev/null || true
        # UFW / firewalld
        command -v ufw >/dev/null 2>&1 && ufw delete allow "$PORT"/tcp 2>/dev/null || true
        command -v firewall-cmd >/dev/null 2>&1 && {
            firewall-cmd --remove-port="${PORT}/tcp" --permanent 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
        }
    else
        echo -e "${YELLOW}⚠ Could not detect port — skipping port-specific iptables rules${NC}"
    fi

    # Remove auto-ban iptables rules (tagged with "auto-ban")
    iptables -S INPUT 2>/dev/null | grep '"auto-ban"' | while read -r rule; do
        # shellcheck disable=SC2086  # intentional: $rule expands to multiple iptables arguments
        iptables -D INPUT ${rule#-A INPUT } 2>/dev/null || true
    done

    # ── Remove tc bandwidth shaping ───────────────────────
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    MAIN_IF=${MAIN_IF:-eth0}
    tc qdisc del dev "$MAIN_IF" root 2>/dev/null || true
    rm -f /etc/systemd/system/tc-proxy-limit.service
    rm -f /etc/network/if-up.d/tc-proxy-limit
    rm -f /opt/proxy-manager/tc-setup.sh

    # ── Remove fail2ban jails for 3proxy ─────────────────
    rm -f /etc/fail2ban/jail.d/3proxy-ddos.conf   2>/dev/null || true
    rm -f /etc/fail2ban/jail.d/3proxy.conf        2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy-ddos.conf 2>/dev/null || true
    rm -f /etc/fail2ban/filter.d/3proxy.conf      2>/dev/null || true
    command -v fail2ban-client >/dev/null 2>&1 && {
        fail2ban-client stop  3proxy-ddos 2>/dev/null || true
        fail2ban-client unban --all       2>/dev/null || true
        systemctl reload fail2ban 2>/dev/null || true
    }

    # ── Remove systemd service files ─────────────────────
    rm -f "$SERVICE_FILE"
    rm -f /etc/systemd/system/auto-ban.service
    rm -f /etc/systemd/system/tc-proxy-limit.service

    # ── Remove binary ─────────────────────────────────────
    # Only remove our binary — don't touch apt-installed one if it differs
    if [ -L "$PROXY_BIN" ]; then
        rm -f "$PROXY_BIN"   # it's a symlink we created
    elif [ -f "$PROXY_BIN" ]; then
        rm -f "$PROXY_BIN"   # compiled binary we installed
    fi

    # ── Remove config, logs, state ────────────────────────
    rm -rf /etc/3proxy
    rm -rf "$PROXY_LOG_DIR"
    rm -f  /etc/logrotate.d/3proxy
    rm -rf /etc/antiddos
    rm -rf /var/lib/antiddos
    rm -f  /var/log/antiddos.log
    rm -f  /tmp/autoban_watch /tmp/autoban_throttle /tmp/autoban_banned 2>/dev/null || true

    # ── Reload systemd ────────────────────────────────────
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed  2>/dev/null || true

    sep
    echo -e "${GREEN}✓ 3proxy and all related components removed.${NC}"
    echo -e "${YELLOW}  Note: Anti-DDoS iptables rules (SYN/UDP/connlimit) are kept${NC}"
    echo -e "${YELLOW}  to protect the server. Run 'antiddos --remove' to remove them too.${NC}"
    sep
    sleep 2
}

show_info() {
    [ ! -f /etc/3proxy/install.info ] && echo -e "${RED}Not installed.${NC}" && return
    local _INFO_USER _INFO_PASS _INFO_PORT
    _INFO_USER=$(grep '^USER=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    _INFO_PASS=$(grep '^PASS=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    _INFO_PORT=$(grep '^PORT=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    SERVER_IP=$(get_server_ip)
    SERVER_IPV6=$(get_server_ipv6)
    sep
    echo -e "  ${CYAN}Connection info:${NC}"; sep
    echo -e "  socks5://${_INFO_USER:-?}:${_INFO_PASS:-?}@$SERVER_IP:${_INFO_PORT:-?}"
    [ -n "$SERVER_IPV6" ] && echo -e "  socks5://${_INFO_USER:-?}:${_INFO_PASS:-?}@[$SERVER_IPV6]:${_INFO_PORT:-?}"
    sep
}

show_stats() {
    PORT=$(get_current_port || true)
    [ -z "$PORT" ] && echo -e "${RED}Not installed.${NC}" && return
    sep; echo -e "  ${CYAN}Stats - port $PORT${NC}"; sep
    ACTIVE=$(ss -tnp 2>/dev/null | grep ":$PORT " | grep -v LISTEN | wc -l || echo 0)
    echo -e "  Active connections: ${GREEN}$ACTIVE${NC}"

    IN_B=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "3proxy_stats_in" | awk '{print $2}' | head -1)
    OUT_B=$(iptables -L OUTPUT -v -n -x 2>/dev/null | grep "3proxy_stats_out" | awk '{print $2}' | head -1)

    _fmt() {
        # Format bytes without depending on `bc` (absent on some systems → used to show blank)
        awk -v n="${1:-0}" 'BEGIN{
            if (n>=1073741824) printf "%.2f GB\n", n/1073741824;
            else if (n>=1048576) printf "%.2f MB\n", n/1048576;
            else if (n>=1024) printf "%.2f KB\n", n/1024;
            else printf "%d B\n", n;
        }'
    }
    # 3proxy_stats_in  = bytes clients SENT to proxy (upload)
    # 3proxy_stats_out = bytes proxy   SENT to clients (download)
    echo -e "  Download (proxy -> client): ${GREEN}$(_fmt "$OUT_B")${NC}"
    echo -e "  Upload   (client -> proxy): ${GREEN}$(_fmt "$IN_B")${NC}"

    # tc stats
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -n "$MAIN_IF" ] && command -v tc >/dev/null 2>&1; then
        echo ""
        echo -e "  ${CYAN}Bandwidth classes (tc):${NC}"
        tc -s class show dev "$MAIN_IF" 2>/dev/null | \
            grep -A2 "class htb" | grep -E "class htb|bytes" | \
            paste - - | awk -F'\t' '{printf "  %-30s %s\n", $1, $2}' | head -6 || true
    fi

    [ -f "$PROXY_LOG_DIR/access.log" ] && {
        echo ""
        echo -e "  ${CYAN}Last 10 connections:${NC}"
        tail -10 "$PROXY_LOG_DIR/access.log" 2>/dev/null || true
    }
    sep
    printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true
}

show_menu() {
    clear; sep; echo -e "  ${CYAN}3proxy SOCKS5 Manager${NC}"; sep
    is_installed && {
        PORT=$(get_current_port || true)
        ST=$(systemctl is-active 3proxy 2>/dev/null || echo "unknown")
        [ "$ST" = "active" ] && \
            echo -e "  Status: ${GREEN}● Running${NC}  Port: ${CYAN}$PORT${NC}" || \
            echo -e "  Status: ${RED}● Stopped${NC}  Port: ${CYAN}$PORT${NC}"
        sep
    }
    echo -e "  ${CYAN}1.${NC} Install/Update   ${CYAN}2.${NC} Remove"
    echo -e "  ${CYAN}3.${NC} Stop             ${CYAN}4.${NC} Restart"
    echo -e "  ${CYAN}5.${NC} Traffic stats    ${CYAN}6.${NC} Connection info"
    echo -e "  ${CYAN}7.${NC} Live log         ${CYAN}8.${NC} tc bandwidth status"
    echo -e "  ${CYAN}0.${NC} Back"
    sep
}

# ── CLI flags (called from proxy-menu.sh) ────────────────
case "${1:-}" in
    --install|-i) install_proxy;  exit 0 ;;
    --remove|-r)  uninstall_proxy; exit 0 ;;
    --stats|-s)   show_stats;      exit 0 ;;
    --info)       show_info; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; exit 0 ;;
    --restart)    systemctl restart 3proxy 2>/dev/null && \
                      echo -e "${GREEN}Restarted${NC}" || echo -e "${RED}Error${NC}"; exit 0 ;;
    --stop)       systemctl stop 3proxy 2>/dev/null && \
                      echo -e "${GREEN}Stopped${NC}" || echo -e "${RED}Error${NC}"; exit 0 ;;
    --start)      systemctl start 3proxy 2>/dev/null && \
                      echo -e "${GREEN}Started${NC}" || echo -e "${RED}Error${NC}"; exit 0 ;;
    --log)        tail -f "$PROXY_LOG_DIR/access.log" 2>/dev/null || \
                      journalctl -u 3proxy -f --no-pager; exit 0 ;;
    --tc-status)  MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
                  echo -e "${CYAN}tc classes on ${MAIN_IF:-eth0}:${NC}"
                  tc class show dev "${MAIN_IF:-eth0}" 2>/dev/null || echo "tc not configured"
                  printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; exit 0 ;;
    --change-pass)
                  NEW_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16 || echo "proxy$(date +%s)")
                  CU=$(grep -oP '(?<=allow )\S+' "$PROXY_CONF" 2>/dev/null | head -1 || echo "")
                  if [ -n "$CU" ]; then
                      echo "users ${CU}:CL:${NEW_PASS}" > "$PROXY_USERS"
                      [ -f /etc/3proxy/install.info ] && \
                          sed -i "s/^PASS=.*/PASS=${NEW_PASS}/" /etc/3proxy/install.info 2>/dev/null || true
                      systemctl restart 3proxy 2>/dev/null && \
                          echo -e "${GREEN}Password changed: ${NEW_PASS}${NC}" || \
                          echo -e "${RED}Restart failed${NC}"
                  else
                      echo -e "${RED}Not installed${NC}"
                  fi
                  exit 0 ;;
esac

# Standalone mode (run directly without args): show own menu
while true; do
    show_menu
    printf '%s' "  Enter choice: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) install_proxy; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) printf '%s' "  Remove 3proxy completely? (y/N): " >/dev/tty; read -r _RC2 </dev/tty || _RC2=""
           [[ "$_RC2" == "y" || "$_RC2" == "Y" ]] && uninstall_proxy || echo -e "  ${DIM}Cancelled.${NC}" ;;
        3) systemctl stop 3proxy 2>/dev/null && \
               echo -e "${GREEN}Stopped${NC}" || \
               echo -e "${RED}Error stopping${NC}"; sleep 1 ;;
        4) systemctl restart 3proxy 2>/dev/null && \
               echo -e "${GREEN}Restarted${NC}" || \
               echo -e "${RED}Error restarting${NC}"; sleep 1 ;;
        5) show_stats ;;
        6) show_info; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        7) tail -f "$PROXY_LOG_DIR/access.log" 2>/dev/null || \
               journalctl -u 3proxy -f --no-pager ;;
        8) MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
           echo -e "${CYAN}tc classes on ${MAIN_IF:-eth0}:${NC}"
           tc class show dev "${MAIN_IF:-eth0}" 2>/dev/null || echo "tc not configured"
           printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
