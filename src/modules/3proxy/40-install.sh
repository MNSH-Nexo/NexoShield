# @part modules/3proxy/40-install.sh - install_proxy
# Assembled into 3proxy-socks5.sh by tools/build.py - not a standalone script.
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

