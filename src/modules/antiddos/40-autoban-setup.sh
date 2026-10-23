# @part modules/antiddos/40-autoban-setup.sh - setup_autoban (writes the auto-ban daemon)
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
setup_autoban() {
    info "Setting up smart throttle+ban..."

    # Phase 1a: install the default scoring config (never overwrites
    # an admin-edited one). The daemon works without it (defaults),
    # but shipping it documents every tunable in place.
    nx_ensure_scoring_config || true

    # Phase 2a: the conntrack event counter feeds the daemon exact
    # arrival/completion data (see setup_countd below).
    setup_countd || true

    # Phase 3: the XDP emergency shield (built only with a BPF
    # toolchain present; dormant otherwise).
    setup_xdp || true

    # Require tcpdump
    if ! command -v tcpdump >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump 2>/dev/null || true
        fi
    fi

    cat > "$AUTOBAN_SCRIPT.nxnew" << 'AUTOBAN_EOF'
@@AUTOBAN_BODY@@
AUTOBAN_EOF

    # Staged activation (BUG-025): never truncate the live daemon script
    if ! bash -n "$AUTOBAN_SCRIPT.nxnew" 2>/dev/null; then
        rm -f "$AUTOBAN_SCRIPT.nxnew"
        error "generated auto-ban script failed its syntax check - keeping the previous one"
        return 1
    fi
    [ -f "$AUTOBAN_SCRIPT" ] && cp -a "$AUTOBAN_SCRIPT" "$AUTOBAN_SCRIPT.prev" 2>/dev/null || true
    mv "$AUTOBAN_SCRIPT.nxnew" "$AUTOBAN_SCRIPT"
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

# setup_countd (Phase 2a): build + install nxcountd when a compiler
# and the conntrack netlink headers are available. ANY failure is a
# warning, never an install failure: without the snapshot file the
# daemon simply keeps its polling behaviour.
setup_countd() {
    if ! command -v cc >/dev/null 2>&1 || [ ! -f /usr/include/linux/netfilter/nfnetlink_conntrack.h ]; then
        warn "nxcountd: compiler/headers missing - event counting unavailable (daemon polls instead)"
        return 0
    fi
    local build_dir
    build_dir=$(mktemp -d) || return 0
    cat > "$build_dir/nxcountd.c" << 'NXCOUNTD_EOF'
@@NXCOUNTD_C@@
NXCOUNTD_EOF
    if ! cc -O2 -o /usr/local/bin/nxcountd "$build_dir/nxcountd.c" 2>/dev/null; then
        warn "nxcountd: build failed - event counting unavailable (daemon polls instead)"
        rm -rf "$build_dir"
        return 0
    fi
    rm -rf "$build_dir"
    cat > /etc/systemd/system/nexoshield-countd.service << 'EOF'
[Unit]
Description=NexoShield conntrack event counter
After=network.target
Before=auto-ban.service

[Service]
Type=simple
ExecStart=/usr/local/bin/nxcountd /run/nexoshield/counters.dat
Restart=always
RestartSec=5
RuntimeDirectory=nexoshield
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run/nexoshield
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable nexoshield-countd.service >/dev/null 2>&1
    systemctl restart nexoshield-countd.service 2>/dev/null || true
    success "nxcountd: conntrack event counter installed (exact arrival counting)"
}

# setup_xdp (Phase 3): build the XDP emergency shield when clang and
# libbpf headers are available (one best-effort package attempt,
# house style). Any failure leaves the feature dormant - the daemon
# probes for the files and simply never attaches.
setup_xdp() {
    if ! command -v clang >/dev/null 2>&1 || [ ! -f /usr/include/bpf/libbpf.h ]; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libbpf-dev >/dev/null 2>&1 || true
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y clang libbpf-devel >/dev/null 2>&1 || true
        fi
    fi
    if ! command -v clang >/dev/null 2>&1 || [ ! -f /usr/include/bpf/libbpf.h ]; then
        info "XDP shield: no clang/libbpf - dormant feature skipped"
        return 0
    fi
    local build_dir
    build_dir=$(mktemp -d) || return 0
    cat > "$build_dir/nx_xdp.c" << 'NXXDP_EOF'
@@NX_XDP_C@@
NXXDP_EOF
    cat > "$build_dir/nx-xdp-loader.c" << 'NXLOADER_EOF'
@@NX_XDP_LOADER_C@@
NXLOADER_EOF
    mkdir -p /usr/local/lib
    if clang -O2 -target bpf -c "$build_dir/nx_xdp.c" -o /usr/local/lib/nx_xdp.o 2>/dev/null \
       && cc -O2 -o /usr/local/bin/nx-xdp "$build_dir/nx-xdp-loader.c" -lbpf 2>/dev/null; then
        success "XDP emergency shield: built (dormant; attaches only under flood pressure)"
    else
        warn "XDP shield: build failed - feature stays dormant"
        rm -f /usr/local/lib/nx_xdp.o /usr/local/bin/nx-xdp
    fi
    rm -rf "$build_dir"
}
