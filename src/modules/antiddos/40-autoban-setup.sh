# @part modules/antiddos/40-autoban-setup.sh - setup_autoban (writes the auto-ban daemon)
# Assembled into antiddos.sh by tools/build.py - not a standalone script.
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
