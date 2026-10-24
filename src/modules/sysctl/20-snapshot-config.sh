# @part modules/sysctl/20-snapshot-config.sh - take_snapshot + write_config
# Assembled into optimize-sysctl.sh by tools/build.py - not a standalone script.
take_snapshot() {
    SNAPSHOT_ID="$(date +%Y%m%d_%H%M%S)"
    SNAPSHOT_PATH="$SNAPSHOT_DIR/$SNAPSHOT_ID"
    mkdir -p "$SNAPSHOT_PATH"
    # Save full sysctl dump (for reference only)
    sysctl -a 2>/dev/null > "$SNAPSHOT_PATH/sysctl_values.txt" || true
    # Save ONLY the keys we actually change — used for targeted rollback
    {
        for KEY in \
            net.core.rmem_max net.core.wmem_max \
            net.core.rmem_default net.core.wmem_default \
            net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_mem \
            net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min net.ipv4.udp_mem \
            net.core.default_qdisc net.ipv4.tcp_congestion_control \
            net.ipv4.tcp_notsent_lowat net.ipv4.tcp_fin_timeout \
            net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl \
            net.ipv4.tcp_keepalive_probes net.ipv4.tcp_slow_start_after_idle \
            net.ipv4.tcp_fastopen net.ipv4.tcp_synack_retries \
            net.ipv4.tcp_syn_retries net.ipv4.tcp_tw_reuse \
            net.core.somaxconn net.core.netdev_max_backlog \
            net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_max_tw_buckets \
            net.ipv4.tcp_max_orphans net.ipv4.tcp_ecn \
            net.ipv4.tcp_mtu_probing net.ipv4.tcp_window_scaling \
            net.core.netdev_budget net.core.netdev_budget_usecs \
            net.netfilter.nf_conntrack_max \
            net.netfilter.nf_conntrack_tcp_timeout_established \
            net.netfilter.nf_conntrack_tcp_timeout_syn_recv \
            net.netfilter.nf_conntrack_tcp_timeout_time_wait \
            net.netfilter.nf_conntrack_tcp_timeout_fin_wait \
            net.netfilter.nf_conntrack_tcp_timeout_close_wait \
            net.netfilter.nf_conntrack_udp_timeout \
            net.netfilter.nf_conntrack_udp_timeout_stream \
            net.netfilter.nf_conntrack_icmp_timeout \
            net.netfilter.nf_conntrack_generic_timeout \
            net.ipv4.ip_forward net.ipv4.conf.all.rp_filter \
            net.ipv4.conf.default.rp_filter net.ipv4.tcp_syncookies \
            net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
            net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route \
            net.ipv4.conf.all.log_martians net.ipv4.icmp_echo_ignore_broadcasts \
            net.ipv4.icmp_ignore_bogus_error_responses \
            vm.swappiness vm.dirty_ratio vm.dirty_background_ratio \
            fs.file-max \
            net.ipv6.conf.all.forwarding \
            net.ipv6.conf.all.accept_redirects \
            net.ipv6.conf.default.accept_redirects \
            net.ipv6.route.max_size \
            net.ipv6.neigh.default.gc_thresh1 \
            net.ipv6.neigh.default.gc_thresh2 \
            net.ipv6.neigh.default.gc_thresh3; do
            V=$(sysctl -n "$KEY" 2>/dev/null) || continue
            echo "$KEY = $V"
        done
    } > "$SNAPSHOT_PATH/our_keys.txt"
    cp /etc/sysctl.conf "$SNAPSHOT_PATH/sysctl.conf" 2>/dev/null || true
    [ -d /etc/sysctl.d ] && cp -r /etc/sysctl.d "$SNAPSHOT_PATH/sysctl.d" 2>/dev/null || true
    # Record the exact list of sysctl.d files present at snapshot time.
    # Used by rollback to remove files that OUR script added after this snapshot,
    # without touching unrelated system files.
    ls /etc/sysctl.d/ 2>/dev/null > "$SNAPSHOT_PATH/sysctl_d_list.txt" || true
    cat > "$SNAPSHOT_PATH/meta.txt" << EOF
SNAPSHOT_ID=$SNAPSHOT_ID
DATE=$(date)
KERNEL=$(uname -r)
OS=$OS_NAME $OS_VERSION
RAM=${RAM_MB}MB
SCRIPT_VERSION=$SCRIPT_VERSION
EOF
    echo "$SNAPSHOT_ID"
}

write_config() {
    [ "$BBR_AVAILABLE" -eq 1 ] && \
        sysctl -w "net.ipv4.tcp_congestion_control=bbr" >/dev/null 2>&1 || \
        CONGESTION="cubic"

    cat > "$TARGET_FILE" << EOF
# VPN/Proxy sysctl Optimized — $(date)
# RAM: ${RAM_MB}MB | CPU: ${CPU_CORES} | OS: ${OS_NAME} | Kernel: ${KERNEL} | Virt: ${VIRT_TYPE}
# rollback: proxy -> Network Optimization -> Rollback
net.core.rmem_max = $BUF_MAX
net.core.wmem_max = $BUF_MAX
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 32768 262144 $BUF_MAX
net.ipv4.tcp_wmem = 32768 262144 $BUF_MAX
net.ipv4.tcp_mem = 65536 $TCP_MEM_PRESSURE $TCP_MEM_MAX
EOF
    [ "$HAS_IPV4" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536
net.ipv4.udp_mem = 65536 262144 786432
EOF
    cat >> "$TARGET_FILE" << EOF
net.core.default_qdisc = $QDISC
net.ipv4.tcp_congestion_control = $CONGESTION
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = $SOMAXCONN
net.core.netdev_max_backlog = $BACKLOG
net.ipv4.tcp_max_syn_backlog = $SYN_BACKLOG
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 4000
EOF
    [ "$CONNTRACK_AVAILABLE" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.netfilter.nf_conntrack_max = $CONNTRACK_MAX
net.netfilter.nf_conntrack_tcp_timeout_established = 120
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 8
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
EOF
    [ "$HAS_IPV4" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.ipv4.ip_forward = $IP_FORWARD
net.ipv4.conf.all.rp_filter = $RP_FILTER
net.ipv4.conf.default.rp_filter = $RP_FILTER
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
    [ "$HAS_IPV6" -eq 1 ] && cat >> "$TARGET_FILE" << EOF
net.ipv6.conf.all.forwarding = $IP_FORWARD
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.route.max_size = 409600
net.ipv6.neigh.default.gc_thresh1 = 1024
net.ipv6.neigh.default.gc_thresh2 = 4096
net.ipv6.neigh.default.gc_thresh3 = 8192
EOF
    cat >> "$TARGET_FILE" << EOF
fs.file-max = 1048576
vm.swappiness = $SWAPPINESS
vm.dirty_ratio = 5
vm.dirty_background_ratio = 2
EOF
    chmod 644 "$TARGET_FILE"
}

