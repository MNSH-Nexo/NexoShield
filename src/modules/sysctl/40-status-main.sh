# @part modules/sysctl/40-status-main.sh - do_status, show_server_info, do_install, main dispatch
# Assembled into optimize-sysctl.sh by tools/build.py - not a standalone script.
do_status() {
    sep; echo -e "  ${CYAN}${BOLD}sysctl Status${NC}"; sep
    for P in net.ipv4.tcp_congestion_control net.core.default_qdisc net.core.rmem_max \
              net.ipv4.tcp_notsent_lowat net.core.somaxconn net.ipv4.ip_forward \
              vm.swappiness net.netfilter.nf_conntrack_max \
              net.ipv4.tcp_keepalive_time net.ipv4.conf.all.rp_filter; do
        V=$(sysctl -n "$P" 2>/dev/null || echo "N/A")
        printf "  ${DIM}%-50s${NC} %s\n" "$P" "$V"
    done
    [ -f "$TARGET_FILE" ] && success "Config installed: $TARGET_FILE" || \
        warn "Config not installed"
    sep
}

show_server_info() {
    sep; echo -e "  ${CYAN}${BOLD}Server Analysis${NC}"; sep
    printf "  %-20s ${GREEN}%s${NC}\n" "OS:"        "$OS_NAME $OS_VERSION"
    printf "  %-20s ${GREEN}%s${NC}\n" "Kernel:"    "$KERNEL"
    printf "  %-20s ${GREEN}%s${NC}\n" "RAM:"       "${RAM_MB}MB"
    printf "  %-20s ${GREEN}%s${NC}\n" "CPU:"       "$CPU_CORES core(s)"
    printf "  %-20s ${GREEN}%s${NC}\n" "Virt:"      "$VIRT_TYPE"
    printf "  %-20s ${GREEN}%s${NC}\n" "IPv4:"      "$([ "$HAS_IPV4" -eq 1 ] && \
        echo "Yes ($IPV4_COUNT, $PUBLIC_IP_COUNT public)" || echo "No")"
    printf "  %-20s ${GREEN}%s${NC}\n" "IPv6:"      "$([ "$HAS_IPV6" -eq 1 ] && \
        echo "Yes ($IPV6_COUNT)" || echo "No")"
    printf "  %-20s ${GREEN}%s${NC}\n" "Swap:"      "$([ "$HAS_SWAP" -eq 1 ] && echo "Yes" || echo "No")"
    printf "  %-20s ${GREEN}%s${NC}\n" "BBR:"       "$([ "$BBR_AVAILABLE" -eq 1 ] && \
        echo "Available ✓" || echo "Not available")"
    printf "  %-20s ${GREEN}%s${NC}\n" "conntrack:" "$([ "$CONNTRACK_AVAILABLE" -eq 1 ] && \
        echo "Available ✓" || echo "Not available")"
    printf "  %-20s ${GREEN}%s${NC}\n" "Multi-IP:"  "$([ "$PUBLIC_IP_COUNT" -gt 1 ] && \
        echo "Yes (rp_filter=0)" || echo "No (rp_filter=1)")"
    echo ""
    echo -e "  ${CYAN}Proposed changes:${NC}"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "congestion:" "$CURRENT_CONGESTION" "$CONGESTION"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "rmem_max:" \
        "$(echo "scale=0; ${CURRENT_RMEM:-0}/1024/1024" | bc 2>/dev/null || echo 0)MB" \
        "$(echo "scale=0; $BUF_MAX/1024/1024" | bc)MB"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "swappiness:" "$CURRENT_SWAPPINESS" "$SWAPPINESS"
    printf "  %-25s %s -> ${CYAN}%s${NC}\n" "keepalive_time:" "$(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || echo '?')" "30"
    sep
}

do_install() {
    show_server_info
    # Read from /dev/tty directly — always reliable
    printf '%s' "  Continue? (y/N): " >/dev/tty
    read -r CF </dev/tty || CF=""
    [[ "$CF" != "y" && "$CF" != "Y" ]] && echo "  Cancelled." && return

    mkdir -p "$SNAPSHOT_DIR"
    touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
    info "Taking snapshot..."
    SNAP_ID=$(take_snapshot)
    success "Snapshot: $SNAP_ID"
    info "Writing config..."
    write_config
    success "File: $TARGET_FILE"
    info "Applying settings..."
    apply_config
    sep
    success "Optimization complete!"
    echo -e "  ${CYAN}Rollback:${NC} proxy -> Network Optimization -> Rollback"
    sep
}

case "${1:-}" in
    --rollback|-r)  acquire_lock; detect_environment; calculate_values; do_rollback; exit 0 ;;
    --status|-s)    detect_environment; calculate_values; do_status; exit 0 ;;
    --analyze|-a)   detect_environment; calculate_values; show_server_info; exit 0 ;;
    --install|-i)   acquire_lock; detect_environment; calculate_values; do_install; exit 0 ;;
    --auto|-y)      acquire_lock; detect_environment; calculate_values
                    mkdir -p "$SNAPSHOT_DIR"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
                    SNAP_ID=$(take_snapshot); write_config; apply_config
                    success "Auto install complete - snapshot: $SNAP_ID"; exit 0 ;;
esac

acquire_lock; detect_environment; calculate_values

while true; do
    clear; sep
    echo -e "  ${CYAN}${BOLD}Network Optimization (sysctl) v${SCRIPT_VERSION}${NC}"; sep
    [ -f "$TARGET_FILE" ] && \
        echo -e "  Status: ${GREEN}✓ Installed${NC}" || \
        echo -e "  Status: ${YELLOW}○ Not installed${NC}"
    echo ""
    echo -e "  ${CYAN}1.${NC}  Install/Optimize     ${CYAN}2.${NC}  Rollback"
    echo -e "  ${CYAN}3.${NC}  Current status       ${CYAN}4.${NC}  Analyze (no changes)"
    echo -e "  ${CYAN}0.${NC}  Back"; sep
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        printf '%s' "  Enter number: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) do_install; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) do_rollback; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        3) do_status; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        4) show_server_info; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
