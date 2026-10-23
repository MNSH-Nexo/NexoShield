#!/bin/bash
set -uo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
TARGET_FILE="/etc/sysctl.d/99-vpn-optimized.conf"
SNAPSHOT_DIR="/var/lib/vpn-sysctl-snapshots"
LOG_FILE="/var/log/vpn-sysctl-optimizer.log"
LOCK_FILE="/var/run/vpn-sysctl.lock"
SCRIPT_VERSION="@@VERSION@@"

[ "$EUID" -ne 0 ] && echo -e "${RED}Root required${NC}" && exit 1

log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }
info()    { echo -e "  ${CYAN}i${NC}  $*"; log "INFO: $*"; }
success() { echo -e "  ${GREEN}✓${NC}  $*"; log "OK: $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; log "WARN: $*"; }
err()     { echo -e "  ${RED}✗${NC}  $*"; log "ERR: $*"; }
sep()     { echo -e "${CYAN}════════════════════════════════════════════════${NC}"; }

acquire_lock() {
    [ -f "$LOCK_FILE" ] && OLD_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo 0) && \
        kill -0 "$OLD_PID" 2>/dev/null && err "Already running (PID:$OLD_PID)" && exit 1
    echo $$ > "$LOCK_FILE"
}
release_lock() { rm -f "$LOCK_FILE"; }
trap release_lock EXIT INT TERM

detect_environment() {
    info "Analyzing server..."
    RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 1048576)
    RAM_KB="${RAM_KB//[^0-9]/}"; RAM_KB="${RAM_KB:-1048576}"
    RAM_MB=$((RAM_KB / 1024))
    CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
    CPU_CORES="${CPU_CORES//[^0-9]/}"; CPU_CORES="${CPU_CORES:-1}"
    KERNEL=$(uname -r)
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_NAME="${NAME:-Unknown}"
        OS_VERSION="${VERSION_ID:-}"
    else
        OS_NAME="Unknown"; OS_VERSION=""
    fi

    HAS_IPV4=0; HAS_IPV6=0; IPV4_COUNT=0; IPV6_COUNT=0
    if ip -4 addr show 2>/dev/null | grep -q 'inet '; then
        HAS_IPV4=1
        IPV4_COUNT=$(ip -4 addr show 2>/dev/null | grep -c 'inet ' || echo 0)
    fi
    if ip -6 addr show 2>/dev/null | grep -v '::1\|fe80' | grep -q 'inet6'; then
        HAS_IPV6=1
        IPV6_COUNT=$(ip -6 addr show 2>/dev/null | grep -v '::1\|fe80' | grep -c 'inet6' || echo 0)
    fi

    PUBLIC_IP_COUNT=$(ip -4 addr show 2>/dev/null | grep 'inet ' | \
        grep -v '127\.\|10\.\|192\.168\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.' | \
        wc -l 2>/dev/null || echo 0)


    BBR_AVAILABLE=0
    modprobe tcp_bbr 2>/dev/null || true
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        BBR_AVAILABLE=1
    fi

    CONNTRACK_AVAILABLE=0
    if modprobe nf_conntrack 2>/dev/null; then CONNTRACK_AVAILABLE=1; fi

    VIRT_TYPE="bare-metal"
    if [ -f /proc/vz/version ]; then VIRT_TYPE="openvz"
    elif systemd-detect-virt 2>/dev/null | grep -qi kvm; then VIRT_TYPE="kvm"
    elif systemd-detect-virt 2>/dev/null | grep -qi lxc; then VIRT_TYPE="lxc"
    fi

    SWAP_TOTAL=$(grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
    HAS_SWAP=0; [ "${SWAP_TOTAL:-0}" -gt 0 ] && HAS_SWAP=1

    CURRENT_CONGESTION=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    CURRENT_RMEM=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    CURRENT_SWAPPINESS=$(sysctl -n vm.swappiness 2>/dev/null || echo 60)
}

calculate_values() {
    if [ "$RAM_MB" -ge 8192 ]; then
        BUF_MAX=268435456; TCP_MEM_MAX=6291456; TCP_MEM_PRESSURE=2097152
        CONNTRACK_MAX=1048576; SOMAXCONN=65536; BACKLOG=65536; SYN_BACKLOG=32768
    elif [ "$RAM_MB" -ge 4096 ]; then
        BUF_MAX=134217728; TCP_MEM_MAX=3145728; TCP_MEM_PRESSURE=1048576
        CONNTRACK_MAX=524288; SOMAXCONN=32768; BACKLOG=32768; SYN_BACKLOG=16384
    elif [ "$RAM_MB" -ge 2048 ]; then
        BUF_MAX=134217728; TCP_MEM_MAX=3145728; TCP_MEM_PRESSURE=1048576
        CONNTRACK_MAX=262144; SOMAXCONN=32768; BACKLOG=32768; SYN_BACKLOG=16384
    elif [ "$RAM_MB" -ge 1024 ]; then
        BUF_MAX=67108864; TCP_MEM_MAX=1572864; TCP_MEM_PRESSURE=524288
        CONNTRACK_MAX=131072; SOMAXCONN=16384; BACKLOG=16384; SYN_BACKLOG=8192
    else
        BUF_MAX=33554432; TCP_MEM_MAX=786432; TCP_MEM_PRESSURE=262144
        CONNTRACK_MAX=65536; SOMAXCONN=8192; BACKLOG=8192; SYN_BACKLOG=4096
    fi

    [ "$BBR_AVAILABLE" -eq 1 ] && CONGESTION="bbr" || CONGESTION="cubic"
    QDISC="fq"

    # Multi-IP servers: rp_filter=0 (important for servers with multiple public IPs)
    [ "$PUBLIC_IP_COUNT" -gt 1 ] && RP_FILTER=0 || RP_FILTER=1
    IP_FORWARD=1
    [ "$HAS_SWAP" -eq 1 ] && SWAPPINESS=10 || SWAPPINESS=1
    [ "$VIRT_TYPE" = "openvz" ] && CONNTRACK_AVAILABLE=0 && BUF_MAX=$((BUF_MAX / 2))
}

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
            vm.swappiness vm.dirty_ratio vm.dirty_background_ratio; do
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
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 5
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

apply_config() {
    FAILED_PARAMS=(); APPLIED_COUNT=0; SKIPPED_COUNT=0
    modprobe tcp_bbr 2>/dev/null || true
    modprobe nf_conntrack 2>/dev/null || true

    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
        VAL=$(echo "$line" | cut -d= -f2- | tr -d ' ')
        [ -z "$KEY" ] || [ -z "$VAL" ] && continue
        if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
            APPLIED_COUNT=$((APPLIED_COUNT + 1))
        else
            FAILED_PARAMS+=("$KEY=$VAL")
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            sed -i "s|^${KEY} = |# [DISABLED] ${KEY} = |g" "$TARGET_FILE" 2>/dev/null || true
        fi
    done < "$TARGET_FILE"

    [ ${#FAILED_PARAMS[@]} -gt 0 ] && warn "${#FAILED_PARAMS[@]} params auto-disabled (virt limits)"
    success "$APPLIED_COUNT applied${SKIPPED_COUNT:+, $SKIPPED_COUNT skipped}"
}

do_rollback() {
    sep; echo -e "  ${CYAN}${BOLD}Rollback${NC}"; sep

    # ── Find snapshots ────────────────────────────────────
    SNAPSHOTS=()
    while IFS= read -r d; do
        [ -d "$SNAPSHOT_DIR/$d" ] && SNAPSHOTS+=("$d")
    done < <(ls -1t "$SNAPSHOT_DIR" 2>/dev/null | head -10)

    if [ ${#SNAPSHOTS[@]} -eq 0 ]; then
        err "No snapshots found in $SNAPSHOT_DIR"
        echo -e "  ${DIM}Snapshots are created automatically before each install.${NC}"
        return
    fi

    # ── List snapshots ────────────────────────────────────
    echo -e "  Available snapshots:"
    echo ""
    for i in "${!SNAPSHOTS[@]}"; do
        DATE=$(grep '^DATE=' "$SNAPSHOT_DIR/${SNAPSHOTS[$i]}/meta.txt" 2>/dev/null | \
            cut -d= -f2- || echo "${SNAPSHOTS[$i]}")
        # Mark if this was a pre-install snapshot
        HAS_KEYS=""; [ -f "$SNAPSHOT_DIR/${SNAPSHOTS[$i]}/our_keys.txt" ] && HAS_KEYS=" ${DIM}(targeted)${NC}"
        echo -e "  ${CYAN}$((i+1)).${NC} ${SNAPSHOTS[$i]}  ${DIM}$DATE${NC}${HAS_KEYS}"
    done
    echo ""

    # ── Select ────────────────────────────────────────────
    printf '%s' "  Which snapshot? (1-${#SNAPSHOTS[@]}, default 1): " >/dev/tty
    read -r CH </dev/tty || CH="1"
    CH=${CH:-1}
    if ! [[ "$CH" =~ ^[0-9]+$ ]] || [ "$CH" -lt 1 ] || [ "$CH" -gt ${#SNAPSHOTS[@]} ]; then
        err "Invalid selection: '$CH'"
        return
    fi

    SELECTED="${SNAPSHOTS[$((CH-1))]}"
    SPATH="$SNAPSHOT_DIR/$SELECTED"
    DATE_SEL=$(grep '^DATE=' "$SPATH/meta.txt" 2>/dev/null | cut -d= -f2- || echo "$SELECTED")

    echo ""
    echo -e "  Snapshot : ${CYAN}$SELECTED${NC}"
    echo -e "  Date     : $DATE_SEL"
    echo ""

    # ── Confirm ───────────────────────────────────────────
    printf '%s' "  Confirm rollback? (y/N): " >/dev/tty
    read -r CF </dev/tty || CF=""
    [[ "$CF" != "y" && "$CF" != "Y" ]] && echo "  Cancelled." && return

    echo ""
    info "Starting rollback to $SELECTED..."

    # ── Step 1: Remove our config file ───────────────────
    rm -f "$TARGET_FILE"
    success "Removed: $TARGET_FILE"

    # ── Step 2: Remove any of OUR config files added after this snapshot ──
    # TARGET_FILE was already removed above. This also catches leftover files
    # from OLDER installs of this script that are NOT in the snapshot's list,
    # without touching unrelated system files in /etc/sysctl.d/.
    if [ -f "$SPATH/sysctl_d_list.txt" ]; then
        local TBASE
        TBASE="$(basename "$TARGET_FILE")"
        while IFS= read -r CURF; do
            [ -z "$CURF" ] && continue
            # Only remove files that belong to OUR script (match TARGET_FILE name
            # or the standard 99-vpn pattern) AND were not present in snapshot.
            if ! grep -qxF "$CURF" "$SPATH/sysctl_d_list.txt" 2>/dev/null; then
                case "$CURF" in
                    "$TBASE"|99-vpn-*.conf)
                        rm -f "/etc/sysctl.d/$CURF" 2>/dev/null && \
                            success "Removed stale: /etc/sysctl.d/$CURF" || true
                        ;;
                esac
            fi
        done < <(ls /etc/sysctl.d/ 2>/dev/null)
    fi

    # ── Step 3: Restore .conf files from snapshot ────────
    if [ -f "$SPATH/sysctl.conf" ]; then
        cp "$SPATH/sysctl.conf" /etc/sysctl.conf 2>/dev/null && \
            success "Restored: /etc/sysctl.conf" || warn "Could not restore sysctl.conf"
    fi
    # Only restore sysctl.d files that existed in snapshot (don't add new ones)
    if [ -d "$SPATH/sysctl.d" ]; then
        for f in "$SPATH/sysctl.d/"*.conf; do
            [ -f "$f" ] || continue
            BNAME="$(basename "$f")"
            # Don't restore our own file (already deleted above)
            [ "$BNAME" = "$(basename "$TARGET_FILE")" ] && continue
            cp "$f" "/etc/sysctl.d/$BNAME" 2>/dev/null && \
                success "Restored: /etc/sysctl.d/$BNAME" || \
                warn "Could not restore: $BNAME"
        done
    fi

    # ── Step 4: Re-apply sysctl values live ──────────────
    # Use our_keys.txt (targeted — only keys we changed)
    # Fall back to sysctl_values.txt only if our_keys.txt missing (old snapshot)
    R=0; F=0; SKIP=0
    KEYS_FILE=""
    [ -f "$SPATH/our_keys.txt" ] && KEYS_FILE="$SPATH/our_keys.txt"

    if [ -n "$KEYS_FILE" ]; then
        info "Applying targeted rollback (${KEYS_FILE##*/})..."
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line//[[:space:]]/}" ]] && continue
            KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
            VAL=$(echo "$line" | cut -d= -f2- | sed 's/^[[:space:]]*//')
            [ -z "$KEY" ] || [ -z "$VAL" ] && SKIP=$((SKIP+1)) && continue
            if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
                R=$((R+1))
            else
                warn "Could not set: $KEY=$VAL"
                F=$((F+1))
            fi
        done < "$KEYS_FILE"
    else
        # Old snapshot: parse sysctl_values.txt — but ONLY apply our known keys
        info "Old snapshot — applying known keys from sysctl_values.txt..."
        KNOWN_KEYS="net.core.rmem_max net.core.wmem_max net.core.default_qdisc \
            net.ipv4.tcp_congestion_control net.ipv4.tcp_keepalive_time \
            net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_tw_reuse \
            net.ipv4.tcp_fin_timeout net.ipv4.tcp_max_orphans \
            vm.swappiness net.core.somaxconn net.ipv4.tcp_syncookies"
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line//[[:space:]]/}" ]] && continue
            KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
            VAL=$(echo "$line" | cut -d= -f2- | sed 's/^[[:space:]]*//')
            [ -z "$KEY" ] || [ -z "$VAL" ] && continue
            echo "$KNOWN_KEYS" | grep -qw "$KEY" || { SKIP=$((SKIP+1)); continue; }
            if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
                R=$((R+1))
            else
                F=$((F+1))
            fi
        done < "$SPATH/sysctl_values.txt"
    fi

    sep
    success "Rollback complete — $R restored${F:+, $F failed}${SKIP:+ ($SKIP skipped)}"
    echo -e "  ${YELLOW}Note: Reboot to fully confirm all settings took effect.${NC}"
    sep
}

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
