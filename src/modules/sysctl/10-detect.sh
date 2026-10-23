# @part modules/sysctl/10-detect.sh - detect_environment + calculate_values
# Assembled into optimize-sysctl.sh by tools/build.py - not a standalone script.
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

