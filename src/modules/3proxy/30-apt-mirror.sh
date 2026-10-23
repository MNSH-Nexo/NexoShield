# @part modules/3proxy/30-apt-mirror.sh - run_spinner, print helpers, apt mirror pick/configure
# Assembled into 3proxy-socks5.sh by tools/build.py - not a standalone script.
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
        cands=( "https://archive.ubuntu.com/ubuntu" "https://mirrors.aliyun.com/ubuntu" \
                "https://mirrors.tuna.tsinghua.edu.cn/ubuntu" "https://mirrors.ustc.edu.cn/ubuntu" \
                "https://mirrors.cloud.aliyuncs.com/ubuntu" "https://mirrors.huaweicloud.com/ubuntu" \
                "https://mirrors.zju.edu.cn/ubuntu" )
    else
        cands=( "https://deb.debian.org/debian" "https://mirrors.aliyun.com/debian" \
                "https://mirrors.tuna.tsinghua.edu.cn/debian" "https://mirrors.ustc.edu.cn/debian" \
                "https://mirrors.huaweicloud.com/debian" "https://mirrors.cloud.aliyuncs.com/debian" )
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

