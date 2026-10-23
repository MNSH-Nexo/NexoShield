# ── Tunable scoring config (DPI upgrade Phase 1a) ─────────────────────
# /etc/antiddos/scoring.conf holds `key=value` lines an admin may tune.
# nx_cfg KEY DEFAULT prints the configured value when it is present AND
# numeric, otherwise DEFAULT. Results are cached per process; the cache
# is dropped automatically when the file's mtime changes, so edits take
# effect without a daemon restart (checked at most once per second).
# The file is OPTIONAL: a stock install without it behaves exactly as
# the compiled-in defaults — which equal the pre-config constants.

# @lib-body
NX_CONFIG_FILE="${NX_CONFIG_FILE:-/etc/antiddos/scoring.conf}"

declare -A _NX_CFG_CACHE=() _NX_CFG_WARNED=()
_NX_CFG_MTIME=""
_NX_CFG_CHECKED=0

_nx_cfg_stat() {
    stat -c %Y "$NX_CONFIG_FILE" 2>/dev/null || echo "absent"
}

# Reload the cache when the file changed (cheap: one stat per second).
_nx_cfg_refresh() {
    local now=$EPOCHSECONDS m
    [ $((now - _NX_CFG_CHECKED)) -lt 1 ] && return 0
    _NX_CFG_CHECKED=$now
    m="$(_nx_cfg_stat)"
    if [ "$m" != "$_NX_CFG_MTIME" ]; then
        _NX_CFG_MTIME="$m"
        _NX_CFG_CACHE=()
    fi
}

_nx_cfg_warn() {
    [ -n "${_NX_CFG_WARNED[$1]:-}" ] && return 0
    _NX_CFG_WARNED[$1]=1
    if declare -F log >/dev/null 2>&1; then
        log " CONFIG: ignoring invalid value for '$1' in $NX_CONFIG_FILE (using default)"
    else
        echo "CONFIG: ignoring invalid value for '$1' in $NX_CONFIG_FILE (using default)" >&2
    fi
}

nx_cfg() {
    local key="$1" def="$2" raw=""
    _nx_cfg_refresh
    if [ -n "${_NX_CFG_CACHE[$key]+set}" ]; then
        printf '%s' "${_NX_CFG_CACHE[$key]}"
        return 0
    fi
    if [ -f "$NX_CONFIG_FILE" ]; then
        raw=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$NX_CONFIG_FILE" 2>/dev/null \
              | tail -n 1 | cut -d= -f2- | tr -d ' \t\r"')
    fi
    if [ -n "$raw" ]; then
        if [[ "$raw" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
            _NX_CFG_CACHE[$key]="$raw"
            printf '%s' "$raw"
            return 0
        fi
        _nx_cfg_warn "$key"
    fi
    _NX_CFG_CACHE[$key]="$def"
    printf '%s' "$def"
}

# Write the default config at install time. NEVER overwrites an existing
# file — admin edits are sacred. Every key is documented inline.
nx_ensure_scoring_config() {
    local f="${NX_CONFIG_FILE:-/etc/antiddos/scoring.conf}"
    [ -f "$f" ] && return 0
    mkdir -p "$(dirname "$f")" 2>/dev/null || return 1
    cat > "$f" <<'EOF'
# NexoShield scoring configuration — every value is optional.
# Delete a line (or this whole file) to return that knob to its default.
# Changes take effect within seconds; the daemon re-reads on mtime.
# All values must be numeric. Invalid values are ignored with a warning.

# ── Score bands (0-100 reputation) ──
score_ban=20            # below: ban (progressive duration)
score_hard=40           # below: hard throttle 50 Mbps
score_throttle=60       # below: throttle 100 Mbps
score_suspect=80        # below: watch only

# ── Score movement (points per minute) ──
score_recover_per_min=6
probation_recover_per_min=10
score_drop_cap_per_min=45
probation_score=50
probation_seconds=1800

# ── Term weights ──
churn_allow_per_sec=2   # free new-connection rate before churn applies
churn_weight=1.2        # points/min per conn/s above the allowance
churn_cap=30
sust_divisor=40         # connections over threshold per point/min
sust_cap=20
syn_min=20              # min half-open conns before the SYN term arms
syn_ratio=0.5           # half-open share that starts costing points
syn_weight=40
syn_cap=15

# ── Gates ──
conn_threshold=120      # active conns from one IP = start watching
ban_conn_threshold=300  # active conns = instant throttle+ban
observe_seconds=45      # watch window before throttle (legit spikes)

# ── Bans ──
ban_base_minutes=30     # first ban; doubles per repeat offence
ban_max_minutes=10080   # cap (7 days)
ban_hours_fallback=4    # legacy flat duration for non-progressive paths

# ── Subnet (/24) ──
subnet_threshold=400        # total conns = start watching
subnet_ban_threshold=1000     # total conns = block (with guardrails)
subnet_min_offenders=5        # distinct IPs that must be over the gate
subnet_ban_minutes=60

# ── Stress gate (Phase 1d) ──
stress_gate=1           # 1: score bans need host stress (or score < 10)
EOF
    chmod 644 "$f" 2>/dev/null || true
}
