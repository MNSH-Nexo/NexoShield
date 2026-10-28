# ── Shared ban-state lock (L5 fix) ────────────────────────────────
# The daemon (ban_ip/ban_subnet) and the admin release path
# (nx_release_ban) are different processes mutating the same state
# files. A plain append races a whole-file rewrite: the release reads
# a stale list, filters one IP, and renames over a ban that landed
# mid-rewrite — nft sets and banned.list diverge (lab-proven, 4/5
# runs). One flock on a shared path serializes every banned.list
# mutation. Re-entrant via a depth counter: ban_ip calls
# state_del_ip inside its locked section, and a second flock on the
# same fd by the same process would deadlock without this guard.
# Fail-open: if flock is missing, the lock file cannot be opened, or
# the lock cannot be taken within 10s (a wedged holder), the
# operation proceeds unlocked rather than stalling the daemon loop —
# the race returns for that one op, but liveness wins over a hung
# loop. Included by both auto-ban.sh and antiddos.sh (same path).

# @lib-body
NX_STATE_LOCK_FILE="${NX_STATE_LOCK_FILE:-/run/nexoshield/state.lock}"
NX_STATE_LOCK_DEPTH=0
nx_state_lock() {
    if [ "${NX_STATE_LOCK_DEPTH:-0}" -gt 0 ]; then
        NX_STATE_LOCK_DEPTH=$(( NX_STATE_LOCK_DEPTH + 1 ))
        return 0
    fi
    mkdir -p /run/nexoshield 2>/dev/null || true
    if command -v flock >/dev/null 2>&1; then
        if exec 200>"$NX_STATE_LOCK_FILE" 2>/dev/null; then
            flock -x -w 10 200 2>/dev/null || true
        fi
    fi
    NX_STATE_LOCK_DEPTH=1
}
nx_state_unlock() {
    [ "${NX_STATE_LOCK_DEPTH:-0}" -gt 0 ] || return 0
    NX_STATE_LOCK_DEPTH=$(( NX_STATE_LOCK_DEPTH - 1 ))
    if [ "$NX_STATE_LOCK_DEPTH" -eq 0 ]; then
        flock -u 200 2>/dev/null || true
        exec 200>&- 2>/dev/null || true
    fi
}
