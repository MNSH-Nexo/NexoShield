# @part modules/sysctl/00-header.sh - Config, print/log helpers, install lock
# Assembled into optimize-sysctl.sh by tools/build.py - not a standalone script.
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
    # Real mutual exclusion (BUG-054): the old pidfile check-then-write
    # had a race window and broke on PID reuse. flock on an open fd is
    # atomic and releases automatically if the holder dies.
    exec 9>"$LOCK_FILE" 2>/dev/null || return 0
    if ! flock -n 9; then
        err "Already running (another optimization holds the lock)"
        exit 1
    fi
    echo $$ >&9 2>/dev/null || true
}
release_lock() { flock -u 9 2>/dev/null || true; }
trap release_lock EXIT INT TERM

