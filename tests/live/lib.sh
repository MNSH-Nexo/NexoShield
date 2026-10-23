#!/bin/bash
# tests/live/lib.sh — shared helpers for the NexoShield live-fire battery.
# Sourced by every tests/live/*.sh script. Not executed directly.
#
# Safety contract (non-negotiable):
#   * Every script requires NX_LIVEFIRE=1 in the environment (explicit opt-in).
#   * Targets are restricted to the lab range 10.99.0.0/24, fd99:99::/64 and
#     loopback. Anything else is refused by guard_target.
#   * Attacks are short, repetition-capped and stoppable (timeout everywhere).
#   * Run ONLY on a disposable test server you own, with the owner's
#     explicit authorization. Never against third-party infrastructure.
# shellcheck disable=SC2034  # constants consumed by sourcing scripts

set -u

LAB_V4_NET="10.99.0.0/24"
LAB_V4_HOST="10.99.0.1"
LAB_V6_NET="fd99:99::/64"
LAB_V6_HOST="fd99:99::1"
NS="nxlab"

# Per-test source IPs (v4 aliases on the namespace veth, v6 for test 60).
IP_CONNFLOOD="10.99.0.11"
IP_XMAS="10.99.0.12"
IP_PROXYAUTH="10.99.0.13"
IP_SYNFLOOD="10.99.0.14"
IP_WHITELIST="10.99.0.15"
IP_V6="fd99:99::21"

# NexoShield on-disk state (see src/modules/autoban/00-header.sh).
NX_LOG="/var/log/auto-ban.log"
NX_SCORES="/var/lib/antiddos/scores/reputation.dat"
NX_BANNED="/etc/antiddos/banned.list"
NX_WHITELIST="/etc/antiddos/whitelist.list"

RESULT_DIR="${NX_LIVEFIRE_DIR:-/root/nx-livefire}"
mkdir -p "$RESULT_DIR" 2>/dev/null || true

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log()  { echo "[$(ts)] $*" | tee -a "$RESULT_DIR/battery.log"; }
pass() { echo "[$(ts)] PASS: $*" | tee -a "$RESULT_DIR/battery.log"; }
fail() { echo "[$(ts)] FAIL: $*" | tee -a "$RESULT_DIR/battery.log"; }

require_livefire() {
    if [ "${NX_LIVEFIRE:-0}" != "1" ]; then
        echo "Refusing to run: set NX_LIVEFIRE=1 to confirm you are testing a" >&2
        echo "server you own with the owner's explicit authorization." >&2
        exit 2
    fi
    if [ "$(id -u)" != "0" ]; then
        echo "Refusing to run: these scripts must run as root on the test server." >&2
        exit 2
    fi
}

# Refuse any target outside the lab ranges or loopback.
guard_target() {
    local t="$1"
    case "$t" in
        10.99.0.*|127.*|fd99:99::*|::1) return 0 ;;
        *) echo "Refusing target outside lab ranges: $t" >&2; exit 2 ;;
    esac
}

in_ns() { ip netns exec "$NS" "$@"; }

# Ground truth: established TCP conns FROM $1 (source IP) right now.
gt_conns_from() { ss -tn state established "( src $1 )" 2>/dev/null | tail -n +2 | wc -l; }

# Last N SCORE lines for an IP from the daemon log.
nx_scores_for() { grep -h "SCORE: $1 |" "$NX_LOG" 2>/dev/null | tail -n "${2:-5}"; }

nx_banned() { grep -qxF "$1" "$NX_BANNED" 2>/dev/null; }
