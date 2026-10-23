# @part modules/autoban/00-header.sh - Config: thresholds, reputation bands, subnet detection, CF include, self IPs
# Assembled into auto-ban.sh by tools/build.py - not a standalone script.
#!/bin/bash
# shellcheck disable=SC2015,SC2094
# Reviewed idioms (Wave 10): SC2015 - `cond && ok-print || err-print`
# chains whose middle command is a print helper that cannot fail;
# SC2094 - atomic state writes via tmp-file + rename, which the
# checker flags as same-file pipelines. Both classes were audited
# site-by-site during the fix waves (docs/FIX-PLAN.md).
# ============================================================
#  Smart Throttle+Ban — Anti-DDoS Layer 4
#  Pipeline: watch(120 conns) → throttle(100Mbps) → ban(4h) | instant ban: 300 conns
#  CF IPs + server own IPs: ALWAYS exempt
# ============================================================

LOG="/var/log/auto-ban.log"
BANNED_LIST="/etc/antiddos/banned.list"
WATCH_LIST="/tmp/autoban_watch"
THROTTLE_LIST="/tmp/autoban_throttle"
# U-11: persistent mirror of the throttle state. The live file sits
# in /tmp (fast, volatile); the generated tc-setup.sh has always
# re-applied throttles from /etc/antiddos/throttled.list after a
# reboot - but nothing ever WROTE that file, so the restore path was
# dead and every reboot silently dropped all throttles. The daemon
# now mirrors tmp -> etc once per cycle and restores etc -> tmp at
# startup when the tmp file is gone.
THROTTLE_MIRROR="/etc/antiddos/throttled.list"
# User whitelist — IPs/CIDRs exempt from ALL anti-DDoS limits.
# Managed by the user via the menu (never auto-modified). One per line.
# Lines starting with # are comments. Server's own IPs + CF IPs are always
# exempt separately (see is_exempt), this file adds MORE whitelisted IPs.
WHITELIST_FILE="/etc/antiddos/whitelist.list"

# ── Reputation scoring state (persistent across cycles) ────
# Each scored IP keeps: score, last connection count, last timestamp.
# Persisted to disk so the value survives the short-lived shell arrays
# and survives service restarts.
SCORE_DIR="/var/lib/antiddos/scores"
SCORE_FILE="$SCORE_DIR/reputation.dat"
# Bands (see research: adaptive/graduated enforcement beats one-shot ban):
#  100-80 NORMAL    no action (only watched if above CONN_THRESHOLD)
#   79-60 SUSPECT   watch only, no penalty
#   59-40 THROTTLED move to class 1:30 (100Mbps)
#   39-20 HARD      move to class 1:40 (50Mbps)
#   <20  BANNED     ban_ip (4h)
SCORE_BAN=20
SCORE_HARD=40
SCORE_THROTTLE=60
SCORE_SUSPECT=80
# Scoring model v2 (docs/SCORING.md): every score movement is rated in
# points per MINUTE and scaled by the real elapsed time of the sample,
# so an IP's fate depends on its behaviour - never on daemon loop speed.
# Fractional points accumulate in the score file instead of rounding
# away each cycle.
SCORE_RECOVER_PER_MIN=6
SCORE_DROP_CAP_PER_MIN=45
# Probation (D3, FR-3): EVERY ban - reputation, classic or instant - ends
# in the same defined state: the IP returns at PROBATION_SCORE with a
# probation window. During probation, recovery is faster (10/min) but
# score drops are doubled; a ban still requires the score to actually
# reach the ban band again, so one minor spike cannot re-ban (the old
# behaviour: score stayed wherever the ban path left it, often <20, so
# the smallest trigger re-banned instantly - a de-facto permanent ban).
PROBATION_SCORE=50
PROBATION_SECONDS=1800
PROBATION_RECOVER_PER_MIN=10
# When connections are counted we snapshot the previous sample to derive the
# new-connection rate (attacker signature) without per-packet overhead.

# Thresholds
# THRESHOLD: minimum active connections from one IP to start watching.
# Normal user: 5-20 connections (browser + download + streaming).
# Heaviest legitimate user (multiple download managers + several services):
# ~50-60 connections. Attacker: hundreds to thousands.
# Set CONN_THRESHOLD well above ANY legitimate user so normal speed is never
# limited, but far below a flood. OBSERVE allows brief legit spikes (a download
# manager burst) to pass untouched before any action.
CONN_THRESHOLD=120    # active connections from one IP = start watching (safe margin)
BAN_CONN_THRESHOLD=300  # active connections from one IP = immediate throttle+ban
OBSERVE_SECONDS=45    # seconds to watch before throttle (tolerates legit spikes)
THROTTLE_MBPS=100    # throttle bandwidth in Mbps (must match tc class 1:30 = 100mbit)
BAN_HOURS=4          # hours to ban after throttle
# Sample cadence. 2s (was 4s): churn rate is already normalized per-second, so
# scoring bands are unchanged, but short <4s bursts from a 120+ conn IP are now
# caught instead of being averaged out. Recovery of well-behaved IPs is also 2x
# faster. The CONN_THRESHOLD=120 gate means normal users are never touched.
# (One-way bytes tracking was deliberately NOT added: on a SOCKS5/tunnel proxy,
# server→client relay makes "sent>>received" the NORMAL heavy-download pattern,
# so it would false-positive on legitimate heavy users.)
SAMPLE_INTERVAL=2    # seconds per measurement

# ── Subnet /24 botnet detection ──────────────────────────────
# Botnet distributes connections across many IPs in same /24 subnet.
# Each IP stays under single-IP threshold, but total subnet load is high.
# SUBNET_CONN_THRESHOLD: total connections from a /24 subnet = start watching.
# Normal ISP: ~5-10 users behind NAT/CGNAT, each ~20 conns = ~200 total.
# A very heavy CGNAT node (many legit users) could reach ~400.
# Botnet with 50 IPs × 100+ conns = 5000 → way above threshold.
SUBNET_THRESHOLD=400       # total conns from /24 = start watching subnet
SUBNET_BAN_THRESHOLD=1000  # total conns from /24 = block subnet
SUBNET_WATCH_LIST="/tmp/autoban_subnet_watch"
touch "$SUBNET_WATCH_LIST" 2>/dev/null || true

# Detect main interface
IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
IF=${IF:-eth0}

# Cloudflare ranges (NEVER touched)
# @include lib/cloudflare-loader.sh
# @include lib/cloudflare6-loader.sh
# @include lib/self-ips.sh

mkdir -p /etc/antiddos
touch "$LOG" && chmod 600 "$LOG"
touch "$BANNED_LIST" "$WATCH_LIST" "$THROTTLE_LIST" 2>/dev/null || true

# Collect all server IPs at startup (never ban these): interface
# addresses PLUS any cached NAT/cloud public IPs (E-6).
SELF_IPS=()
while IFS= read -r sip; do
    [ -n "$sip" ] && SELF_IPS+=("$sip")
done < <(list_self_ips_all)

# IPv6 self addresses (Wave 9): the same hard immunity as IPv4 (FR-2).
SELF6_IPS=()
while IFS= read -r sip6; do
    [ -n "$sip6" ] && SELF6_IPS+=("$sip6")
done < <(list_self_ips6)

# BUG-020: precompute Cloudflare network integers ONCE. is_cf_ip() then
# costs zero forks per check (previously up to ~1,500 per call: 753 ranges
# x 2 subshells in ip_to_int, paid for every hot IP every cycle).
declare -a CF_NET_INT=() CF_SHIFT=()
ip_int() {
    local IFS=. _a _b _c _d
    read -r _a _b _c _d <<< "$1"
    IP_INT=$(( (10#$_a << 24) + (10#$_b << 16) + (10#$_c << 8) + 10#$_d ))
}
for _cfr in "${CF_RANGES[@]}"; do
    ip_int "${_cfr%%/*}"
    CF_NET_INT+=("$IP_INT")
    CF_SHIFT+=("$(( 32 - ${_cfr#*/} ))")
done
unset _cfr

