#!/usr/bin/env bash
# Regression test for the 2026-10-28 live finding (box 18.118.217.55):
# apply_fail2ban enabled the 3proxy-ddos jail UNCONDITIONALLY, but its
# logpath glob /var/log/3proxy/access.log.* matched zero files on a box
# where 3proxy was gone, so fail2ban-client -t failed the WHOLE config
# ("Have not found any log file for 3proxy-ddos") and no new jails were
# applied at all. Same class as T-1, which gated http-flood on log
# existence but left this jail ungated. The fix gates 3proxy-ddos the
# same way: enabled only when the log glob matches at least one file.
#
# The test sources the real apply_fail2ban and stubs its backends:
# - fail2ban-client -t implements fail2ban's real rule faithfully:
#   every enabled jail must have >=1 existing logpath file, else the
#   exact "Have not found any log file for <jail>" failure.
# - systemctl reload/restart/is-active are no-ops that succeed.
# - list_self_ips_all/6, info/warn/success are stubbed.
set -uo pipefail
cd "$(dirname "$0")/../.."

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $*"; }

T=$(mktemp -d)
cleanup() {
    rm -rf "$T"
    # Remove ONLY the 3proxy log dir this suite created (case B).
    if [ "${PROXYLOG_CREATED:-0}" = "1" ]; then
        rm -rf /var/log/3proxy
    fi
}
trap cleanup EXIT

mkdir -p "$T/jail.d" "$T/filter.d" "$T/bin"

# ── Stubs ────────────────────────────────────────────────────
cat > "$T/bin/fail2ban-client" << 'STUBEOF'
#!/usr/bin/env bash
# Faithful -t: parse $F2B_JAIL_DIR/antiddos.conf; an enabled jail whose
# logpath globs match zero existing files fails the whole test, exactly
# like real fail2ban (v1.1.0 on the live box).
if [ "${1:-}" = "-t" ]; then
    jail=""; enabled=""; logpaths=""
    check_jail() {
        [ "$enabled" = "true" ] || return 0
        local found=0
        for g in $logpaths; do
            for f in $g; do [ -e "$f" ] && found=1; done
        done
        if [ "$found" = "0" ]; then
            echo "ERROR   Failed during configuration: Have not found any log file for $jail" >&2
            echo "ERROR: test configuration failed" >&2
            exit 1
        fi
    }
    while IFS= read -r line; do
        case "$line" in
            \[*\]*)
                check_jail
                jail="${line#[}"; jail="${jail%]}"
                enabled=""; logpaths=""
                ;;
            enabled*=*)
                enabled="$(echo "$line" | sed 's/.*=[[:space:]]*//')"
                ;;
            logpath*=*)
                logpaths="$logpaths $(echo "$line" | sed 's/.*=[[:space:]]*//')"
                ;;
            " "*)
                # continuation line of the previous key (logpath lists)
                if [ -n "$logpaths" ]; then
                    logpaths="$logpaths $(echo "$line" | sed 's/^[[:space:]]*//')"
                fi
                ;;
        esac
    done < "$F2B_JAIL_DIR/antiddos.conf"
    check_jail
    exit 0
fi
if [ "${1:-}" = "status" ]; then
    echo "Status"
    echo "|- Number of jail:	2"
    echo "\`- Jail list:	conn-flood, portscan"
    exit 0
fi
exit 0
STUBEOF
cat > "$T/bin/systemctl" << 'STUBEOF'
#!/usr/bin/env bash
# reload/restart/is-active all succeed.
exit 0
STUBEOF
chmod +x "$T/bin/fail2ban-client" "$T/bin/systemctl"
export PATH="$T/bin:$PATH"

info()    { :; }
warn()    { echo "  (warn) $*" >&2; }
success() { :; }
list_self_ips_all() { echo "203.0.113.1"; }
list_self_ips6()    { :; }

export F2B_JAIL_DIR="$T/jail.d" F2B_FILTER_DIR="$T/filter.d"
WHITELIST_FILE="$T/whitelist-missing"
CF_RANGES=()
CF6_RANGES=()

# shellcheck disable=SC1091
. "src/modules/antiddos/30-fail2ban.sh"
run_apply() { apply_fail2ban; }

jail_enabled() { # section -> enabled value
    awk -v sec="[$1]" '$0==sec{f=1;next} /^\[/{f=0} f&&/^enabled/{print $3;exit}' \
        "$T/jail.d/antiddos.conf"
}

# After a failed apply, name the jail the faithful -t rejects (empty if
# -t passes). A failure on 3proxy-ddos is the regression; a failure on
# any other jail means this environment lacks that jail's syslog files
# (non-root CI runners have no /var/log/kern.log or auth.log, and the
# installer's touch loop cannot create them there) - an environment
# gap, not the product, so those cases SKIP instead of failing.
apply_failed_on() {
    "$T/bin/fail2ban-client" -t 2>&1 | sed -n 's/.*Have not found any log file for //p' | head -1
}

check_apply_rc() { # $1 = rc; ok, or SKIP/FAIL by failing jail
    if [ "$1" = "0" ]; then ok; return; fi
    local fj
    fj=$(apply_failed_on)
    if [ "$fj" = "3proxy-ddos" ]; then
        bad "apply failed on 3proxy-ddos (rc=$1)"
    elif [ -n "$fj" ]; then
        echo "  SKIP: apply failed on '$fj' (env lacks its log files)"
    else
        bad "apply failed for unknown reason (rc=$1)"
    fi
}

# ── Negative control: the stub must reproduce the live failure ──
# A hand-written config with 3proxy-ddos enabled and no log file must
# fail -t exactly like real fail2ban did on the box.
mkdir -p "$T/ctl"
cat > "$T/jail.d/antiddos.conf" << 'EOF'
[3proxy-ddos]
enabled   = true
filter    = 3proxy-ddos
logpath   = /var/log/3proxy/access.log.*
maxretry  = 100
EOF
if "$T/bin/fail2ban-client" -t 2>"$T/ctl.err"; then
    bad "stub -t passed a config real fail2ban rejects (stub not faithful)"
else
    grep -q "Have not found any log file for 3proxy-ddos" "$T/ctl.err" \
        && ok || bad "stub -t error text differs from live fail2ban error"
fi

# ── Case A (the box scenario): no 3proxy log at all ────────────
# The installer itself touches kern.log/auth.log (T-1 ensure logic), so
# conn-flood/portscan/sshd-aggressive have files; only 3proxy is absent.
rm -f "$T/jail.d/antiddos.conf"
run_apply; rc=$?
check_apply_rc "$rc"
[ "$(jail_enabled 3proxy-ddos)" = "false" ] \
    && ok || bad "3proxy-ddos not disabled without a log file"
[ "$(jail_enabled http-flood)" = "false" ] \
    && ok || bad "http-flood gating regressed (no web log present)"
# End-to-end: the generated config must pass the faithful -t. If it
# fails on a NON-3proxy jail, that is an environment gap (syslog files
# missing), not this regression - skip, don't fail.
if "$T/bin/fail2ban-client" -t 2>"$T/a.err"; then
    ok
else
    if grep -q "3proxy-ddos" "$T/a.err"; then
        bad "generated config still fails -t on 3proxy-ddos"
    else
        echo "  SKIP: -t fails on another jail (env lacks its log files)"
    fi
fi

# ── Case B (proxy box): a 3proxy log file exists ───────────────
# Best-effort: needs write access to /var/log (root in sandbox, sudo
# re-exec suites elsewhere). If unavailable, skip rather than fail.
PROXYLOG_CREATED=0
if [ -e /var/log/3proxy ]; then
    echo "  SKIP: /var/log/3proxy pre-exists, case B unsafe to stage"
else
    if mkdir -p /var/log/3proxy 2>/dev/null && touch /var/log/3proxy/access.log.2026.10.28 2>/dev/null; then
        PROXYLOG_CREATED=1
        rm -f "$T/jail.d/antiddos.conf"
        run_apply; rc=$?
        check_apply_rc "$rc"
        [ "$(jail_enabled 3proxy-ddos)" = "true" ] \
            && ok || bad "3proxy-ddos disabled even though a log file exists"
    else
        echo "  SKIP: cannot stage /var/log/3proxy here (no write access)"
    fi
fi

echo "fail2ban jail gating: $pass passed, $fail failed"
[ "$fail" = "0" ]
