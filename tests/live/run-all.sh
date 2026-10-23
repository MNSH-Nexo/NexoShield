#!/bin/bash
# run-all.sh — full battery in dependency order, each step time-boxed.
# Designed for short-lived test servers: setup → attacks → evidence → teardown.
# Usage on the test server (as root):
#   export NX_LIVEFIRE=1
#   bash tests/live/run-all.sh
set -u
HERE="$(dirname "$(readlink -f "$0")")"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_livefire

run_step() {
    local script="$1" budget="$2"
    log ">>> $script (budget ${budget}s)"
    if timeout "$budget" bash "$HERE/$script"; then
        log "<<< $script finished"
    else
        fail "$script hit its time budget or errored — continuing with next step"
    fi
}

run_step 00-lab-setup.sh          180
run_step 10-conn-flood.sh         300
run_step 20-xmas-scan.sh          240
run_step 30-proxy-authfail.sh     240
run_step 40-syn-flood.sh          180
run_step 50-whitelist-exemption.sh 240
run_step 60-ipv6.sh               240
run_step 90-collect.sh            180

log "battery complete. Results in $RESULT_DIR/battery.log"
log "PASS count: $(grep -c "PASS:" "$RESULT_DIR/battery.log" 2>/dev/null || echo 0)"
log "FAIL count: $(grep -c "FAIL:" "$RESULT_DIR/battery.log" 2>/dev/null || echo 0)"
