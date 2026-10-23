#!/usr/bin/env bash
# Phase 1a: the tunable scoring config (src/lib/config.sh).
# Defaults without a file, valid overrides (int + float), invalid
# values ignored, mtime-based reload, install-time default writer
# that never overwrites admin edits.
set -uo pipefail
cd "$(dirname "$0")/../.."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

export NX_CONFIG_FILE="$TMP/scoring.conf"
# shellcheck disable=SC1091
. src/lib/config.sh

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
eq()  { [ "$1" = "$2" ] && ok || bad "$3 (got '$1', want '$2')"; }

# 1) no file -> compiled-in defaults
eq "$(nx_cfg conn_threshold 120)" "120" "missing file gives default"
eq "$(nx_cfg churn_weight 1.2)" "1.2" "missing file gives float default"

# 2) valid overrides
printf 'conn_threshold=77\nchurn_weight=2.5\n' > "$NX_CONFIG_FILE"
touch -d '+2 seconds' "$NX_CONFIG_FILE"; sleep 1.1
eq "$(nx_cfg conn_threshold 120)" "77" "int override wins"
eq "$(nx_cfg churn_weight 1.2)" "2.5" "float override wins"
eq "$(nx_cfg observe_seconds 45)" "45" "unset key still defaults"

# 3) spaces around = are tolerated; junk is ignored with fallback
printf 'conn_threshold = 88\nban_base_minutes=abc\n' > "$NX_CONFIG_FILE"
touch -d '+4 seconds' "$NX_CONFIG_FILE"; sleep 1.1
eq "$(nx_cfg conn_threshold 120)" "88" "spaced assignment parses"
eq "$(nx_cfg ban_base_minutes 30)" "30" "non-numeric value falls back"

# 4) reload on mtime change (no restart)
printf 'conn_threshold=99\n' > "$NX_CONFIG_FILE"
touch -d '+6 seconds' "$NX_CONFIG_FILE"; sleep 1.1
eq "$(nx_cfg conn_threshold 120)" "99" "edit takes effect after mtime change"

# 5) ensure writer: creates a documented default, never overwrites
rm -f "$NX_CONFIG_FILE"
nx_ensure_scoring_config
[ -f "$NX_CONFIG_FILE" ] && grep -q '^conn_threshold=120' "$NX_CONFIG_FILE" && ok || bad "ensure writes the default config"
printf '# admin edit\nconn_threshold=555\n' > "$NX_CONFIG_FILE"
nx_ensure_scoring_config
grep -q '^conn_threshold=555' "$NX_CONFIG_FILE" && ok || bad "ensure must not overwrite admin edits"
[ "$(grep -c '^score_ban=' "$NX_CONFIG_FILE")" -eq 0 ] && ok || bad "ensure appended defaults over an admin file"

echo "config (Phase 1a): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
