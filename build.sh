#!/usr/bin/env bash
# Rebuild install.sh from the modular sources in src/.
# The generated installer is the single file end users download and run.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 tools/build.py "$@"
