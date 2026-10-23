#!/usr/bin/env bash
# Regex tests for the fail2ban filters (BUG-017, Wave 5). The failregex
# lines are extracted from the shipped generator (30-fail2ban.sh),
# <HOST> is translated to a capture group, and sample log lines are
# checked with Python's re (the same engine fail2ban uses).
set -uo pipefail
cd "$(dirname "$0")/../.."
SRC="src/modules/antiddos/30-fail2ban.sh"
python3 - "$SRC" << 'PYEOF'
import re, sys

src = open(sys.argv[1]).read()

def filter_block(name):
    m = re.search(r'\$F2B_FILTER_DIR/' + name + r"\.conf\" << 'EOF'\n(.*?)EOF", src, re.S)
    assert m, f"filter {name} not found"
    return m.group(1)

def patterns(name, key):
    block = filter_block(name)
    out = []
    in_key = False
    for line in block.splitlines():
        if line.startswith(key):
            rhs = line.split('=', 1)[1].strip()
            if rhs: out.append(rhs)
            in_key = True
        elif in_key and line.startswith((' ', '\t')) and line.strip():
            out.append(line.strip())
        elif line.strip() and not line.startswith((' ', '\t')):
            in_key = False
    return [p.replace('<HOST>', r'(?P<host>\d{1,3}(?:\.\d{1,3}){3})') for p in out]

def matches(name, line):
    for p in patterns(name, 'failregex'):
        m = re.search(p, line)
        if m:
            for ig in patterns(name, 'ignoreregex'):
                if ig and re.search(ig, line):
                    return None
            return m.group('host')
    return None

fails = []
def check(name, line, want):
    got = matches(name, line)
    ok = (got == want)
    print(('ok  ' if ok else 'FAIL'), name, '->', got, '(want', str(want) + ')')
    if not ok: fails.append((name, line))

# 3proxy-ddos: ONLY error lines (%E != 0) may match
check('3proxy-ddos', 'L23-10-2026 10:00:00 alice 5.5.5.5:40000 93.184.216.34:443 5000 300 0 CONNECT', None)
check('3proxy-ddos', 'L23-10-2026 10:00:01 - 5.5.5.5:40001 0.0.0.0:0 0 0 13 CONNECT', '5.5.5.5')
check('3proxy-ddos', 'L23-10-2026 10:00:02 bob 5.5.5.5:40002 10.0.0.5:80 0 0 6 GET', '5.5.5.5')

# http-flood: combined log format; static assets ignored
check('http-flood', '9.9.9.9 - - [23/Oct/2026:10:00:00 +0300] "GET /index.html HTTP/1.1" 200 1234', '9.9.9.9')
check('http-flood', '9.9.9.9 - - [23/Oct/2026:10:00:00 +0300] "GET /style.css HTTP/1.1" 200 123', None)
check('http-flood', 'L23-10-2026 10:00:00 alice 9.9.9.9:40000 1.2.3.4:443 1 1 0 CONNECT', None)

# portscan: our [NX-SCAN] kernel lines
check('portscan', 'Oct 23 10:00:00 srv kernel: [12345.6] [NX-SCAN] IN=eth0 OUT= SRC=9.9.9.9 DST=10.0.0.1 PROTO=TCP SPT=40000 DPT=80', '9.9.9.9')

# conn-flood: our [CONNLIMIT DROP] kernel lines
check('conn-flood', 'Oct 23 10:00:00 srv kernel: [12345.6] [CONNLIMIT DROP] IN=eth0 OUT= SRC=9.9.9.9 DST=10.0.0.1 PROTO=TCP', '9.9.9.9')

print('fail2ban filters:', 'FAILED' if fails else 'ALL PASSED')
sys.exit(1 if fails else 0)
PYEOF
