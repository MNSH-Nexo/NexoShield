# Development Guide

NexoShield ships to users as **one single file** (`install.sh`) — but it is
*developed* as modules. Never edit `install.sh` directly: it is a generated
file. Edit the sources in `src/`, rebuild, and commit both.

## Repository layout

```
install.sh                  GENERATED single-file installer (what users run)
build.sh                    Rebuild install.sh  (wrapper for tools/build.py)
Makefile                    make build / make check
VERSION                     Single source of truth for the version string
src/
  installer/
    preamble.sh             Installer head: banner, root check, CF array
    outro.sh                Installer tail: permissions, `proxy` link, banner
  modules/
    3proxy-socks5.sh        SOCKS5 (3proxy) manager      -> /opt/proxy-manager/
    optimize-sysctl.sh      Kernel optimizer (sysctl)    -> /opt/proxy-manager/
    proxy-menu.sh           Main menu (`proxy` command)  -> /opt/proxy-manager/
    antiddos.sh             5-layer Anti-DDoS manager    -> /opt/proxy-manager/
    auto-ban.sh             Smart auto-ban daemon, nested inside antiddos.sh
  data/
    cloudflare-ipv4.list    753 Cloudflare IPv4 ranges (one CIDR per line)
tools/
  build.py                  Assembler: src/ -> install.sh
  verify.py                 Build-integrity + round-trip verification
  check.sh                  Full quality gate (syntax + lint + verify)
docs/
  DEVELOPMENT.md            This file
```

## Workflow

```bash
# 1. edit sources under src/
# 2. rebuild the installer
make build
# 3. run the quality gate — must pass before committing
make check
# 4. commit src/ AND the regenerated install.sh together
```

## Build placeholders

The assembler substitutes three tokens; the build fails if any survives:

| Token             | Replaced with                                  |
|-------------------|------------------------------------------------|
| `@@VERSION@@`     | Contents of the `VERSION` file                 |
| `@@CF_ENTRIES@@`  | The Cloudflare ranges as a bash array body     |
| `@@AUTOBAN_BODY@@`| `src/modules/auto-ban.sh` inside antiddos.sh   |

## Quality gate (`make check`)

1. `bash -n` on every source file.
2. ShellCheck at **warning** level on all modules — must be clean.
   Intentional exceptions carry an inline `# shellcheck disable=...`
   comment **with a reason** (e.g. the word-splitting in the iptables
   rule-removal loop is deliberate: a rule string must expand to argv).
3. `tools/verify.py` — rebuilds in memory and asserts:
   - `install.sh` on disk is byte-identical to a fresh build;
   - every heredoc body extracted from `install.sh` round-trips to its
     module source exactly;
   - the Cloudflare list has 753 unique, well-formed CIDRs.

## Known lint debt (note level, deliberately deferred)

ShellCheck reports ~68 *notes* (no errors, no warnings) across the modules,
dominated by SC2015 (`A && B || C` chains, ~48). These are behaviour-neutral
today but fragile if a middle command ever starts failing. They are scheduled
for the improvement phase, one module at a time, each with its own commit —
not as part of structural cleanups.

## Releasing

1. Bump `VERSION`.
2. `make build && make check`.
3. Commit, then tag: `git tag v$(cat VERSION)` and publish a GitHub release
   from that tag so users can pin and verify an exact installer.
