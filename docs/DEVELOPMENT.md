# Development Guide

NexoShield ships to users as **one single file** (`install.sh`) — but it is
*developed* as small modules. Never edit `install.sh` directly: it is a
generated file. Edit the sources in `src/`, rebuild, and commit both.

## Repository layout

```
install.sh                  GENERATED single-file installer (what users run)
build.sh                    Rebuild install.sh  (wrapper for tools/build.py)
Makefile                    make build / make check
VERSION                     Single source of truth for the version string
src/
  installer/
    preamble.sh             Installer head: banner, root check, CF array
    outro.sh                Installer tail: permissions, `shield` link, banner
  modules/                  Runtime scripts, one directory per script.
                            Parts assemble in filename order (00-, 10-, ...).
    3proxy/                 -> 3proxy-socks5.sh   (SOCKS5 manager)
      00-header.sh            config, includes, small getters
      10-tc.sh                bandwidth classes (tc) + persistence
      20-iptables.sh          per-port iptables rules
      30-apt-mirror.sh        spinner helpers + apt mirror selection
      40-install.sh           install_proxy
      50-uninstall.sh         uninstall_proxy
      60-cli-menu.sh          info/stats, menu, CLI dispatch
    sysctl/                 -> optimize-sysctl.sh (kernel optimizer)
      00-header.sh  10-detect.sh  20-snapshot-config.sh
      30-apply-rollback.sh    40-status-main.sh
    menu/                   -> proxy-menu.sh      (the `shield` command)
      00-header.sh  10-proxy-menu.sh  20-sysctl-monitor-menus.sh
      30-monitor-dashboard.sh         40-security-services-system.sh
      50-antiddos-menu.sh             60-autoban-main.sh
    antiddos/               -> antiddos.sh        (5-layer Anti-DDoS)
      00-header.sh  10-sysctl.sh  20-iptables.sh  30-fail2ban.sh
      40-autoban-setup.sh     50-tc.sh  60-status-remove.sh
      70-whitelist-main.sh
    autoban/                -> auto-ban.sh        (smart auto-ban daemon,
      00-header.sh  10-ip-utils.sh  20-enforce.sh   nested in antiddos.sh)
      30-reputation.sh        40-subnet.sh  50-main-loop.sh
  lib/                      Shared snippets — each exists exactly ONCE.
    cloudflare-loader.sh    Populates CF_RANGES from the shared data file
    server-ips.sh           get_server_ips()
  data/
    cloudflare-ipv4.list    753 Cloudflare IPv4 ranges (one CIDR per line)
tools/
  build.py                  Two-stage assembler: parts -> modules -> install.sh
  verify.py                 Build-integrity, round-trip + dedupe verification
  check.sh                  Full quality gate (syntax + lint + verify)
docs/
  DEVELOPMENT.md            This file
```

No source file exceeds ~320 lines; most are under 200. The one exception by
design is `antiddos/20-iptables.sh` (313 lines): a single cohesive function
that would be harder to read if split mid-body.

## How assembly works

Stage 1 — modules. Parts of a module are concatenated in filename order.
Two dev-only directives are resolved at this stage and never ship:

- A part starts with two `# @part ...` header lines (what it is, what it
  assembles into). They are stripped during assembly.
- A line `# @include lib/<file>` is replaced by the body of
  `src/lib/<file>` — the part below its `# @lib-body` marker. This is how
  the Cloudflare loader, previously copy-pasted in **five** places, now
  lives in exactly one file while every runtime script stays self-contained.

Stage 2 — installer. Assembled modules are embedded as heredocs between
the installer preamble and outro, exactly as users have always received
them. `auto-ban.sh` is nested into `antiddos.sh` at this stage.

Substitutions (the build fails if any survives):

| Token / directive   | Replaced with                                  |
|---------------------|------------------------------------------------|
| `@@VERSION@@`       | Contents of the `VERSION` file                 |
| `@@CF_ENTRIES@@`    | The Cloudflare ranges as a bash array body     |
| `@@AUTOBAN_BODY@@`  | The assembled auto-ban module                  |
| `# @include lib/…`  | The shared snippet from `src/lib/`             |
| `# @part …` headers | Stripped (development metadata only)           |

## Workflow

```bash
# 1. edit parts under src/modules/<name>/ (or src/lib/, src/installer/)
# 2. rebuild the installer
make build
# 3. run the quality gate — must pass before committing
make check
# 4. commit src/ AND the regenerated install.sh together
```

## Quality gate (`make check`)

1. `bash -n` on every part, lib file and installer fragment, and on every
   assembled module.
2. ShellCheck at **warning** level on the assembled modules — must be
   clean. Intentional exceptions carry an inline
   `# shellcheck disable=...` comment **with a reason**.
3. `tools/verify.py` asserts:
   - `install.sh` on disk is byte-identical to a fresh build;
   - every heredoc body extracted from `install.sh` round-trips to its
     assembled module exactly;
   - the Cloudflare list has 753 unique, well-formed CIDRs;
   - the Cloudflare loader body exists in exactly one source file
     (`src/lib/cloudflare-loader.sh`) — no private copies in parts.

## Known lint debt (note level, deliberately deferred)

ShellCheck reports ~68 *notes* (no errors, no warnings) across the modules,
dominated by SC2015 (`A && B || C` chains, ~48). These are behaviour-neutral
today but fragile if a middle command ever starts failing. They are
scheduled for the improvement phase, one module at a time, each with its
own commit — not as part of structural cleanups.

## Releasing

1. Bump `VERSION`.
2. `make build && make check`.
3. Commit, then tag: `git tag v$(cat VERSION)` and publish a GitHub release
   from that tag so users can pin and verify an exact installer.
