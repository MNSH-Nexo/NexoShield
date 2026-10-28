# UI redesign — v3.7

Direction chosen by the maintainer's delegate (the agent): **no new
dependencies**. `dialog`/full-screen TUI frameworks were rejected —
on arbitrary SSH terminals and minimal images they add failure modes
a server tool cannot afford. Instead the classic numbered menus were
rebuilt on a single in-house framework, the home screen became a
dashboard, and the main views gained scriptable CLI equivalents.

## What changed

- **One framework** (`src/modules/menu/05-ui.sh`): `ui_input` (the
  single read idiom — /dev/tty first, stdin fallback when no tty is
  attached, which previously meant an infinite empty-read redraw),
  `ui_confirm` (the single (y/N) idiom), `ui_title` (header +
  breadcrumb), `ui_options` (aligned menu rows with live status),
  `press_enter` reimplemented on the same input path. All 21 former
  hand-rolled read sites now go through it.
- **Dashboard home**: the main menu opens with an Overview panel —
  active ban/throttle counts, whitelist size, the three lowest
  reputation scores with band colours, and the latest auto-ban
  events — above the seven sections with their live status dots.
- **Branding**: the header banner said "Proxy Manager"; it now says
  NexoShield — Server Security Toolkit.
- **CLI parity**: `proxy-menu.sh --status` (plain-text health view),
  `--bans` (active bans with since/expires), `--version`, `--help`.
- **U-1 (bug found during the redesign):** the Suspicious IPs screen
  scraped `iptables -L` for bans, matching on rule comments — which
  never appear in `-L` output, so the section could never show
  anything. It now reads `banned.list`, the source of truth.

## Section audit addendum (same release)

A follow-up line-by-line audit of every menu section found and
fixed a family of stale-state bugs (full register in the commit):

- **U-2** — Security → Unblock IP deleted a rule spec the daemon
  never creates and never edited `banned.list`, so "unblocked" IPs
  were re-banned at the next reconcile. All unban flows now share
  one engine-grade `nx_unban_ip` in the framework.
- **U-3** — Security → Blocked IPs showed, as a jail's ban "count",
  the last octet of the last banned IP. It now parses fail2ban's
  `Currently banned:` total; the auto-ban half lists state, not an
  `iptables -L` scrape.
- **U-5** — the Services screen listed every candidate as installed:
  bare `systemctl list-unit-files` exits 0 even with zero matches.
- **U-6** — SSH brute-force view reads the journal when auth.log is
  absent (journal-only images).
- **U-7** — Monitoring → Traffic top IPs read a log file that never
  exists (daily rotation, T-2) *and* counted field 5 (%R, the server
  side) instead of field 4 (%C, the client). Both fixed.
- **U-9** — the live dashboard's "active threats" had the same
  dead `-L` comment scrape as U-1; it reads state files now.
- **U-10** — the log viewer's 3proxy entry resolves the dated log.
- **U-11 (the audit's most valuable find)** — the daemon's throttle
  state lives in `/run/nexoshield/autoban_throttle`, while the generated
  `tc-setup.sh` has always restored throttles after reboot from
  `/etc/antiddos/throttled.list` — a file *nothing ever wrote*. The
  restore path was dead and every reboot silently dropped all
  throttles. The daemon now mirrors its throttle state to the
  persistent file each cycle and restores from it at startup;
  displays read the live file with the mirror as fallback.
  (An early draft of this redesign misread the situation and pointed
  two displays at the mirror as if it were the live file; the audit
  caught and corrected that before release.)

## Deliberately unchanged

- Every action, delegate and confirmation *decision* is byte-for-byte
  the old behaviour; only rendering and input plumbing moved.
- The data-heavy screens (live monitor dashboard, log viewers) keep
  their layouts, now on the shared header/input path.
- Submenu option grids in the Security/Services screens keep their
  compact two-column form under the unified titles.

## Verification

`tests/unit/test-menu-ui.sh` assembles the real menu from its parts,
stubs the system surface, and drives it with scripted input: home
dashboard content, navigation into the Anti-DDoS and Proxy screens,
and all four CLI views — 12 assertions, plus the full suite and
`make check` gates.
