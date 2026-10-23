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
  read throttled IPs from `/tmp/autoban_throttle` — a path nothing in
  the product writes, so the section was permanently empty — and
  scraped `iptables -L` for bans. It now reads the state files, the
  product's source of truth.

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
