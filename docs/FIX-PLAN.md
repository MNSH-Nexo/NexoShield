# Fix Plan — NexoShield

**Status:** APPROVED by the maintainer 2026-10-23 ("شروع کن" — start).
Execution follows the waves below. Open questions Q1/Q2 proceed with the
recommended defaults (Q1: full IPv6 parity in Wave 9; Q2: probation
score 50 / 30-minute window) unless the maintainer overrides them before
those waves land.

**Progress log:**
- Wave 0 — DONE. Quick-win patch applied (BUG-029 validator into the
  whitelist manager, BUG-049 password fallback removed ×3, BUG-006
  sha256 pin scaffold — value still to be filled per Q4), CI workflow
  added (`.github/workflows/ci.yml`, runs `make check` + `make test` +
  install.sh sync guard), test skeleton added (`tests/unit/`, first
  suite: `valid_ip_or_cidr`, 30/30). `make check` + `make test` green.
- Wave 1 — DONE. D1: canonical exempt set — `exempt.list`/`self-ips.list`
  snapshots written by `apply_iptables`; fail2ban `ignoreip` now built
  from CF + self + whitelist and refreshed live on every whitelist
  add/remove (`update_f2b_ignoreip`); 3proxy per-port rules gained a
  whitelist ACCEPT step (tagged `3proxy_wl_allow`, symmetric cleanup);
  both manual Block-IP flows refuse exempt/invalid targets via the new
  `antiddos.sh --exempt-check <ip>` (per-layer report, exit-code
  contract). D2: `list_self_ips()` single lib implementation (all local
  addresses); `ban_ip` choke-point self guard; subnet-ban guard checks
  every self IP (BUG-065); `self_guard` watchdog sweeps DROP rules and
  throttle state for self IPs every daemon cycle. Also: BUG-005 (menu
  restores the CF list from the installer's new pristine copy
  `/opt/proxy-manager/data/`, never fabricates it; blank file no longer
  counts as present), BUG-027 (apply_iptables fails closed when the CF
  list is empty). Tests: exempt_check 10/10, daemon whitelist
  validation 5/5 (garbage masks can no longer widen a match, BUG-029
  daemon half). `make check` + `make test` green.

**Inputs:** `docs/BUGS.md` — 68 audited findings (BUG-001…068) plus the
maintainer's field reports FR-1 (whitelist must exempt from *everything*),
FR-2 (server's own IPs must *never* be blocked), FR-3 (reputation never
recovers after an unban → de-facto permanent ban).

**Goal:** every registry item fixed or explicitly closed, with the
product's core promise — *aggressive against floods, incapable of harming
Cloudflare, the server itself, whitelisted admins, or legitimate heavy
users* — enforced by construction and by tests, not by convention.

---

## Principles (apply to every wave)

1. **One source of truth per concept.** Exemption set, rule identity, and
   reputation state each get exactly one owner (see D1, D5, D3).
2. **Fail closed for exemptions, fail loud for failures.** If exemption
   data is missing, refuse to install/arm rather than proceed unprotected
   (kills theme T8). No `|| true` on a security-relevant mutation without
   a state check afterwards (kills T6).
3. **State ⇔ reality.** Anything recorded in a state file must be
   verifiable against the kernel (iptables/tc), and anything the kernel
   holds must be reflected in state. Startup reconciles the two (D6).
4. **No fix without a test.** Pure logic gets unit tests; command flows
   get stub-bin integration tests (fake `iptables`/`tc`/`systemctl` on
   PATH that record invocations); kernel behaviour gets a live-VM
   checklist per wave. `make check` gates everything.
5. **One wave = one commit series on this branch**, each wave leaving
   `make check` green and the shipped `install.sh` reviewable as a
   focused diff. Behaviour changes are flagged per item (⚠).

---

## Design decisions

### D1 — Exemption is a subsystem, not a check (FR-1 → BUG-027/028/029/039)
A single canonical **exempt set**: Cloudflare ranges ∪ server self IPs ∪
admin whitelist. One builder produces it; every consumer reads it:
- `apply_iptables`: early ACCEPT jumps (INPUT + raw/SYNPROXY) — as today,
  but generated from the set in one place.
- tc: exempt destinations → unlimited class (after the D4 direction fix;
  today this leg is nominal only, per BUG-001).
- auto-ban daemon: `is_exempt()` over the set — as today, but the set is
  loaded from one file (`/etc/antiddos/exempt.list`, generated) instead
  of three ad-hoc readers.
- **fail2ban: `ignoreip` is *generated* from the same set** (localhost +
  CF + self + whitelist) and fail2ban is reloaded whenever the whitelist
  changes. (Fixes the biggest FR-1 gap.)
- **3proxy per-port rules gain a whitelist step** (CF → self → whitelist
  → rate-limit), mirroring the antiddos order.
- **Manual Block-IP refuses exempt IPs** with a clear message, in every
  menu path.
- Whitelist writes go through the validator (already drafted in the
  Wave 0 patch), are applied to all layers *immediately and verifiably*,
  and the daemon rejects malformed entries at load (defense in depth for
  BUG-029's mask-arithmetic path).
- New operator surface: `antiddos.sh --exempt-check <ip>` prints, per
  layer, whether that IP is exempt — the proof tool for FR-1/FR-2.

### D2 — Self-IP immunity as a guarantee (FR-2 → BUG-028/065/039)
- Self set = **all** addresses from `ip addr` (v4) + `hostname -I`,
  snapshotted to `/etc/antiddos/self-ips.list` at install and refreshed
  on daemon start and hourly (new addresses join the exempt set via D1).
- **Choke-point guard:** every code path that installs a DROP/ban —
  `ban_ip`, `ban_subnet`, manual block, fail2ban config — checks the
  target against the self set. `ban_subnet` checks overlap with *every*
  self IP (fixes BUG-065's `head -1`).
- **Watchdog (defense in depth):** once per daemon cycle, verify no
  DROP rule in INPUT matches a self IP and no tc filter throttles one;
  if found (bug, foreign tool, manual error), remove it and log loudly.
  This turns "never" from a hope into a monitored invariant.

### D3 — Reputation lifecycle redesign (FR-3 → BUG-034/020/003)
Current flaw, precisely: post-ban score depends on which path banned
you; `unban_expired` ignores score; recovery only accrues while an IP is
hot; there is no defined post-ban state. Redesign as an explicit state
machine, owned by the two choke points that already funnel every ban:

```
NORMAL ──score<60──► THROTTLED ──score<40──► HARD ──score<20──► BANNED
  ▲                                                              │
  │                                                    ban served (4h)
  │                                                              ▼
  └──── clean for probation window ◄── PROBATION (score := 50) ◄─┘
              │ re-offense in probation: drops are doubled,
              │ but a ban still requires the score to *reach* <20 —
              │ a single minor spike cannot re-ban.
  Manual unban (menu) also lands in PROBATION, never in a stale score.
```

Rules:
- `ban_ip()` is the single entry for *every* ban (reputation, classic,
  instant) — verified: all call sites already funnel through it. It
  records `banned_at`, duration, and path.
- `unban_expired()` / manual unban set the score to **PROBATION_SCORE
  (50)** and stamp `probation_until = now + 30 min` — the same for every
  path. (Parameters are §Decisions Q2.)
- Recovery is evaluated **every cycle for every known IP**, hot or
  quiet: clean cycle ⇒ +3 (as today), faster during probation (+5) so a
  well-behaved IP is fully normal ~10 quiet minutes after release.
- Re-offense during probation: score drops are ×2 (a real repeat
  attacker returns to ban quickly), but bans only ever fire from the
  score bands — no instant re-ban from a stale state.
- Entries are pruned when an IP is NORMAL at score 100 for 24 h;
  `reputation.dat` is rewritten atomically (tmp + rename) under `flock`
  (with BUG-033), and `dt` is computed from the persisted timestamps,
  not assumed to be 2 s (fixes the BUG-020 distortion).

### D4 — tc egress redesign (BUG-001/021/022/024/032)
On an egress root qdisc, classify by **destination** (the client):
- filters: `match ip dst <client>` → CF/self/whitelist ⇒ 1:10
  (unlimited), throttled ⇒ 1:30, hard ⇒ 1:40, default ⇒ 1:20.
- `throttle_ip`/`hard_throttle_ip` add `dst` filters; the recorded
  handle/prio is allocated from a persistent monotonic counter kept in
  the state dir (no line-count reuse, no RANDOM collisions — BUG-021),
  and the state entry is written **only after** the tc command succeeds
  (BUG-024).
- `setup_tc` preserves live throttle state: after rebuilding the qdisc
  it re-applies filters from THROTTLE_LIST (BUG-022), keeps the detected
  link speed in the boot script instead of hardcoding 1gbit, and checks
  for a pre-existing foreign qdisc — it warns and records it instead of
  silently deleting (BUG-032).
- If shaping is ever needed for *forwarded* traffic, that is a separate
  ingress/IFB design — explicitly out of scope here (see BUG-064).

### D5 — Rule identity: tag everything, delete by tag (BUG-013/014/010/008/031, theme T2/T5)
- Every rule NexoShield creates carries `-m comment --comment "nx:<id>"`.
- All deletion/cleanup enumerates rules via `iptables -S` (which prints
  full specs including comments — unlike `-L`) and deletes by exact
  spec. No feature may grep `iptables -L` output for comments again.
- Reinstall becomes provably idempotent: delete-by-tag first, then add.

### D6 — State integrity (BUG-004/012/019/033)
- All iptables mutations use `-w 5` (xtables lock wait).
- Daemon startup **reconciles**: re-applies unexpired bans from
  `banned.list`, drops expired ones through the D3 transition, rebuilds
  throttle filters from THROTTLE_LIST. (BUG-004)
- Persistence snapshots contain **only the static base ruleset**: rules
  tagged dynamic (`nx:dyn:*` — auto-ban/fail2ban-style transient rules)
  are excluded from `iptables-save` outputs, and `remove_rules` also
  refreshes/removes the persisted file + restore service. (BUG-012)
- All multi-writer state files move to `flock` + atomic rewrite.

### D7 — Truth in UI (BUG-008/036/041/050/053, theme T4)
Every status number must come from the authoritative source (per-jail
fail2ban status, `iptables -S`, tc filter list, service state) and every
mutating action verifies its postcondition before printing ✓. Where a
value can't be obtained, the UI says so instead of printing 0/success.

---

## Waves

### Wave 0 — Safety net + staged quick wins  *(size: S)*
Apply the already-prepared, already-verified patch
(`~/workspace/drafts/nexoshield/quickwins.patch`): whitelist validator,
password-fallback removal (BUG-049), 3proxy sha256 pin (BUG-006, hash to
be filled per Q4), banner fix. Add the CI workflow (same draft) and a
`tests/` harness skeleton + `make test`. **Gate:** CI green on the
branch. *Prerequisite for everything else.*

### Wave 1 — Exemption integrity (D1 + D2)  *(size: M)* ⚠behaviour
FR-1, FR-2; BUG-005 (menu CF recreate uses the canonical writer),
BUG-027 (missing CF data aborts arming), BUG-028, BUG-029 (daemon-side
validation), BUG-039 (block guard), BUG-065. **Tests:** unit tests for
the exempt-set builder; stub-bin test: whitelist add ⇒ ignoreip file
regenerated + reload called; block of a self/whitelisted IP refused.
**Live check:** `--exempt-check` against a whitelisted IP shows exempt
in all layers.

### Wave 2 — tc truth (D4)  *(size: M)* ⚠behaviour
BUG-001, BUG-021, BUG-022, BUG-024, BUG-032 (tc legs), BUG-036 (verify
postcondition before ✓). **Tests:** stub-tc sequence tests for
throttle/release/rebuild; live check: throttle a test IP, measure with
iperf3/curl that download is actually capped; reboot persistence check.

### Wave 3 — iptables correctness (D5 + D6 halves)  *(size: M)*
BUG-002 (move `http_req_rate`/`bw_per_ip` *above* the ESTABLISHED
accept — or scope the accept to non-web ports; decision in-wave with a
packet-order test), BUG-019 (`-w`), BUG-012 (static-only snapshots),
BUG-013/BUG-014 (delete-by-tag symmetry for the 3proxy ruleset),
BUG-063 (tier change replaces by tag), BUG-031 (removal by tag; stop
deleting foreign raw ACCEPTs). **Tests:** stub-iptables idempotency
test (install ×2 ⇒ rule count stable), removal completeness test.

### Wave 4 — Auto-ban core (D3 + D6)  *(size: L)* ⚠behaviour
BUG-003 (exact field matching everywhere — one `ip_matches()` helper,
anchored, dot-safe), BUG-004 (startup reconcile), BUG-034 + FR-3 (D3
state machine), BUG-011 (subnet: watch 400 / ban 1000 as designed; CF
overlap by real range intersection, not `.1`; exempt traffic excluded
from aggregation), BUG-030 (count conntrack peers in defined states;
exclude server-originated flows; document the sample cap), BUG-020
(precompute CF ranges into a sorted int array + binary search in bash;
real `dt` from timestamps), BUG-033 (flock + atomic writes), BUG-045
(logrotate for both logs). **Tests:** unit tests for score transitions
(full lifecycle incl. probation), substring-torture tests
(1.2.3.4 vs 11.2.3.4 vs 1.2.3.45), restart-reconcile stub test.

### Wave 5 — fail2ban truth  *(size: M)*
BUG-017: portscan jail gets its own LOG rule (or is removed — Q3);
http-flood filter rewritten for the logs it actually reads, or the jail
is dropped and the README corrected; 3proxy-ddos filter keys on the
`%E` error field so successful connections never count. BUG-028 already
closed in Wave 1 (ignoreip generation) — this wave verifies per-jail.
**Tests:** failregex regression tests with real sample log lines
(`fail2ban-regex` in CI).

### Wave 6 — 3proxy lifecycle & hardening  *(size: M)* ⚠behaviour
BUG-018 (dedicated `nexoproxy` system user + systemd sandbox;
ports <1024 via `AmbientCapabilities=CAP_NET_BIND_SERVICE`), BUG-026
(update preserves credentials; rotation only via explicit reset),
BUG-015/BUG-037/BUG-060 (uninstall touches only its own tagged rules
and its own jails' bans; never `/etc/antiddos`; stop service instead of
`pkill -f`), BUG-035 (complete the SSRF deny list incl. 0.0.0.0/8),
BUG-061 (fail fast on port exhaustion, before writing anything),
BUG-025 (installer: stage modules to a temp dir, verify, atomic swap,
keep previous version for rollback), BUG-016 (apt mirror becomes
opt-in `--with-mirror`/menu toggle, default off; originals restored on
uninstall), BUG-059 (don't advertise an IPv6 URL), BUG-044-RHEL leg.

### Wave 7 — sysctl correctness  *(size: M)*
BUG-007 (parse on first `=`; never strip spaces inside values),
BUG-010 (`tcp_mem` computed in **pages** from RAM with sane fractions),
BUG-009 (the snapshot key list is *generated from* the write set — one
list, two uses — so they can never drift again), BUG-040 (preserve
current `ip_forward` unless `--forward` is chosen), BUG-042 (read-only
paths never modprobe), BUG-054 (`flock`), BUG-055 (drop `bc`),
BUG-056/BUG-050-style counter cosmetics in this module.

### Wave 8 — Menu & monitoring truth (D7)  *(size: M)*
BUG-008 (flush-all via D5 delete-by-tag + postcondition check),
BUG-041 (counters: `BANNED:` anchored so `UNBANNED:` doesn't match;
per-jail fail2ban counts; Top-IPs uses the client field; synproxy
metric parsed as hex from the right column or removed), BUG-038
(unban via exact-match helpers), BUG-043 (cache server IP for the
session), BUG-044 (update chain logic + honest result), BUG-051
(delete the dead duplicate `_proxy_stats`/`_proxy_change_pass`),
BUG-052 (backup verifies archive, warns it contains credentials),
BUG-053 (state from real probes, not file existence).

### Wave 9 — IPv6 (Q1 decides scope)  *(size: L)* ⚠behaviour
BUG-023 + BUG-059 + BUG-064 (assess). Full-parity path: CF v6 data
file, `ip6tables` mirror of the INPUT design, daemon sampler counts v6
peers, tc v6 filters, fail2ban already dual-stack via ignoreip set.
Fallback path (if Q1 = warn-only): installer detects global v6,
prints a prominent warning, and offers `--disable-ipv6` sysctl
hardening as an explicit opt-in — never silently.

### Wave 10 — Debt, docs, release  *(size: S–M)*
SC2015 note debt, one module per commit (68 notes); README truth-sync
(BUG-046 UDP port list vs message — fix the list *and* the message;
threshold tables; fail2ban claims after Wave 5); BUG-050/056/062
cosmetics; BUG-047/048/054/066/067/068 suspects resolved by live tests
or closed as documented non-issues. Version → **3.5.0**, tag
`v3.5.0`, GitHub release with the installer's sha256 (Q5).

---

## Test strategy (summary)

- **Unit (CI):** `tests/unit/` — bash tests sourcing pure functions:
  validator, `ip_in_cidr`, score state machine, exempt-set builder,
  delete-by-tag enumeration. No root, no kernel.
- **Stub-bin integration (CI):** `tests/stub/` — fake
  `iptables`/`tc`/`systemctl`/`fail2ban-client` scripts on PATH that
  log argv; run install/ban/unban/whitelist flows and assert the exact
  command sequences (this is what would have caught BUG-013/014/008).
- **Live-VM checklist (per wave):** a disposable Ubuntu VM run-through:
  install → attack simulations (hping3 SYN flood, slowhttptest,
  connection churn from a second host) → verify layers, exemption of a
  whitelisted client, reboot persistence, removal completeness.
- **Regression rule:** every BUG id closed by a wave names its test in
  the commit message.

## Decisions needed from Mahan

- **Q1 — IPv6 scope:** full parity in Wave 9 (recommended), or
  warn-only for 3.5.0 and parity in 3.6?
- **Q2 — Probation parameters (D3):** PROBATION_SCORE 50 and 30-minute
  probation (recommended defaults). Stricter (40 / 60 min) or lighter
  (60 / 15 min)?
- **Q3 — Portscan jail:** add a dedicated LOG rule so it can work
  (recommended), or remove the jail?
- **Q4 — 3proxy sha256:** the pin must come from a download *you* trust
  (the staged patch leaves it empty = check skipped until filled).
- **Q5 — Release mechanics:** push `refactor/modular-src`, open a PR
  to master, tag `v3.5.0` at Wave 10 (recommended) — or keep stacking
  local commits?

## Non-goals
No language rewrite, no new features beyond FR-1…FR-3, no change to the
single-file distribution model, no threshold retuning beyond what a
bug fix requires (D3 parameters excepted, per Q2).
