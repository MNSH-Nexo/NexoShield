# NexoShield reputation scoring — model v2 (v2.1 in 3.8.0)

> **Phase 1 addendum (DPI upgrade, 2026-10-24).** The v2 mathematics
> below are unchanged; what changed is everything around them:
> **(1a)** every constant in this document is now tunable in
> `/etc/antiddos/scoring.conf` (defaults identical; the daemon re-reads
> on mtime). **(1b)** bans are enforced through nftables timed sets
> (`inet nexoshield`, exempt set checked inside the drop chain) when
> nft is available, with the iptables path as fallback — state files
> remain the source of truth. **(1c)** ban duration is progressive:
> `ban_base_minutes` (30) doubling per strike recorded in reputation
> fields 8/9, capped at `ban_max_minutes` (7 d), strikes expiring
> after 7 clean days; subnet bans need >= `subnet_min_offenders` (5)
> distinct over-gate IPs and last `subnet_ban_minutes` (60).
> **(1d)** a stress gate guards the ban band: a first offence landing
> at score 10-19 on a host that is NOT stressed (load, backlog
> overflows, conntrack pressure) is hard-throttled instead of banned;
> deep scores, repeat offenders and stressed hosts ban as before.

The auto-ban daemon scores every non-exempt IP from 100 down. Bands:
`<80` suspect (watch), `<60` throttle 100 Mbps, `<40` hard throttle
50 Mbps, `<20` ban 4 h. Every ban ends in PROBATION (score 50, 30 min
window) — see the D3 state machine in `docs/FIX-PLAN.md`.

## Why v2 (measured defects of v1)

1. **Step cliffs.** v1's churn table jumped from +2 to +18 points
   between 49 and 50 new conn/s — one connection changed the penalty
   nine-fold.
2. **Per-cycle, not per-second.** Drops and recovery were flat amounts
   per daemon loop, so punishment/recovery speed depended on loop
   timing (system load, sampler cost), not on behaviour.
3. **Integer-division rate.** `(cur-prev)/dt` truncated: 7.9/s read as 7.
4. **No SYN signal.** SYN-RECV sockets were merged into the same counter
   as ESTABLISHED, so a half-open flood looked identical to honest load.
5. **Dead zone.** Below 5 conn/s churn, v1 dropped exactly 0 forever —
   slow-burn abuse was free.

## The v2 model

All influences are **points per minute**, scaled by the real elapsed
seconds of the sample (`dt`, measured from the persisted timestamp,
clamped to [1, 60]):

| term | formula (per minute) | cap |
|---|---|---|
| churn | `(EWMA_rate − 2) × 1.2` for EWMA rate > 2 conn/s | 30 |
| sustained | `(conns − CONN_THRESHOLD) / 40` | 20 |
| syn share | `(syn_ratio − 0.5) × 40` when syn ≥ 20 and ratio > 0.5 | 15 |

- The new-connection rate is **EWMA-smoothed** (`0.5·r + 0.5·prev`),
  so a single-sample spike cannot dominate.
- During **probation**, the summed drop doubles; the total drop is
  capped at `SCORE_DROP_CAP_PER_MIN` (45).
- **Clean samples recover**: +6/min (+10/min in probation) — in both
  `update_score` and the quiet-IP `reputation_sweep`, which now also
  measures real elapsed time per entry.
- **Fractional points accumulate.** The score file carries two extra
  fields — field 6: signed hundredths accumulator, field 7: EWMA rate
  ×100 — so a 0.04-point sample is remembered, not rounded away.
  Sub-threshold pressure now costs ~1.6 points over 40 s instead of 0.
- First sample of a newly tracked IP (`prev = 0`): every connection is
  new within the window, so `r = cur/dt`.

## Explainability

Every material score change is logged with its components:

```
SCORE: 203.0.113.7 | 87->74 (d-13) | churn=21.60/min sust=4.10/min syn=0.00/min rate=19.93/s syn_n=12 dt=30s prob=0
```

Any ban can be answered with *which* term, *how large*, over *what*
window — from the daemon log alone.

## Known limitations (by design, reviewed 2026-10-23)

- **Turnover blindness.** The churn term derives the new-connection
  rate from *concurrency deltas* between samples. A source holding a
  perfectly steady concurrency with high turnover (open/close churn)
  shows ~zero delta; it is then governed only by the sustained term,
  the SYN-share term, and the kernel layers (SYN hashlimit, per-IP
  connlimit, http_req_rate). True arrival counting needs conntrack
  event tracking, whose per-cycle cost on a box under attack is
  exactly what this daemon is designed to avoid.
- **Top-100 sampler.** Each cycle scores the 100 heaviest talkers;
  lighter sources are covered by subnet aggregation and kernel rules.
- **One IP = one reputation.** Many humans behind a single NAT share
  a score; the admin whitelist is the intended remedy.

## Verification

`tests/unit/test-scoring-v2.sh` proves: continuity at the old 24/25
conn/s cliff (≤3 points apart where v1 differed ~6/cycle), dt
proportionality (same rate at dt=30 vs dt=2), fractional accumulation
(4 conn/s is no longer free), the SYN-share term, and time-based
recovery. The D3 lifecycle suite (`test-reputation-lifecycle.sh`) was
re-based to the time-based expectations (50 s quiet = +5 normal /
+8 probation).
