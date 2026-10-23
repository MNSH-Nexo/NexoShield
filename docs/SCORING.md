# NexoShield reputation scoring — model v2

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

## Verification

`tests/unit/test-scoring-v2.sh` proves: continuity at the old 24/25
conn/s cliff (≤3 points apart where v1 differed ~6/cycle), dt
proportionality (same rate at dt=30 vs dt=2), fractional accumulation
(4 conn/s is no longer free), the SYN-share term, and time-based
recovery. The D3 lifecycle suite (`test-reputation-lifecycle.sh`) was
re-based to the time-based expectations (50 s quiet = +5 normal /
+8 probation).
