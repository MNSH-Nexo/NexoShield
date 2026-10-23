# NexoShield DPI upgrade plan — measurement, adaptivity, enforcement

Approved by Mahan 2026-10-24 ("شروع کن و انجام بده هر 3 فاز رو").
Evidence base: `research_notes/ddos-detection-scoring-research-20261023-2221/report.md`
(38 sources: Chinese, Indian, US/EU research + production engineering).
Design rule inherited from the research verdict: the interpretable score
stays the actuator; no opaque model ever bans. ML is offline-only.

## Phase 1 — policy & enforcement (bash, current architecture) — DONE in v3.8.0

### 1a. Tunable scoring config (closes the standing "hardcoded constants" debt)
`/etc/antiddos/scoring.conf`, `key=value`, installed with documented
defaults equal to today's constants. New lib `src/lib/config.sh`:
`nx_cfg KEY DEFAULT` — numeric-validated, per-process cached, re-read on
mtime change. Every scoring constant (thresholds, weights, caps,
recovery rates, ban schedule, gate switches) moves behind it. Invalid
values fall back to the default and log a warning once.

### 1b. nftables timed ban sets
Dynamic bans (auto, instant, manual, subnet) move from per-IP iptables
rules (linear scan per packet) to one `inet nexoshield` table:

```
set ban4/ban6  { type ipv4_addr/ipv6_addr; flags interval, timeout; }
set exempt4/6  { type ipv4_addr/ipv6_addr; flags interval; }
chain input { type filter hook input priority -10; policy accept;
  ip  saddr @exempt4 accept;  ip  saddr @ban4 drop;
  ip6 saddr @exempt6 accept;  ip6 saddr @ban6 drop; }
```

- Priority -10 runs before the iptables-nft INPUT chain (0). The exempt
  set is checked *inside* the drop chain: defence in depth behind the
  existing ban-choke guards (FR-1/FR-2 stay provable).
- State files remain the source of truth; the sets are a projection,
  rebuilt by `reconcile_bans` and on every ban/unban. Kernel-side
  timeout = ban duration, so expiry happens even if the daemon dies.
- Backend is feature-detected: no `nft` binary -> legacy iptables path
  (current behaviour), selected once, logged, shown in `--status`.
- fail2ban keeps its own actions (auth-abuse layer, unchanged).
- Uninstall deletes the table.

### 1c. Progressive bans + subnet guardrails
Reputation record gains field 8 `strikes` and field 9 `last_ban_ts`
(strikes reset when the last ban is > 7 days old).
Duration of the n-th ban (strikes counted before increment):

    minutes = min(ban_base_min * 2^strikes, ban_max_min)
    defaults: base 30, max 10080 (7 d) -> 30m, 1h, 2h, 4h, 8h, ...

Applies to score bans and instant bans; manual bans keep admin duration.
Subnet (/24) actions additionally require: >= 5 distinct member IPs each
>= conn_threshold in the window, aggregate >= subnet threshold, no
exempt member (existing CIDR-overlap guard), fixed 60-minute duration.
Rationale: CGNAT collateral research — a shared egress IP fronts
hundreds of users; first offences must be cheap, recidivism expensive.

### 1d. Stress gate + kernel global counters
Per cycle the daemon parses TcpExt counters (ListenOverflows,
ListenDrops, SyncookiesSent) from /proc/net/netstat and conntrack
usage. Host is STRESSED when any holds: load1 >= 0.9 * nproc,
ListenOverflows rose in the last 60 s, conntrack count >= 80% of max.
A score-band ban (not instant, not a repeat offender) on a NON-stressed
host is converted to hard-throttle + sticky watch; if the score still
falls below 10 the ban fires anyway ("egregious"). Every gate decision
is logged (`GATE:` lines). SyncookiesSent rising is logged as a global
SYN-pressure signal — this is the counter that stays truthful exactly
when SYN-RECV socket state disappears under syncookies (RFC 4987).

## Phase 2 — measurement core

### 2a. nxcountd — conntrack event counter (C, libc + kernel headers only)
Subscribes to NFNLGRP_CONNTRACK_NEW/UPDATE/DESTROY over raw netlink.
Per source IP aggregates: syn_new, est_new (transitions into
ESTABLISHED), cur_syn, cur_est, closed, bytes_orig, age_ms_sum. Every
1 s it atomically publishes the top-500 active sources (cumulative
counters + timestamp) to /run/nexoshield/counters.dat. Built at install
time when a C compiler and nfnetlink_conntrack headers exist; shipped
as a sandboxed systemd unit like the proxy. Any failure -> the daemon
falls back to `ss` polling (status quo), detected per cycle by
snapshot freshness. Daemon diffs consecutive snapshots (restart-safe:
a base change re-bases the window).

Why: polling samples a *stock*; Little's Law (L = lambda * W) makes
arrival rate underivable from concurrency deltas — short-lived
connections vanish between polls and a steady flood shows delta ~ 0
(the documented turnover blindness). Events count arrivals exactly.

### 2b. Handshake-completion ratio term
Rolling 60 s window per IP from event counters:
`r = est_new / max(syn_new, 1)`, active when syn_new >= 20:

    term = min(15, max(0, 0.5 - r) * 40)   points/min

A SYN flooder or scanner has r ~ 0 (full 15); a busy real NAT has
r ~ 0.9 (zero). Replaces the instantaneous SYN-RECV-share term when
event data is fresh; the two never stack (max wins).

### 2c. CUSUM accumulators (Tartakovsky line: accumulation, not smoothing)
Reputation fields 10/11 hold S_arr and S_syn (integers, x100 not
needed). Per 2 s sample, from event arrivals a and incomplete
handshakes i = max(0, syn_new - est_new):

    S_arr = max(0, S_arr + a - 2*dt)        allowance 2/s
    S_syn = max(0, S_syn + i - 0.25*dt)     allowance 0.25/s

While S_arr >= 120: +8 points/min ("cusum" log component).
While S_syn >= 60:  +8 points/min. Pulse trains and slow ramps that
never cross an instantaneous threshold accumulate across the
allowance — the gap EWMA alone cannot close.

### 2d. Adaptive global thresholds
Global per-sample totals (event counters, `ss` sums as fallback):
EWMA mean mu and EWMA absolute-deviation sigma of total arrivals.
z = (A - mu) / sigma. ATTACK state: z >= 4 for 3 consecutive samples;
clears at z < 2 for 30 samples (hysteresis). While ATTACK: baseline
learning FROZEN (F5's rule — attack traffic must not train the
baseline), conn_threshold x 0.6, observe_seconds x 0.5, both clamped
(threshold floor 40, ceiling 400). CALM: baseline updates, rho = 0.02.

### 2e. Slow-attack features (Ye et al., Guangdong, IoT 2025)
From event aggregates over the window: mean connection age and
bytes/connection per IP. Term: when cur_est >= 30, mean age >= 120 s
and bytes/conn <= 2000 -> min(10, (cur_est - 30) / 10) points/min
("slow" log component). Rate features are structurally blind to
Slowloris-class attacks; age x bytes is the cheap behavioural pair.

## Phase 3 — XDP escape hatch (dormant insurance)

`src/native/nx_xdp.c`: XDP program with an LPM-trie ban map (v4+v6,
values carry expiry) and per-CPU counters (SYNs seen, drops). Loader
`nx-xdp` (libbpf; built only when libbpf headers exist at install) —
load / unload / sync (ban state -> map). The daemon attaches ONLY in
emergency: SyncookiesSent delta > 500/min, or ListenOverflows delta
> 1000/min, or global SYN arrivals > 3000/s sustained 30 s; detaches
after 10 calm minutes. Generic-XDP fallback when native attach fails.
Published headroom: 8–26 Mpps dropped per core pre-conntrack, vs
iptables/nftables collapsing in the low Mpps — this is insurance for
the day pps, not bps, is the binding constraint. If libbpf is absent
the feature registers unavailable in `--status`; nothing else changes.

Deferred by evidence, not forgotten: HeavyKeeper (Peking Univ.,
USENIX ATC 2018) if distinct-source cardinality ever outgrows exact
maps; offline RF distillation of score weights from own logs.

## Invariants (every phase)
- Exemption guarantees (FR-1/FR-2, E-audit) are re-proven per phase;
  no enforcement path may bypass the choke points or the exempt sets.
- Every new signal degrades to today's behaviour when its data source
  is absent. No phase may make a stock install *worse* than v3.7.1.
- Each phase: unit suites + `make check` green, separate commit,
  minor version bump (3.8.0 / 3.9.0 / 3.10.0), docs updated.
- Push only on Mahan's explicit instruction (standing rule).
