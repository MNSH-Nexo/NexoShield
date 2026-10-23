# NexoShield live-fire battery (`tests/live/`)

Controlled attack scenarios that run **on a disposable test server you own**,
verifying NexoShield's detection, scoring, exemption and enforcement paths
end to end. This is the battery documented as "still owed" in
`docs/FIELD-TEST-2026-10-23.md` — the scenarios unit tests cannot prove:
real packet paths, real daemon sampling, real fail2ban jails.

## Authorization & safety

- Every script refuses to run unless `NX_LIVEFIRE=1` is exported — an
  explicit, per-session opt-in that you own the target and authorize testing.
- `guard_target` (in `lib.sh`) rejects any destination outside the lab
  ranges `10.99.0.0/24`, `fd99:99::/64` and loopback. No external traffic,
  ever — the attacks never leave the test server.
- Each step is time-boxed (`timeout`) and repetition-capped; nothing runs
  `--flood`-style uncapped.
- Run only on a throwaway box. The scripts must run as root.

## Runbook (on the test server, as root)

```bash
export NX_LIVEFIRE=1
bash tests/live/run-all.sh
# results: /root/nx-livefire/battery.log
# evidence tarball: /root/nx-livefire/nx-livefire-<ts>.tar.gz  (copy it off before the box dies)
```

Individual steps can be run standalone (`bash tests/live/20-xmas-scan.sh`)
as long as `00-lab-setup.sh` ran first; `90-collect.sh` tears the lab down.

## What each step proves

| Step | Attack (source IP) | Claim under test |
|------|--------------------|------------------|
| 00 | lab setup | netns `nxlab` + veth up on v4+v6; baseline snapshot |
| 10 | 170 concurrent conns, 60 s hold (10.99.0.11) | daemon's counted conns vs `ss` ground truth; scoring moves; ban at sustained load |
| 20 | XMAS scan, nmap (10.99.0.12) | `[NX-SCAN]` LOG path fires; `portscan` jail bans |
| 30 | 12 bad SOCKS5 auths + 3 clean connects (10.99.0.13) | `3proxy-ddos` jail counts only errors (Wave-5 `%E` keying); T-2 dated-log glob works |
| 40 | 3000-SYN burst, ~3 s (10.99.0.14) | `SYN_COUNT` sampler feeds the `syn=` term of scoring v2 |
| 50 | 60 conns from whitelisted IP (10.99.0.15) | **FR-1**: whitelisted IP is exempt from *everything* — no SCORE lines, no ban |
| 60 | 120 v6 conns (fd99:99::21) | Wave-9 parity: v6 counted, scored, enforced like v4 |
| 90 | — | evidence tarball + lab teardown |

## Reading the results

`battery.log` carries `PASS:`/`FAIL:` lines plus the raw daemon `SCORE:`
lines per test IP. A `FAIL` is a finding, not a verdict — investigate with
the evidence tarball (`auto-ban.log`, `reputation.dat`, jail statuses,
iptables/tc dumps) before concluding.

Known design notes:
- The daemon samples in cycles; each attack step sleeps through at least
  one full cycle before asserting.
- `50` restores `whitelist.list` byte-identical afterwards.
- If a step times out, `run-all.sh` continues — partial evidence is still
  collected by `90`.
