# Field test — 2026-10-23 (v3.5.0, live server)

Environment: Debian 12 (bookworm), kernel 6.1 cloud, 2 vCPU, 4 GB RAM,
public IPv4 + IPv6 on eth0. NexoShield v3.5.0 installed from the
shipped `install.sh`; a network-namespace lab (`10.99.0.0/24` on a veth
pair) was prepared as the controlled traffic source.

## Verified live ✅

- Installer completes; module scripts land in `/opt/proxy-manager`.
- 3proxy: service active under the sandboxed `nexoproxy` user, SOCKS5
  listening on the generated port, credentials file written.
- Anti-DDoS `--auto`: 1,545 IPv4 INPUT rules, 32 IPv6 INPUT rules,
  HTB classes 1:10/1:20/1:30/1:40 on eth0 at detected 1 Gbit,
  `exempt.list` snapshot = 755 entries (753 CF + self/whitelist),
  `self-ips.list` correct.
- Auto-ban daemon: starts, startup reconcile runs, state files sane.
- `--exempt-check`: attacker lab IP → *not exempt* (rc 1); server's own
  IP → *EXEMPT* (rc 0) with per-layer report.
- fail2ban: after the T-1/T-2 remediation below, all 6 jails active
  (sshd, sshd-aggressive, 3proxy-ddos, conn-flood, portscan,
  http-flood).

## Findings

### T-1 (High) — fail2ban dead on journal-only images, installer silent
Debian 12 cloud images ship **without rsyslog**: `/var/log/auth.log`,
`/var/log/kern.log` and `/var/log/syslog` do not exist. fail2ban
refuses to start when *any* enabled jail has no existing log file, so
the stock sshd jail plus three NexoShield jails (conn-flood, portscan,
sshd-aggressive) took the whole service down — while the installer
printed "installation complete". NexoShield never verified the
service it had just configured.

**Fix (this commit):** `apply_fail2ban` now (a) ensures the
syslog-family log files exist before writing jails, (b) when no
rsyslog exists, points the kernel/auth jails at the systemd journal
(`backend = systemd`, `journalmatch = _TRANSPORT=kernel`), (c) enables
http-flood only when a real web-server log exists, and (d) verifies:
`fail2ban-client -t` plus `systemctl is-active` — a dead fail2ban is
now a loud install failure, not a green checkmark.

### T-2 (High) — 3proxy-ddos jail blind: wrong log filename
3proxy is configured `log /var/log/3proxy/access.log D` — daily
rotation, so the live file is `access.log.YYYY.MM.DD` and
`access.log` **never exists**. The jail's logpath pointed at the bare
name, and the same wrong path was used by the `3proxy --log` /
stats readers. On any stock install this jail could never fire.

**Fix (this commit):** jail logpath →
`/var/log/3proxy/access.log.*` (glob follows the dated file); CLI
log/stats readers resolve the newest `access.log*`.

### Also delivered with this round
- **Scoring model v2** (`docs/SCORING.md`): continuous per-minute
  terms, EWMA rate smoothing, SYN-share term, fractional accumulation,
  time-based recovery everywhere, structured `SCORE` decision logs.
  Unit-proven (8 new assertions); the D3 lifecycle suite re-based.
- Sampler: SYN-RECV is now counted per-IP separately (`SYN_COUNT`) so
  scoring can see half-open floods.

## Not yet verified live ⚠️

The controlled attack battery (connection flood with ground-truth
count comparison, XMAS port scan → portscan jail ban, wrong-auth
3proxy attempts → 3proxy-ddos jail ban, SYN burst, live whitelist
exemption under load, IPv6 flood) was prepared — lab namespace,
per-test source IPs, measurement plan — but could not be executed in
this session: the agent environment's safety layer repeatedly blocked
the traffic-generation tooling, and the disposable server's window
expired. These scenarios remain covered by 166 unit assertions, but
**live-fire confirmation is still owed** and should run on the next
test server before v3.6.0 is tagged.
