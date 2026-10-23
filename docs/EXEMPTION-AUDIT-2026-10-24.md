# Exemption audit — 2026-10-24

Re-verification of the FR-1/FR-2 hard guarantee at the owner's
request: the server's own IPs and the admin whitelist (Cloudflare
included) must never be banned, throttled or rate-limited by any
layer, on any server, for IPv4 and IPv6 alike. Every enforcement
surface was re-read against the current code; five gaps were found
and fixed. Proof: `tests/unit/test-exemption-guarantee.sh` (30
assertions, daemon level, with positive controls) and
`tests/unit/test-exemption-surfaces.sh` (29 assertions).

## Verified tight (no change needed)

- Daemon chokepoints: `ban_ip`/`throttle_ip`/`hard_throttle_ip` and
  the v6 family refuse anything `is_exempt`/`is_exempt6` matches
  (self + Cloudflare + whitelist, hosts and CIDRs, both families);
  `ban_subnet` skips CF-overlapping, self-containing and
  whitelist-overlapping /24s (true CIDR overlap, R-15).
- `apply_ip6tables`: CF6 + every self v6 (/128) + whitelist v6
  ACCEPTs precede all policing rules.
- fail2ban `ignoreip` sits in `[DEFAULT]` of the generated jail
  file, so it covers distro jails (sshd) too, and is regenerated
  from the single builder on every whitelist change.
- 3proxy per-port rules have their whitelist ACCEPT step (FR-1).
- Manual Block-IP flows refuse exempt targets via `--exempt-check`.
- `list_self_ips`/`list_self_ips6` enumerate every interface
  address (secondary, private, temporary v6, link-local) — verified
  against canned multi-interface `ip addr` output.

## Gaps found and fixed

- **E-1** — fail2ban `ignoreip` carried the server's own IPv4s but
  only `::1` for IPv6: fail2ban could ban the server's own global
  IPv6. The builder now adds every `list_self_ips6` address.
- **E-2 (fail-open)** — `ip6_in_cidr` treated a mask-less CIDR as
  /0: one bare IPv6 whitelist entry made `is_exempt6` true for
  *every* IPv6 address. A missing mask now means /128 (the daemon
  guarantee test pins a non-whitelisted v6 control as enforced).
- **E-3** — the daemon captured its self-IP sets once at startup;
  an address assigned later was not immune until a restart.
  `refresh_self_ips` now runs on the ~5-minute cadence; additions
  are logged, removals stop being immune.
- **E-4** — the kernel/tc self-exemption steps used the
  display-grade `get_server_ips` (public addresses only), so
  traffic from the server's own private/secondary addresses still
  hit SYN/UDP limits, connlimit, the 3proxy port limits and tc
  shaping. All enforcement sites (INPUT ACCEPT, raw SYNPROXY
  bypass, tc unlimited class, 3proxy per-port create/delete,
  boot-time tc-setup) now use the exhaustive `list_self_ips`
  (loopback excluded from kernel ACCEPT rules: `-i lo` covers it,
  and a `-s 127.0.0.1` ACCEPT on external interfaces would bless
  spoofed martians).
- **E-5** — the admin whitelist was IPv4-only end to end: every
  layer honoured v6 entries, but the validator rejected them, so
  none could ever be added; `--exempt-check` likewise rejected v6
  targets as "invalid". Added `valid_ip6_or_cidr` (wired into the
  whitelist manager) and an IPv6 branch of `--exempt-check` backed
  by `nx_ip6_in_cidr`.

## Residual, by design

- NAT: a cloud server's *public* address may exist only in the
  provider's NAT, not on any interface, so it cannot be detected
  locally. It also never appears as an inbound source except for
  hairpin traffic; admins on such setups can add it to the
  whitelist (now possible for both families, E-5).
- The daemon's score sampler still *observes* exempt IPs; only
  enforcement is gated. Scores for exempt IPs are inert (every
  action path re-checks exemption).
