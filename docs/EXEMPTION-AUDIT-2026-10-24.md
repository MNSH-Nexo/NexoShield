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

## Addendum — E-6: NAT / cloud public-IP discovery (v3.7.1)

Field verification on an Azure VM (2026-10-24) confirmed the NAT
residual below: the interface carried only 172.16.0.4 while the
server's public address (65.52.x.x) existed solely in Azure's NAT,
so `--exempt-check` correctly-but-unhelpfully reported it "not
exempt". The owner directed that such servers be detected too.

`src/lib/self-ips.sh` now discovers the public IPv4:

- **Metadata first** (link-local, no internet): Azure IMDS
  (first two addresses of the primary NIC), AWS IMDS (token, then
  plain), GCP, DigitalOcean, Hetzner — 2s timeouts.
- **External echo as last resort** (install-time only): ipify,
  checkip.amazonaws.com, ifconfig.me — 3s timeouts.
- **Hard validation** (`nx_is_public_ipv4`): every candidate must
  be a globally routable address — RFC1918, CGNAT, loopback,
  link-local, documentation (TEST-NET-1/2/3), benchmarking and
  multicast answers are rejected, so a spoofed or broken metadata
  reply can never widen the immune set.
- Results cache to `/etc/antiddos/public-ips.list`; a failed
  discovery never wipes a good cache. `list_self_ips_all()` (local
  + cached) is now the self feed for the kernel ACCEPT steps, the
  snapshots, the fail2ban builder, `--exempt-check`, the 3proxy
  steps, tc, and the daemon (startup + refresh). On hosts with a
  cache, the daemon re-runs *metadata* discovery on its ~5-minute
  refresh, so a reallocated cloud public IP becomes immune without
  a reinstall; hosts without a cache never pay for the probes.
- Proof: `tests/unit/test-public-ip-discovery.sh` (33 assertions:
  validator truth table, per-provider stubbed discovery, private
  answer rejection, cache survival).

Residual, still by design: a NAT server with no metadata service
*and* no outbound internet cannot self-discover (the admin
whitelist remains the manual path), and IPv6 needs no equivalent —
v6 is routed, not NATed, in practice; a global v6 is on an
interface and `list_self_ips6` already sees it.

Field note (same day, the Azure VM above): Azure IMDS can report
`publicIpAddress: ""` even for a VM that is publicly reachable -
metadata alone is *not* sufficient, which is why the echo fallback
exists and why all three echo services were cross-checked against
the connected address during verification. For such hosts the
install-time cache is authoritative: the daemon's refresh re-runs
metadata only (an echo-discovered address is kept, not refreshed),
so if the provider later reallocates the public IP, re-running
the installer (or one `--exempt-check` after a manual whitelist
add) re-discovers it.
