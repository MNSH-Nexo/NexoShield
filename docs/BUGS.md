# Bug & Logic-Flaw Registry — NexoShield

**Status:** IDENTIFICATION ONLY (2026-10-23 audit). Nothing in this file has
been fixed yet. Fixes are a separate phase, to be prioritized together with
the maintainer's field reports (see the empty section at the bottom).

**Method:** full read of all 33 source parts + lib + installer fragments
(three independent review passes, one per component family), plus targeted
spot-verification of every Critical by re-reading the cited lines.
Line numbers refer to the part files under `src/` (they carry a 2-line
`@part` header vs. the assembled scripts).

**Severity:** Critical = a headline protection silently does not work, or
actively harms. High = protection/state corruption under realistic
conditions. Medium = wrong behaviour in common flows, misleading operator
output. Low = edge cases, cosmetic-but-misleading, dead code with latent
risk. "Suspect" = mechanism verified in code, impact needs a live repro.

---

## Cross-cutting root causes (read these first)

Most findings are instances of eight recurring design mistakes:

- **T1 — tc direction confusion.** All tc shaping hangs off the root
  (egress) qdisc, but filters match the *client* IP as packet **source**.
  On egress the source is always the server itself. (BUG-001)
- **T2 — Parsing `iptables -L` text for things it never prints.** Rule
  comments and match names only appear with `-v`; several features grep
  plain `-L` output for them and silently never match. (BUG-008, BUG-031)
- **T3 — Unanchored substring/regex matching on IPs.** `grep -qF "$ip"`,
  `sed -i "/$ip/d"` — `1.2.3.4` matches `11.2.3.4` and `1.2.3.45`, and dots
  are regex wildcards. (BUG-003 and many others)
- **T4 — State files and kernel reality drift apart, while the UI prints
  success unconditionally.** Bans recorded but not applied, throttles
  claimed but never installed, removals reported but not performed.
  (BUG-004, BUG-024, BUG-025, BUG-036 …)
- **T5 — `iptables -D` spec mismatches.** Delete specs differ from create
  specs (missing comment match, different hitcount), so deletes silently
  no-op. (BUG-013, BUG-014, BUG-010)
- **T6 — Silent failure swallowing in security-critical paths** (`|| true`,
  `>/dev/null 2>&1`) exactly where failure changes the security posture.
- **T7 — Components destroy each other.** Uninstall/rebuild flows of one
  component delete another component's state, rules or files.
  (BUG-015, BUG-016, BUG-023)
- **T8 — Fail-open on missing Cloudflare data.** The product's central
  invariant ("CF is never limited/banned") evaporates silently when one
  file is missing. (BUG-005, BUG-027)

---

## CRITICAL

### BUG-001 — All tc shaping matches the wrong direction; Layer 5 and the throttle pipeline are no-ops [T1] ✔verified
- **Where:** `antiddos/50-tc.sh:25,33,43` (+ generated tc-setup.sh `:64+`), `3proxy/10-tc.sh:31,39,49,105,112,121`, `autoban/20-enforce.sh:14,37`
- **Evidence:** root qdisc (egress) + `u32 match ip src "$CF"` / `match ip src "$ip/32"`. On egress, src = server, dst = client. CF/throttle filters can never match a client; the server-IP filters match *all* egress, pushing everything into the "unlimited" class 1:10.
- **Impact:** CF class, 500 Mbps normal class (except as HTB default), and the auto-ban's 100/50 Mbps throttle classes never shape a single packet. The graduated watch→throttle→ban design collapses to ban-or-nothing, while logs print "THROTTLE: ip -> 100Mbps".

### BUG-002 — ESTABLISHED fast-path ACCEPT kills the ESTABLISHED-state defenses ✔verified
- **Where:** `antiddos/20-iptables.sh:20` vs `:211` (`http_req_rate`, `--ctstate ESTABLISHED`) and `:252` (`bw_per_ip`, `--ctstate ESTABLISHED,RELATED`)
- **Evidence:** the fast-path ACCEPT is inserted at position 1 (`iptables -I`); the two rules that exist to police established connections are appended far below it and are unreachable. RST-flood and UDP/ICMP flow rules are likewise bypassed after the first packet of a flow.
- **Impact:** HTTP-burst-over-keepalive and per-IP byte caps — two advertised layers — are dead code.

### BUG-003 — Unanchored substring matching on IPs corrupts ban/watch/throttle state [T3] ✔verified
- **Where:** `autoban/50-main-loop.sh:60,68,77,86,111,124` (`grep -qF "$ip"`), `:72,89,90,95,112,137` (`sed -i "/$ip/d"`), `autoban/20-enforce.sh:6,46`, `autoban/30-reputation.sh:87`, `antiddos/70-whitelist-main.sh:69`
- **Impact:** `1.2.3.4` is skipped for banning when `11.2.3.4` is banned; inherits `1.2.3.45`'s watch start (premature throttle/ban); `sed` deletes other IPs' watch/throttle lines, orphaning tc filters; same flaw in /24 space (`1.2.3` matches `1.2.30`).

### BUG-004 — Bans are never re-applied after reboot/restart; the daemon then refuses to re-ban ✔verified
- **Where:** `autoban/00-header.sh:84` (startup only `touch`es the lists), `autoban/50-main-loop.sh:29-33` (no re-apply), skip checks `:60,124`
- **Impact:** iptables is volatile, `banned.list` persists. After any reboot or `systemctl restart auto-ban`, every unexpired ban has a list entry but no DROP rule — and the loop skips those IPs as "already banned" until nominal expiry. Attackers are free; status still counts them as banned.

### BUG-005 — Menu recreates the Cloudflare whitelist from an undefined variable and poisons it permanently [T8] ✔verified
- **Where:** `menu/10-proxy-menu.sh:27-33`
- **Evidence:** `printf "%s\n" "${CF_RANGES[@]}" > /etc/antiddos/cloudflare-ipv4.list` — `CF_RANGES` is never defined anywhere in the menu module (grep-verified, single reference). No `set -u`, so it writes one blank line. The guard `[ -s file ] ||` then sees a non-empty (1-byte) file and never repairs it.
- **Impact:** After the list file was deleted/emptied (e.g. by an anti-DDoS remove), installing the proxy from the menu proceeds with an effectively empty CF whitelist → Cloudflare IPs get conn-limited/throttled/banned.

### BUG-006 — 3proxy source tarball is compiled and run as root with zero integrity verification
- **Where:** `3proxy/40-install.sh:45-51`
- **Evidence:** `wget …/3proxy/archive/refs/tags/0.9.4.tar.gz` → `make` → installed to `/usr/local/bin/3proxy`, run as root (BUG-018). No sha256/signature anywhere (grep-verified).
- **Impact:** A compromised release asset or TLS middlebox turns into a root daemon. This is the fallback path whenever the apt install fails.

---

## HIGH

### BUG-007 — sysctl `apply_config` strips all spaces from values; multi-value tunables always fail and get disabled ✔verified
- **Where:** `sysctl/30-apply-rollback.sh:13` (`VAL=$(… | tr -d ' ')`), values at `sysctl/20-snapshot-config.sh:78-79`
- **Impact:** `tcp_rmem = 32768 262144 N` becomes one giant number, the kernel rejects it, and the failure path comments the key out of the config as `[DISABLED]`. `tcp_rmem`, `tcp_wmem`, `tcp_mem`, `udp_mem` — the core buffer tuning — fail on *every* install, live and at boot, with the warning misattributed to "virt limits".

### BUG-008 — Menu features grep `iptables -L` (no `-v`) for comments/matches that never appear [T2] ✔verified (flush path)
- **Where:** `menu/60-autoban-main.sh:31-38` (Flush all auto-bans), `menu/30-monitor-dashboard.sh:101-105`, `menu/10-proxy-menu.sh:108-111`, `menu/50-antiddos-menu.sh:27`
- **Impact:** Worst case: "Flush all auto-bans" never deletes a single rule (it even greps for the *quoted* string `"auto-ban"`), then truncates `banned.list` + throttle/watch state and prints "All auto-bans flushed" → bans become **permanent and invisible**. Dashboard/threat views always report "no threats" during real ban waves; the layer-status view reports iptables as not installed when it is.

### BUG-009 — Snapshot/rollback can never restore 8 of the 63 keys the optimizer changes
- **Where:** snapshot list `sysctl/20-snapshot-config.sh:14-53` vs writes `:139-149` (key-set diff verified)
- **Missing:** all 7 IPv6 keys written (`net.ipv6.conf.all.forwarding`, `accept_redirects` ×2, `route.max_size`, `neigh.default.gc_thresh1/2/3`) + `fs.file-max`.
- **Impact:** Rollback prints "complete" while IPv6 forwarding stays on and the other values persist in the running kernel indefinitely.

### BUG-010 — `tcp_mem` tiers confuse pages with bytes; pressure thresholds exceed physical RAM
- **Where:** `sysctl/10-detect.sh:62-78`, applied `sysctl/20-snapshot-config.sh:84`
- **Impact:** `tcp_mem` is in 4 KiB pages. ≥8 GB tier: pressure = 2,097,152 pages = 8 GiB (all of RAM), max = 24 GiB (3× RAM). <1 GB tier: max = 3 GiB. TCP memory pressure never engages before OOM — worst on the small VPSs the tool targets.

### BUG-011 — Subnet ban fires at 400-for-45 s (not the advertised 1000), tests CF overlap only at `.1`, and counts exempt traffic
- **Where:** `autoban/50-main-loop.sh` subnet section; `autoban/40-subnet.sh:7` (`is_cf_ip "${subnet}.1"`); thresholds `autoban/00-header.sh:71-72`
- **Impact:** A heavy CGNAT/VPN/university /24 (the code's own comment estimates ~400 for a heavy CGNAT node) gets dropped wholesale for 4 h. CF ranges are not /24-aligned, so a CF block covering part of a banned /24 is dropped too (ban rules insert at position 1, above the CF ACCEPTs). Subnet totals include CF/self/whitelisted traffic.

### BUG-012 — Full-ruleset snapshots make transient bans permanent; removal is undone by reboot [T4]
- **Where:** `antiddos/20-iptables.sh:306`, `antiddos/50-tc.sh:124` (`iptables-save` of the *entire* live ruleset), restore via `antiddos-restore` + iptables-persistent
- **Impact:** Every `apply_iptables` run — including every whitelist add/remove — snapshots whatever IPs are banned at that second into the boot-restore file, without expiry. Conversely `remove_rules` never updates `/etc/iptables/rules.v4` nor removes iptables-persistent, so after "Remove all protection" + reboot, the stale ruleset (and its bans) returns.

### BUG-013 — 3proxy reinstall duplicates 753 CF rules; stale rate-limit rule survives forever [T5] ✔verified
- **Where:** `3proxy/20-iptables.sh:14-21` (deletes) vs `:28-29,41-43` (creates)
- **Evidence:** CF deletes omit the `-m comment --comment "3proxy_cf_allow"` the creates carry; the DROP delete uses `--hitcount $((MAX_CONN * 2))` while create uses `MAX_CONN * 3`. `iptables -D` needs an exact spec → both deletes always miss (silently, `|| true`).
- **Impact:** Each "Install/Update" run adds another 753 ACCEPT rules; the old DROP rule with the previous MAX_CONN threshold stays in force alongside the new one.

### BUG-014 — 3proxy uninstall cannot remove what install created [T5]
- **Where:** `3proxy/50-uninstall.sh:35-38,46-48,67-68`
- **Impact:** Same spec mismatches as BUG-013, plus a single `-D` for a 753-rule set and a hard-coded `--hitcount 60` (only right when MAX_CONN was the default 20). Residue: CF ACCEPTs + a rate DROP for a dead port; any later service binding that port silently inherits them.

### BUG-015 — Proxy uninstall destroys the Anti-DDoS component while claiming the opposite [T7]
- **Where:** `3proxy/50-uninstall.sh:14-18,88,106,121-122` vs the message at `:132-133`
- **Evidence:** it stops/kills auto-ban, deletes `auto-ban.service`, deletes the shared tc root qdisc, and `rm -rf /etc/antiddos` + `/var/lib/antiddos` (CF list, whitelist, ban state, reputation) — then prints "Anti-DDoS iptables rules are kept to protect the server."
- **Impact:** Removing only the proxy leaves anti-DDoS rules in the kernel with a dead daemon, no state, and (via BUG-027 mechanics) an empty CF whitelist on the next run.

### BUG-016 — apt sources are permanently rewritten; the "backup" self-destructs on the second run [T7]
- **Where:** `3proxy/30-apt-mirror.sh:63-71`, called on every `install_proxy` (`3proxy/40-install.sh:15-18`)
- **Impact:** `ubuntu.sources` is deleted, `sources.list` replaced with 3 lines from the fastest mirror (list includes plain-`http://` third-party mirrors, chosen by speed only). On re-run, the `.bak` is overwritten with the *already-rewritten* file, destroying the only copy of the original — despite the "nothing is lost" comment. No restore exists in uninstall or anywhere else (grep-verified).

### BUG-017 — fail2ban: two jails are dead, one bans legitimate proxy users
- **Where:** `antiddos/30-fail2ban.sh:54,91-110`; 3proxy log format at `3proxy/40-install.sh:106`
- **Evidence:** portscan failregex needs `[UFW BLOCK]` or the literal word `iptables` in kernel logs — the stack installs no LOG rules for scans and doesn't use UFW → can never fire. `http-flood` failregex is Apache combined-log format pointed at 3proxy's log (format `L date time user client remote …`) → never matches. `3proxy-ddos`'s second regex matches *any* log line containing host:port, including successful connections (ignores the `%E` error field) → a legit user with >100 connections/min earns a 24 h all-ports ban for using the proxy.
- **Suspect (related):** on servers without nginx/apache, http-flood's other logpaths don't exist and the jail errors at fail2ban start.

### BUG-018 — Network-facing proxy runs as root with no systemd sandboxing
- **Where:** `3proxy/40-install.sh:131-142` (`User=root`, no `NoNewPrivileges`/`ProtectSystem`/`PrivateTmp`/capability bounds; `LimitNPROC` is ignored for root)
- **Impact:** Any 3proxy vulnerability = instant root. Root is only ever needed to bind ports <1024, yet applies to any user-chosen port.

### BUG-019 — No `iptables --wait` anywhere; daemon records bans that failed to apply [T4/T6]
- **Where:** grep-verified zero `-w/--wait` in antiddos+autoban; `autoban/20-enforce.sh:50`, `autoban/40-subnet.sh` (insert `|| true`, then unconditionally append to BANNED_LIST)
- **Impact:** Under xtables lock contention (fail2ban + daemon + admin concurrently), inserts fail with "Resource temporarily unavailable"; the state file still records the ban and the skip-check prevents any retry until expiry → attacker unblocked while every view shows them banned. Mirror failure in `antiddos.sh` (runs under `set -e`): a failed insert can abort install mid-apply, leaving a half-written ruleset and no state file.

### BUG-020 — Exemption checks are O(753) subshell forks per IP per cycle; timing math assumes they are free
- **Where:** `autoban/10-ip-utils.sh:18,20,27` (`is_cf_ip` loops ≤753 ranges, `ip_in_cidr` spawns 2 `$(ip_to_int)` per range; `is_self_ip` forks `ip`/`hostname` pipelines per check); `update_score` is passed a hard-coded `dt = SAMPLE_INTERVAL` (`autoban/50-main-loop.sh:64`) while the persisted REP_TS is never used
- **Impact:** With ~100 hot IPs a 2 s cycle can take tens of seconds; churn rate `Δconns/2` is systematically overestimated exactly during real attacks (and after any restart), so reputation collapses early for borderline-legit heavy users.

### BUG-021 — tc filter priorities collide; deleting one IP's throttle can delete another's [T4]
- **Where:** `autoban/20-enforce.sh:11` (prio = 10000 + *current line count* of THROTTLE_LIST), `:34` (prio = 20000 + `RANDOM % 4000`); deletes by bare prio in enforce + auto-release paths
- **Impact:** Line-count prios are reused after any removal; random prios collide outright. `tc filter del … prio N` deletes *all* filters at that prio → releasing IP A un-throttles IP B, whose THROTTLE_LIST entry remains and whose grep-guard then prevents re-adding. (Compounds BUG-001.)

### BUG-022 — Rebuilding the tc qdisc silently wipes all throttle filters; the daemon never notices
- **Where:** `antiddos/50-tc.sh:11` (`tc qdisc del … root` at the top of `setup_tc`), reached from any whitelist edit via `apply_tc_runtime` (`antiddos/70-whitelist-main.sh`)
- **Impact:** A routine whitelist change during an attack instantly releases every throttled IP; THROTTLE_LIST and the UI keep claiming they are throttled.

### BUG-023 — IPv6 is entirely unprotected and invisible to detection
- **Where:** grep-verified: no `ip6tables` anywhere; CF list IPv4-only; the daemon's sampler (`autoban/50-main-loop.sh:39-41`) extracts only IPv4 peers from `ss`
- **Impact:** On any dual-stack VPS (the provider default), services reachable over IPv6 bypass all five layers, and IPv6 attack traffic isn't even counted.

### BUG-024 — Throttle state is recorded before the tc command runs; "autoban-only" mode has no tc classes at all
- **Where:** `autoban/20-enforce.sh` (`throttle_ip` appends to THROTTLE_LIST, then `tc filter add … || true`); `antiddos.sh --autoban` runs `setup_autoban` alone, which never creates classes 1:30/1:40
- **Impact:** Every throttle in autoban-only mode fails silently and is never retried (grep guard); logs/status report IPs as throttled that are not. (Compounds BUG-001.)

---

## MEDIUM

### BUG-025 — Installer overwrites live modules in place; a mid-install failure leaves a version mix [T4]
- **Where:** `installer/preamble.sh:28` (`set -euo pipefail`) + heredoc writes; `installer/outro.sh:3-6`
- **Impact:** Re-running the installer to update writes each runtime script directly over the working copy. Disk-full/interrupt midway → some modules new, one truncated, rest old; no backup or rollback of the previous set.

### BUG-026 — "Install/Update" silently rotates proxy credentials
- **Where:** `3proxy/40-install.sh:93-94,98,174-177`
- **Impact:** Every install run generates a fresh random user/password and overwrites `users.cfg`/`install.info`. An operator changing only the port invalidates every deployed client's credentials with no warning and no recovery.

### BUG-027 — Missing Cloudflare data fails open everywhere [T8]
- **Where:** `src/lib/cloudflare-loader.sh` (body) and all its consumers
- **Impact:** If `/etc/antiddos/cloudflare-ipv4.list` is absent (e.g. `antiddos.sh` run standalone), one stderr warning is printed and everything proceeds with an empty CF whitelist: full ruleset installed, daemon treats CF IPs as ordinary. The central safety invariant has no hard guard.

### BUG-028 — fail2ban `ignoreip` omits the server's own IPs and the user whitelist
- **Where:** `antiddos/30-fail2ban.sh:73,85-95` (only `127.0.0.1/8 ::1` + CF ranges)
- **Impact:** The promised "whitelist = exempt from ALL limits" doesn't hold: a whitelisted admin IP can be banned 24 h by the sshd-aggressive jail (3 fails/30 s) or the 3proxy-ddos counter.

### BUG-029 — Whitelist input is never validated; a malformed CIDR can exempt the world in the daemon
- **Where:** `antiddos/70-whitelist-main.sh:69-72,84`; mask math at `autoban/10-ip-utils.sh:20`
- **Impact:** Raw input is appended unchecked. In the CLI path an invalid entry can abort `apply_iptables` mid-way under `set -e`; in the menu path the failure is hidden (`>/dev/null 2>&1 || true`) behind a "✓ Added". In the daemon, a mask like `/abc` reaches bash arithmetic as 0 → mask 0 → `ip_in_cidr` true for every IP → `is_exempt` exempts everything and banning stops (exact shift mechanics **suspect**, input path verified). Also: duplicate check is substring-based (`1.2.3.4` refused because `11.2.3.4` exists) while removal is exact-match after a substring pre-check → the UI can claim "Removed" for an entry still present.

### BUG-030 — Connection counting conflates states and directions
- **Where:** `autoban/50-main-loop.sh:39-41`
- **Impact:** Counts come from `ss -tn` peer addresses across all TCP states (TIME-WAIT/CLOSE-WAIT inflate churn-heavy legit clients toward 120/300) and both directions — the server's own *outbound* connections count against upstream peers, so a backend the server opens 300 connections to can be instant-banned, severing the server's own upstream. The `head -100` cap blinds detection beyond the 100 noisiest peers. (Impact size partially **suspect**; method verified.)

### BUG-031 — Anti-DDoS removal is materially incomplete; some of it deletes other software's rules [T2/T7]
- **Where:** `antiddos/60-status-remove.sh:96,100` (deletion driven by `iptables -L` text matching)
- **Impact:** Rules whose rendered form contains none of the MATCH_PAT tokens survive a "full removal": loopback ACCEPT, the ESTABLISHED ACCEPT (BUG-002), INVALID DROPs, flag-scan DROPs, fragment DROP, CONNLIMIT LOG, the SYN fallback pair (connlimit REJECT survival **suspect**, rendering-dependent). The raw-table loop's bare `ACCEPT` token can delete *other software's* raw PREROUTING ACCEPT rules. Files/services left behind: `tc-setup.sh`, `restore-rules.sh`, scores, logs, `rules.v4` + iptables-persistent (see BUG-012). And `rm sysctl file` + `sysctl --system` never resets the running kernel's conntrack/keepalive values, yet prints "Kernel hardening: removed".

### BUG-032 — `setup_tc` destroys foreign shaping and hard-caps every server at 1 Gbit/s
- **Where:** `antiddos/50-tc.sh:11,15-16`; same hardcoding in the generated boot script (`3proxy/10-tc.sh:97-98` vs live detection `:8-20`)
- **Impact:** The root qdisc is deleted unconditionally (any admin/CAKE/fq setup is destroyed, and re-destroyed at every boot by the persistence service). Classes are hard-coded 1gbit: a 10 Gbit server's egress is capped at 1 Gbit by installing "protection"; on a 100 Mbit uplink the tree makes thresholds meaningless. Live-vs-boot values differ (live uses detected link speed, boot script hardcodes 1gbit), and the boot script's self-IP scan drops the 172.16/12 exclusion. tc failures mid-sequence abort the antiddos install under `set -e` *after* the old qdisc was already deleted.

### BUG-033 — State-file rewrites race with other writers; unbans and bans are lost
- **Where:** `autoban/50-main-loop.sh:22`, `autoban/40-subnet.sh` (read-whole-file → rewrite), vs menu `sed -i` (`antiddos/70-whitelist-main.sh:188`) and `ban_ip` appends; no locking anywhere
- **Impact:** An admin unban landing between the daemon's read and rewrite is resurrected; a ban appended in that window is dropped from the file while its iptables rule remains → orphan rule the daemon will never expire (compounds BUG-004/BUG-038 mechanics).

### BUG-034 — Reputation never recovers for quiet IPs; score file grows forever
- **Where:** `autoban/30-reputation.sh`; `autoban/50-main-loop.sh:64`
- **Impact:** `update_score` runs only for IPs currently ≥120 conns, so recovery (+3/cycle) only happens while an IP stays hot. An IP parked in the SUSPECT band that goes quiet keeps its degraded score indefinitely and re-enters much closer to a ban weeks later. `reputation.dat` is never pruned — one line per unique IP ever scored, unbounded, and grep-scanned per IP per cycle (compounds BUG-020).

### BUG-035 — SSRF deny list has bypass gaps
- **Where:** `3proxy/40-install.sh:115-120`
- **Impact:** Denies 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 — but not `0.0.0.0/8` (Linux treats 0.x.x.x destinations as local → reaches localhost-bound services), 192.0.0.0/24, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4. No IPv6 deny entries at all (**suspect** reachability — depends on 3proxy's handling of `-e0.0.0.0`, which the config never pins down).

### BUG-036 — tc setup reports success unconditionally [T4/T6]
- **Where:** `3proxy/10-tc.sh:18-23,65,132-134`; caller `3proxy/40-install.sh:165-167` ignores return codes
- **Impact:** On a VM/container without HTB support every tc command fails and the install still prints "✓ tc bandwidth control configured" and "✓ tc persistence configured (reboot-safe)".

### BUG-037 — Proxy uninstall unbans every fail2ban prisoner on the box [T7]
- **Where:** `3proxy/50-uninstall.sh:98-102` (`fail2ban-client unban --all`)
- **Impact:** Removing the proxy releases IPs banned by *all* jails — SSH brute-forcers and anti-DDoS bans included.

### BUG-038 — Menu unban uses the typed IP as an unescaped, unanchored sed regex, then declares total success
- **Where:** `menu/50-antiddos-menu.sh:62-76`, `menu/40-security-services-system.sh:35-47`; antiddos-side twin at `antiddos/70-whitelist-main.sh:185-195` (also: its plain `-D` can't match the comment-carrying auto-ban rules at all — see T5 — so the rule stays while its bookkeeping is deleted → permanent invisible ban)
- **Impact:** Unbanning `1.2.3.4` also deletes `11.2.3.45`'s banned.list lines; a `/` in input breaks sed (swallowed); "unblocked (all layers)" prints even if every step failed.

### BUG-039 — Menu Block-IP accepts arbitrary unvalidated input, including `0.0.0.0/0`
- **Where:** `menu/40-security-services-system.sh:25-29`, `menu/10-proxy-menu.sh:139-145`
- **Impact:** Anything iptables parses is inserted at the top of INPUT with no validation, no self-IP guard, no confirmation — `0.0.0.0/0` drops all traffic including the operator's SSH. On malformed input, the error message wrongly says "No IP entered".

### BUG-040 — sysctl optimizer forces `ip_forward = 1` on every install
- **Where:** `sysctl/10-detect.sh:83`
- **Impact:** A SOCKS5 proxy doesn't need kernel forwarding; enabling it (v4 + v6) on every "hardened" server widens the network posture and contradicts the hardening goal. Combined with BUG-009, the IPv6 bit is never rolled back.

### BUG-041 — Dashboard/monitor numbers are wrong in at least four independent ways
- **Where:** `menu/30-monitor-dashboard.sh:19-22,82-88` (`grep -c "BANNED:"` also matches `UNBANNED:` → every expiry double-counts as a ban); `:139-145` (greps `fail2ban-client status` for `Currently banned:` which only exists per-jail → always 0); `menu/20-sysctl-monitor-menus.sh:47-53` ("Top 20 source IPs" prints field $5 of the 3proxy log = the *destination* host, not the client at $4); `menu/40-security-services-system.sh:14-19` (per-jail "IP count" extracts `\d+$` from the "Banned IP list:" line = last octet of the last banned IP)
- **Suspect (5th):** `menu/30-monitor-dashboard.sh:96-99` sums column $8 of `/proc/net/stat/synproxy` (only 6 counters exist, printed in hex) → SYNPROXY hits always 0.

### BUG-042 — "Analyze (no changes)" and `--status` load kernel modules
- **Where:** `sysctl/10-detect.sh:40-48` (`modprobe tcp_bbr`, `modprobe nf_conntrack`), called from every path incl. `sysctl/40-status-main.sh:75-78`
- **Impact:** Read-only paths mutate system state — on a server where the admin deliberately avoids conntrack (a common anti-DDoS stance), merely viewing status loads it.

### BUG-043 — `draw_header` makes a live external HTTP call on every menu render
- **Where:** `menu/00-header.sh:46-50,58-75`
- **Impact:** `curl --max-time 4 https://api.ipify.org` runs on every navigation in every submenu, with no caching. On an offline/egress-filtered server — or during the very DDoS the tool defends against — every screen stalls up to 4 s.

### BUG-044 — System → Update prints "Update complete" even when the update failed
- **Where:** `menu/40-security-services-system.sh:152-158`
- **Impact:** `apt-get … || yum update -y` chain: any apt failure triggers the yum fallback on a Debian box; the success message is unconditional. Same RHEL dead-branch pattern in the 3proxy installer (`yum` for deps, then unconditional `apt-get install 3proxy`, which always fails there and degrades to BUG-006's path).

### BUG-045 — Unbounded log growth in the anti-DDoS components
- **Where:** `autoban/10-ip-utils.sh` `log()` → `/var/log/auto-ban.log`; `/var/log/antiddos.log`
- **Impact:** Neither component installs a logrotate fragment (only the 3proxy module does). Under a long attack the logs (plus journal duplicates) grow unbounded on the root filesystem.

### BUG-046 — UDP amplification rule doesn't cover the ports its success message claims
- **Where:** `antiddos/20-iptables.sh:132` (ports 19 111 137 161 1900 5353 11211) vs its own message "UDP Amplification (DNS/NTP/SSDP/memcached): blocked"
- **Impact:** Neither 53 (DNS) nor 123 (NTP) is in the list; reflection traffic by source port is only covered by the general UDP hashlimit, not blocked as claimed.

### BUG-047 — Per-IP proxy connection limit is probably not enforced by 3proxy itself [suspect]
- **Where:** `3proxy/40-install.sh:112-123` (`maxconn` is global; the generated config contains no `connlim` statement — grep-verified; `socks … -n$MAX_CONN` passes a number to a flag that takes no documented numeric argument)
- **Impact:** The prompted "Max connections per IP" likely survives only via the iptables `recent` rules (see BUG-013/014 for their lifecycle). If those rules are flushed while 3proxy keeps running, the per-IP cap is silently gone.

### BUG-048 — Appended proxy ACCEPTs can land behind existing DROP rules [suspect]
- **Where:** `3proxy/20-iptables.sh:28,35,48` (`-A` appends; only stats counters use `-I`)
- **Impact:** With the Anti-DDoS layer installed first, appended CF/self ACCEPTs can sit below earlier DROP/limit rules for the same chain, so legitimate proxy traffic is dropped before reaching them — while install reports success.

---

## LOW

- **BUG-049 — Predictable fallback secrets.** If urandom extraction fails, the proxy password falls back to `proxy$(date +%s)` and the username to the constant `proxyuser`, with no warning (`3proxy/40-install.sh:93-94`; pattern repeated in the change-pass path `3proxy/60-cli-menu.sh:98`, and in the menu's dead copy — BUG-053). Fail instead of falling back.
- **BUG-050 — Wrong thresholds printed after autoban setup.** `antiddos/40-autoban-setup.sh:43` prints `watch:${CONN_THRESHOLD:-80}` / `ban:${BAN_CONN_THRESHOLD:-200}`, but those variables live only inside the daemon; the message always says 80/200 while the real thresholds are 120/300.
- **BUG-051 — Dead duplicate implementations in the menu have drifted.** `menu/10-proxy-menu.sh:50-101` (`_proxy_stats`, `_proxy_change_pass`) have zero callers (menu delegates to the 3proxy script), yet carry latent bugs: unvalidated password into `sed s/^PASS=…/` (`/` breaks it, `&` corrupts it) and into the `users` line (a space breaks the token format); its stats copy labels the unban-inflated all-time count "Auto-bans today". Fixes (e.g. the v3.4.12 stats fixes) land in only one copy.
- **BUG-052 — Backup claims success on partial archives and bundles plaintext credentials.** `menu/40-security-services-system.sh:176-185`: `tar … 2>/dev/null || true` then unconditional "Backup saved"; the archive contains `/etc/3proxy/` (cleartext SOCKS password in `users.cfg` + `install.info`) with default permissions and no warning.
- **BUG-053 — Installed/optimized state is detected purely by file existence** (`menu/20-sysctl-monitor-menus.sh:6-11`, `menu/60-autoban-main.sh:62-64`, `sysctl/40-status-main.sh:10-11`): after a partially-failed install (BUG-007) the UI still reports "✓ Optimized / ● Active"; Monitoring infers "auto-ban not running" from log-file existence, which persists after the service stops.
- **BUG-054 — sysctl install lock is a check-then-write race** (`sysctl/00-header.sh:23-27`): two simultaneous runs can both pass; a stale lock whose PID was recycled by an unrelated process wedges every future run with "Already running" (**suspect**).
- **BUG-055 — `bc` dependency reintroduced in sysctl status** (`sysctl/40-status-main.sh:40-42`): the proposed `rmem_max` is rendered via `bc` without the fallback its neighbour has — on `bc`-less systems (the exact case v3.4.12 fixed elsewhere) Analyze shows `-> MB` (empty).
- **BUG-056 — Cosmetic counters always print ", 0 skipped" / ", 0 failed"** (`sysctl/30-apply-rollback.sh:25,173`; twin at `antiddos/10-sysctl.sh:147`): `${VAR:+, …}` expands for the non-empty string `"0"`.
- **BUG-057 — Proxy password stored in cleartext `CL` form in two files** (`3proxy/40-install.sh:98,174-183`): both chmod 600 (mitigating), but 3proxy supports hashed entries; any root-level file disclosure yields a working credential.
- **BUG-058 — Installer clobbers any existing `/usr/local/bin/proxy`** (`installer/outro.sh:11`): `ln -sf` with no existence check or backup; `proxy` is a generic name other tools use.
- **BUG-059 — An IPv6 connection URL is advertised for an IPv4-only listener** (`3proxy/40-install.sh:123,210`; `3proxy/60-cli-menu.sh:14`): nothing listens on IPv6, so the printed `socks5://…@[v6]:port` can never connect.
- **BUG-060 — `pkill -f "auto-ban.sh"` in proxy uninstall can kill unrelated processes** (`3proxy/50-uninstall.sh:18`): full-cmdline matching hits editors/viewers/monitoring wrappers mentioning the path.
- **BUG-061 — Port search gives up silently after 20 tries** (`3proxy/40-install.sh:73-78`): with 1080–1100 occupied, install proceeds to write config/firewall/tc for a port that is still occupied and only fails at the final service check — a half-applied install.
- **BUG-062 — `apply_tc_runtime`'s interface argument is dead** (`antiddos/70-whitelist-main.sh` vs `antiddos/50-tc.sh`): the caller passes `"$IF"`, `setup_tc` takes no parameters and uses the global `$MAIN_IF`. Harmless today (both derive from the default route), confusing forever.
- **BUG-063 — Re-running with a different RAM tier leaves the old rate rules in force** (**suspect** severity): `apply_iptables` idempotency is exact-spec `-C`; a new tier's hashlimit/connlimit rules are appended *alongside* the old ones under the same `--hashlimit-name`, and the earlier rule decides first — raising a limit never takes effect until manual cleanup.
- **BUG-064 — FORWARD chain is essentially unprotected** (design gap): only the INVALID drop is installed there (`antiddos/20-iptables.sh` Step 1); all whitelist/rate logic is INPUT-only, so a box acting as router/tunnel gateway gets no forwarded-traffic protection despite box-wide marketing.
- **BUG-065 — `ban_subnet`'s own-subnet guard checks only the first local IP** (`autoban/40-subnet.sh:10`, `head -1`): on multi-IP servers the /24 of every other local address is unguarded — a subnet ban can drop the datacenter /24 containing the server's secondary IP, gateway or resolver.
- **BUG-066 — Aggressive unscaled kernel values presented as universally "optimal"** (**suspect**): `sysctl/20-snapshot-config.sh:94-96,109,112` — keepalive 30 s/10 s/5 (~80 s dead-peer detection), `tcp_fin_timeout = 10`, `tcp_max_tw_buckets = 1440000`, `tcp_ecn = 1`, identical on a 512 MB VPS and a 64 GB host; a behavioural change long-lived idle tunnels may not expect from an "optimizer".
- **BUG-067 — Services menu "only installed services" detection likely matches everything** (**suspect**): `menu/40-security-services-system.sh:101-110` relies on `systemctl list-unit-files <pattern>` exit code, which is 0 with "0 unit files listed" on many systemd versions → phantom services listed. Not reproducible in the audit sandbox (no systemd as PID 1).
- **BUG-068 — systemd `Type=simple` may not match 3proxy's daemonization** (**suspect**): `3proxy/40-install.sh:127-142` assumes a foreground main process (`ExecReload=kill -HUP $MAINPID`, `Restart=always`) while the generated config has no `daemon`/`service` directive; if the build self-daemonizes, supervision/reload semantics degrade (incl. duplicate instances). Needs a live-install check.

---

## Maintainer's field reports

Reported by Mahan from production experience, 2026-10-23. Cross-checked
against the audit registry — all three map to verified audit findings,
which raises their priority in the fix plan (docs/FIX-PLAN.md).

### FR-1 — Whitelisting an arbitrary admin IP must exempt it from EVERYTHING
- **Requirement:** an admin must be able to whitelist any IP, and
  "whitelisted" must mean exempt in every layer, no exceptions.
- **Current state (verified by census):** the whitelist IS consulted by
  iptables INPUT (`user_whitelist` ACCEPT), the raw/SYNPROXY table, tc
  (nominally — broken by BUG-001), and the auto-ban daemon's `is_exempt`.
  It is **NOT** consulted by: fail2ban `ignoreip` (BUG-028), the 3proxy
  per-port rate-limit rules (no whitelist step in
  `3proxy/20-iptables.sh`), or the menus' manual Block-IP flows
  (BUG-039). Input validation is missing (BUG-029).
- **Maps to:** BUG-028, BUG-029, BUG-039, BUG-001 (tc leg).

### FR-2 — The server's own IPs must never be blocked, under any circumstance
- **Requirement:** a hard guarantee, not a best effort, across every
  blocking mechanism (auto-ban, subnet ban, fail2ban, manual blocks,
  rate-limit DROPs).
- **Current state (verified):** self IPs are whitelisted in iptables and
  in the daemon's `is_exempt`, but fail2ban `ignoreip` omits them
  (BUG-028), the subnet-ban self-guard checks only the *first* local IP
  (BUG-065), and manual Block-IP has no self guard at all (BUG-039).
  There is no watchdog that would detect/remove a self-block if one
  ever slipped through.
- **Maps to:** BUG-028, BUG-065, BUG-039.

### FR-3 — After an unban, reputation does not recover; the IP re-blocks on the smallest trigger and effectively stays blocked
- **Requirement:** the reputation lifecycle after a ban must be redesigned
  properly: serving a ban must have a defined, fair effect on score, and
  a released IP must be able to earn its way back to normal.
- **Current state (verified by call-site census):** post-ban score
  handling is inconsistent *by ban path*. The reputation path clears the
  score when it bans (`autoban/30-reputation.sh:92`); the classic
  watch→throttle→ban paths (`autoban/50-main-loop.sh:71,88`) never touch
  the score; `unban_expired` never touches the score; and
  `update_score` only runs for IPs currently ≥120 connections, so no
  recovery is possible while quiet or while banned (BUG-034). Net
  effect matches the field report exactly: an IP unbanned with a stale
  low score re-crosses the ban band on a trivial spike, and the cycle
  repeats — a de-facto permanent ban.
- **Maps to:** BUG-034, BUG-020 (dt distortion accelerates the fall),
  BUG-003 (substring state corruption can worsen it).

---

## Audit notes

- Findings marked ✔verified were independently re-read at the cited lines
  after the review passes (BUG-001, 002, 003, 004, 005, 007, 008-flush,
  013).
- The four antiddos/autoban Criticals reinforce each other: BUG-001 means
  throttling never works even when state tracking is right; BUG-002 means
  two advertised iptables layers never fire; BUG-003 corrupts the state
  all other logic trusts; BUG-004 makes every ban evaporate on reboot
  while the UI keeps counting it.
- No code was changed by this audit. This file is the only artifact.
