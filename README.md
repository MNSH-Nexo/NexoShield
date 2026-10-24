<div align="center">

<img src="logo.png" width="120" alt="NexoShield Logo" />

# NexoShield

**Professional Server Hardening & Anti-DDoS Toolkit**

*Secure any Ubuntu server in minutes — with optional SOCKS5 proxy management*

<img src="https://img.shields.io/badge/Platform-Ubuntu%2020%2B-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Platform"/>
<img src="https://img.shields.io/badge/Shell-Bash%205%2B-4EAA25?style=flat-square&logo=gnubash&logoColor=white" alt="Shell"/>
<img src="https://img.shields.io/badge/Version-3.11.0-7c3aed?style=flat-square" alt="Version"/>
<img src="https://img.shields.io/badge/License-MIT-1a73e8?style=flat-square" alt="License"/>

</div>

---

## What is NexoShield?

NexoShield is a single-script toolkit that transforms a bare Ubuntu server into a hardened, DDoS-resistant machine in under 5 minutes.

Its detection engine measures **real connection events** (conntrack/netlink), scores every source IP with an interpretable reputation model, and escalates **watch → throttle → progressive ban** — while Cloudflare ranges, the server's own IPs and your whitelist are *guaranteed* exempt at every layer.

You can use it purely for **server security** — or also enable the built-in **SOCKS5 proxy manager** if needed.

---

## Credits & Contributors

<div align="center">

با صمیمانه‌ترین تقدیر و سپاس از **Xarheon** و **AssA7778** که با زمان، حوصله و دانش خود در توسعه و بهبود NexoShield سهیم بودند. همراهی ارزشمند شما برای این پروژه مایه‌ی دلگرمی است — بی‌نهایت سپاسگزاریم.

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/Xarheon">
        <img src="https://github.com/Xarheon.png?size=120" width="120" height="120" alt="Xarheon" />
        <br />
        <sub><b>Xarheon</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/AssA7778">
        <img src="https://github.com/AssA7778.png?size=120" width="120" height="120" alt="AssA7778" />
        <br />
        <sub><b>AssA7778</b></sub>
      </a>
    </td>
  </tr>
</table>

</div>

---

## امکانات

**حفاظت و تشخیص**

- 🛡 **۵ لایه حفاظت DDoS** — kernel hardening، iptables، fail2ban، smart auto-ban و tc — به‌علاوه‌ی یک **سپر اضطراری XDP** که فقط زیر فشار واقعی حمله فعال می‌شه
- 🧠 **موتور امتیازدهی Reputation** — هر IP از ۱۰۰ شروع می‌کنه؛ رفتار مشکوک امتیاز کم می‌کنه و باندها تعیین می‌کنن: watch ← throttle ‏۱۰۰M‏ ← throttle ‏۵۰M‏ ← ban
- 📡 **اندازه‌گیری رویدادمحور (nxcountd)** — شمارنده‌ی C روی رویدادهای conntrack/netlink: نرخ ورود واقعی، نسبت تکمیل handshake و رفتار اتصال‌ها — نه حدس از روی snapshot
- 📈 **تشخیص تجمعی CUSUM** — حمله‌های پالسی و ramp آهسته که زیر رادار آستانه‌های لحظه‌ای می‌مونن، در طول زمان لو می‌رن
- 🎚 **آستانه‌های تطبیقی** — baseline ترافیک خود سرور (EWMA)؛ در وضعیت حمله گیت‌ها خودکار سخت‌گیرانه‌تر می‌شن و baseline فریز می‌مونه
- 🚦 **Stress Gate** — روی سرورِ بدون فشار، تخلف اولِ مرزی به‌جای ban فقط throttle می‌شه؛ ban برای فشار واقعی و تکرار تخلفه
- ⏱ **Ban پلکانی (Progressive)** — از ۳۰ دقیقه شروع و با هر تکرار دوبرابر تا سقف ۷ روز؛ سابقه‌ی تخلف بعد از ۷ روز پاک می‌شه
- 🐌 **تشخیص حمله‌ی آهسته** — اتصال‌های پیر و کم‌حجم (Slowloris و مشابه) با ترکیب سن اتصال، بایت/اتصال و هم‌زمانی شناسایی می‌شن
- 🚫 **تشخیص Subnet botnet** — حمله‌ی توزیع‌شده از یک /24، با guardrail ضد CGNAT (حداقل ۵ IP مهاجم متمایز)
- 🗄 **بک‌اند nftables timed-set** برای banها (انقضای داخل کرنل) با fallback خودکار به iptables
- ⚙️ **کاملاً قابل تنظیم** — همه‌ی ثابت‌های امتیازدهی در `/etc/antiddos/scoring.conf` بدون نیاز به ویرایش کد

**معافیت تضمینی**

- ☁️ **753 رنج رسمی Cloudflare** + همه‌ی IPهای خود سرور + whitelist شما — در **تمام** لایه‌ها exempt، بدون استثنا
- 🌐 **کشف خودکار IP عمومی پشت NAT/ابر** (Azure/AWS/GCP/DO/Hetzner) تا سرور پشت NAT هم خودش رو ban نکنه
- ✅ دستور `--exempt-check` برای راستی‌آزمایی معافیت هر IP در هر لحظه

**مدیریت و مانیتورینگ**

- 🖥 **داشبورد زنده** با دستور `shield` — وضعیت banها، throttleها، پایین‌ترین امتیازها و آخرین رویدادها در صفحه‌ی اصلی
- 📊 **مانیتورینگ کامل** — داشبورد تهدید real-time، کانکشن‌ها، CPU/RAM، دیسک، لاگ‌ها و top IPها
- 🛠 **SOCKS5 Proxy Manager** اختیاری (3proxy) — نصب، تغییر پسورد، **حذف کامل یوزر/پسورد**، آمار ترافیک و لاگ زنده
- 🔄 **Snapshot و Rollback** برای تنظیمات kernel
- ⚡ **نصب و آپگرید در کمتر از ۵ دقیقه** — فقط با یک دستور؛ آپگرید اعتبارهای پروکسی رو نگه می‌داره

---

## نصب آسان

**یک دستور — همه چیز آماده:**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MNSH-Nexo/NexoShield/master/install.sh)
```

> نیازی به clone یا دانلود جداگانه نیست. فقط این دستور رو روی سرور Ubuntu اجرا کن.

**بعد از نصب، با این دستور اجرا کن:**

```bash
shield
```

> **آپگرید:** کافیه همین دستور نصب رو دوباره اجرا کنی — نسخه‌ی جدید جایگزین می‌شه، یوزر/پسورد پروکسی و تنظیماتت حفظ می‌شن و لینک قدیمی `proxy` به‌صورت خودکار به `shield` مهاجرت می‌کنه.

**پیش‌نیاز**

- Ubuntu 20.04 / 22.04 / 24.04
- دسترسی root
- اتصال اینترنت

---

## لایه‌های حفاظتی

NexoShield از **۵ لایه موازی** برای محافظت استفاده می‌کنه:

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1 │ Kernel Hardening   SYN cookies, tight TCP timeouts │
│  Layer 2 │ iptables Rules     CF whitelist → rate limits      │
│  Layer 3 │ fail2ban           Auto-ban repeated attackers     │
│  Layer 4 │ Smart Auto-Ban     Watch → Throttle → Ban pipeline │
│  Layer 5 │ tc Bandwidth       CF=unlimited, others=500Mbps    │
└──────────────────────────────────────────────────────────────┘
```

> **لایه‌ی ششم (خفته):** وقتی فشار SYN از آستانه‌ی بحرانی رد بشه (رشد شدید syncookie/overflow یا موج SYN)، یک برنامه‌ی **XDP** در سطح درایور شبکه attach می‌شه و SYNهای IPهای ban‌شده رو قبل از stack کرنل drop می‌کنه — exemptها همیشه اول چک می‌شن. با آرام شدن اوضاع، خودش detach می‌شه.

**جزئیات حفاظت**

| حمله | روش مقابله | وضعیت |
|------|-----------|--------|
| SYN Flood (direct) | SYNPROXY kernel-level + completion-ratio detection | Active |
| SYN Flood (spoofed IP) | Global rate cap + nxcountd event counting | Active |
| Slowloris / Conn-Hold | تشخیص رفتاری (سن/حجم اتصال) + connlimit + fail2ban | Active |
| Pulse / slow-ramp floods | CUSUM accumulators | Active |
| HTTP Burst (pipeline) | hashlimit + fail2ban 200req/30s | Active |
| Botnet distributed (/24) | Subnet aggregate tracking (+ CGNAT guardrail) | Active |
| UDP Flood | hashlimit per-IP | Active |
| UDP Amplification | chargen/DNS/rpcbind/NetBIOS/NTP/SNMP/SSDP/memcached/mDNS blocked | Active |
| ICMP Flood | rate-limited per-IP | Active |
| Port Scan | NULL/XMAS/FIN/bogus flags DROP | Active |
| SSH Brute Force | fail2ban (3 tries → 24h ban) | Active |
| IP Spoofing | rp_filter + SYNPROXY | Active |

---

## موتور تشخیص و امتیازدهی (DPI)

قلب NexoShield یه مدل امتیازدهی **قابل تفسیر**ـه — نه black box. هر IP از **۱۰۰** شروع می‌کنه و بر اساس سیگنال‌های اندازه‌گیری‌شده امتیاز از دست می‌ده (حداکثر ‎۴۵ امتیاز در دقیقه‎):

| سیگنال | چی رو می‌سنجه |
|--------|---------------|
| Churn (EWMA) | نرخ جابه‌جایی اتصال‌ها — باز و بسته کردن سریع و مداوم |
| Sustained | حجم اتصال هم‌زمانِ پایدار بالای گیت |
| Handshake completion | نسبت SYNهایی که واقعاً به اتصال کامل می‌رسن — امضای SYN flood |
| CUSUM ×2 | انباشت تدریجی ورود بیش‌ازحد و handshakeهای ناقص در طول زمان |
| Slow-attack | اتصال‌های پیر (≥۱۲۰ ثانیه) و کم‌حجم با هم‌زمانی بالا |

**باندهای تصمیم:** ‎۸۰‎ watch ‏← ‏‎۶۰‎ throttle ‏۱۰۰M‏‎‎ ‏← ‏‎۴۰‎ throttle ‏۵۰M‏‎‎ ‏← ‏‎۲۰‎ ban‎‎.

بعد از هر ban، IP وارد **probation** می‌شه: با امتیاز ۵۰ برمی‌گرده و برای مدت متناسب با ban واقعیش، افت امتیازش دوبرابره — نه امتیاز سوخته‌ی قدیم که فوراً دوباره banش کنه، نه بخشش کامل. امتیاز با سکوت و رفتار خوب، خودکار ترمیم می‌شه.

در وضعیت **ATTACK** (انحراف معنادار از baseline)، گیت اتصال ‎۴۰٪‎ پایین میاد و زمان observe نصف می‌شه؛ روی سرور آرام، **Stress Gate** جلوی ban عجولانه رو می‌گیره.

📖 جزئیات کامل مدل: [docs/SCORING.md](docs/SCORING.md) — نقشه‌ی ارتقای موتور: [docs/DPI-UPGRADE-PLAN.md](docs/DPI-UPGRADE-PLAN.md)

---

## معافیت تضمینی (Exemption Guarantee)

سه دسته، در **همه‌ی** لایه‌ها (iptables، nftables، tc، fail2ban، auto-ban و حتی XDP) بدون استثنا exempt هستن:

- **Cloudflare** — هر 753 رنج رسمی v4 + رنج‌های v6
- **IPهای خود سرور** — همه‌ی آدرس‌های interfaceها + IP عمومی کشف‌شده از متادیتای ابر/سرویس‌های echo برای سرورهای پشت NAT
- **Whitelist شما** — هر IP/CIDRی که خودت اضافه کنی

این تضمین با تست‌های اختصاصی پوشش داده شده (`test-exemption-guarantee` و `test-exemption-surfaces`) و هر وقت خواستی می‌تونی برای هر IP راستی‌آزمایی کنی:

```bash
/opt/proxy-manager/antiddos.sh --exempt-check 1.2.3.4
```

📖 گزارش ممیزی معافیت: [docs/EXEMPTION-AUDIT-2026-10-24.md](docs/EXEMPTION-AUDIT-2026-10-24.md)

---

## Cloudflare Integration

NexoShield دارای **753 رنج IP رسمی Cloudflare** است که در **تمام لایه‌ها** whitelist شده‌اند:

- هیچ rate-limit، connlimit یا hashlimit روی CF IPs اعمال نمی‌شه
- کاربرانی که از پشت Cloudflare وصل می‌شن هیچ‌وقت ban نمی‌شن
- CF IPs در iptables، fail2ban، tc و auto-ban همه exempt هستن

---

## منوی اصلی (shield)

صفحه‌ی اصلی یه **داشبورد زنده**ست: تعداد ban و throttleهای فعال، اندازه‌ی whitelist، سه IP با پایین‌ترین امتیاز و آخرین رویدادهای auto-ban — بالای ۷ بخش اصلی:

```
════════════════════════════════════════════════════
  NexoShield v3.11.0 — Server Security Toolkit
════════════════════════════════════════════════════
  1.  SOCKS5 Proxy        ● Running
  2.  Network Optimization ● Optimized
  3.  Anti-DDoS           ● Active
  4.  Monitoring
  5.  Security
  6.  Services
  7.  System
  0.  Exit
════════════════════════════════════════════════════
```

**SOCKS5 Proxy** — نصب/آپدیت 3proxy با یوزرنیم/پسورد تصادفی، start/stop/restart، لاگ زنده، آمار ترافیک، تغییر پسورد، **حذف یوزر و پسورد** (پروکسی بدون احراز هویت — با تأیید و هشدار صریح) و فهرست IPهای مشکوک

**Network Optimization** — بهینه‌سازی sysctl (BBR و تنظیمات TCP متناسب با سخت‌افزار) با snapshot و rollback

**Anti-DDoS** — نصب هر ۵ لایه، وضعیت و banهای فعال، unban، کنترل auto-ban (start/stop/log/flush) و حذف کامل حفاظت

**Monitoring** — داشبورد تهدید real-time (حمله‌ها، banهای اخیر، پهنای باند، سلامت سیستم)، کانکشن‌ها، CPU & RAM، دیسک، لاگ‌ها (3proxy/fail2ban/SSH/سیستم/auto-ban)، لاگ auto-ban و top IPها از لاگ پروکسی

**Security** — همه‌ی IPهای block‌شده (fail2ban + auto-ban)، block/unblock دستی با گارد معافیت، قوانین iptables، تلاش‌های SSH brute-force و وضعیت auto-ban

**Services** — مدیریت سرویس‌های نصب‌شده (start/stop/restart/status) — فقط سرویس‌هایی که واقعاً روی سیستم هستن

**System** — اطلاعات سرور، آپدیت سیستم، پاک‌سازی لاگ‌ها، reboot و بک‌آپ کانفیگ

**بدون منو هم می‌شه** — برای اسکریپت و مانیتورینگ خارجی:

```bash
shield --status    # وضعیت متنی سرویس‌ها و حفاظت
shield --bans      # banهای فعال با زمان شروع و انقضا
shield --version
```

---

## Smart Auto-Ban Pipeline

```
Connection events (nxcountd / conntrack-netlink)
        │
        ▼
  active conns ≥ 120/IP ────────────► WATCHING (observe 45s)
        │                                       │
        │                        still high after 45s?
        │                                       │
  active conns ≥ 300/IP ─► INSTANT BAN          ▼
                        (progressive)   THROTTLE 100 Mbps
                                                │
                                       still high after 45s?
                                                │
                                                ▼
                                            BAN (progressive)

  /24 subnet ≥ 400 total ──► WATCHING subnet
  /24 subnet ≥ 1000 (≥5 distinct IPs) ──► BAN /24 for 60 min

  Reputation:  100 → <80 watch → <60 throttle 100M → <40 throttle 50M
               → <20 ban
  Ban length:  30 min, doubling per repeat offence → cap 7 days
               (strikes forgotten after 7 clean days)
  Probation:   every ban ends in probation — return at score 50,
               doubled drops for the real ban duration
  Stress gate: first borderline offence on a calm host throttles
               instead of banning; bans are for real pressure
  Adaptive:    during ATTACK state the conn gate drops 40% and
               the observe window halves
```

---

## Thresholds — auto-scaled by RAM

| پارامتر | RAM < 2GB | RAM 2–4GB | RAM > 4GB |
|---------|-----------|-----------|-----------|
| SYN limit/IP | 500/s | 1000/s | 2000/s |
| New conn/IP | 50/s | 100/s | 200/s |
| Max conn/IP | 50 | 100 | 200 |
| BW cap/IP | 50 Mbps | 100 Mbps | 200 Mbps |

> همه‌ی ثابت‌های موتور امتیازدهی (گیت‌ها، باندها، سقف افت، زمان‌های ban و probation و تریگرهای XDP) در `/etc/antiddos/scoring.conf` قابل تنظیمن — فایل موقع آپگرید دست نمی‌خوره و تغییراتش بدون restart خونده می‌شه.

---

## فایل‌های نصب شده

```
/usr/local/bin/shield              ← دستور اصلی
/opt/proxy-manager/                ← اسکریپت‌های ماژول‌ها (menu, antiddos, 3proxy, sysctl)
/etc/antiddos/                     ← state، لیست‌ها (ban/throttle/whitelist/exempt)
/etc/antiddos/scoring.conf         ← تنظیمات موتور امتیازدهی
/var/lib/antiddos/scores/          ← دیتابیس reputation آی‌پی‌ها
/run/nexoshield/counters.dat       ← خروجی زنده‌ی nxcountd (رویدادهای conntrack)
/etc/3proxy/                       ← تنظیمات SOCKS5 (اختیاری)
/var/log/auto-ban.log              ← لاگ ban/unban
/etc/sysctl.d/99-vpn-*.conf        ← kernel tweaks
systemd: auto-ban, nexoshield-countd
```

---

## کیفیت و تست

- ✅ **۳۳ سوئیت تست unit** — از ریاضی امتیازدهی و تضمین معافیت تا تست دودیِ سرتاسریِ همه‌ی بخش‌های منو
- ✅ گیت `make check` روی هر تغییر: ShellCheck + راستی‌آزمایی build از روی `src/`
- ✅ CI گیت‌هاب روی هر push و هر تگ اجرا می‌شه
- ✅ ممیزی امنیتی ۶۸ یافته‌ای (v3.5) و بازبینی‌های میدانی روی سرورهای واقعی Debian/Ubuntu — [docs/BUGS.md](docs/BUGS.md)

---

## سازگاری

| سیستم | وضعیت |
|-------|--------|
| Ubuntu 20.04 LTS | Full support |
| Ubuntu 22.04 LTS | Full support |
| Ubuntu 24.04 LTS | Full support |
| KVM / VMware | Full support |
| LXC Container | Supported (no SYNPROXY) |
| OpenVZ | Limited |

---

## توسعه‌دهندگان

کد منبع به‌صورت ماژولار در پوشه‌ی `src/` نگهداری می‌شه و `install.sh` از روی اون ساخته می‌شه — برای مشارکت، راهنمای [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) رو ببین.

---

## License

MIT License — آزادانه استفاده، تغییر و توزیع کن.

---

## Credits

<a href="https://happyseeds.ai">
  <img src="happyseeds.png" width="64" alt="HappySeeds AI" />
</a>

Built with the assistance of [HappySeeds AI](https://happyseeds.ai)

**TARS** 🤖 — AI engineering partner to Mahan: architect of the v3.5 → v3.11 rebuild — modular refactor, the 68-finding security audit, scoring engine v2 and the DPI upgrade (event measurement, CUSUM, adaptive gates, XDP shield), the exemption guarantee, field testing and releases.

---

<div align="center">

Made with care by [MNSH-Nexo](https://github.com/MNSH-Nexo)

</div>
