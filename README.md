<div align="center">

<img src="logo.png" width="120" alt="NexoShield Logo" />

# NexoShield

**Professional Server Hardening & Anti-DDoS Toolkit**

*Secure any Ubuntu server in minutes — with optional SOCKS5 proxy management*

<img src="https://img.shields.io/badge/Platform-Ubuntu%2020%2B-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Platform"/>
<img src="https://img.shields.io/badge/Shell-Bash%205%2B-4EAA25?style=flat-square&logo=gnubash&logoColor=white" alt="Shell"/>
<img src="https://img.shields.io/badge/Version-3.15.0-7c3aed?style=flat-square" alt="Version"/>
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

<div dir="rtl">

## امکانات

### حفاظت و تشخیص

- **۵ لایه‌ی حفاظت DDoS** — سخت‌سازی کرنل، قوانین iptables، سرویس fail2ban، موتور Smart Auto-Ban و مدیریت پهنای باند با tc؛ به‌همراه یک **سپر اضطراری XDP** که فقط زیر فشار واقعی حمله فعال می‌شود.
- **موتور امتیازدهی Reputation** — هر IP با امتیاز ۱۰۰ شروع می‌کند؛ رفتار مشکوک امتیاز می‌کاهد و باندهای امتیاز، واکنش سیستم را تعیین می‌کنند.
- **اندازه‌گیری رویدادمحور با nxcountd** — شمارنده‌ی C روی رویدادهای conntrack/netlink: نرخ واقعی ورود اتصال، نسبت تکمیل handshake و رفتار اتصال‌ها، به‌جای حدس از روی snapshot.
- **تشخیص تجمعی CUSUM** — حمله‌های پالسی و شیب‌دارِ آهسته که زیر آستانه‌های لحظه‌ای پنهان می‌مانند، در طول زمان شناسایی می‌شوند.
- **آستانه‌های تطبیقی** — خط مبنای ترافیک عادی سرور با EWMA آموخته می‌شود؛ در وضعیت حمله، گیت‌ها به‌صورت خودکار سخت‌گیرانه‌تر می‌شوند و خط مبنا فریز می‌ماند.
- **گیت فشار (Stress Gate)** — روی سرورِ بدون فشار، اولین تخلفِ مرزی به‌جای ban فقط throttle می‌شود؛ ban برای فشار واقعی و تکرار تخلف است.
- **Ban پلکانی** — از ۳۰ دقیقه آغاز می‌شود و با هر تکرار دوبرابر تا سقف ۷ روز؛ سابقه‌ی تخلف پس از ۷ روز رفتار پاک فراموش می‌شود.
- **تشخیص حمله‌ی آهسته** — اتصال‌های پیر و کم‌حجم (مانند Slowloris) با ترکیب سن اتصال، حجم بر اتصال و هم‌زمانی شناسایی می‌شوند.
- **تشخیص بات‌نت زیرشبکه‌ای** — حمله‌ی توزیع‌شده از یک /24، با محافظ ضد CGNAT (حداقل ۵ آی‌پی مهاجم متمایز).
- **بک‌اند nftables با timed set** — انقضای banها داخل کرنل انجام می‌شود و در نبود nftables، مسیر iptables به‌صورت خودکار جایگزین است.
- **قابل تنظیم بدون ویرایش کد** — تمام ثابت‌های موتور امتیازدهی در فایل `/etc/antiddos/scoring.conf` قرار دارند.

### معافیت تضمینی

- **753 رنج رسمی Cloudflare**، تمام آی‌پی‌های خود سرور و whitelist شما — در **همه‌ی لایه‌ها** معاف‌اند، بدون استثنا.
- **کشف خودکار آی‌پی عمومی پشت NAT و ابر** (Azure، ‏AWS، ‏GCP، ‏DigitalOcean و Hetzner) تا سرور هرگز خودش را ban نکند.
- **راستی‌آزمایی در هر لحظه** با دستور `--exempt-check` برای هر آی‌پی.

### مدیریت و مانیتورینگ

- **داشبورد زنده با دستور `shield`** — banها و throttleهای فعال، پایین‌ترین امتیازها و آخرین رویدادها در صفحه‌ی اصلی.
- **مانیتورینگ کامل** — داشبورد تهدید بلادرنگ، اتصال‌ها، پردازنده و حافظه، دیسک، لاگ‌ها و پرتکرارترین آی‌پی‌ها.
- **مدیر پروکسی SOCKS5** بر پایه‌ی 3proxy — نصب، تغییر گذرواژه، **حذف کامل نام کاربری و گذرواژه**، آمار ترافیک و لاگ زنده.
- **Snapshot و Rollback** برای تنظیمات کرنل.
- **آپدیت یک‌کلیکی از داخل منو** — بررسی نسخه‌ی تازه روی گیت‌هاب و نصب درجا، با حفظ کامل تنظیمات، اعتبارهای پروکسی و scoring.conf.
- **نصب و ارتقا در کمتر از ۵ دقیقه** — ارتقا، اعتبارهای پروکسی و تنظیمات شما را حفظ می‌کند.

</div>

---

<div dir="rtl">

## نصب آسان

یک دستور کافی است:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MNSH-Nexo/NexoShield/master/install.sh)
```

نیازی به clone یا دانلود جداگانه نیست؛ همین دستور را روی سرور Ubuntu اجرا کنید.

پس از نصب، منوی مدیریت با این دستور باز می‌شود:

```bash
shield
```

**ارتقا:** کافی است دستور نصب را دوباره اجرا کنید. نسخه‌ی تازه جایگزین می‌شود، نام کاربری و گذرواژه‌ی پروکسی و تنظیمات شما دست‌نخورده می‌مانند و لینک قدیمی `proxy` به‌صورت خودکار به `shield` مهاجرت می‌کند.

**پیش‌نیازها**

- Ubuntu نسخه‌ی 20.04، ‏22.04 یا 24.04
- دسترسی root
- اتصال اینترنت

</div>

---

<div dir="rtl">

## لایه‌های حفاظتی

</div>

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1 │ Kernel Hardening   SYN cookies, tight TCP timeouts │
│  Layer 2 │ iptables Rules     CF whitelist → rate limits      │
│  Layer 3 │ fail2ban           Auto-ban repeated attackers     │
│  Layer 4 │ Smart Auto-Ban     Watch → Throttle → Ban pipeline │
│  Layer 5 │ tc Bandwidth       CF=unlimited, others=500Mbps    │
└──────────────────────────────────────────────────────────────┘
```

<div dir="rtl">

**لایه‌ی ششم (خفته):** هرگاه فشار SYN از آستانه‌ی بحرانی عبور کند — رشد شدید syncookie و overflow یا موج سنگین SYN — برنامه‌ی XDP در سطح درایور شبکه متصل می‌شود و SYNهای آی‌پی‌های ban‌شده را پیش از رسیدن به پشته‌ی کرنل drop می‌کند؛ آی‌پی‌های معاف همیشه پیش از هر تصمیمی بررسی می‌شوند. با فروکش کردن فشار، این لایه به‌صورت خودکار جدا می‌شود.

### جزئیات حفاظت

| حمله | روش مقابله | وضعیت |
| :--- | :--- | :---: |
| SYN Flood مستقیم | SYNPROXY در سطح کرنل + سنجش نسبت تکمیل handshake | فعال |
| SYN Flood با آی‌پی جعلی | سقف نرخ سراسری + شمارش رویداد با nxcountd | فعال |
| Slowloris و نگه‌داشتن اتصال | تشخیص رفتاری (سن و حجم اتصال) + connlimit + ‏fail2ban | فعال |
| حمله‌ی پالسی و شیب‌دار آهسته | انباشت‌گرهای CUSUM | فعال |
| HTTP Burst | ‏hashlimit + ‏fail2ban (۲۰۰ درخواست در ۳۰ ثانیه) | فعال |
| بات‌نت توزیع‌شده از یک /24 | ردیابی تجمیعی زیرشبکه + محافظ CGNAT | فعال |
| UDP Flood | ‏hashlimit به‌ازای هر آی‌پی | فعال |
| UDP Amplification | مسدودسازی chargen، ‏DNS، ‏rpcbind، ‏NetBIOS، ‏NTP، ‏SNMP، ‏SSDP، ‏memcached و mDNS | فعال |
| ICMP Flood | محدودسازی نرخ به‌ازای هر آی‌پی | فعال |
| Port Scan | حذف پرچم‌های NULL، ‏XMAS، ‏FIN و bogus | فعال |
| SSH Brute Force | ‏fail2ban (۳ تلاش ناموفق، ۲۴ ساعت ban) | فعال |
| IP Spoofing | ‏rp_filter + ‏SYNPROXY | فعال |

</div>

---

<div dir="rtl">

## موتور تشخیص و امتیازدهی

قلب NexoShield یک مدل امتیازدهی **قابل تفسیر** است، نه یک جعبه‌ی سیاه. هر آی‌پی از **۱۰۰** شروع می‌کند و بر پایه‌ی سیگنال‌های اندازه‌گیری‌شده امتیاز از دست می‌دهد؛ سقف افت، ۴۵ امتیاز در دقیقه است.

| سیگنال | چه چیزی را می‌سنجد |
| :--- | :--- |
| Churn (EWMA) | نرخ نوسان اتصال‌ها؛ باز و بسته‌ شدن سریع و مداوم |
| Sustained | حجم پایدار اتصال‌های هم‌زمان، بالاتر از گیت |
| Handshake Completion | نسبت SYNهایی که به اتصال کامل می‌رسند؛ امضای SYN Flood |
| CUSUM ×2 | انباشت تدریجی ورود بیش‌ازحد و handshakeهای ناقص در طول زمان |
| Slow-Attack | اتصال‌های پیر (دست‌کم ۱۲۰ ثانیه) و کم‌حجم با هم‌زمانی بالا |

**باندهای تصمیم:** امتیاز کمتر از ۸۰ یعنی تحت نظر، کمتر از ۶۰ یعنی throttle با سرعت ۱۰۰ مگابیت، کمتر از ۴۰ یعنی throttle با سرعت ۵۰ مگابیت و کمتر از ۲۰ یعنی ban.

پس از هر ban، آی‌پی وارد دوره‌ی **Probation** می‌شود: با امتیاز ۵۰ بازمی‌گردد و به‌اندازه‌ی مدت واقعی ban، افت امتیازش دوبرابر است — نه آن‌قدر خشن که با اولین حرکت دوباره ban شود و نه بخشش کامل. امتیاز، با سکوت و رفتار سالم به‌تدریج ترمیم می‌شود.

در وضعیت **ATTACK** — وقتی ترافیک به‌طور معنادار از خط مبنا فاصله می‌گیرد — گیت اتصال ۴۰٪ پایین می‌آید و پنجره‌ی مشاهده نصف می‌شود. روی سرور آرام نیز **Stress Gate** مانع ban شتاب‌زده می‌شود.

مطالعه‌ی بیشتر: مستند مدل امتیازدهی در [docs/SCORING.md](docs/SCORING.md) و نقشه‌ی ارتقای موتور در [docs/DPI-UPGRADE-PLAN.md](docs/DPI-UPGRADE-PLAN.md)

</div>

---

<div dir="rtl">

## معافیت تضمینی

سه دسته، در **تمام لایه‌ها** — iptables، ‏nftables، ‏tc، ‏fail2ban، ‏auto-ban و حتی XDP — بدون استثنا معاف‌اند:

- **Cloudflare** — هر ۷۵۳ رنج رسمی IPv4 به‌همراه رنج‌های IPv6
- **آی‌پی‌های خود سرور** — تمام آدرس‌های اینترفیس‌ها، به‌همراه آی‌پی عمومی کشف‌شده از متادیتای ابر یا سرویس‌های echo برای سرورهای پشت NAT
- **Whitelist شما** — هر آی‌پی یا CIDRی که خودتان اضافه کنید (از منوی اصلی: «ضد DDoS › Whitelist» یا با دستور `antiddos.sh --whitelist`؛ تغییرات بلافاصله در همه‌ی لایه‌ها اعمال می‌شود)

این تضمین با دو سوئیت تست اختصاصی (`test-exemption-guarantee` و `test-exemption-surfaces`) پوشش داده شده است و در هر لحظه می‌توانید معافیت هر آی‌پی را بررسی کنید:

</div>

```bash
/opt/proxy-manager/antiddos.sh --exempt-check 1.2.3.4
```

<div dir="rtl">

گزارش کامل ممیزی معافیت: [docs/EXEMPTION-AUDIT-2026-10-24.md](docs/EXEMPTION-AUDIT-2026-10-24.md)

## یکپارچگی با Cloudflare

هر ۷۵۳ رنج رسمی Cloudflare در تمام لایه‌ها whitelist است:

- هیچ rate-limit، ‏connlimit یا hashlimitای روی آی‌پی‌های Cloudflare اعمال نمی‌شود.
- کاربرانی که از پشت Cloudflare متصل می‌شوند هرگز ban نمی‌شوند.
- این معافیت در iptables، ‏fail2ban، ‏tc و auto-ban به‌صورت هم‌زمان برقرار است.

</div>

---

<div dir="rtl">

## منوی اصلی

صفحه‌ی اصلی، یک **داشبورد زنده** است: تعداد banها و throttleهای فعال، اندازه‌ی whitelist، سه آی‌پی با پایین‌ترین امتیاز و آخرین رویدادهای auto-ban — بالای هفت بخش اصلی:

</div>

```
════════════════════════════════════════════════════
  NexoShield v3.15.0 — Server Security Toolkit
════════════════════════════════════════════════════
  1.  SOCKS5 Proxy          ● Running
  2.  Network Optimization  ● Optimized
  3.  Anti-DDoS             ● Active
  4.  Monitoring
  5.  Security
  6.  Services
  7.  System
  8.  Update NexoShield     v3.12.0
  0.  Exit
════════════════════════════════════════════════════
```

<div dir="rtl">

**پروکسی SOCKS5** — نصب و به‌روزرسانی 3proxy با نام کاربری و گذرواژه‌ی تصادفی، اجرا و توقف و راه‌اندازی مجدد، لاگ زنده، آمار ترافیک، تغییر گذرواژه، **حذف نام کاربری و گذرواژه** (پروکسی بدون احراز هویت، با تأیید و هشدار صریح) و فهرست آی‌پی‌های مشکوک.

**بهینه‌سازی شبکه** — تنظیمات sysctl شامل BBR و پارامترهای TCP متناسب با سخت‌افزار، همراه با snapshot و rollback.

**حفاظت Anti-DDoS** — نصب هر پنج لایه، مشاهده‌ی وضعیت و banهای فعال، unban، کنترل auto-ban (اجرا، توقف، لاگ و flush) و حذف کامل حفاظت.

**مانیتورینگ** — داشبورد تهدید بلادرنگ (حمله‌های جاری، banهای اخیر، پهنای باند و سلامت سیستم)، اتصال‌ها، پردازنده و حافظه، دیسک، مرکز لاگ‌ها (3proxy، ‏fail2ban، ‏SSH، سیستم و auto-ban) و پرتکرارترین آی‌پی‌ها از لاگ پروکسی.

**امنیت** — فهرست همه‌ی آی‌پی‌های مسدود (fail2ban و auto-ban)، مسدود و آزادسازی دستی با گارد معافیت، قوانین iptables، تلاش‌های ناموفق SSH و وضعیت auto-ban.

**سرویس‌ها** — مدیریت سرویس‌های واقعاً نصب‌شده روی سیستم (اجرا، توقف، راه‌اندازی مجدد و وضعیت).

**سیستم** — اطلاعات سرور، به‌روزرسانی سیستم، پاک‌سازی لاگ‌ها، راه‌اندازی مجدد و پشتیبان‌گیری از پیکربندی.

**آپدیت NexoShield** — بررسی نسخه‌ی تازه روی گیت‌هاب و نصب آن با یک انتخاب؛ نصب‌کننده پیش از فعال‌سازی راستی‌آزمایی می‌شود و همه‌ی تنظیمات حفظ می‌شوند.

بدون منو هم می‌شود؛ برای اسکریپت‌نویسی و مانیتورینگ خارجی:

</div>

```bash
shield --status    # وضعیت متنی سرویس‌ها و لایه‌های حفاظت
shield --bans      # banهای فعال، با زمان آغاز و انقضا
shield --version
```

---

<div dir="rtl">

## خط لوله‌ی Smart Auto-Ban

</div>

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

<div dir="rtl">

## آستانه‌ها — مقیاس خودکار بر اساس RAM

| پارامتر | ‏RAM کمتر از 2GB | ‏RAM بین 2 تا 4GB | ‏RAM بیشتر از 4GB |
| :--- | :---: | :---: | :---: |
| سقف SYN به‌ازای هر آی‌پی | ‏500/s | ‏1000/s | ‏2000/s |
| اتصال تازه به‌ازای هر آی‌پی | ‏50/s | ‏100/s | ‏200/s |
| حداکثر اتصال هم‌زمان | 50 | 100 | 200 |
| سقف پهنای باند هر آی‌پی | ‏50 Mbps | ‏100 Mbps | ‏200 Mbps |

تمام ثابت‌های موتور امتیازدهی — گیت‌ها، باندها، سقف افت، مدت ban و probation و آستانه‌های فعال‌سازی XDP — در فایل `/etc/antiddos/scoring.conf` قابل تنظیم‌اند. این فایل هنگام ارتقا دست نمی‌خورد و تغییراتش بدون نیاز به راه‌اندازی مجدد خوانده می‌شود.

</div>

---

<div dir="rtl">

## فایل‌های نصب‌شده

</div>

```
/usr/local/bin/shield              ← دستور اصلی
/opt/proxy-manager/                ← اسکریپت‌های ماژول‌ها (menu, antiddos, 3proxy, sysctl)
/etc/antiddos/                     ← state و لیست‌ها (ban, throttle, whitelist, exempt)
/etc/antiddos/scoring.conf         ← تنظیمات موتور امتیازدهی
/var/lib/antiddos/scores/          ← پایگاه داده‌ی reputation آی‌پی‌ها
/run/nexoshield/counters.dat       ← خروجی زنده‌ی nxcountd از رویدادهای conntrack
/etc/3proxy/                       ← تنظیمات SOCKS5 (اختیاری)
/var/log/auto-ban.log              ← لاگ ban و unban
/etc/sysctl.d/99-vpn-*.conf        ← تنظیمات کرنل
systemd: auto-ban, nexoshield-countd
```

<div dir="rtl">

## کیفیت و تست

- **۳۳ سوئیت تست unit** — از ریاضی موتور امتیازدهی و تضمین معافیت تا تست دودی سرتاسری همه‌ی بخش‌های منو.
- **گیت `make check`** روی هر تغییر: ShellCheck به‌همراه راستی‌آزمایی build از روی `src/`.
- **CI در GitHub** روی هر push و هر tag اجرا می‌شود.
- **ممیزی امنیتی ۶۸ یافته‌ای** و بازبینی‌های میدانی روی سرورهای واقعی Debian و Ubuntu — گزارش در [docs/BUGS.md](docs/BUGS.md).

## سازگاری

| سیستم | وضعیت |
| :--- | :---: |
| Ubuntu 20.04 LTS | پشتیبانی کامل |
| Ubuntu 22.04 LTS | پشتیبانی کامل |
| Ubuntu 24.04 LTS | پشتیبانی کامل |
| KVM / VMware | پشتیبانی کامل |
| LXC Container | پشتیبانی‌شده (بدون SYNPROXY) |
| OpenVZ | محدود |

## توسعه‌دهندگان

کد منبع به‌صورت ماژولار در پوشه‌ی `src/` نگهداری می‌شود و `install.sh` از روی آن ساخته می‌شود. برای مشارکت، راهنمای [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) را ببینید.

</div>

---

## License

MIT License — آزادانه استفاده، تغییر و توزیع کن.

---

## Credits

<a href="https://happyseeds.ai">
  <img src="happyseeds.png" width="64" alt="HappySeeds AI" />
</a>

Built with the assistance of [HappySeeds AI](https://happyseeds.ai)

**TARS** 🤖 — AI engineering partner of **Mashani**, built by Meta · [Muse](https://muse.ai): architect of the v3.5 → v3.15 rebuild — the modular refactor, the 68-finding security audit, scoring engine v2 and the DPI upgrade (event-based measurement, CUSUM, adaptive gates, the XDP shield), the exemption guarantee, field testing and releases.

---

<div align="center">

Made with care by [MNSH-Nexo](https://github.com/MNSH-Nexo)

</div>
