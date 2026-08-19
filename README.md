<div align="center">

<img src="logo.png" width="120" alt="NexoShield Logo" />

# NexoShield

**Professional Server Hardening & Anti-DDoS Toolkit**

*Secure any Ubuntu server in minutes — with optional SOCKS5 proxy management*

<img src="https://img.shields.io/badge/Platform-Ubuntu%2020%2B-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Platform"/>
<img src="https://img.shields.io/badge/Shell-Bash%205%2B-4EAA25?style=flat-square&logo=gnubash&logoColor=white" alt="Shell"/>
<img src="https://img.shields.io/badge/Version-3.0-7c3aed?style=flat-square" alt="Version"/>
<img src="https://img.shields.io/badge/License-MIT-1a73e8?style=flat-square" alt="License"/>

</div>

---

## What is NexoShield?

NexoShield is a single-script toolkit that transforms a bare Ubuntu server into a hardened, DDoS-resistant machine in under 5 minutes.

You can use it purely for **server security** — or also enable the built-in **SOCKS5 proxy manager** if needed.

---

## امکانات

- 🛡 **۵ لایه حفاظت DDoS** — kernel hardening، iptables، fail2ban، smart auto-ban و tc
- 🧠 **Smart Auto-Ban با امتیازدهی Reputation** — تمایز کاربرِ سنگینِ واقعی از بات
- ☁️ **753 رنج رسمی Cloudflare** — کاربران CF همیشه نامحدود و بدون ban
- ⚡ **نصب در کمتر از ۵ دقیقه** — فقط با یک دستور
- 📊 **داشبورد real-time** برای مانیتور حمله، banها و top IPها
- 🛠 **SOCKS5 Proxy Manager** اختیاری (3proxy) با پسورد تصادفی و لاگ زنده
- 🔄 **SnapShot و Rollback** برای تنظیمات kernel
- 🚫 **تشخیص Subnet botnet** برای حمله‌های توزیع‌شده از یک /24

---

## نصب آسان

**یک دستور — همه چیز آماده:**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MNSH-Nexo/NexoShield/master/install.sh)
```

> نیازی به clone یا دانلود جداگانه نیست. فقط این دستور رو روی سرور Ubuntu اجرا کن.

**بعد از نصب، با این دستور اجرا کن:**

```bash
proxy
```

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

**جزئیات حفاظت**

| حمله | روش مقابله | وضعیت |
|------|-----------|--------|
| SYN Flood (direct) | SYNPROXY kernel-level | Active |
| SYN Flood (spoofed IP) | Global rate cap | Active |
| Slowloris / Conn-Hold | connlimit + keepalive=30s + fail2ban | Active |
| HTTP Burst (pipeline) | hashlimit + fail2ban 200req/30s | Active |
| Botnet distributed (/24) | Subnet aggregate tracking | Active |
| UDP Flood | hashlimit per-IP | Active |
| UDP Amplification | DNS/NTP/SSDP/memcached blocked | Active |
| ICMP Flood | rate-limited per-IP | Active |
| Port Scan | NULL/XMAS/FIN/bogus flags DROP | Active |
| SSH Brute Force | fail2ban (3 tries → 24h ban) | Active |
| IP Spoofing | rp_filter + SYNPROXY | Active |

---

## Cloudflare Integration

NexoShield دارای **753 رنج IP رسمی Cloudflare** است که در **تمام لایه‌ها** whitelist شده‌اند:

- هیچ rate-limit، connlimit یا hashlimit روی CF IPs اعمال نمی‌شه
- کاربرانی که از پشت Cloudflare وصل می‌شن هیچ‌وقت ban نمی‌شن
- CF IPs در iptables، fail2ban، tc و auto-ban همه exempt هستن

---

## منوی اصلی

```
════════════════════════════════════════
  NexoShield — Server Toolkit v3.0
════════════════════════════════════════
  1.  SOCKS5 Proxy Manager
  2.  Kernel Optimizer (sysctl)
  3.  Anti-DDoS Protection
  4.  Live Threat Monitor
  0.  Exit
════════════════════════════════════════
```

**SOCKS5 Proxy Manager** — نصب، مدیریت و مانیتور 3proxy  
نصب خودکار با یوزرنیم/پسورد تصادفی، تغییر پسورد، restart، مشاهده لاگ، نمایش اطلاعات اتصال

**Kernel Optimizer** — بهینه‌سازی سیستم  
تنظیم TCP timeouts، conntrack، buffer sizes — با snapshot و rollback

**Anti-DDoS Protection** — نصب همه ۵ لایه  
Auto-detect سخت‌افزار و تنظیم threshold متناسب — ماندگار بعد از reboot

**Live Threat Monitor** — داشبورد real-time  
نمایش حملات فعال، ban‌های اخیر، top IP‌ها، آمار شبکه، CPU، RAM، conntrack

---

## Smart Auto-Ban Pipeline

```
Connection Detected
        │
        ▼
  active conns ≥ 120/IP ────────────► WATCHING (observe 45s)
        │                                       │
        │                        still high after 45s?
        │                                       │
  active conns ≥ 300/IP ─► INSTANT BAN          ▼
                        (4h)            THROTTLE 100 Mbps
                                                │
                                       still high after 45s?
                                                │
                                                ▼
                                            BAN 4 hours

  /24 subnet ≥ 400 total ──► WATCHING subnet
  /24 subnet ≥ 1000 total ──► BAN entire /24 CIDR (botnet defense)

  Reputation scoring:  80+ normal → 60+ watch → 40+ 100M throttle
                       → 20+ 50M → <20 instant ban (4h)
  auto-release:        IPs that calm down are automatically released
```

---

## Thresholds — auto-scaled by RAM

| پارامتر | RAM < 2GB | RAM 2–4GB | RAM > 4GB |
|---------|-----------|-----------|-----------|
| SYN limit/IP | 500/s | 1000/s | 2000/s |
| New conn/IP | 50/s | 100/s | 200/s |
| Max conn/IP | 50 | 100 | 200 |
| BW cap/IP | 50 Mbps | 100 Mbps | 200 Mbps |

---

## فایل‌های نصب شده

```
/usr/local/bin/proxy          ← دستور اصلی
/etc/antiddos/                ← تنظیمات و banned list
/etc/3proxy/                  ← تنظیمات SOCKS5 (اختیاری)
/var/log/auto-ban.log         ← لاگ ban/unban
/etc/sysctl.d/99-vpn-*.conf   ← kernel tweaks
```

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

## License

MIT License — آزادانه استفاده، تغییر و توزیع کن.

---

## Credits & Contributors

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

<a href="https://happyseeds.ai">
  <img src="happyseeds.png" width="64" alt="HappySeeds AI" />
</a>

Built with the assistance of [HappySeeds AI](https://happyseeds.ai)

---

<div align="center">

Made with care by [MNSH-Nexo](https://github.com/MNSH-Nexo)

</div>
