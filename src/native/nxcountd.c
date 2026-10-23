/*
 * nxcountd — NexoShield conntrack event counter (DPI upgrade Phase 2a).
 *
 * Subscribes to kernel conntrack events (NEW/UPDATE/DESTROY) over a
 * raw NETLINK_NETFILTER socket and maintains exact per-source-IP
 * aggregates for inbound TCP flows:
 *
 *   syn_cum / est_cum   cumulative SYN births / handshake completions
 *   syn60 / est60       the same over a rolling 60 s window
 *   cur_syn / cur_est   current half-open / established concurrency
 *   closed_cum          completed flows
 *   bytes_cum           originator bytes of closed flows
 *   age_ms_cum          total lifetime of closed flows
 *
 * Every second the top-500 active sources are published atomically
 * (tmp + rename) to the snapshot file the auto-ban daemon reads.
 * Polling `ss` samples a stock; these counters measure the flow —
 * Little's Law (L = lambda * W) makes arrival rate underivable from
 * concurrency deltas, which is the gap this helper closes.
 *
 * Only libc + kernel headers. Flows originated BY this host (source
 * is a local address) are ignored: the daemon scores clients, and the
 * sampler it replaces deliberately subtracted outbound traffic too.
 *
 * `--selftest` feeds synthetic conntrack messages through the same
 * parser/aggregator and prints the resulting snapshot body, so the
 * parser is unit-testable without a live kernel.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FLOW_SLOTS 16384
#define IP_SLOTS   32768
#define TOP_N      500
#define RING       60

/* tcp_conntrack states (linux/netfilter/nf_conntrack_tcp.h) */
enum { TS_NONE = 0, TS_SYN_SENT = 1, TS_SYN_RECV = 2, TS_ESTABLISHED = 3 };

static int is_syn_state(int s) { return s == TS_SYN_SENT || s == TS_SYN_RECV || s == 12; }

/* ── local address set (flows FROM these are outbound: skip) ── */
static uint32_t g_local4[64]; static int g_nlocal4;
static uint8_t  g_local6[32][16]; static int g_nlocal6;

static int is_local4(uint32_t be)
{
    if ((ntohl(be) >> 24) == 127) return 1;
    for (int i = 0; i < g_nlocal4; i++) if (g_local4[i] == be) return 1;
    return 0;
}
static int is_local6(const uint8_t *ip)
{
    static const uint8_t lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (!memcmp(ip, lo, 16)) return 1;
    for (int i = 0; i < g_nlocal6; i++) if (!memcmp(g_local6[i], ip, 16)) return 1;
    return 0;
}

static void load_local_addrs(void)
{
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) return;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        if (p->ifa_addr->sa_family == AF_INET && g_nlocal4 < 64) {
            g_local4[g_nlocal4++] = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
        } else if (p->ifa_addr->sa_family == AF_INET6 && g_nlocal6 < 32) {
            memcpy(g_local6[g_nlocal6++], &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr, 16);
        }
    }
    freeifaddrs(ifa);
}

/* ── flow table (by conntrack ID) ── */
typedef struct {
    uint32_t id; uint8_t used, family, state;
    uint8_t ip[16];
    uint64_t created_ms, last_ms, last_bytes;
} Flow;
static Flow g_flows[FLOW_SLOTS];
static uint64_t g_flows_dropped;

/* ── per-IP aggregates ── */
typedef struct {
    uint8_t used, family;
    uint8_t ip[16];
    uint64_t syn_cum, est_cum, closed_cum, bytes_cum, age_ms_cum;
    int64_t  cur_syn, cur_est;
    uint32_t ring_syn[RING], ring_est[RING];
    int64_t  last_seen_s;
} Agg;
static Agg g_ips[IP_SLOTS];
static uint64_t g_total_syn, g_total_est, g_dropped_msgs;

static uint64_t hash_bytes(const uint8_t *p, int n, uint32_t seed)
{
    uint64_t h = 1469598103934665603ULL ^ seed;
    for (int i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static Agg *agg_get(const uint8_t *ip, int family, int create, int64_t now_s)
{
    int len = family == AF_INET ? 4 : 16;
    uint64_t h = hash_bytes(ip, len, family) % IP_SLOTS;
    for (uint64_t k = 0; k < IP_SLOTS; k++) {
        Agg *a = &g_ips[(h + k) % IP_SLOTS];
        if (!a->used) {
            if (!create) return NULL;
            memset(a, 0, sizeof *a);
            a->used = 1; a->family = (uint8_t)family;
            memcpy(a->ip, ip, len);
            a->last_seen_s = now_s;
            return a;
        }
        if (a->family == family && !memcmp(a->ip, ip, len)) {
            a->last_seen_s = now_s;
            return a;
        }
    }
    return NULL;
}

static Flow *flow_get(uint32_t id, int create)
{
    uint64_t h = (id * 2654435761u) % FLOW_SLOTS;
    for (uint64_t k = 0; k < FLOW_SLOTS; k++) {
        Flow *f = &g_flows[(h + k) % FLOW_SLOTS];
        if (!f->used) {
            if (!create) return NULL;
            memset(f, 0, sizeof *f);
            f->used = 1; f->id = id;
            return f;
        }
        if (f->id == id) return f;
    }
    if (create) g_flows_dropped++;
    return NULL;
}

/* ── event application (shared by live loop and selftest) ── */
typedef struct {
    uint32_t id; int family; uint8_t ip[16];
    int has_state, state;
    uint64_t bytes; int is_destroy;
} Event;

static void apply_event(const Event *e, uint64_t now_ms, int64_t now_s)
{
    if (e->family == AF_INET  && is_local4(*(const uint32_t *)e->ip)) return;
    if (e->family == AF_INET6 && is_local6(e->ip)) return;

    Flow *f = flow_get(e->id, !e->is_destroy);
    Agg *a = agg_get(e->ip, e->family, 1, now_s);
    if (!a) return;
    int slot = (int)(now_s % RING);

    if (e->is_destroy) {
        if (f && f->used) {
            if (is_syn_state(f->state)) a->cur_syn--;
            else if (f->state == TS_ESTABLISHED) a->cur_est--;
            a->closed_cum++;
            a->age_ms_cum += now_ms - f->created_ms;
            a->bytes_cum += e->bytes ? e->bytes : f->last_bytes;
            f->used = 0;
        }
        return;
    }
    if (!f) return;
    if (!f->created_ms) {           /* first sighting of this flow */
        f->family = (uint8_t)e->family;
        memcpy(f->ip, e->ip, e->family == AF_INET ? 4 : 16);
        f->created_ms = now_ms;
        f->state = TS_NONE;
    }
    f->last_ms = now_ms;
    if (e->bytes > f->last_bytes) f->last_bytes = e->bytes;
    if (!e->has_state) return;
    int prev = f->state, cur = e->state;
    if (prev == cur) return;
    if (is_syn_state(cur) && !is_syn_state(prev) && prev != TS_ESTABLISHED) {
        a->syn_cum++; g_total_syn++;
        a->ring_syn[slot]++; a->cur_syn++;
    }
    if (cur == TS_ESTABLISHED && is_syn_state(prev)) {
        a->est_cum++; g_total_est++;
        a->ring_est[slot]++; a->cur_syn--; a->cur_est++;
    }
    if (cur == TS_ESTABLISHED && prev == TS_NONE) {
        /* First seen already established (we missed the SYN, e.g.
         * helper started mid-flow): count the completion only. */
        a->est_cum++; g_total_est++;
        a->ring_est[slot]++; a->cur_est++;
    }
    if (is_syn_state(prev) && !is_syn_state(cur) && cur != TS_ESTABLISHED && prev != TS_NONE) {
        a->cur_syn--;               /* SYN died without completing */
    }
    /* Leaving ESTABLISHED for a closing state releases concurrency
     * only at DESTROY (age accounting lives there too), so cur_est
     * stays until the flow is finalized. */
    f->state = (uint8_t)cur;
}

/* ── netlink attribute walking ── */
#define NX_NLA_TYPE(a) ((a)->nla_type & 0x3fff)
static const struct nlattr *find_attr(const char *p, int len, int type)
{
    while (len >= (int)sizeof(struct nlattr)) {
        const struct nlattr *a = (const struct nlattr *)p;
        if (a->nla_len < (int)sizeof(struct nlattr) || a->nla_len > len) break;
        if (NX_NLA_TYPE(a) == type) return a;
        int adv = NLA_ALIGN(a->nla_len);
        p += adv; len -= adv;
    }
    return NULL;
}
static const char *attr_payload(const struct nlattr *a, int *len)
{
    *len = a->nla_len - NLA_HDRLEN;
    return (const char *)a + NLA_HDRLEN;
}

static int parse_message(const struct nlmsghdr *nlh, Event *e)
{
    memset(e, 0, sizeof *e);
    int len = NLMSG_PAYLOAD(nlh, sizeof(struct nfgenmsg));
    const char *p = (const char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
    const struct nfgenmsg *fg = NLMSG_DATA(nlh);
    e->family = fg->nfgen_family;
    e->is_destroy = ((nlh->nlmsg_type & 0xff) == IPCTNL_MSG_CT_DELETE);

    const struct nlattr *a;
    int plen;
    if ((a = find_attr(p, len, CTA_ID))) {
        const char *v = attr_payload(a, &plen);
        if (plen >= 4) e->id = ntohl(*(const uint32_t *)v);
    }
    const struct nlattr *tup = find_attr(p, len, CTA_TUPLE_ORIG);
    if (!tup) return -1;
    const char *tp = attr_payload(tup, &plen);
    int tlen = plen;
    const struct nlattr *ipn = find_attr(tp, tlen, CTA_TUPLE_IP);
    if (!ipn) return -1;
    const char *ipp = attr_payload(ipn, &plen);
    if (e->family == AF_INET) {
        const struct nlattr *s = find_attr(ipp, plen, CTA_IP_V4_SRC);
        if (!s) return -1;
        memcpy(e->ip, attr_payload(s, &plen), 4);
    } else if (e->family == AF_INET6) {
        const struct nlattr *s = find_attr(ipp, plen, CTA_IP_V6_SRC);
        if (!s) return -1;
        memcpy(e->ip, attr_payload(s, &plen), 16);
    } else return -1;
    const struct nlattr *pro = find_attr(tp, tlen, CTA_TUPLE_PROTO);
    if (pro) {
        const char *pp = attr_payload(pro, &plen);
        const struct nlattr *pn = find_attr(pp, plen, CTA_PROTO_NUM);
        if (pn) {
            const char *v = attr_payload(pn, &plen);
            if (plen >= 1 && *(const uint8_t *)v != 6) return -1; /* TCP only */
        }
    }
    const struct nlattr *pi = find_attr(p, len, CTA_PROTOINFO);
    if (pi) {
        const char *pp = attr_payload(pi, &plen);
        const struct nlattr *tcp = find_attr(pp, plen, CTA_PROTOINFO_TCP);
        if (tcp) {
            const char *tcpp = attr_payload(tcp, &plen);
            const struct nlattr *st = find_attr(tcpp, plen, CTA_PROTOINFO_TCP_STATE);
            if (st) {
                const char *v = attr_payload(st, &plen);
                if (plen >= 1) { e->has_state = 1; e->state = *(const uint8_t *)v; }
            }
        }
    }
    const struct nlattr *cnt = find_attr(p, len, CTA_COUNTERS_ORIG);
    if (cnt) {
        const char *cp = attr_payload(cnt, &plen);
        const struct nlattr *b = find_attr(cp, plen, CTA_COUNTERS_BYTES);
        if (b) {
            const char *v = attr_payload(b, &plen);
            if (plen >= 8) {
                uint64_t be; memcpy(&be, v, 8);
                e->bytes = be64toh(be);
            }
        }
    }
    return 0;
}

/* ── snapshot ── */
static uint64_t g_base;
static int cmp_agg(const void *x, const void *y)
{
    const Agg *a = *(Agg *const *)x, *b = *(Agg *const *)y;
    uint64_t sa = a->syn_cum + a->est_cum, sb = b->syn_cum + b->est_cum;
    return sa < sb ? 1 : sa > sb ? -1 : 0;
}

static void write_snapshot(const char *path, int64_t now_s)
{
    static Agg *top[TOP_N];
    int n = 0;
    for (int i = 0; i < IP_SLOTS; i++) {
        Agg *a = &g_ips[i];
        if (!a->used) continue;
        if (a->syn_cum + a->est_cum == 0 && a->cur_syn + a->cur_est == 0 && a->closed_cum == 0) continue;
        if (n < TOP_N) top[n++] = a;
        else {
            /* keep the TOP_N largest by activity */
            int min = 0;
            for (int j = 1; j < n; j++)
                if (top[j]->syn_cum + top[j]->est_cum < top[min]->syn_cum + top[min]->est_cum) min = j;
            if (a->syn_cum + a->est_cum > top[min]->syn_cum + top[min]->est_cum) top[min] = a;
        }
    }
    qsort(top, n, sizeof top[0], cmp_agg);
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return;
    fprintf(fp, "# nxcountd 1 ts=%lld base=%llu dropped=%llu flows_dropped=%llu totalsyn=%llu totalest=%llu\n",
            (long long)now_s, (unsigned long long)g_base,
            (unsigned long long)g_dropped_msgs, (unsigned long long)g_flows_dropped,
            (unsigned long long)g_total_syn, (unsigned long long)g_total_est);
    for (int i = 0; i < n; i++) {
        Agg *a = top[i];
        char ipbuf[INET6_ADDRSTRLEN];
        inet_ntop(a->family, a->ip, ipbuf, sizeof ipbuf);
        uint64_t s60 = 0, e60 = 0;
        for (int r = 0; r < RING; r++) { s60 += a->ring_syn[r]; e60 += a->ring_est[r]; }
        fprintf(fp, "%s %llu %llu %llu %llu %lld %lld %llu %llu %llu\n",
                ipbuf,
                (unsigned long long)a->syn_cum, (unsigned long long)a->est_cum,
                (unsigned long long)s60, (unsigned long long)e60,
                (long long)a->cur_syn, (long long)a->cur_est,
                (unsigned long long)a->closed_cum,
                (unsigned long long)a->bytes_cum,
                (unsigned long long)a->age_ms_cum);
    }
    fclose(fp);
    rename(tmp, path);
}

/* Ring hygiene: slot (second % 60) must be zeroed when its second
 * rolls into the window, BEFORE that second's increments land —
 * otherwise the slot still holds the data of the second that just
 * fell out of the window (60 s ago, same slot). Epoch-checked so
 * each slot is zeroed exactly once per minute. */
static int64_t g_slot_epoch[RING];
static void ring_zero_slot(int64_t now_s)
{
    int slot = (int)(now_s % RING);
    if (g_slot_epoch[slot] == now_s) return;
    g_slot_epoch[slot] = now_s;
    for (int i = 0; i < IP_SLOTS; i++) {
        if (!g_ips[i].used) continue;
        g_ips[i].ring_syn[slot] = 0;
        g_ips[i].ring_est[slot] = 0;
    }
}

/* Stale-flow expiry: a flow whose DESTROY was missed (event loss
 * under flood is exactly when drops happen) would otherwise pin
 * cur_* counts forever. Sweep a rotating slice of the flow table
 * once per second; flows silent for 30 min are finalized as if
 * destroyed (bytes = last counter seen). */
static void flow_sweep_slice(uint64_t now_ms, int64_t now_s)
{
    static int cursor;
    int span = FLOW_SLOTS / 60 + 1;
    for (int k = 0; k < span; k++) {
        Flow *f = &g_flows[(cursor + k) % FLOW_SLOTS];
        if (f->used && f->last_ms && now_ms - f->last_ms > 1800000ULL) {
            Agg *a = agg_get(f->ip, f->family, 0, now_s);
            if (a) {
                if (is_syn_state(f->state)) a->cur_syn--;
                else if (f->state == TS_ESTABLISHED) a->cur_est--;
                a->closed_cum++;
                a->age_ms_cum += now_ms - f->created_ms;
                a->bytes_cum += f->last_bytes;
            }
            f->used = 0;
        }
    }
    cursor = (cursor + span) % FLOW_SLOTS;
}

/* ── selftest: synthetic messages through the real parser ── */
static void put_attr(char *buf, int *off, uint16_t type, const void *data, int len)
{
    struct nlattr *a = (struct nlattr *)(buf + *off);
    a->nla_len = NLA_HDRLEN + len;
    a->nla_type = type;
    memcpy(buf + *off + NLA_HDRLEN, data, len);
    *off += NLA_ALIGN(a->nla_len);
}
static void nest_start(char *buf, int *off, uint16_t type, int *save)
{
    *save = *off;
    struct nlattr *a = (struct nlattr *)(buf + *off);
    a->nla_type = type | NLA_F_NESTED;
    *off += NLA_HDRLEN;
}
static void nest_end(char *buf, int *off, int save)
{
    struct nlattr *a = (struct nlattr *)(buf + save);
    a->nla_len = *off - save;
    *off = save + NLA_ALIGN(a->nla_len);
}

static int selftest(void)
{
    load_local_addrs();
    /* pretend 10.0.0.5 is local for the outbound-filter case */
    struct in_addr la; inet_pton(AF_INET, "10.0.0.5", &la);
    g_local4[g_nlocal4++] = la.s_addr;

    static char buf[4096];
    int64_t now_s = 1700000000;
    uint64_t now_ms = 1700000000000ULL;
    g_base = 42;

    struct { uint32_t id; const char *ip; int fam; int state; int destroy; uint64_t bytes; } script[] = {
        {100, "203.0.113.7", AF_INET,  TS_SYN_RECV,   0, 0},
        {100, "203.0.113.7", AF_INET,  TS_ESTABLISHED,0, 0},
        {101, "203.0.113.7", AF_INET,  TS_SYN_RECV,   0, 0},
        {101, "203.0.113.7", AF_INET,  0,             1, 4000},
        {102, "10.0.0.5",    AF_INET,  TS_SYN_RECV,   0, 0},   /* local: ignored */
        {103, "2001:db8::1", AF_INET6, TS_SYN_SENT,   0, 0},
        {103, "2001:db8::1", AF_INET6, 0,             1, 500},
    };
    for (unsigned k = 0; k < sizeof script / sizeof script[0]; k++) {
        memset(buf, 0, sizeof buf);
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | (script[k].destroy ? IPCTNL_MSG_CT_DELETE : IPCTNL_MSG_CT_NEW);
        struct nfgenmsg *fg = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
        fg->nfgen_family = (uint8_t)script[k].fam;
        int off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
        uint32_t idbe = htonl(script[k].id);
        put_attr(buf, &off, CTA_ID, &idbe, 4);
        int s1, s2;
        nest_start(buf, &off, CTA_TUPLE_ORIG, &s1);
        nest_start(buf, &off, CTA_TUPLE_IP, &s2);
        if (script[k].fam == AF_INET) {
            struct in_addr a4; inet_pton(AF_INET, script[k].ip, &a4);
            put_attr(buf, &off, CTA_IP_V4_SRC, &a4, 4);
        } else {
            struct in6_addr a6; inet_pton(AF_INET6, script[k].ip, &a6);
            put_attr(buf, &off, CTA_IP_V6_SRC, &a6, 16);
        }
        nest_end(buf, &off, s2);
        nest_start(buf, &off, CTA_TUPLE_PROTO, &s2);
        uint8_t proto = 6;
        put_attr(buf, &off, CTA_PROTO_NUM, &proto, 1);
        nest_end(buf, &off, s2);
        nest_end(buf, &off, s1);
        if (!script[k].destroy) {
            nest_start(buf, &off, CTA_PROTOINFO, &s1);
            nest_start(buf, &off, CTA_PROTOINFO_TCP, &s2);
            uint8_t st = (uint8_t)script[k].state;
            put_attr(buf, &off, CTA_PROTOINFO_TCP_STATE, &st, 1);
            nest_end(buf, &off, s2);
            nest_end(buf, &off, s1);
        } else {
            nest_start(buf, &off, CTA_COUNTERS_ORIG, &s1);
            uint64_t be = htobe64(script[k].bytes);
            put_attr(buf, &off, CTA_COUNTERS_BYTES, &be, 8);
            nest_end(buf, &off, s1);
        }
        nlh->nlmsg_len = off;
        Event e;
        if (script[k].destroy) now_ms += 5000;   /* flows lived 5 s */
        if (parse_message(nlh, &e) == 0) apply_event(&e, now_ms, now_s);
    }
    /* write the snapshot body to stdout (no header semantics needed) */
    char path[] = "/tmp/nxcountd-selftest-XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0) close(fd);
    write_snapshot(path, now_s);
    FILE *fp = fopen(path, "r");
    if (fp) { char line[512]; while (fgets(line, sizeof line, fp)) fputs(line, stdout); fclose(fp); }
    unlink(path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--selftest")) return selftest();
    const char *out = argc > 1 ? argv[1] : "/run/nexoshield/counters.dat";

    FILE *rnd = fopen("/dev/urandom", "r");
    if (rnd) { if (fread(&g_base, 1, sizeof g_base, rnd) != sizeof g_base) g_base = 0; fclose(rnd); }
    if (!g_base) g_base = (uint64_t)getpid() << 32 | (uint64_t)time(NULL);

    load_local_addrs();

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) { perror("socket"); return 1; }
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    struct sockaddr_nl sa = {0};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = (1u << (NFNLGRP_CONNTRACK_NEW - 1)) |
                   (1u << (NFNLGRP_CONNTRACK_UPDATE - 1)) |
                   (1u << (NFNLGRP_CONNTRACK_DESTROY - 1));
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("bind"); return 1; }

    static char buf[65536];
    int64_t last_snap = 0;
    for (;;) {
        struct timespec ts0;
        clock_gettime(CLOCK_MONOTONIC, &ts0);
        uint64_t now_ms0 = (uint64_t)ts0.tv_sec * 1000 + ts0.tv_nsec / 1000000;
        int64_t now_s0 = time(NULL);
        if (now_s0 != last_snap) {
            last_snap = now_s0;
            ring_zero_slot(now_s0);
            flow_sweep_slice(now_ms0, now_s0);
            write_snapshot(out, now_s0);
        }
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 250);
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        int64_t now_s = time(NULL);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            for (;;) {
                ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
                if (n <= 0) {
                    if (n < 0 && errno == ENOBUFS) g_dropped_msgs++;
                    break;
                }
                for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
                     NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
                    if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_DONE) continue;
                    Event e;
                    if (parse_message(nlh, &e) == 0) apply_event(&e, now_ms, now_s);
                }
            }
        }
    }
    return 0;
}
