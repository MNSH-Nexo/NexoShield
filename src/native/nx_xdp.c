/*
 * nx_xdp — NexoShield emergency XDP shield (DPI upgrade Phase 3).
 *
 * Dormant line-rate relief for volumetric SYN floods. The daemon
 * attaches this program ONLY while the host is drowning (syncookie
 * storms / backlog overflows / extreme SYN arrival rates) and
 * detaches it when calm returns. It drops NEW connection attempts
 * (pure SYNs) from sources present in the ban LPM tries — the same
 * ban state the nftables backend enforces at netfilter — before
 * conntrack allocation, which is the resource a SYN flood actually
 * exhausts. Established traffic and non-SYN packets pass untouched;
 * exempt sources (self / whitelist / Cloudflare) are checked first
 * and always pass: FR-1/FR-2 hold at line rate too.
 *
 * Ban values are monotonic-clock expiry stamps (ns), mirroring the
 * timed nft sets; an expired entry passes (the daemon's state files
 * remain the source of truth and re-sync while attached).
 *
 * Counters (per-CPU): 0 = SYNs seen, 1 = drops, 2 = exempt passes.
 *
 * Built only when clang + libbpf headers exist at install time.
 * Known limits: no VLAN tag parsing (cloud NICs are untagged);
 * XDP_PASS for anything unparsable — fail-open by design.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct lpm4_key { __u32 prefixlen; __u32 addr; };
struct lpm6_key { __u32 prefixlen; __u8 addr[16]; };

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm4_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ban4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm6_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ban6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm4_key);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} exempt4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm6_key);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} exempt6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} counters SEC(".maps");

enum { C_SYN = 0, C_DROP = 1, C_EXEMPT_PASS = 2 };

static __always_inline void bump(__u32 k)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &k);
    if (v) (*v)++;
}

SEC("xdp")
int nx_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    __u16 proto = bpf_ntohs(eth->h_proto);
    __u64 now = bpf_ktime_get_ns();

    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        if (tcp->syn) bump(C_SYN);
        if (!tcp->syn || tcp->ack) return XDP_PASS;
        struct lpm4_key ek = { .prefixlen = 32, .addr = ip->saddr };
        if (bpf_map_lookup_elem(&exempt4, &ek)) { bump(C_EXEMPT_PASS); return XDP_PASS; }
        struct lpm4_key bk = { .prefixlen = 32, .addr = ip->saddr };
        __u64 *exp = bpf_map_lookup_elem(&ban4, &bk);
        if (exp && *exp > now) { bump(C_DROP); return XDP_DROP; }
        return XDP_PASS;
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        if (ip6->nexthdr != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        if (tcp->syn) bump(C_SYN);
        if (!tcp->syn || tcp->ack) return XDP_PASS;
        struct lpm6_key ek = { .prefixlen = 128 };
        __builtin_memcpy(ek.addr, &ip6->saddr, 16);
        if (bpf_map_lookup_elem(&exempt6, &ek)) { bump(C_EXEMPT_PASS); return XDP_PASS; }
        struct lpm6_key bk = { .prefixlen = 128 };
        __builtin_memcpy(bk.addr, &ip6->saddr, 16);
        __u64 *exp = bpf_map_lookup_elem(&ban6, &bk);
        if (exp && *exp > now) { bump(C_DROP); return XDP_DROP; }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
