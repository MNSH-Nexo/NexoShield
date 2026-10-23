/*
 * nx-xdp — loader/sync tool for the NexoShield XDP shield (Phase 3).
 *
 *   nx-xdp load <iface> <obj.o>   attach (native, else generic), pin maps
 *   nx-xdp unload <iface>         detach + unpin
 *   nx-xdp sync-bans <file>       lines: <ip|cidr> <ttl_seconds>
 *   nx-xdp sync-exempt <file>     lines: <ip|cidr>
 *   nx-xdp stats                  syn= drops= exempt_pass= (per-CPU sums)
 *   nx-xdp check <bans> <exempt>  parse-only validation (no BPF touched)
 *
 * Maps are pinned under /sys/fs/bpf/nexoshield so the daemon can
 * re-sync ban state while the program is attached without holding
 * the object open. Ban values are CLOCK_MONOTONIC nanosecond expiry
 * stamps, exactly what the XDP program compares against
 * bpf_ktime_get_ns().
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PIN_DIR "/sys/fs/bpf/nexoshield"

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── sync-file parsing (shared by check + sync; unit-testable) ── */
typedef struct {
    int family;              /* AF_INET / AF_INET6 */
    int prefix;              /* 0..32 / 0..128 */
    uint8_t addr[16];
    uint64_t ttl;            /* bans only */
} Entry;

static int parse_cidr(const char *text, int *family, int *prefix, uint8_t *addr)
{
    char buf[128];
    snprintf(buf, sizeof buf, "%s", text);
    char *slash = strchr(buf, '/');
    int pfx = -1;
    if (slash) { *slash = 0; pfx = atoi(slash + 1); }
    if (strchr(buf, ':')) {
        if (inet_pton(AF_INET6, buf, addr) != 1) return -1;
        if (pfx < 0) pfx = 128;
        if (pfx > 128) return -1;
        *family = AF_INET6;
    } else {
        if (inet_pton(AF_INET, buf, addr) != 1) return -1;
        if (pfx < 0) pfx = 32;
        if (pfx > 32) return -1;
        *family = AF_INET;
    }
    *prefix = pfx;
    return 0;
}

/* Returns entry count, or -1 with *badline set (1-based). */
static int parse_file(const char *path, int with_ttl, Entry *out, int max, int *badline)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[256], cidr[128], extra[64];
    unsigned long long ttl;
    int n = 0, ln = 0;
    while (fgets(line, sizeof line, fp)) {
        ln++;
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        int got = with_ttl ? sscanf(line, " %127s %llu %63s", cidr, &ttl, extra)
                           : sscanf(line, " %127s %63s", cidr, extra);
        if (got <= 0) continue;                    /* blank/comment */
        if (with_ttl && got != 2) { *badline = ln; fclose(fp); return -1; }
        if (!with_ttl && got != 1) { *badline = ln; fclose(fp); return -1; }
        if (n >= max) { *badline = ln; fclose(fp); return -1; }
        Entry *e = &out[n];
        memset(e, 0, sizeof *e);
        if (parse_cidr(cidr, &e->family, &e->prefix, e->addr) != 0) {
            *badline = ln; fclose(fp); return -1;
        }
        e->ttl = with_ttl ? ttl : 0;
        n++;
    }
    fclose(fp);
    return n;
}

static int cmd_check(const char *bans_path, const char *exempt_path)
{
    static Entry entries[65536];
    int bad = 0;
    int nb = parse_file(bans_path, 1, entries, 65536, &bad);
    if (nb < 0) { fprintf(stderr, "check: %s: invalid (line %d or unreadable)\n", bans_path, bad); return 1; }
    int ne = parse_file(exempt_path, 0, entries, 65536, &bad);
    if (ne < 0) { fprintf(stderr, "check: %s: invalid (line %d or unreadable)\n", exempt_path, bad); return 1; }
    printf("bans=%d exempt=%d\n", nb, ne);
    return 0;
}

/* ── map helpers ── */
static int open_pinned(const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", PIN_DIR, name);
    int fd = bpf_obj_get(path);
    if (fd < 0) fprintf(stderr, "nx-xdp: cannot open pinned map %s (shield attached?)\n", path);
    return fd;
}

static void clear_map(int fd, size_t key_size)
{
    uint8_t *key = calloc(1, key_size), *next = calloc(1, key_size);
    if (!key || !next) { free(key); free(next); return; }
    int first = 1;
    /* collect-then-delete: deleting while iterating an LPM trie is unsafe */
    size_t cap = 1024, cnt = 0;
    uint8_t *all = malloc(cap * key_size);
    if (!all) { free(key); free(next); return; }
    while (bpf_map_get_next_key(fd, first ? NULL : key, next) == 0) {
        memcpy(key, next, key_size);
        first = 0;
        if (cnt == cap) { cap *= 2; all = realloc(all, cap * key_size); if (!all) { free(key); free(next); return; } }
        memcpy(all + cnt * key_size, next, key_size);
        cnt++;
    }
    for (size_t i = 0; i < cnt; i++) bpf_map_delete_elem(fd, all + i * key_size);
    free(key); free(next); free(all);
}

static int sync_map(const char *map_name, const Entry *entries, int n, int is_ban, size_t key_size)
{
    int fd = open_pinned(map_name);
    if (fd < 0) return 1;
    clear_map(fd, key_size);
    uint64_t now = mono_ns();
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const Entry *e = &entries[i];
        uint8_t key[20];
        memset(key, 0, sizeof key);
        uint32_t pfx = (uint32_t)e->prefix;
        memcpy(key, &pfx, 4);
        if (e->family == AF_INET) memcpy(key + 4, e->addr, 4);
        else memcpy(key + 4, e->addr, 16);
        if (is_ban) {
            uint64_t exp = now + e->ttl * 1000000000ULL;
            if (bpf_map_update_elem(fd, key, &exp, BPF_ANY) != 0) rc = 1;
        } else {
            uint32_t one = 1;
            if (bpf_map_update_elem(fd, key, &one, BPF_ANY) != 0) rc = 1;
        }
    }
    close(fd);
    return rc;
}

static int cmd_sync(const char *path, int is_ban)
{
    static Entry entries[65536];
    int bad = 0;
    int n = parse_file(path, is_ban, entries, 65536, &bad);
    if (n < 0) { fprintf(stderr, "nx-xdp: %s invalid (line %d)\n", path, bad); return 1; }
    int rc = 0, v4 = 0, v6 = 0;
    static Entry fam4[65536], fam6[65536];
    for (int i = 0; i < n; i++)
        if (entries[i].family == AF_INET) fam4[v4++] = entries[i];
        else fam6[v6++] = entries[i];
    if (sync_map(is_ban ? "ban4" : "exempt4", fam4, v4, is_ban, 8) != 0) rc = 1;
    if (sync_map(is_ban ? "ban6" : "exempt6", fam6, v6, is_ban, 20) != 0) rc = 1;
    if (!rc) printf("synced %s: %d entries\n", is_ban ? "bans" : "exempt", n);
    return rc;
}

static int cmd_load(const char *iface, const char *obj_path)
{
    unsigned ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "nx-xdp: no such interface %s\n", iface); return 1; }
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) { fprintf(stderr, "nx-xdp: cannot open %s\n", obj_path); return 1; }
    if (bpf_object__load(obj) != 0) { fprintf(stderr, "nx-xdp: cannot load %s\n", obj_path); return 1; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "nx_xdp_prog");
    if (!prog) { fprintf(stderr, "nx-xdp: program not found in %s\n", obj_path); return 1; }
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    const char *mode = "native";
    if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_DRV_MODE, NULL) != 0) {
        if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL) != 0) {
            fprintf(stderr, "nx-xdp: attach failed on %s (native and generic)\n", iface);
            return 1;
        }
        mode = "generic";
    }
    mkdir(PIN_DIR, 0755);
    const char *names[5] = { "ban4", "ban6", "exempt4", "exempt6", "counters" };
    for (int i = 0; i < 5; i++) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, names[i]);
        if (!m) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", PIN_DIR, names[i]);
        unlink(path);
        bpf_map__pin(m, path);
    }
    printf("attached %s (%s mode)\n", iface, mode);
    return 0;
}

static int cmd_unload(const char *iface)
{
    unsigned ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "nx-xdp: no such interface %s\n", iface); return 1; }
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    const char *names[5] = { "ban4", "ban6", "exempt4", "exempt6", "counters" };
    for (int i = 0; i < 5; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", PIN_DIR, names[i]);
        unlink(path);
    }
    rmdir(PIN_DIR);
    printf("detached %s\n", iface);
    return 0;
}

static int cmd_stats(void)
{
    int fd = open_pinned("counters");
    if (fd < 0) return 1;
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 1) cpus = 1;
    uint64_t *vals = calloc((size_t)cpus, sizeof(uint64_t));
    if (!vals) { close(fd); return 1; }
    uint64_t sums[3] = {0, 0, 0};
    for (uint32_t k = 0; k < 3; k++) {
        if (bpf_map_lookup_elem(fd, &k, vals) == 0)
            for (int c = 0; c < cpus; c++) sums[k] += vals[c];
    }
    printf("syn=%llu drops=%llu exempt_pass=%llu\n",
           (unsigned long long)sums[0], (unsigned long long)sums[1],
           (unsigned long long)sums[2]);
    free(vals);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (argc >= 2 && !strcmp(argv[1], "check") && argc == 4) return cmd_check(argv[2], argv[3]);
    if (argc >= 2 && !strcmp(argv[1], "sync-bans") && argc == 3) return cmd_sync(argv[2], 1);
    if (argc >= 2 && !strcmp(argv[1], "sync-exempt") && argc == 3) return cmd_sync(argv[2], 0);
    if (argc >= 2 && !strcmp(argv[1], "load") && argc == 4) return cmd_load(argv[2], argv[3]);
    if (argc >= 2 && !strcmp(argv[1], "unload") && argc == 3) return cmd_unload(argv[2]);
    if (argc >= 2 && !strcmp(argv[1], "stats") && argc == 2) return cmd_stats();
    fprintf(stderr, "usage: nx-xdp load <iface> <obj> | unload <iface> | sync-bans <file> | sync-exempt <file> | stats | check <bans> <exempt>\n");
    return 2;
}
