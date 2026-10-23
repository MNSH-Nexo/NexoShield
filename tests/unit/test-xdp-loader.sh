#!/usr/bin/env bash
# Phase 3a: the nx-xdp loader. Compiled against the real libbpf when
# present, otherwise against generated stub headers implementing the
# same API surface as graceful failures — either way the sync-file
# parser (check command) is exercised for real, and sync against
# missing pinned maps must fail cleanly, never crash.
set -uo pipefail
cd "$(dirname "$0")/../.."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }

mkdir -p "$TMP/inc/bpf"
if [ -f /usr/include/bpf/libbpf.h ]; then
    cc -O2 -Wall -o "$TMP/nx-xdp" src/native/nx-xdp-loader.c -lbpf 2>"$TMP/cc.log" \
        || { cat "$TMP/cc.log"; bad "loader must compile against real libbpf"; echo "xdp loader (Phase 3a): $pass passed, $fail failed"; exit 1; }
    echo "  (compiled against real libbpf)"
else
    cat > "$TMP/inc/bpf/libbpf.h" <<'EOF'
#pragma once
#include <stdint.h>
#include <stddef.h>
struct bpf_object; struct bpf_program; struct bpf_map;
enum libbpf_strict_mode { LIBBPF_STRICT_ALL = 0xffff };
int libbpf_set_strict_mode(enum libbpf_strict_mode mode);
struct bpf_object *bpf_object__open_file(const char *path, void *opts);
int bpf_object__load(struct bpf_object *obj);
struct bpf_program *bpf_object__find_program_by_name(struct bpf_object *obj, const char *name);
struct bpf_map *bpf_object__find_map_by_name(struct bpf_object *obj, const char *name);
int bpf_program__fd(struct bpf_program *prog);
int bpf_map__pin(struct bpf_map *map, const char *path);
int libbpf_num_possible_cpus(void);
EOF
    cat > "$TMP/inc/bpf/bpf.h" <<'EOF'
#pragma once
#include <stdint.h>
#include <stddef.h>
#define BPF_ANY 0
#define XDP_FLAGS_SKB_MODE 2
#define XDP_FLAGS_DRV_MODE 4
int bpf_xdp_attach(int ifindex, int fd, uint32_t flags, void *opts);
int bpf_xdp_detach(int ifindex, uint32_t flags, void *opts);
int bpf_obj_get(const char *pathname);
int bpf_map_get_next_key(int fd, const void *key, void *next_key);
int bpf_map_delete_elem(int fd, const void *key);
int bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags);
int bpf_map_lookup_elem(int fd, const void *key, void *value);
EOF
    cat > "$TMP/stubs.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
enum libbpf_strict_mode { LIBBPF_STRICT_ALL = 0xffff };
int libbpf_set_strict_mode(enum libbpf_strict_mode mode) { (void)mode; return 0; }
void *bpf_object__open_file(const char *p, void *o) { (void)p; (void)o; return NULL; }
int bpf_object__load(void *o) { (void)o; return -1; }
void *bpf_object__find_program_by_name(void *o, const char *n) { (void)o; (void)n; return NULL; }
void *bpf_object__find_map_by_name(void *o, const char *n) { (void)o; (void)n; return NULL; }
int bpf_program__fd(void *p) { (void)p; return -1; }
int bpf_map__pin(void *m, const char *p) { (void)m; (void)p; return -1; }
int libbpf_num_possible_cpus(void) { return 1; }
int bpf_xdp_attach(int i, int f, uint32_t fl, void *o) { (void)i; (void)f; (void)fl; (void)o; return -1; }
int bpf_xdp_detach(int i, uint32_t fl, void *o) { (void)i; (void)fl; (void)o; return -1; }
int bpf_obj_get(const char *p) { (void)p; return -1; }
int bpf_map_get_next_key(int f, const void *k, void *n) { (void)f; (void)k; (void)n; return -1; }
int bpf_map_delete_elem(int f, const void *k) { (void)f; (void)k; return -1; }
int bpf_map_update_elem(int f, const void *k, const void *v, uint64_t fl) { (void)f; (void)k; (void)v; (void)fl; return -1; }
int bpf_map_lookup_elem(int f, const void *k, void *v) { (void)f; (void)k; (void)v; return -1; }
EOF
    cc -O2 -Wall -I"$TMP/inc" -o "$TMP/nx-xdp" src/native/nx-xdp-loader.c "$TMP/stubs.c" 2>"$TMP/cc.log" \
        || { cat "$TMP/cc.log"; bad "loader must compile against the stub API"; echo "xdp loader (Phase 3a): $pass passed, $fail failed"; exit 1; }
    echo "  (compiled against stub libbpf — parser exercised, BPF calls fail-soft)"
fi
ok

printf '%s\n' "# comment" "" "1.2.3.4 300" "2001:db8::/32 60" "5.6.7.0/24 120" > "$TMP/bans.txt"
printf '%s\n' "10.0.0.1" "173.245.48.0/20" "2001:db8::99" > "$TMP/exempt.txt"
OUT="$("$TMP/nx-xdp" check "$TMP/bans.txt" "$TMP/exempt.txt" 2>&1)" && RC=0 || RC=$?
[ "$RC" -eq 0 ] && [ "$OUT" = "bans=3 exempt=3" ] && ok || bad "check valid files (rc=$RC out='$OUT')"

printf '%s\n' "not-an-ip 30" > "$TMP/bad1.txt"
"$TMP/nx-xdp" check "$TMP/bad1.txt" "$TMP/exempt.txt" >/dev/null 2>&1 && bad "invalid IP must fail check" || ok
printf '%s\n' "1.2.3.4" > "$TMP/bad2.txt"
"$TMP/nx-xdp" check "$TMP/bad2.txt" "$TMP/exempt.txt" >/dev/null 2>&1 && bad "missing TTL must fail check" || ok
printf '%s\n' "1.2.3.4/33 30" > "$TMP/bad3.txt"
"$TMP/nx-xdp" check "$TMP/bad3.txt" "$TMP/exempt.txt" >/dev/null 2>&1 && bad "impossible prefix must fail check" || ok

"$TMP/nx-xdp" sync-bans "$TMP/bans.txt" >/dev/null 2>&1 && bad "sync without pinned maps must fail" || ok
"$TMP/nx-xdp" stats >/dev/null 2>&1 && bad "stats without pinned maps must fail" || ok
"$TMP/nx-xdp" 2>/dev/null && bad "bare invocation must exit non-zero" || ok

echo "xdp loader (Phase 3a): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
