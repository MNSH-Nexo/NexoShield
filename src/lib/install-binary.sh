# nx_install_binary - the ONLY copy in the repository (included at build time).
# @lib-body
# nx_install_binary SRC DEST [MODE]
# Atomically replace DEST with SRC: copy to a staging file in the
# SAME directory, then rename over DEST. A plain `cp` onto a
# RUNNING executable fails with ETXTBSY ("Text file busy") - this
# broke 3proxy Install/Update on every live server (v3.16.0 field
# report: the service runs from /usr/local/bin/3proxy while the
# update tried to overwrite that very file). rename(2) swaps the
# path instantly; the running process keeps its old inode and is
# undisturbed until its service restarts onto the new binary.
nx_install_binary() {
    local src="$1" dst="$2" mode="${3:-755}" tmp
    tmp="${dst}.new.$$"
    if cp "$src" "$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$dst"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}
