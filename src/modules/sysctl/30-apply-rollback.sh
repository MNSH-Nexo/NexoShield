# @part modules/sysctl/30-apply-rollback.sh - apply_config + do_rollback
# Assembled into optimize-sysctl.sh by tools/build.py - not a standalone script.
apply_config() {
    FAILED_PARAMS=(); APPLIED_COUNT=0; SKIPPED_COUNT=0
    modprobe tcp_bbr 2>/dev/null || true
    modprobe nf_conntrack 2>/dev/null || true

    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
        VAL=$(echo "$line" | cut -d= -f2- | tr -d ' ')
        [ -z "$KEY" ] || [ -z "$VAL" ] && continue
        if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
            APPLIED_COUNT=$((APPLIED_COUNT + 1))
        else
            FAILED_PARAMS+=("$KEY=$VAL")
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            sed -i "s|^${KEY} = |# [DISABLED] ${KEY} = |g" "$TARGET_FILE" 2>/dev/null || true
        fi
    done < "$TARGET_FILE"

    [ ${#FAILED_PARAMS[@]} -gt 0 ] && warn "${#FAILED_PARAMS[@]} params auto-disabled (virt limits)"
    success "$APPLIED_COUNT applied${SKIPPED_COUNT:+, $SKIPPED_COUNT skipped}"
}

do_rollback() {
    sep; echo -e "  ${CYAN}${BOLD}Rollback${NC}"; sep

    # ── Find snapshots ────────────────────────────────────
    SNAPSHOTS=()
    while IFS= read -r d; do
        [ -d "$SNAPSHOT_DIR/$d" ] && SNAPSHOTS+=("$d")
    done < <(ls -1t "$SNAPSHOT_DIR" 2>/dev/null | head -10)

    if [ ${#SNAPSHOTS[@]} -eq 0 ]; then
        err "No snapshots found in $SNAPSHOT_DIR"
        echo -e "  ${DIM}Snapshots are created automatically before each install.${NC}"
        return
    fi

    # ── List snapshots ────────────────────────────────────
    echo -e "  Available snapshots:"
    echo ""
    for i in "${!SNAPSHOTS[@]}"; do
        DATE=$(grep '^DATE=' "$SNAPSHOT_DIR/${SNAPSHOTS[$i]}/meta.txt" 2>/dev/null | \
            cut -d= -f2- || echo "${SNAPSHOTS[$i]}")
        # Mark if this was a pre-install snapshot
        HAS_KEYS=""; [ -f "$SNAPSHOT_DIR/${SNAPSHOTS[$i]}/our_keys.txt" ] && HAS_KEYS=" ${DIM}(targeted)${NC}"
        echo -e "  ${CYAN}$((i+1)).${NC} ${SNAPSHOTS[$i]}  ${DIM}$DATE${NC}${HAS_KEYS}"
    done
    echo ""

    # ── Select ────────────────────────────────────────────
    printf '%s' "  Which snapshot? (1-${#SNAPSHOTS[@]}, default 1): " >/dev/tty
    read -r CH </dev/tty || CH="1"
    CH=${CH:-1}
    if ! [[ "$CH" =~ ^[0-9]+$ ]] || [ "$CH" -lt 1 ] || [ "$CH" -gt ${#SNAPSHOTS[@]} ]; then
        err "Invalid selection: '$CH'"
        return
    fi

    SELECTED="${SNAPSHOTS[$((CH-1))]}"
    SPATH="$SNAPSHOT_DIR/$SELECTED"
    DATE_SEL=$(grep '^DATE=' "$SPATH/meta.txt" 2>/dev/null | cut -d= -f2- || echo "$SELECTED")

    echo ""
    echo -e "  Snapshot : ${CYAN}$SELECTED${NC}"
    echo -e "  Date     : $DATE_SEL"
    echo ""

    # ── Confirm ───────────────────────────────────────────
    printf '%s' "  Confirm rollback? (y/N): " >/dev/tty
    read -r CF </dev/tty || CF=""
    [[ "$CF" != "y" && "$CF" != "Y" ]] && echo "  Cancelled." && return

    echo ""
    info "Starting rollback to $SELECTED..."

    # ── Step 1: Remove our config file ───────────────────
    rm -f "$TARGET_FILE"
    success "Removed: $TARGET_FILE"

    # ── Step 2: Remove any of OUR config files added after this snapshot ──
    # TARGET_FILE was already removed above. This also catches leftover files
    # from OLDER installs of this script that are NOT in the snapshot's list,
    # without touching unrelated system files in /etc/sysctl.d/.
    if [ -f "$SPATH/sysctl_d_list.txt" ]; then
        local TBASE
        TBASE="$(basename "$TARGET_FILE")"
        while IFS= read -r CURF; do
            [ -z "$CURF" ] && continue
            # Only remove files that belong to OUR script (match TARGET_FILE name
            # or the standard 99-vpn pattern) AND were not present in snapshot.
            if ! grep -qxF "$CURF" "$SPATH/sysctl_d_list.txt" 2>/dev/null; then
                case "$CURF" in
                    "$TBASE"|99-vpn-*.conf)
                        rm -f "/etc/sysctl.d/$CURF" 2>/dev/null && \
                            success "Removed stale: /etc/sysctl.d/$CURF" || true
                        ;;
                esac
            fi
        done < <(ls /etc/sysctl.d/ 2>/dev/null)
    fi

    # ── Step 3: Restore .conf files from snapshot ────────
    if [ -f "$SPATH/sysctl.conf" ]; then
        cp "$SPATH/sysctl.conf" /etc/sysctl.conf 2>/dev/null && \
            success "Restored: /etc/sysctl.conf" || warn "Could not restore sysctl.conf"
    fi
    # Only restore sysctl.d files that existed in snapshot (don't add new ones)
    if [ -d "$SPATH/sysctl.d" ]; then
        for f in "$SPATH/sysctl.d/"*.conf; do
            [ -f "$f" ] || continue
            BNAME="$(basename "$f")"
            # Don't restore our own file (already deleted above)
            [ "$BNAME" = "$(basename "$TARGET_FILE")" ] && continue
            cp "$f" "/etc/sysctl.d/$BNAME" 2>/dev/null && \
                success "Restored: /etc/sysctl.d/$BNAME" || \
                warn "Could not restore: $BNAME"
        done
    fi

    # ── Step 4: Re-apply sysctl values live ──────────────
    # Use our_keys.txt (targeted — only keys we changed)
    # Fall back to sysctl_values.txt only if our_keys.txt missing (old snapshot)
    R=0; F=0; SKIP=0
    KEYS_FILE=""
    [ -f "$SPATH/our_keys.txt" ] && KEYS_FILE="$SPATH/our_keys.txt"

    if [ -n "$KEYS_FILE" ]; then
        info "Applying targeted rollback (${KEYS_FILE##*/})..."
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line//[[:space:]]/}" ]] && continue
            KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
            VAL=$(echo "$line" | cut -d= -f2- | sed 's/^[[:space:]]*//')
            [ -z "$KEY" ] || [ -z "$VAL" ] && SKIP=$((SKIP+1)) && continue
            if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
                R=$((R+1))
            else
                warn "Could not set: $KEY=$VAL"
                F=$((F+1))
            fi
        done < "$KEYS_FILE"
    else
        # Old snapshot: parse sysctl_values.txt — but ONLY apply our known keys
        info "Old snapshot — applying known keys from sysctl_values.txt..."
        KNOWN_KEYS="net.core.rmem_max net.core.wmem_max net.core.default_qdisc \
            net.ipv4.tcp_congestion_control net.ipv4.tcp_keepalive_time \
            net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_tw_reuse \
            net.ipv4.tcp_fin_timeout net.ipv4.tcp_max_orphans \
            vm.swappiness net.core.somaxconn net.ipv4.tcp_syncookies"
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line//[[:space:]]/}" ]] && continue
            KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
            VAL=$(echo "$line" | cut -d= -f2- | sed 's/^[[:space:]]*//')
            [ -z "$KEY" ] || [ -z "$VAL" ] && continue
            echo "$KNOWN_KEYS" | grep -qw "$KEY" || { SKIP=$((SKIP+1)); continue; }
            if sysctl -w "${KEY}=${VAL}" >/dev/null 2>&1; then
                R=$((R+1))
            else
                F=$((F+1))
            fi
        done < "$SPATH/sysctl_values.txt"
    fi

    sep
    success "Rollback complete — $R restored${F:+, $F failed}${SKIP:+ ($SKIP skipped)}"
    echo -e "  ${YELLOW}Note: Reboot to fully confirm all settings took effect.${NC}"
    sep
}

