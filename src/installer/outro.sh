
# ── Activate staged module scripts (BUG-025) ───────────────
# Each module was written to a staging name. Verify ALL of them first;
# if any is broken, keep the previous install untouched and abort.
for _NXF in 3proxy-socks5.sh optimize-sysctl.sh proxy-menu.sh antiddos.sh; do
    _NXSTAGED="$INSTALL_DIR/.$_NXF.nxnew"
    if [ ! -s "$_NXSTAGED" ] || ! bash -n "$_NXSTAGED" 2>/dev/null; then
        err "Staged script $_NXF is missing or invalid - previous install left untouched."
        rm -f "$INSTALL_DIR"/.*.nxnew
        exit 1
    fi
done
for _NXF in 3proxy-socks5.sh optimize-sysctl.sh proxy-menu.sh antiddos.sh; do
    [ -f "$INSTALL_DIR/$_NXF" ] && \
        cp -a "$INSTALL_DIR/$_NXF" "$INSTALL_DIR/$_NXF.prev" 2>/dev/null || true
    mv "$INSTALL_DIR/.$_NXF.nxnew" "$INSTALL_DIR/$_NXF"
done
ok "Module scripts verified and activated (previous versions kept as *.prev)"

# ── Permissions ───────────────────────────────────────────
chmod +x "$INSTALL_DIR/3proxy-socks5.sh" \
         "$INSTALL_DIR/optimize-sysctl.sh" \
         "$INSTALL_DIR/proxy-menu.sh" \
         "$INSTALL_DIR/antiddos.sh"
ok "Files created"

# ── Link shield command ───────────────────────────────────
# LOW-4: the BUG-058 guard for the old 'proxy' link, applied to the
# new name too - never silently replace a foreign /usr/local/bin/
# shield (another tool, a user's script). Replace only when absent,
# already ours, or a NexoShield menu from a previous install.
info "Installing shield command..."
if [ -e "$BIN_LINK" ] && [ ! -L "$BIN_LINK" ]; then
    warn "$BIN_LINK exists and is not a symlink - leaving it untouched; run $INSTALL_DIR/proxy-menu.sh directly."
elif [ -L "$BIN_LINK" ] && [ "$(readlink "$BIN_LINK" 2>/dev/null)" != "$INSTALL_DIR/proxy-menu.sh" ] && \
     [ "$(readlink "$BIN_LINK" 2>/dev/null)" != "$INSTALL_DIR/proxy-menu.sh.prev" ]; then
    warn "$BIN_LINK points elsewhere ($(readlink "$BIN_LINK" 2>/dev/null)) - leaving it untouched; run $INSTALL_DIR/proxy-menu.sh directly."
else
    ln -sf "$INSTALL_DIR/proxy-menu.sh" "$BIN_LINK"
    chmod +x "$BIN_LINK"
    ok "Command ${W}shield${NC} installed"
fi
# Pre-v3.11 installs linked the menu as /usr/local/bin/proxy. Drop
# that link on upgrade - but only if it is OURS (a symlink to this
# menu); never touch a foreign binary of the same name (BUG-058).
if [ "/usr/local/bin/proxy" != "$BIN_LINK" ] && [ -L /usr/local/bin/proxy ] && \
   [ "$(readlink /usr/local/bin/proxy 2>/dev/null)" = "$INSTALL_DIR/proxy-menu.sh" ]; then
    rm -f /usr/local/bin/proxy
    info "Removed the old 'proxy' command link (the menu is 'shield' now)"
fi

# ── Final result ──────────────────────────────────────────
echo ""
sep
echo -e "  ${G}${BOLD}✓ Installation complete! v${VERSION}${NC}"
sep
echo -e "  Install path : ${DIM}$INSTALL_DIR${NC}"
echo -e "  Command      : ${W}${BOLD}shield${NC}"
echo -e "  Install log  : ${DIM}$LOG${NC}"
echo ""
echo -e "  ${C}Scripts installed:${NC}"
echo -e "  ${DIM}->${NC}  3proxy-socks5.sh    (SOCKS5 proxy + CF unlimited)"
echo -e "  ${DIM}->${NC}  optimize-sysctl.sh  (kernel optimization)"
echo -e "  ${DIM}->${NC}  antiddos.sh         (5-layer DDoS protection)"
echo -e "  ${DIM}->${NC}  proxy-menu.sh       (main control panel)"
echo ""
echo -e "  ${C}Run now:${NC}"
echo -e "  ${W}${BOLD}  shield${NC}"
sep

