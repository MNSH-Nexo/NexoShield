
# ── Permissions ───────────────────────────────────────────
chmod +x "$INSTALL_DIR/3proxy-socks5.sh" \
         "$INSTALL_DIR/optimize-sysctl.sh" \
         "$INSTALL_DIR/proxy-menu.sh" \
         "$INSTALL_DIR/antiddos.sh"
ok "Files created"

# ── Link proxy command ────────────────────────────────────
info "Installing proxy command..."
ln -sf "$INSTALL_DIR/proxy-menu.sh" "$BIN_LINK"
chmod +x "$BIN_LINK"
ok "Command ${W}proxy${NC} installed"

# ── Final result ──────────────────────────────────────────
echo ""
sep
echo -e "  ${G}${BOLD}✓ Installation complete! v${VERSION}${NC}"
sep
echo -e "  Install path : ${DIM}$INSTALL_DIR${NC}"
echo -e "  Command      : ${W}${BOLD}proxy${NC}"
echo -e "  Install log  : ${DIM}$LOG${NC}"
echo ""
echo -e "  ${C}Scripts installed:${NC}"
echo -e "  ${DIM}->${NC}  3proxy-socks5.sh    (SOCKS5 proxy + CF unlimited)"
echo -e "  ${DIM}->${NC}  optimize-sysctl.sh  (kernel optimization)"
echo -e "  ${DIM}->${NC}  antiddos.sh         (5-layer DDoS protection)"
echo -e "  ${DIM}->${NC}  proxy-menu.sh       (main control panel)"
echo ""
echo -e "  ${C}Run now:${NC}"
echo -e "  ${W}${BOLD}  proxy${NC}"
sep

