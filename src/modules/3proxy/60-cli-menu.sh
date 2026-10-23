# @part modules/3proxy/60-cli-menu.sh - show_info, show_stats, show_menu, CLI dispatch + standalone loop
# Assembled into 3proxy-socks5.sh by tools/build.py - not a standalone script.
show_info() {
    [ ! -f /etc/3proxy/install.info ] && echo -e "${RED}Not installed.${NC}" && return
    local _INFO_USER _INFO_PASS _INFO_PORT
    _INFO_USER=$(grep '^USER=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    _INFO_PASS=$(grep '^PASS=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    _INFO_PORT=$(grep '^PORT=' /etc/3proxy/install.info 2>/dev/null | cut -d= -f2- || echo "?")
    SERVER_IP=$(get_server_ip)
    sep
    echo -e "  ${CYAN}Connection info:${NC}"; sep
    echo -e "  socks5://${_INFO_USER:-?}:${_INFO_PASS:-?}@$SERVER_IP:${_INFO_PORT:-?}"
    # (No IPv6 form: 3proxy binds 0.0.0.0 only - BUG-059.)
    sep
}

show_stats() {
    PORT=$(get_current_port || true)
    [ -z "$PORT" ] && echo -e "${RED}Not installed.${NC}" && return
    sep; echo -e "  ${CYAN}Stats - port $PORT${NC}"; sep
    ACTIVE=$(ss -tnp 2>/dev/null | grep ":$PORT " | grep -v LISTEN | wc -l || echo 0)
    echo -e "  Active connections: ${GREEN}$ACTIVE${NC}"

    IN_B=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "3proxy_stats_in" | awk '{print $2}' | head -1)
    OUT_B=$(iptables -L OUTPUT -v -n -x 2>/dev/null | grep "3proxy_stats_out" | awk '{print $2}' | head -1)

    _fmt() {
        # Format bytes without depending on `bc` (absent on some systems → used to show blank)
        awk -v n="${1:-0}" 'BEGIN{
            if (n>=1073741824) printf "%.2f GB\n", n/1073741824;
            else if (n>=1048576) printf "%.2f MB\n", n/1048576;
            else if (n>=1024) printf "%.2f KB\n", n/1024;
            else printf "%d B\n", n;
        }'
    }
    # 3proxy_stats_in  = bytes clients SENT to proxy (upload)
    # 3proxy_stats_out = bytes proxy   SENT to clients (download)
    echo -e "  Download (proxy -> client): ${GREEN}$(_fmt "$OUT_B")${NC}"
    echo -e "  Upload   (client -> proxy): ${GREEN}$(_fmt "$IN_B")${NC}"

    # tc stats
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -n "$MAIN_IF" ] && command -v tc >/dev/null 2>&1; then
        echo ""
        echo -e "  ${CYAN}Bandwidth classes (tc):${NC}"
        tc -s class show dev "$MAIN_IF" 2>/dev/null | \
            grep -A2 "class htb" | grep -E "class htb|bytes" | \
            paste - - | awk -F'\t' '{printf "  %-30s %s\n", $1, $2}' | head -6 || true
    fi

    [ -f "$PROXY_LOG_DIR/access.log" ] && {
        echo ""
        echo -e "  ${CYAN}Last 10 connections:${NC}"
        tail -10 "$PROXY_LOG_DIR/access.log" 2>/dev/null || true
    }
    sep
    printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true
}

show_menu() {
    clear; sep; echo -e "  ${CYAN}3proxy SOCKS5 Manager${NC}"; sep
    is_installed && {
        PORT=$(get_current_port || true)
        ST=$(systemctl is-active 3proxy 2>/dev/null || echo "unknown")
        [ "$ST" = "active" ] && \
            echo -e "  Status: ${GREEN}● Running${NC}  Port: ${CYAN}$PORT${NC}" || \
            echo -e "  Status: ${RED}● Stopped${NC}  Port: ${CYAN}$PORT${NC}"
        sep
    }
    echo -e "  ${CYAN}1.${NC} Install/Update   ${CYAN}2.${NC} Remove"
    echo -e "  ${CYAN}3.${NC} Stop             ${CYAN}4.${NC} Restart"
    echo -e "  ${CYAN}5.${NC} Traffic stats    ${CYAN}6.${NC} Connection info"
    echo -e "  ${CYAN}7.${NC} Live log         ${CYAN}8.${NC} tc bandwidth status"
    echo -e "  ${CYAN}0.${NC} Back"
    sep
}

# ── CLI flags (called from proxy-menu.sh) ────────────────
case "${1:-}" in
    --install|-i) install_proxy;  exit 0 ;;
    --remove|-r)  uninstall_proxy; exit 0 ;;
    --stats|-s)   show_stats;      exit 0 ;;
    --info)       show_info; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; exit 0 ;;
    --restart)    systemctl restart 3proxy 2>/dev/null && \
                      echo -e "${GREEN}Restarted${NC}" || echo -e "${RED}Error${NC}"; exit 0 ;;
    --stop)       systemctl stop 3proxy 2>/dev/null && \
                      echo -e "${GREEN}Stopped${NC}" || echo -e "${RED}Error${NC}"; exit 0 ;;
    --start)      systemctl start 3proxy 2>/dev/null && \
                      echo -e "${GREEN}Started${NC}" || echo -e "${RED}Error${NC}"; exit 0 ;;
    --log)        tail -f "$PROXY_LOG_DIR/access.log" 2>/dev/null || \
                      journalctl -u 3proxy -f --no-pager; exit 0 ;;
    --tc-status)  MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
                  echo -e "${CYAN}tc classes on ${MAIN_IF:-eth0}:${NC}"
                  tc class show dev "${MAIN_IF:-eth0}" 2>/dev/null || echo "tc not configured"
                  printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true; exit 0 ;;
    --change-pass)
                  NEW_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16)
                  if [ -z "$NEW_PASS" ]; then
                      echo -e "${RED}Failed to generate a secure password (/dev/urandom unavailable). Aborting.${NC}" >&2
                      exit 1
                  fi
                  CU=$(grep -oP '(?<=allow )\S+' "$PROXY_CONF" 2>/dev/null | head -1 || echo "")
                  if [ -n "$CU" ]; then
                      echo "users ${CU}:CL:${NEW_PASS}" > "$PROXY_USERS"
                      [ -f /etc/3proxy/install.info ] && \
                          sed -i "s/^PASS=.*/PASS=${NEW_PASS}/" /etc/3proxy/install.info 2>/dev/null || true
                      systemctl restart 3proxy 2>/dev/null && \
                          echo -e "${GREEN}Password changed: ${NEW_PASS}${NC}" || \
                          echo -e "${RED}Restart failed${NC}"
                  else
                      echo -e "${RED}Not installed${NC}"
                  fi
                  exit 0 ;;
esac

# Standalone mode (run directly without args): show own menu
while true; do
    show_menu
    printf '%s' "  Enter choice: " >/dev/tty; read -r CH </dev/tty || CH=""
    case "$CH" in
        1) install_proxy; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        2) printf '%s' "  Remove 3proxy completely? (y/N): " >/dev/tty; read -r _RC2 </dev/tty || _RC2=""
           [[ "$_RC2" == "y" || "$_RC2" == "Y" ]] && uninstall_proxy || echo -e "  ${DIM}Cancelled.${NC}" ;;
        3) systemctl stop 3proxy 2>/dev/null && \
               echo -e "${GREEN}Stopped${NC}" || \
               echo -e "${RED}Error stopping${NC}"; sleep 1 ;;
        4) systemctl restart 3proxy 2>/dev/null && \
               echo -e "${GREEN}Restarted${NC}" || \
               echo -e "${RED}Error restarting${NC}"; sleep 1 ;;
        5) show_stats ;;
        6) show_info; printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        7) tail -f "$PROXY_LOG_DIR/access.log" 2>/dev/null || \
               journalctl -u 3proxy -f --no-pager ;;
        8) MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
           echo -e "${CYAN}tc classes on ${MAIN_IF:-eth0}:${NC}"
           tc class show dev "${MAIN_IF:-eth0}" 2>/dev/null || echo "tc not configured"
           printf '%s\n' "  Press Enter to continue..." >/dev/tty; read -r _PE </dev/tty 2>/dev/null || true ;;
        0) exit 0 ;;
    esac
done
