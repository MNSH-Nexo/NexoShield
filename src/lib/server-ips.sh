# get_server_ips was removed in v3.18.0 (F9): defined here but never
# called anywhere - the sweep over src/ and tests/ found only these
# comments mentioning it. Display lookups live in
# modules/3proxy/00-header.sh (get_server_ip); enforcement uses
# list_self_ips_all in lib/self-ips.sh.
# @lib-body
# (intentionally empty: the only function this lib held was removed - see above)
