#!/usr/bin/env bash
# Reverse proxy, host side: send every public TCP/UDP port the host does not use itself into the
# GameBond container, which forwards it on to the tunnel client (see container-entrypoint.sh).
#
#   tools/host-forward.sh apply  <container>   install (or refresh) the rules
#   tools/host-forward.sh remove               remove them
#   tools/host-forward.sh show                 print what would be excluded, change nothing
#
# Never forwarded: SSH (22), anything a host process listens on, every port Docker publishes, and any
# extra ports in EXTRA_EXCLUDE_TCP / EXTRA_EXCLUDE_UDP (comma-separated). Rules live in their own nft
# table, "gamebond_exit", so removing it restores the host exactly. Re-run `apply` after the container
# is recreated: its bridge address can change. Run as root on the Docker host.
set -euo pipefail
TABLE=gamebond_exit
TAG=gamebond-reverse-forward

# Remove every DOCKER-USER rule this script added (the container address may have changed).
drop_user_rule() {
    command -v iptables >/dev/null 2>&1 || return 0
    local n
    while n=$(iptables -L DOCKER-USER --line-numbers -n 2>/dev/null | awk -v t="$TAG" '$0 ~ t {print $1; exit}'); [[ -n "$n" ]]; do
        iptables -D DOCKER-USER "$n"
    done
}
cmd=${1:-show}

wan=$(ip -4 route show default | awk 'NR==1{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
[[ -n "$wan" ]] || { echo 'no default route' >&2; exit 1; }

ports() { # proto -> sorted unique list of ports this host or Docker already uses
    local proto=$1 flag
    [[ $proto == tcp ]] && flag=-ltnH || flag=-lunH
    {
        ss $flag | awk '{n=split($4,a,":"); print a[n]}'
        docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | grep -E "/$proto" | sed -E 's/.*:([0-9]+)(-([0-9]+))?->.*/\1/' | grep -E '^[0-9]+$' || true
    } | grep -E '^[0-9]+$' | sort -n | uniq
}

join() { paste -sd, -; }

exclusions() {
    local proto=$1 extra=${2:-}
    { [[ $proto == tcp ]] && echo 22; ports "$proto"; tr ',' '\n' <<< "$extra"; } | grep -E '^[0-9]+$' | sort -n | uniq | join
}

tcp_ex=$(exclusions tcp "${EXTRA_EXCLUDE_TCP:-}")
udp_ex=$(exclusions udp "${EXTRA_EXCLUDE_UDP:-}")

case $cmd in
show)
    echo "wan interface: $wan"
    echo "tcp excluded:  ${tcp_ex:-none}"
    echo "udp excluded:  ${udp_ex:-none}"
    ;;
remove)
    nft delete table ip $TABLE 2>/dev/null || true
    drop_user_rule
    echo 'removed'
    ;;
apply)
    container=${2:?container name required}
    cip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")
    [[ "$cip" =~ ^[0-9.]+$ ]] || { echo "no address for container $container" >&2; exit 1; }
    pub=$(ip -4 -o addr show dev "$wan" | awk '{sub(/\/.*/,"",$4); print $4}' | paste -sd, -)
    [[ -n "$pub" ]] || { echo "no address on $wan" >&2; exit 1; }
    tcp_set=${tcp_ex:-0}
    udp_set=${udp_ex:-0}
    nft delete table ip $TABLE 2>/dev/null || true
    nft -f - <<RULES
add table ip $TABLE
add chain ip $TABLE pre { type nat hook prerouting priority dstnat - 10; policy accept; }
add rule ip $TABLE pre iifname "$wan" ip daddr { $pub } tcp dport != { $tcp_set } dnat to $cip
add rule ip $TABLE pre iifname "$wan" ip daddr { $pub } udp dport != { $udp_set } dnat to $cip
RULES
    # Docker drops new connections from outside to container ports it does not publish (its DOCKER
    # chain), and an accept in another nft table cannot override that. DOCKER-USER runs first, so
    # accept the forwarded traffic there; the rule is tagged so it can be found and removed.
    drop_user_rule
    iptables -I DOCKER-USER 1 -d "$cip" -m comment --comment "$TAG" -j ACCEPT
    echo "forwarding every other port on $pub to $container ($cip)"
    echo "excluded tcp: $tcp_set"
    echo "excluded udp: $udp_set"
    ;;
*)
    echo 'usage: host-forward.sh apply <container> | remove | show' >&2; exit 2
    ;;
esac
