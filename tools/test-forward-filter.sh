#!/bin/bash
# Functional check of the container's forward filter (needs root, `ip`, `nft`, `ping`).
# Builds client / container / upstream network namespaces, loads the filter exactly as
# container-entrypoint.sh defines it, and expects a public address to be reachable and
# a private one behind the container to be dropped. Run:  sudo bash tools/test-forward-filter.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
FILTER=$(sed -n "s/^        FORWARD_FILTER='\(.*\)'\$/\1/p" "$HERE/container-entrypoint.sh")
[ -n "$FILTER" ] || { echo "could not extract the filter from container-entrypoint.sh" >&2; exit 2; }
ip netns add gbC; ip netns add gbS; ip netns add gbT
cleanup(){ ip netns del gbC; ip netns del gbS; ip netns del gbT; } ; trap cleanup EXIT
# client <-> server (server side is named gamebond0, like the TUN)
ip link add cl netns gbC type veth peer name gamebond0 netns gbS
# server <-> upstream (server side eth0)
ip link add tup netns gbT type veth peer name eth0 netns gbS
ip -n gbC addr add 10.77.0.2/24 dev cl; ip -n gbC link set cl up; ip -n gbC link set lo up
ip -n gbS addr add 10.77.0.1/24 dev gamebond0; ip -n gbS link set gamebond0 up
ip -n gbS addr add 198.51.100.2/24 dev eth0; ip -n gbS link set eth0 up
ip -n gbT addr add 198.51.100.1/24 dev tup; ip -n gbT link set dev tup up; ip -n gbT link set lo up
ip -n gbT addr add 1.1.1.1/32 dev lo; ip -n gbT addr add 192.168.9.9/32 dev lo
ip -n gbT route add 10.77.0.0/24 via 198.51.100.2
ip -n gbC route add default via 10.77.0.1
ip -n gbS route add 1.1.1.1/32 via 198.51.100.1; ip -n gbS route add 192.168.9.9/32 via 198.51.100.1
ip netns exec gbS sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0
ip netns exec gbT sysctl -qw net.ipv4.conf.all.rp_filter=0
FORWARD_FILTER="$FILTER"
ip netns exec gbS nft -f - <<EOF
add table ip gamebond
add chain ip gamebond forward { type filter hook forward priority filter; policy accept; }
add rule ip gamebond forward ct state established,related accept
add rule ip gamebond forward oifname "gamebond0" accept
$FORWARD_FILTER
EOF
ip netns exec gbC ping -c1 -W1 10.77.0.1 >/dev/null 2>&1 && echo "client->server ok" || echo "client->server FAILED"
pub=$(ip netns exec gbC ping -c1 -W1 1.1.1.1 >/dev/null 2>&1 && echo reachable || echo blocked)
priv=$(ip netns exec gbC ping -c1 -W1 192.168.9.9 >/dev/null 2>&1 && echo reachable || echo blocked)
echo "public 1.1.1.1: $pub | private 192.168.9.9: $priv"
[ "$pub" = reachable ] && [ "$priv" = blocked ] && echo PASS || { echo FAIL; exit 1; }
