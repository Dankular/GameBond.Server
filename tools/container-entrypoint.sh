#!/bin/bash
# All commands operate in the container's private network namespace. The
# Compose service supplies NET_ADMIN, /dev/net/tun and namespaced forwarding.
set -euo pipefail

CONFIG=/run/config/server.json
KEY=/run/secrets/gamebond.key
child=
nat_added=0

cleanup() {
    status=$?
    trap - EXIT TERM INT
    rm -f /tmp/gamebond-ready /tmp/gamebond.pid
    if [[ -n "$child" ]]; then
        kill -TERM "$child" 2>/dev/null || true
        # Give the edge signal handler time to close packet workers and TUN.
        for ((attempt=0; attempt<50; attempt++)); do
            if ! kill -0 "$child" 2>/dev/null; then break; fi
            sleep 0.1
        done
        if kill -0 "$child" 2>/dev/null; then kill -KILL "$child" 2>/dev/null || true; fi
        wait "$child" 2>/dev/null || true
    fi
    if [[ $nat_added == 1 ]]; then nft delete table ip gamebond 2>/dev/null || true; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

[[ -c /dev/net/tun ]] || { echo '/dev/net/tun device is required' >&2; exit 1; }
[[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]] || {
    echo 'Container requires namespaced net.ipv4.ip_forward=1 from Compose' >&2; exit 1;
}

# Validate the fixed container topology and derive the tunnel subnet and NAT
# sources from the current config. Runs at start and again on every portal restart,
# so a configuration saved from the admin portal is checked before it is used.
plan() {
    jq -e '.role == "server" and .bind == [["0.0.0.0", 4433]]
        and (.tun_name // "GameBond") == "gamebond0" and (.mtu // 1280) == 1280
        and .client_tunnel_ip == "10.77.0.2"' "$CONFIG" >/dev/null || {
        echo 'Container config must use server, 0.0.0.0:4433, gamebond0, MTU1280 and client 10.77.0.2' >&2; exit 1;
    }
    [[ $(stat -c %s "$KEY") == 32 ]] || {
        echo 'The read-only shared key must contain exactly 32 bytes' >&2; exit 1;
    }
    # Attached LAN devices (for example a console behind a client USB adapter) each get their
    # own tunnel address. Without any, the original lone-client /30 and single-source NAT stay.
    LAN_IPS=$(jq -r '(.lan_tunnel_ips // []) | join(" ")' "$CONFIG")
    TUNNEL_PREFIX=30
    NAT_SOURCES='10.77.0.2/32'
    if [[ -n "$LAN_IPS" ]]; then
        for lan_ip in $LAN_IPS; do
            [[ "$lan_ip" =~ ^10\.77\.0\.([3-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])$ ]] || {
                echo "LAN device address $lan_ip must be 10.77.0.3 to 10.77.0.254" >&2; exit 1;
            }
        done
        TUNNEL_PREFIX=24
        NAT_SOURCES="{ 10.77.0.2, ${LAN_IPS// /, } }"
    fi

    # Tunnel clients get the internet, not the networks behind this container: its bridge, the Docker
    # host and any private range. Traffic between tunnel addresses (client <-> LAN devices) is still
    # forwarded. GAMEBOND_ALLOW_PRIVATE_FORWARD=1 turns the filter off.
    FORWARD_FILTER=
    if [[ "${GAMEBOND_ALLOW_PRIVATE_FORWARD:-0}" != 1 ]]; then
        FORWARD_FILTER='add rule ip gamebond forward iifname "gamebond0" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 } drop'
    fi

    NFT_TABLES=$(nft list tables)
    if grep -Fxq 'table ip gamebond' <<< "$NFT_TABLES"; then
        echo 'Container gamebond nft table already exists; refusing overwrite' >&2; exit 1
    fi
    [[ ! -e /sys/class/net/gamebond0 ]] || { echo 'gamebond0 already exists; refusing reuse' >&2; exit 1; }
    WAN=$(ip -4 route show default | awk 'NR == 1 { for (i=1;i<NF;i++) if ($i == "dev") {print $(i+1); exit} }')
    [[ "$WAN" =~ ^[a-zA-Z0-9_.:-]+$ && "$WAN" != gamebond0 ]] || {
        echo 'No valid container bridge egress interface found' >&2; exit 1;
    }
}

launch() {
    /usr/local/bin/gamebond-native-edge --config "$CONFIG" --key "$KEY" &
    child=$!
    printf '%s\n' "$child" > /tmp/gamebond.pid
    # The packet process creates TUN. Bound startup wait to ten seconds and fail
    # promptly when the child exits rather than configuring an unrelated device.
    for ((attempt=0; attempt<100; attempt++)); do
        if ! kill -0 "$child" 2>/dev/null; then
            wait "$child" || exit $?
            echo 'GameBond exited during startup' >&2; exit 1
        fi
        if [[ -e /sys/class/net/gamebond0 ]]; then break; fi
        sleep 0.1
    done
    [[ -e /sys/class/net/gamebond0 ]] || { echo 'Timed out waiting for gamebond0' >&2; exit 1; }
    ip address add "10.77.0.1/$TUNNEL_PREFIX" dev gamebond0
    ip link set dev gamebond0 mtu 1280 up
    nft -f - <<EOF
add table ip gamebond
add chain ip gamebond postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule ip gamebond postrouting ip saddr $NAT_SOURCES oifname "$WAN" masquerade
add chain ip gamebond forward { type filter hook forward priority filter; policy accept; }
add rule ip gamebond forward ct state established,related accept
add rule ip gamebond forward oifname "gamebond0" accept
$FORWARD_FILTER
add chain ip gamebond defrag { type filter hook prerouting priority -150; policy accept; }
add rule ip gamebond defrag iifname "$WAN" ip protocol udp meta length > 1280 ip frag-off & 0x4000 != 0 ip frag-off set 0
EOF
    nat_added=1
    kill -0 "$child"
    touch /tmp/gamebond-ready
    echo 'GameBond container locally ready; client reachability has not been measured'
}

plan
while :; do
    launch
    rc=0
    wait "$child" || rc=$?
    # Exit status 75 is the admin portal's restart request; anything else ends the container.
    [[ $rc == 75 ]] || exit "$rc"
    echo 'GameBond restart requested from the admin portal'
    rm -f /tmp/gamebond-ready /tmp/gamebond.pid
    child=
    if [[ $nat_added == 1 ]]; then nft delete table ip gamebond 2>/dev/null || true; nat_added=0; fi
    for ((attempt=0; attempt<100; attempt++)); do
        [[ -e /sys/class/net/gamebond0 ]] || break
        sleep 0.1
    done
    plan
done
