#!/bin/bash
# Enables peer gating on an exit: serves this node's probe state to its peer and tells the probe
# where the peer is. Run as root on each exit, after copying server-probe.sh and probe-status.py:
#   PEER_IP=<other exit ip> PEER_TOKEN=<shared secret> NODE_RANK=<0 primary | 1 backup> bash install-peer-status.sh
set -euo pipefail
: "${PEER_IP:?}" "${PEER_TOKEN:?}" "${NODE_RANK:?}"
install -d /etc/gamebond
umask 077; printf '%s' "$PEER_TOKEN" > /etc/gamebond/peer.token; umask 022
install -m 755 "$(dirname "$0")/probe-status.py" /usr/local/bin/gamebond-probe-status
cat > /etc/systemd/system/gamebond-probe-status.service <<UNIT
[Unit]
Description=GameBond probe state, served to the peer exit
After=network-online.target
[Service]
# Only the peer may reach the port.
ExecStartPre=/bin/sh -c 'iptables -C INPUT -p tcp --dport 8099 ! -s $PEER_IP -j DROP 2>/dev/null || iptables -I INPUT -p tcp --dport 8099 ! -s $PEER_IP -j DROP'
ExecStart=/usr/local/bin/gamebond-probe-status
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
touch /etc/gamebond/probe.env
sed -i '/^GAMEBOND_PEERS=/d;/^GAMEBOND_PEER_TOKEN_FILE=/d;/^GAMEBOND_PROBE_RANK=/d' /etc/gamebond/probe.env
cat >> /etc/gamebond/probe.env <<ENV
GAMEBOND_PEERS=http://$PEER_IP:8099
GAMEBOND_PEER_TOKEN_FILE=/etc/gamebond/peer.token
GAMEBOND_PROBE_RANK=$NODE_RANK
ENV
install -m 755 "$(dirname "$0")/server-probe.sh" /usr/local/bin/gamebond-probe
systemctl daemon-reload
systemctl enable --now gamebond-probe-status
systemctl restart gamebond-probe
sleep 2; systemctl is-active gamebond-probe gamebond-probe-status
