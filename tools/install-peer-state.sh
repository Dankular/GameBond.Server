#!/bin/bash
# Enables peer gating on an exit (run as root, with server-probe.sh beside this script):
#   PEER_NAME=<other node's hostname> NODE_RANK=<0 primary | 1 backup> STATE_TOKEN=<token> bash install-peer-state.sh
# Needs the Gitea source already configured in /etc/gamebond/probe.env.
set -euo pipefail
: "${PEER_NAME:?}" "${NODE_RANK:?}" "${STATE_TOKEN:?}"
install -d /etc/gamebond
umask 077; printf '%s' "$STATE_TOKEN" > /etc/gamebond/state.token; umask 022
sed -i '/^GAMEBOND_PEERS=/d;/^GAMEBOND_PEER_TOKEN_FILE=/d;/^GAMEBOND_STATE_TOKEN_FILE=/d;/^GAMEBOND_PROBE_RANK=/d' /etc/gamebond/probe.env
cat >> /etc/gamebond/probe.env <<ENV
GAMEBOND_PEERS=$PEER_NAME
GAMEBOND_STATE_TOKEN_FILE=/etc/gamebond/state.token
GAMEBOND_PROBE_RANK=$NODE_RANK
ENV
install -m 755 "$(dirname "$0")/server-probe.sh" /usr/local/bin/gamebond-probe
systemctl restart gamebond-probe
sleep 2; systemctl is-active gamebond-probe
