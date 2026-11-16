#!/bin/sh
set -eu

case "${1:-}" in
  --remove)
    for peer in __PEER_IPS__; do
      while iptables -C DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT 2>/dev/null; do
        iptables -D DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT
      done
    done
    while iptables -C DOCKER-USER -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP 2>/dev/null; do
      iptables -D DOCKER-USER -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP
    done
    ;;
  *)
    # Docker DNATs published ports before they reach DOCKER-USER, so these rules
    # match the original host UDP ports and peer source addresses.
    iptables -S DOCKER-USER >/dev/null
    iptables -C DOCKER-USER -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP 2>/dev/null || \
      iptables -I DOCKER-USER 1 -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP
    for peer in __PEER_IPS__; do
      iptables -C DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT 2>/dev/null || \
        iptables -I DOCKER-USER 1 -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT
    done
    ;;
esac
