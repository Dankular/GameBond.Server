#!/bin/sh
set -eu

case "${1:-}" in
  --remove)
    for peer in __PEER_IPS__; do
      while iptables -C DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT 2>/dev/null; do
        iptables -D DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT
      done
      while iptables -C DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT 2>/dev/null; do
        iptables -D DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT
      done
    done
    while iptables -C DOCKER-USER -p udp -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP 2>/dev/null; do
      iptables -D DOCKER-USER -p udp -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP
    done
    while iptables -C DOCKER-USER -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP 2>/dev/null; do
      iptables -D DOCKER-USER -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP
    done
    ;;
  *)
    # Docker DNATs published ports before they reach DOCKER-USER, so these rules
    # match the original public host IP and UDP ports. The destination-IP match
    # keeps container-originated peer packets from hitting the inbound drop.
    iptables -S DOCKER-USER >/dev/null
    # Remove broad rules from prior releases before installing the scoped rules.
    while iptables -C DOCKER-USER -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP 2>/dev/null; do
      iptables -D DOCKER-USER -p udp -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP
    done
    for peer in __PEER_IPS__; do
      while iptables -C DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT 2>/dev/null; do
        iptables -D DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT
      done
    done
    iptables -C DOCKER-USER -p udp -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP 2>/dev/null || \
      iptables -I DOCKER-USER 1 -p udp -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-drop -j DROP
    for peer in __PEER_IPS__; do
      iptables -C DOCKER-USER -p udp -s "$peer" -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT 2>/dev/null || \
        iptables -I DOCKER-USER 1 -p udp -s "$peer" -m conntrack --ctorigdst '__LOCAL_PUBLIC_IP__' --ctorigdstport 51820:51821 -m comment --comment gamebond-backbone-peer -j ACCEPT
    done
    ;;
esac
