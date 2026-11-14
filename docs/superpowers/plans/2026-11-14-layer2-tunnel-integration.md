# Layer 2 on the bonding transport

**Goal:** the Layer 2 capabilities live in the bonding transport itself, so they improve what GameBond sells (bonded, redundant, loss-hardened links) instead of only configuring a Linux gateway beside it. The Linux gateway daemon becomes an optional edge adapter for the same policy.

**Status:** plan, nothing implemented. Replaces the first version of this document, which put L2 policy on the exit's `gamebond0` and Ethernet carriage last. That was the wrong shape: it treated the transport as a pipe. Here the transport is the switch fabric.

## Rule: nothing ships unused

- One source of policy. The existing `gateway/layer2` desired-state schema (validation, capability gating, plan/apply, status) is the only configuration model. The transport consumes it; there is no parallel `bond/l2` config. If a field has no effect on the live path it is rejected as unsupported, never accepted silently.
- Every phase is a vertical slice that is enabled on the backup exit and one real client device, moves real traffic, and shows counters in the panel before it counts as done. Library-only phases and simulator-only features do not count.
- A feature is removed from the roadmap, not parked, if it has no path to the live transport.

## Principle

The bond is a virtual switch: its "ports" are the client LAN adapters and the exit, and its "trunk" is the set of bonded paths. L2 features are implemented where the packets already are, in `GameBond.Core/bond` (shared by client and server), reusing duplication, SACK, repair, reorder, BFD and the failover logic.

## What already exists (checked 2026-11-14)

- Client `native-edge/iec62439`: PRP redundancy control trailer (RCT), HSR tag, duplicate discard keyed by source MAC and sequence, supervision frames, node table with per-LAN status. Works on Ethernet frames, not wired into the Core transport.
- Client `native-edge/lan`: raw Ethernet access to LAN adapters; it terminates Ethernet (ARP, DHCP) and sends IP into the tunnel.
- Core `bond`: IPv4-only packet model (`ParseIPv4`, flow classification), per-path budget, BFD, FRER-style first-wins accounting, adaptive duplication, FEC, loss repair, failover.
- Server: exit tunnel is `IFF_TUN` (layer 3).
- Server `gateway/layer2`: Linux provider/plan/apply for bridge, VLAN, bond, ACL, QoS, storm control, LLDP-MED, VRRP, with capability-gated status. Host service, kept out of the tunnel container by design.

## Mapping: which L2 feature becomes what in the transport

| L2 feature | In the transport | Notes |
|---|---|---|
| LACP / link aggregation | Already the bond: per-flow striping, path health by BFD. Add a LACP-style status view (members, collecting/distributing, partner = exit) and flow-hash policy (per-flow pinning exists as `FlowsPinned`). | No LACP protocol needed: both ends are ours. |
| Redundancy (PRP/HSR) | Ethernet-frame PRP: RCT or HSR tag on frames, duplicate discard at the receiver across paths. Reuse `iec62439` and Core's number/first-wins merge so there is one dedup, not two. | Delivers the standing IEC 62439-3 goal on real frames. |
| Loop protection / STP-like | A transport-edge loop guard: duplicate-source-MAC across ports, frame TTL/loop counter on the tunnel port, hold-down that shuts only the offending port. | The bond itself is loop-free by construction (one trunk); loops come from client LANs. |
| Storm control, multicast/broadcast limits | Token buckets per port and class (unknown-unicast, multicast, broadcast) at the tunnel edge, counters in panel. | Needs Ethernet frames, hence Phase 1. |
| VLANs / Virtual Network Override | 802.1Q tag carried end to end; per-port VLAN membership and tag mapping in the transport's port table. | |
| QoS / DSCP, egress rate limit | Map 802.1p/DSCP to the existing priority/bulk classes and per-path budget; per-port rate limit. | Share the adaptive QoS, never a second one. |
| MAC limits, port security, MAC blocking/ACLs, port isolation | Port table in the switch core (FDB with per-port MAC cap, static entries, deny list, isolation groups). | |
| IGMP/MLD snooping, querier | Snooping table in the switch core so multicast is replicated only to member ports and sent on all paths as priority copies. | |
| DHCP snooping, 802.1X | Edge-adapter responsibility (client LAN side and exit bridge); transport carries EAPOL and DHCP and marks trusted ports. | Backend-dependent. |
| LLDP / LLDP-MED | LLDP frames terminated at the port; the supervision frame doubles as the peer-discovery TLV between client and exit. | |
| Port mirroring | Mirror a port's frames to a local monitor port. | |
| MC-LAG | Not applicable as two peers: dual exits are failover, not an aggregate. Report unsupported. | |
| STP/RSTP, VRRP | Edge adapter (Linux bridge, keepalived) with the transport's path/exit health as input. | One owner per decision. |

## Phases

### Phase 1 - first live slice: Ethernet carriage with FDB, loop guard and storm control

The switch core (Ethernet II / 802.1Q parsing, FDB with aging, per-port MAC cap, forwarding decision, loop guard, storm buckets) is built here together with the wire carriage and the panel, driven by `gateway/layer2` config, with a simulator harness as its test. Live target: one opt-in LAN device on the backup exit.

- Panel (Loss and Aggregation sections): frames carried per port, FDB size, flooded vs known-unicast, storm drops, loop-guard holds, oversize counts.
- Done when a real device passes ARP, DHCP and traffic through the bond with one path cut, and the counters move.

- New authenticated payload kind (`KindEthernet`) numbered and handled like IP packets, so duplication, SACK, repair and reorder apply unchanged. Classification uses inner VLAN/PCP and the IP 5-tuple when present, MAC pair otherwise.
- Control frames (ARP, ND, DHCP, EAPOL, LLDP, IGMP, BPDU) are priority copies on every path.
- MTU: choose fragmentation, MSS clamp or a larger tunnel MTU; oversize frames are counted, never silent.
- Server: TAP device beside the existing TUN (opt-in config section), joined to the switch core and, for Linux features, to a bridge via veth.
- Client: pass-through bridging per LAN device (today it terminates Ethernet), opt-in per device; normal traffic routing unchanged.
- Tests: codec vectors, simulator with two lossy links (ARP/DHCP survive 5% loss, order preserved per flow, duplicate suppression), namespace test for TAP + bridge, soak on the backup exit first.

Wire details for Phase 1:

### Phase 1 wire and ports

- Use RCT or HSR tags on carried Ethernet frames and merge with Core's first-wins accounting. Supervision frames feed the node table and the panel's per-node LAN A/B status.
- Gate: IEC 62439-3 conformance vectors for RCT/HSR encode, decode and discard.

### Phase 2 - PRP/HSR on carried frames

- Use RCT or HSR tags on carried Ethernet frames and merge with Core's first-wins accounting. Supervision frames feed the node table and the panel's per-node LAN A/B status.
- Gate: IEC 62439-3 conformance vectors for RCT/HSR encode, decode and discard, plus the live check above.

### Phase 3 - policy features in the switch core

In this order, each a live slice with its own tests and panel counters: VLAN membership and mapping, MAC cap and blocking, port isolation, storm control and multicast limits, QoS map and per-port rate limit, loop guard, IGMP snooping, LLDP termination, port mirroring.

### Phase 4 - Linux gateway as edge adapter

- `gatewayd` consumes the same policy and applies the parts that need the host (bridge VLAN filtering on the exit, STP, VRRP via keepalived, 802.1X, DHCP snooping).
- Transport health (path state, exit failover, BFD) is exported to `gatewayd` read-only and is the tracked-health input for VRRP. One owner per failover decision, recorded in status; no competing controllers. Failover events join the outage journal.

## Gates for every phase

Tests green, `GOOS=linux go build ./...`, rollout in the standard order (stop backup probe, push Server, wait primary, start backup probe, wait backup, deploy client), soak on the backup exit first, and a clean panel from the operator before the next phase. No live failover drills on the production exits.

## Open decisions

1. First real device for Phase 1 (PS5, camera, switch) to drive MTU and VLAN choices.
2. Whether the TAP port joins the switch core only, or also a Linux bridge from day one.
3. PRP trailer versus HSR tag as the default for carried frames (PRP fits two independent paths; HSR fits a ring).
