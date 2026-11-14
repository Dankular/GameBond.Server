# Layer 2 and tunnel transport integration

**Goal:** make the managed Layer 2 gateway subsystem useful to the bonded tunnel: (1) apply L2 policy to the tunnel interface, (2) carry Ethernet frames over the bond, (3) tie redundancy to the transport's own health signals.

**Status:** plan, nothing implemented. Supersedes the "does not change the tunnel transport" boundary in `specs/2026-11-13-layer2-subsystem-design.md` for the items below only; every phase stays opt-in and defaults to today's behaviour.

## Facts the design rests on (checked 2026-11-14)

- The exit's tunnel device is `IFF_TUN | IFF_NO_PI` (`edge/runtime_linux.go`): layer 3. No Ethernet frames, broadcast or unknown-unicast exist on it today.
- The Windows client's LAN gateway (`native-edge/lan/gateway.go`) terminates Ethernet at the client (ARP, DHCP) and forwards IP into the tunnel. L2 does not cross the tunnel.
- `gamebond0` lives in the container's network namespace. `gatewayd` is a host service and must not give the container host-network authority, so it reaches `gamebond0` only by entering that namespace (fixed-argv `nsenter`/`ip netns`), never by widening container capabilities.
- Both exits (primary 138.199.201.16 and backup 195.154.119.136) carry live traffic, and the primary also hosts ~25 other containers on 2 vCPU / 3.8 GB. Anything that mutates their networking needs read-only discovery first, a rollback, and the usual rollout order (backup probe stopped, one exit at a time).
- Duplication, SACK, repair and exit failover already provide PRP-like redundancy at the transport; the L2 provider adds VRRP, bonding and STP, which must not become competing controllers.

## Phase 0 - read-only discovery (no behaviour change)

- Run `gatewayd` in discovery mode on the backup exit only; report capabilities for the container netns (`tc`, `nft`, bridge, bonding, `mstpd`, `keepalived`).
- Status shows `gamebond0` counters, MTU, qdisc and DSCP marks as seen from the host.
- Exit criterion: capability report matches reality; nothing was written.

## Phase 1 - L2 policy on the tunnel interface (Server only)

What is honest on a layer 3 TUN:

| Control | On gamebond0 (TUN) | Notes |
|---|---|---|
| DSCP / QoS classes | yes | Share one root qdisc with the adaptive QoS (`qos_bridge.go`); never rewrite the DSCP the tunnel uses to pick priority copies. |
| Egress rate limit, policing | yes | Per client tunnel IP via `tc`/`nft` in the container netns. |
| IP ACLs, network isolation | yes | Per tunnel client IP, GameBond-owned nft table only. |
| MAC ACLs, port security, DHCP snooping, storm control, loop protection, STP, LLDP-MED | no | No L2 on a TUN. These become meaningful only after Phase 2 and are reported "unsupported" until then, never silently accepted. |

- Apply through the existing plan/apply/rollback lifecycle; one new provider target `tunnel` in `gateway/layer2`.
- Tests: namespace + veth harness for tc/nft application and rollback; fake-provider vectors for validation.

## Phase 2 - Ethernet frames over the bond (largest change)

Core (`GameBond.Core`):
- New payload kind for Ethernet frames, authenticated and numbered like IP packets so duplication, SACK, repair and reorder apply unchanged. Flow identity for classification comes from the inner frame (VLAN id, inner IP 5-tuple when present, otherwise MAC pair).
- Broadcast, multicast and ARP/ND are priority-copied; unknown-unicast flooding is rate-limited at the tunnel edge (storm control on the tunnel port: separate token buckets for unknown-unicast, multicast, broadcast).
- MTU: 1500-byte frames do not fit the 1280 tunnel MTU. Decide between fragmentation, MSS clamping or raising the tunnel MTU; do not pass oversize frames silently (report and count them like `oversize_dropped`).
- Loop protection: duplicate-MAC and frame-looping detection on the tunnel port, with a hold-down that shuts only the tunnel port, never the exit's management interface.

Server:
- A TAP device in the container namespace (new `IFF_TAP` path beside the existing TUN) joined to a gatewayd-managed Linux bridge by a veth into the host namespace. VLAN filtering, port isolation, MAC limits, 802.1X and DHCP snooping then apply on the bridge port using the existing providers.
- Off by default; a distinct config section, so the TUN path is unchanged.

Client:
- Pass-through bridging mode per LAN device (today the gateway terminates Ethernet). MAC learning table, split horizon, per-client MAC limit, 802.1Q tag mapping.
- Must not change the Windows client's routing of normal traffic; opt-in per device.

Tests: Core codec and classification vectors, a simulator test that carries frames over two lossy links and checks loss/ordering of ARP/DHCP, namespace tests for the TAP/bridge path, and a live soak on the backup exit only before the primary.

## Phase 3 - redundancy tied to the transport

- Define one owner per failover decision and record it in status:
  - Exit failover (client switches between 138.* and 195.*): owned by the transport (`native-edge/client/failover.go`).
  - Gateway VIP failover (VRRP shadow mode): owned by keepalived, with tracked health taken from the transport (exit healthy, bond paths up) so a VRRP node never claims the VIP while its tunnel is down. The existing spec lists "tracked health policy" as not implemented; this phase implements it.
  - STP/loop protection: owned by the bridge, scoped to bridge ports; never blocks the tunnel port based on a topology change it did not cause.
- Expose the transport's path state (BFD, suspect/down, exit failover events) to `gatewayd` over its Unix socket as read-only input.
- MC-LAG stays unsupported: two independent exits are not a verified MC-LAG peer pair. Say so in status; do not emulate it.
- Failover event history joins the existing outage journal so one timeline shows link, exit and VRRP transitions.
- Do not drill live failover on the production exits; use namespaces and the simulator, and a guarded test window agreed with the operator.

## Order and gates

1. Phase 0 on the backup exit, read-only.
2. Phase 1 on the backup exit, then the primary after a clean soak.
3. Phase 3 signals (read-only export) next, since they are cheap and unblock honest status.
4. Phase 2 last: it needs the Core frame kind, a design review of MTU and loop handling, and its own soak.

Every phase ships separately, tests green, `GOOS=linux go build ./...`, rollout in the standard order, and a clean panel from the operator before the next phase.

## Open questions for the operator

- Is the first use of Phase 2 a specific device (PS5, a camera, a switch) so the MTU and VLAN choices can be driven by a real case?
- Should the backup exit stay the test bed until a phase is proven, accepting that failover then also tests the new code?
