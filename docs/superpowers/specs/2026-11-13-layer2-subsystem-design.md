# Layer 2 subsystem design

## Goal

Add the requested Layer 2 capabilities to GameBond as a planned roadmap, then implement and integrate them incrementally on a GameBond managed Linux gateway. The subsystem must expose which capabilities are supported by the current host and provider, and must never claim a feature is active when the host cannot provide it.

This is an expansion of GameBond beyond its current tunnel and small gateway role. Existing docs explicitly say that GameBond is not a general router and does not provide VLANs. The server is a Go service in a Docker deployment; any feature that changes host networking must therefore be designed around container network namespace, privileges, host capabilities and safe rollback.

## Approaches considered

1. **Linux gateway provider first (recommended):** a platform-neutral desired-state and capability model, with a Linux implementation using kernel networking facilities and narrowly scoped host integrations. It fits the current server and gives a testable starting point. Hardware and kernel support varies, so features report capability and status explicitly.
2. **Vendor switch provider first:** build against one chosen switch API/OS. This can offer hardware-specific features such as MC-LAG and AV profiles, but the vendor is not specified and it would not naturally configure GameBond's Linux gateway.
3. **Vendor-neutral external-switch manager first:** define adapters across multiple switch vendors before delivering a useful initial capability. This adds integration and support burden without a selected target.

The approved direction is approach 1. External switch adapters are out of the initial subsystem scope.

## Product boundaries

- The initial managed device is a Linux gateway running GameBond Server. The first provider targets Linux kernel networking and documents required privileges and host capabilities.
- This is a new server subsystem. It does not change the Windows desktop client's tunnel transport or imply that the client is a managed switch.
- Linux-native mechanisms are used where they provide the behavior. Features that require a peer control plane, hardware offload, a specific daemon, switch silicon, or vendor protocol are capability-gated and may remain unavailable on a given host.
- The design must distinguish configured, supported, applied, degraded, and failed states. Unsupported settings are rejected or marked unsupported; they are never silently accepted as effective.
- Existing tunnel/NAT behavior and its current Docker safety checks remain intact unless a separately reviewed deployment change explicitly adds the required host networking model.

## Subsystem design

### Desired state and capability model

Add a versioned Layer 2 configuration section to server configuration. Model interfaces, bridges, VLAN/network membership, port policies, protocol settings, and feature-specific options as validated desired state. Validate references, ranges, conflicts, interface ownership, and dependencies before applying any change.

The foundation must implement the underlying managed bridge, VLAN-filtering, and port-membership primitives. Higher-level features such as Virtual Network Override and network isolation depend on those primitives and must not create competing bridge/VLAN state.

A provider interface reports host capabilities and applies a validated plan. The Linux provider translates supported operations into kernel or explicitly configured system integrations. The API returns per-feature capability and lifecycle state, plus actionable errors. Configuration validation is separate from application so the existing admin workflow can preview invalid or unsupported settings before writing them.

### Apply and recovery lifecycle

- Read and snapshot the relevant current state before mutation.
- Compute a deterministic plan and show the operations and affected interfaces.
- Apply only supported operations, in dependency order.
- If an operation fails, roll back completed operations from the snapshot where safe and report any rollback failure.
- Persist enough state to reconcile after restart, and reconcile drift without deleting unrelated host networking.
- Provide a disabled-by-default, read-only discovery/status mode before enabling writes on a host.
- Do not reconfigure the interface used for remote administration unless an explicit safe migration/rollback mechanism exists.

### Management surface

The Linux gateway daemon is a host service, separate from the existing tunnel container. The current admin portal runs inside that isolated container, so it must not receive host networking capabilities. When gateway management is enabled, an optional Compose overlay mounts only the daemon's Unix API socket into the portal container read-only and adds a dedicated shared group for socket access. The daemon exposes a small allowlist of status, validation, plan, apply, and rollback operations; it never accepts shell commands or generic kernel operations. The existing portal authenticates remote users and forwards only validated requests through this socket. The daemon independently validates every request and its complete desired state before host changes. If the overlay or socket is absent, the existing tunnel server continues to work and the portal reports gateway management as unavailable.

The socket is a privileged management channel even though it does not grant `NET_ADMIN` to the container. Its API must therefore be narrow, input-bounded, auditable, and restricted to the portal's dedicated group. Add status for provider capabilities, configured/applied state, interface/port state, and feature-specific counters. Keep secrets out of status and logs.

### Capability semantics

- Virtual Network Override assigns an authorized device identity to a configured Linux bridge VLAN/network and has explicit precedence over default network membership.
- Redundancy is a coordinated health and status policy over configured mechanisms (such as LACP, STP/RSTP, or VRRP); it is not a second independent failover protocol. It reports which mechanism owns each failover decision and avoids conflicting controllers.
- MC-LAG requires a compatible peer implementation and is unsupported when no provider is installed and verified.
- “Shadow Mode (VRRP) Gateway Failover” means a VRRP backup/standby gateway role with explicit tracked health and failover status. It does not imply replicated conntrack state or session continuity.
- Pro AV profile names are configuration presets. Each preset may change only settings backed by current primary vendor/standards documentation; profiles do not imply certification, device discovery, or tested interoperability.

### Test strategy

Use deterministic provider fakes for validation, plan ordering, partial failure, rollback, capability gating, and reconciliation. Linux integration tests should use isolated network namespaces/veth pairs where available and never mutate the developer host's live interfaces. Add configuration vector coverage and admin API tests for the new schema/status. Hardware-dependent behavior needs provider-specific acceptance evidence before being described as supported.

### Provider baseline

- Linux bonding supports the 802.3ad LACP mode, but the directly connected peer switch must be configured for the same aggregate. Report the negotiated partner and collecting/distributing member state rather than inferring success from a created bond.
- The Linux bridge provides VLAN filtering, STP controls, and IGMP/MLD snooping. Kernel, bridge, and driver versions determine which per-VLAN multicast and offload controls are available, so discover each setting rather than assuming all hosts behave the same.
- VRRP is provided by a supervised Linux VRRP implementation such as Keepalived; GameBond owns validated desired state and lifecycle, while the provider owns protocol timing and election.
- LLDP-MED requires a provider built with the relevant TLVs enabled and must report provider build capability. Voice VLAN behavior coordinates LLDP-MED advertisement with actual bridge VLAN membership.
- Generic Linux bonding does not provide multi-chassis peer coordination. MC-LAG requires a specifically supported peer/vendor provider; otherwise it stays unsupported.
- Port policing, pause flow control, mirroring, storm control, and multicast controls vary across kernel, qdisc, NIC driver, and switchdev hardware. Report the enforcement layer and fail validation when the requested action cannot be enforced.

Reference documentation for implementation research: [Linux bonding](https://docs.kernel.org/networking/bonding.html), [Linux bridge](https://docs.kernel.org/networking/bridge.html), [Linux switchdev](https://docs.kernel.org/networking/switchdev.html), [Keepalived](https://keepalived.org/documentation/), and [lldpd usage](https://lldpd.github.io/usage.html).

## Roadmap and requested capabilities

The repeated entries in the request are represented once below. Each capability remains a distinct roadmap item and is only marked implemented after its Linux provider and GameBond integration are complete.

### Foundation

- Layer 2 configuration schema, validation, provider/capability discovery, status, apply planning, safe rollback and reconciliation.
- Virtual Network Override.
- Jumbo Frames.

### Link and loop resilience

- LACP Port Aggregation.
- MC-LAG (provider/peer dependent).
- Redundancy.
- STP and RSTP.
- Loop Protection.
- Shadow Mode (VRRP) Gateway Failover.

### Multicast and media

- IGMP Snooping.
- Advanced IGMP Configuration: Querier, Fast Leave and Router Port.
- Pro AV Profiles: Play, Dante, Q-SYS, NDI, SDVoE, Shure, AES67 and Crestron (profile behavior is validated against documented requirements; vendor/device-specific actions require a matching provider).
- Voice VLAN.
- LLDP-MED.

### Access control and isolation

- MAC-Based ACLs and Device Isolation.
- IP-Based ACLs and Network Isolation.
- MAC Address Blocking.
- MAC-Based Port Restriction.
- Port Isolation.
- DHCP Snooping and Guarding.
- 802.1X Control (backend/authenticator integration dependent).

### Traffic control and operations

- Egress Rate Limit.
- Flow Control.
- QoS (DSCP).
- Storm Control.
- Multicast and Broadcast Rate Limiting.
- Port Mirroring.

## Suggested integration sequence

Each capability is a separately reviewable increment after the foundation is in place. Dependencies may move an item, but unrelated capabilities should not be bundled into one integration. Pro AV profile names are each integrated and validated separately.

1. Foundation: schema, capability discovery, read-only status, plan/apply lifecycle, rollback and namespace-based test harness.
2. Virtual Network Override.
3. Jumbo Frames.
4. Port Isolation.
5. MAC-Based Port Restriction.
6. MAC Address Blocking.
7. MAC-Based ACLs and Device Isolation.
8. IP-Based ACLs and Network Isolation.
9. Egress Rate Limit.
10. Flow Control.
11. QoS (DSCP).
12. Storm Control.
13. Multicast and Broadcast Rate Limiting.
14. IGMP Snooping.
15. Advanced IGMP Configuration (Querier, Fast Leave, Router Port).
16. DHCP Snooping and Guarding.
17. 802.1X Control.
18. Voice VLAN.
19. LLDP-MED.
20. STP and RSTP.
21. Loop Protection.
22. LACP Port Aggregation.
23. Redundancy.
24. MC-LAG, when a compatible peer/provider is available.
25. Shadow Mode (VRRP) Gateway Failover.
26. Port Mirroring.
27. Pro AV Profile: Play.
28. Pro AV Profile: Dante.
29. Pro AV Profile: Q-SYS.
30. Pro AV Profile: NDI.
31. Pro AV Profile: SDVoE.
32. Pro AV Profile: Shure.
33. Pro AV Profile: AES67.
34. Pro AV Profile: Crestron.

This order is provisional and should be revisited during implementation planning after kernel/provider capability research. The roadmap itself includes all requested items regardless of initial host support.

## Acceptance criteria

- `FEATURES.md` has a clearly labeled planned Layer 2 section with each unique requested capability listed once.
- Runtime behavior is never advertised as available solely because a setting exists in configuration; provider capability and applied state are visible.
- Unsupported or conflicting settings fail validation with actionable errors.
- Applying a change is planned, validated, observable and recoverable; unrelated host networking is preserved.
- The subsystem can run read-only and be tested without altering host networking.
- Each roadmap capability is integrated in its own incremental delivery with tests appropriate to its provider and documented requirements.
- Existing server tunnel, NAT, admin authentication and client behavior continue to work.

## Risks and constraints to resolve in implementation research

- The current server container entrypoint expects a narrow server layout and currently configures tunnel/NAT behavior, not a host switch. Privileges, host networking, persistence, and rollback need an explicit deployment design before mutating physical interfaces.
- Linux capabilities vary by kernel, drivers, bridge/bond support and installed daemons. LACP, MC-LAG, spanning tree, VRRP, 802.1X, LLDP-MED and Pro AV behaviors cannot be promised universally by one generic provider.
- The names “Shadow Mode” and “Pro AV Profiles” need concrete semantics and acceptance criteria before those items are implemented. Pro AV profiles must not imply certification or device interoperability without validation.
- DHCP snooping, ACLs, port security and isolation can interrupt connectivity if misconfigured. Safe defaults and rollback are required.
- A long-running daemon or host-level agent may be required for features unavailable inside the current container. This is an implementation decision to research before planning the foundation.
