# Layer 2 Gateway Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the requested Layer 2 roadmap and integrate each capability through GameBond's Linux gateway control plane, with truthful per-host support reporting and safe apply/rollback.

**Architecture:** Extend the planned host `gatewayd` control plane and shared network model. Linux kernel facilities and explicitly selected Linux services provide Layer 2 behavior through fixed-argument adapters; the existing edge container remains in its isolated network namespace. The authenticated admin portal reaches only a bounded gateway management API. Each requested feature is delivered as a separate integration increment and is reported supported only when capability detection and effective-state verification succeed.

**Tech Stack:** Go 1.26; Linux netlink/iproute2, bridge, bonding, `tc`, `nft`, `ethtool`; systemd host service; existing GameBond Server admin portal; provider-specific services only when required and documented.

**Spec:** `GameBond.Client/docs/superpowers/specs/2026-11-13-linux-router-capabilities-design.md`; `GameBond.Server/docs/superpowers/specs/2026-11-13-layer2-subsystem-design.md`; prerequisite `docs/superpowers/plans/2026-11-13-linux-gateway-foundation.md`.

## Global Constraints

- Manage a Linux GameBond gateway; do not add host-network authority to the existing edge container.
- Validate the complete proposed state and host capabilities before changing live state.
- Accept no shell command strings from configuration or API input; use fixed executables and argv.
- Preserve the last known-good state and roll back completed stages in reverse order on failure.
- Report configured, supported, applied, degraded, failed, and unsupported states distinctly.
- Keep secrets out of status, API responses, and logs.
- Never alter an unmanaged interface or the remote management path without a recovery mechanism.
- Keep IPv6, external switch vendor APIs, and device certification outside this initial scope.
- A feature is complete only when its provider behavior, GameBond configuration, status, failure handling, and acceptance evidence are integrated.

## Review Focus

- **Unsupported kernel or driver behavior:** capability discovery rejects the configuration before apply and explains the missing prerequisite.
- **Interface ownership conflict:** one interface cannot simultaneously belong to incompatible WAN, bridge, VLAN, or bond roles.
- **Partial configuration failure:** reverse-order rollback restores the prior known-good state or exposes the exact failed recovery stage.
- **Management path disruption:** applying a change that would disconnect the management path requires an explicit rollback/recovery plan.
- **Misleading feature status:** desired configuration alone never reports a feature active; provider verification is required.

---

## Dependency and File Map

The existing gateway foundation plan is a prerequisite and owns the `gateway` daemon, Unix management socket, versioned configuration, host capability inventory, fixed-argv runner, transaction coordinator, systemd unit, and common status API. Extend those components rather than creating a second daemon or applying host networking from `cmd/edge`.

- Modify `GameBond.Client/FEATURES.md`: add a planned Layer 2 section with each unique request listed once and links to the Linux gateway scope.
- Modify `GameBond.Client/docs/superpowers/specs/2026-11-13-linux-router-capabilities-design.md`: merge the Layer 2 model, boundaries, and capability list into the canonical router design.
- Modify `GameBond.Server/docs/superpowers/specs/2026-11-13-layer2-subsystem-design.md`: preserve the host socket boundary and the exact semantics of Redundancy, Virtual Network Override, VRRP shadow mode, MC-LAG, and AV profiles.
- Create or extend `GameBond.Server/gateway/layer2/config.go`: typed Layer 2 desired state and cross-reference validation.
- Create or extend `GameBond.Server/gateway/layer2/capabilities_linux.go`: kernel, driver, tool, and provider capability reporting.
- Create or extend `GameBond.Server/gateway/layer2/plan.go`: deterministic operations and dependency ordering for Layer 2 state.
- Create or extend `GameBond.Server/gateway/layer2/provider_linux.go`: Linux bridge, bond, VLAN, `tc`, `nft`, `ethtool`, and service adapters using fixed argv.
- Create or extend `GameBond.Server/gateway/layer2/status_linux.go`: effective interface, bridge, VLAN, FDB, MDB, bond, and provider state.
- Extend `GameBond.Server/gateway/api.go` and `GameBond.Server/adminportal/gateway.go`: bounded status, validate, plan, apply, and rollback requests over a Unix socket; the portal forwards only authenticated requests and the daemon validates them again.
- Add `GameBond.Server/compose.gateway.yaml` as an optional overlay mounting only the gateway API socket directory read-only and adding the dedicated socket group. Keep the default Compose deployment usable without `gatewayd`.
- Do not add `network_mode: host`, host `NET_ADMIN`, arbitrary command APIs, or a Docker socket to the edge service.
- Add focused tests adjacent to each config, planner, provider, status, and portal component. Linux integration verification uses isolated network namespaces and veth devices, never a live host interface.

## Execution Rules

- Finish and verify the gateway foundation plan before applying any Layer 2 state.
- The roadmap includes all requested features even if the initial host cannot support some of them.
- Implement each feature below in its own change and review cycle. Do not combine adjacent entries into a single feature integration.
- Research provider and distribution behavior before the feature's implementation; record the provider/version and required kernel capability in its capability report.
- Hardware- or peer-dependent features may be integrated as explicit capability-gated providers. Do not emulate MC-LAG or AV-device behavior and call it support.
- The requested Pro AV profiles are eight separate integrations: Play, Dante, Q-SYS, NDI, SDVoE, Shure, AES67, and Crestron.

## Ordered Integration Tasks

### Task 1: Publish the deduplicated roadmap

**Files:** `GameBond.Client/FEATURES.md`, `GameBond.Client/docs/superpowers/specs/2026-11-13-linux-router-capabilities-design.md`.

- [ ] Add a `Layer 2 Gateway Features (planned)` section listing each requested capability exactly once.
- [ ] Group the list by switching, resilience, multicast/media, access control, and traffic control while preserving individual feature names.
- [ ] State that configuration availability is not proof of host support or application.
- [ ] Add the Layer 2 design to the canonical Linux router spec and identify the `gatewayd` host boundary.
- [ ] Review the list against the user's request and confirm no item or AV profile is missing or duplicated.

### Task 1b: Integrate the optional admin-portal gateway socket

**Files:** `GameBond.Server/adminportal/gateway.go`, `GameBond.Server/adminportal/portal.go`, `GameBond.Server/cmd/edge/main_linux.go`, `GameBond.Server/gateway/api.go`, `GameBond.Server/compose.gateway.yaml`, `GameBond.Server/docs/admin-portal.md`.

- [ ] Define a client that dials only the configured Unix socket and supports the allowlisted status, validate, plan, apply, and rollback API operations with request/response size bounds.
- [ ] Require the existing portal authentication and CSRF checks before forwarding mutating requests; keep the daemon-side schema/capability validation authoritative.
- [ ] Add an optional Compose overlay with a read-only bind mount of the dedicated socket directory and a configured shared group ID; do not change the default Compose service's network mode or capabilities.
- [ ] If the socket is absent, expose gateway management as unavailable and preserve existing tunnel/admin portal startup.
- [ ] Document the host socket ownership/mode, group mapping, optional overlay activation, and the fact that the socket still grants its allowlisted host-management API to the edge container.

### Task 2: Define shared Layer 2 desired state and capability contract

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/config_test.go`, `gateway/layer2/capabilities_test.go`.

- [ ] Add strict, versioned configuration objects for managed interfaces, bridges, VLANs/virtual networks, port membership, feature settings, and provider selection.
- [ ] Implement the base managed bridge, VLAN-filtering, and port-membership provider operations needed by every higher-level Layer 2 capability; snapshot current state and include these operations in the existing reversible apply transaction.
- [ ] Reject unknown fields, invalid identifiers, duplicate interface ownership, missing references, invalid ranges, and feature dependency conflicts before creating an apply plan.
- [ ] Report each capability as supported, unsupported, or unavailable with a machine-readable reason and discovered kernel/tool/provider requirements.
- [ ] Define the operation interface consumed by the existing reversible gateway transaction coordinator.
- [ ] Add tests for malformed configuration, interface conflicts, unsupported capability rejection, and deterministic serialization.

### Task 3: Add virtual network override

**Files:** `gateway/layer2/config.go`, `gateway/layer2/plan.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define Virtual Network Override as an authorized device-to-network/VLAN assignment with explicit precedence over default network membership.
- [ ] Validate that the target device identity is allowed and the selected network exists.
- [ ] Apply the VLAN/bridge membership using the detected Linux bridge support and verify effective membership.
- [ ] Report assignment, effective network, and rejection reason in status.

### Task 4: Add Jumbo Frames

**Files:** `gateway/layer2/config.go`, `gateway/layer2/plan.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Validate requested MTU against every interface in the affected L2 path and the provider's reported maximum.
- [ ] Apply MTU changes in dependency order and roll back if any member or bridge rejects the size.
- [ ] Verify effective MTU on the bridge, VLAN, bond, and physical members.

### Task 5: Add Port Isolation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/plan.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define isolated and permitted-forwarding port groups with explicit bridge/VLAN scope.
- [ ] Reject rules that would isolate the gateway management path or contradict an explicit allow policy.
- [ ] Apply and verify bridge port isolation or an equivalent supported Linux forwarding policy.

### Task 6: Add MAC-Based Port Restriction

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define allowed MAC identities, maximum learned devices, violation action, and per-port policy.
- [ ] Select only a provider mechanism that enforces the configured restriction; reject display-only limits.
- [ ] Report learned identity, violation counters, and enforcement status without exposing unrelated host data.

### Task 7: Add MAC Address Blocking

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Validate unicast MAC addresses and network/port scope.
- [ ] Apply scoped L2 drop rules using the selected Linux bridge/nft provider and verify active rules.
- [ ] Provide bounded counters and remove only GameBond-owned rules during rollback or disable.

### Task 8: Add MAC-Based ACLs and Device Isolation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define ordered allow/deny rules with MAC, ingress network/port, destination scope, and terminal action.
- [ ] Reject ambiguous rule order and unsupported match combinations before apply.
- [ ] Apply scoped L2 policy and report rule counters and effective order.

### Task 9: Add IP-Based ACLs and Network Isolation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define ordered IP prefix/protocol/port policies tied to named virtual networks.
- [ ] Ensure policy boundaries prevent traffic crossing isolated networks except through explicit allows.
- [ ] Apply with the GameBond-owned firewall table and verify counters without replacing unrelated host firewall state.

### Task 10: Add Egress Rate Limit

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define per-port and per-network rate and burst parameters with explicit units and bounds.
- [ ] Apply supported `tc` shaping and report the effective qdisc and rate.
- [ ] Reject unsupported offload or queue combinations instead of silently falling back to an unshaped path.

### Task 11: Add Flow Control

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define RX/TX pause behavior per physical interface.
- [ ] Detect driver and ethtool support before apply; never apply to an aggregate member independently when policy belongs to the bond.
- [ ] Verify effective pause settings and report unsupported directions separately.

### Task 12: Add QoS (DSCP)

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define DSCP-to-class and class-to-queue/rate policy shared with the existing adaptive QoS model.
- [ ] Apply `tc` classification and queue policy without overriding GameBond tunnel DSCP semantics.
- [ ] Report class counters and effective mappings.

### Task 13: Add Storm Control

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define per-port broadcast, multicast, and unknown-unicast thresholds and action.
- [ ] Apply only supported policers and report whether enforcement is kernel, driver, or hardware offload.
- [ ] Verify thresholds and expose drop counters.

### Task 14: Add Multicast and Broadcast Rate Limiting

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define separate multicast and broadcast rate/burst policies and scope.
- [ ] Apply supported policers without disabling IGMP control traffic needed by snooping.
- [ ] Verify counters and policy precedence with ACL and storm-control settings.

### Task 15: Add IGMP Snooping

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Configure Linux bridge multicast snooping per bridge and VLAN where available.
- [ ] Report MDB membership, listener ports, and querier presence from effective kernel state.
- [ ] Reject unsupported per-VLAN behavior rather than silently applying a bridge-global setting.

### Task 16: Add Advanced IGMP Configuration

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Implement Querier, Fast Leave, and Router Port as independently configurable settings.
- [ ] Validate that Fast Leave is not enabled on shared downstream segments where multiple listeners can share one port.
- [ ] Verify effective bridge/VLAN settings and report the detected multicast-router port state.

### Task 17: Add DHCP Snooping and Guarding

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define trusted DHCP server ports, untrusted access ports, rate limits, and optional binding-table retention.
- [ ] Enforce DHCP server replies only on trusted ports and validate client binding before applying related IP/MAC guards.
- [ ] Preserve the existing DHCP server behavior where configured and report lease/binding conflicts.

### Task 18: Add 802.1X Control

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

- [ ] Select and package a Linux authenticator provider only after documenting supported driver modes and RADIUS behavior.
- [ ] Define port authorization states, controlled/uncontrolled traffic, reauthentication, and failure policy.
- [ ] Keep credentials write-only, validate provider-native config before activation, and report supplicant/authenticator state per port.

### Task 19: Add Voice VLAN

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define voice VLAN membership, tagged/untagged behavior, and device identification source.
- [ ] Validate it against LLDP-MED policy and existing access VLAN assignments.
- [ ] Apply and report effective VLAN membership per port.

### Task 20: Add LLDP-MED

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

- [ ] Select a Linux LLDP provider and document its supported LLDP-MED policies and capabilities.
- [ ] Configure network policy, voice/application VLAN, and power-via-MDI fields only when supported by provider and NIC.
- [ ] Report advertised and received LLDP-MED data with secrets and untrusted input handled safely.

### Task 21: Add STP and RSTP

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

- [ ] Report the kernel bridge STP mode and select a compatible RSTP implementation where rapid convergence is requested.
- [ ] Define bridge priority, port priority, path cost, edge/point-to-point role, and BPDU guard behavior.
- [ ] Validate one authoritative STP controller per bridge and report root, role, state, and topology changes.

### Task 22: Add Loop Protection

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define per-port loop detection, recovery delay, and shutdown/blocked action.
- [ ] Clarify interaction with STP/RSTP and reject conflicting controllers.
- [ ] Report detection, blocked state, recovery timer, and reason.

### Task 23: Add LACP Port Aggregation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/plan.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define dedicated member interfaces, actor/system identity, mode, minimum active links, and hash policy.
- [ ] Reject any member already owned by a WAN, bridge, VLAN, or other bond.
- [ ] Create Linux 802.3ad bond, attach members in safe order, and verify LACP partner and collecting/distributing state.
- [ ] Never claim added bandwidth unless the peer switch and flow hash behavior support the negotiated aggregate.

### Task 24: Add Redundancy

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define the supported redundancy policy as a health/status coordinator over configured mechanisms such as LACP, STP/RSTP, and VRRP; do not implement a second independent failover protocol.
- [ ] Attribute every transition to the mechanism that owns it and reject overlapping failover controllers on the same network/interface.
- [ ] Report active/standby state, tracked health, transitions, recovery behavior, and any mechanism that is unavailable on this host.

### Task 25: Add MC-LAG

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, provider-specific adapter and status files.

- [ ] Define MC-LAG only for an explicitly supported peer/vendor control protocol or documented Linux peer implementation.
- [ ] Detect peer identity, consistency, and split-brain state before allowing apply.
- [ ] If no compatible provider exists, expose MC-LAG as unsupported and reject configuration; do not emulate it with a single-node bond.

### Task 26: Add Shadow Mode (VRRP) Gateway Failover

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

- [ ] Define shadow/standby role, virtual IP/MAC behavior, priority, preemption, advertisements, and tracked health.
- [ ] Select a Linux VRRP provider and validate peer subnet/interface compatibility.
- [ ] Apply provider-native config transactionally and report MASTER/BACKUP/FAULT role and failover events.
- [ ] State that conntrack/session continuity is unavailable unless a separate state-sync capability is configured and verified.

### Task 27: Add Port Mirroring

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define source interfaces/directions, one destination, VLAN scope, and capture limits.
- [ ] Detect supported driver/`tc` mirroring behavior before apply and reject a destination that is also a forwarding source.
- [ ] Report effective mirror action and counters without retaining packet payloads.

### Tasks 28–35: Add Pro AV profiles one at a time

**Files for each task:** `gateway/layer2/avprofiles/<profile>.go`, matching tests, shared profile registry, config validation, and status output.

For each separate profile (28 Play, 29 Dante, 30 Q-SYS, 31 NDI, 32 SDVoE, 33 Shure, 34 AES67, 35 Crestron):

- [ ] Research current primary vendor/standards documentation for the named profile and record exact multicast, QoS/DSCP, VLAN, and MTU recommendations that the profile changes.
- [ ] Represent only documented settings as a named preset; do not claim protocol certification, device discovery, or interoperability testing.
- [ ] Validate compatibility with the active network, DSCP map, IGMP configuration, and other profiles before apply.
- [ ] Apply through the same reversible provider plan and expose the selected profile plus effective settings.
- [ ] Add a profile-specific configuration/plan test that proves its settings and conflict handling independently.

## Completion and Integration

- [ ] Run focused gateway package and admin portal tests after each feature integration, then the complete Server and Client suites after all features are integrated.
- [ ] Run Linux namespace/veth integration checks for bridge, VLAN, ACL, IGMP, DHCP guarding, shaping, LACP where two virtual peers are available, and rollback.
- [ ] Run a deployment acceptance check proving the existing edge Compose service remains isolated and the host daemon alone owns host interfaces.
- [ ] Update the admin portal documentation, install guide, capability matrix, and `FEATURES.md` to distinguish available, unsupported, and implemented capabilities.
- [ ] Review all diffs and stage only Layer 2 integration files; preserve pre-existing local file mode changes and unrelated working tree edits.
- [ ] Commit the Client roadmap/spec change separately. Commit each Server feature integration as its own descriptive commit so every capability remains independently reviewable.
- [ ] Push the requested commits only after confirming the intended branch and the commits already ahead of each remote.
