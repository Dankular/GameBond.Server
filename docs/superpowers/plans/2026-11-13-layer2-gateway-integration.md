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

- [x] Add a `Layer 2 Gateway Features` status section listing each requested capability exactly once.
- [x] Group the list by switching, resilience, multicast/media, access control, and traffic control while preserving individual feature names.
- [x] State that configuration availability is not proof of host support or application.
- [x] Add the Layer 2 design to the canonical Linux router spec and identify the `gatewayd` host boundary.
- [x] Review the list against the user's request and confirm no item or AV profile is missing or duplicated.

### Task 1b: Integrate the optional admin-portal gateway socket

**Files:** `adminportal/gateway.go`, `adminportal/portal.go`, `cmd/edge/main_linux.go`, `gateway/api_linux.go`, `compose.gateway.yaml`, `docs/linux-router.md`.

- [x] Define a client that dials only the configured Unix socket and supports the allowlisted status, validate, plan, apply, and rollback API operations with request/response size bounds.
- [x] Require the existing portal authentication and CSRF checks before forwarding mutating requests; keep the daemon-side schema/capability validation authoritative.
- [x] Add an optional Compose overlay with a read-only bind mount of the dedicated socket directory and a configured shared group ID; do not change the default Compose service's network mode or capabilities.
- [x] If the socket is absent, expose gateway management as unavailable and preserve existing tunnel/admin portal startup.
- [x] Document the host socket ownership/mode, group mapping, optional overlay activation, and the fact that the socket still grants its allowlisted host-management API to the edge container.

### Task 2: Define shared Layer 2 desired state and capability contract

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/config_test.go`, `gateway/layer2/capabilities_test.go`.

- [x] Add strict, versioned configuration objects for managed interfaces, bridges, VLANs/virtual networks, port membership, and feature settings.
- [x] Select the sole verified Linux provider for each integrated capability; STP/RSTP provider mode is explicit in typed bridge settings (`stp_mode` selects `mstpd` RSTP). Unsupported vendor or alternate providers are rejected rather than selected implicitly.
- [x] Implement the base managed bridge, VLAN-filtering, and port-membership operations; snapshot and reversible transaction integration are in place.
- [x] Reject unknown fields, invalid identifiers, duplicate interface ownership, missing references, invalid ranges, and feature dependency conflicts before planning.
- [x] Report capabilities as supported, unsupported, or unavailable with machine-readable reasons and discovered kernel/tool/provider requirements.
- [x] Feed deterministic Layer 2 plan operations into the existing reversible gateway transaction coordinator.
- [x] Test malformed configuration, interface conflicts, unsupported capability rejection, and deterministic serialization.

### Task 3: Add virtual network override

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/plan.go`, `gateway/hostapply_linux.go`, `gateway/runtime.go`, `gateway/api_linux.go`.

- [x] Define Virtual Network Override as an authorized device-to-network/VLAN assignment with explicit precedence over default network membership.
- [x] Validate that the target device identity is allowed and the selected network exists.
- [x] Apply the VLAN/bridge membership using detected bridge and `tc` support and verify effective membership and filters.
- [x] Report assignment, effective network, and rejection reason in status.

### Task 4: Add Jumbo Frames

**Files:** `gateway/layer2/capabilities_linux.go`, `gateway/layer2/plan.go`, and their focused tests.

- [x] Validate requested MTU against every physical interface in the affected bridge path and reject jumbo MTUs if the host maximum is missing or too small; check the bridge maximum when it already exists.
- [x] Apply MTU changes in dependency order and roll back if any member or bridge rejects the size.
- [x] Verify effective MTU on the bridge and physical members through the transaction's post-apply topology check. Bond path verification remains part of the later LACP integration.

### Task 5: Add Port Isolation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/plan.go`, `gateway/layer2/plan_test.go`, `gateway/layer2/capabilities_linux_test.go`.

- [x] Define per-port bridge isolation with scope inherited from that port's configured bridge/VLAN membership; isolated ports cannot forward to other isolated ports, while the bridge host port remains outside the isolated set.
- [x] Reject isolation when the bridge provider is unavailable and refuse changes when live isolation state cannot be observed.
- [x] Apply and verify Linux bridge isolated-port flags with reversible updates.

### Task 6: Add MAC-Based Port Restriction

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define allowed MAC identities, maximum learned devices, violation action, and per-port policy.
- [x] Enforce a whitelist with Linux bridge locked ports and static FDB entries; because Linux learned-FDB limits are bridge-wide, reject topologies with more than one managed access port on the bridge.
- [x] Report the configured allow-list, live learned-device count, locked FDB entries, and applied state from only the managed port and bridge.

### Task 7: Add MAC Address Blocking

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Validate unicast MAC addresses and single-network port scope.
- [x] Apply atomic nftables bridge input/output/forward drop rules with packet counters and verify the exact active GameBond rule set.
- [x] Bound the configured rule count and replace/remove only the marked GameBond-owned table, with rollback scripts restoring the previous policy.

### Task 8: Add MAC-Based ACLs and Device Isolation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define ordered allow/deny rules with source/destination MAC, direction, network/port scope, and terminal action.
- [x] Reject duplicate match tuples, invalid rule order identifiers, and unsupported combinations before apply.
- [x] Apply an atomic scoped bridge-family ACL table and report active rule order plus packet/byte counters.

### Task 9: Add IP-Based ACLs and Network Isolation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define ordered IP prefix/protocol/port policies tied to named virtual networks.
- [x] Enforce routed inter-network isolation through an owned inet forward chain, with explicit allows between named networks and default deny for other routed pairs.
- [x] Apply an atomic GameBond-owned bridge-family ACL table and report active rule counters without replacing unrelated host firewall state.

### Task 10: Add Egress Rate Limit

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define per-port TBF and tagged-trunk per-network rate/burst parameters with explicit units and bounds; reject access-port VLAN scope that cannot be matched after egress untagging.
- [x] Apply `tc` TBF shaping for whole-interface policies and `clsact` policing for tagged VLAN policies; report observed rate and burst.
- [x] Reject interfaces whose root qdisc is unmanaged or unsupported instead of silently replacing it.

### Task 11: Add Flow Control

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define RX/TX pause and autonegotiation behavior per physical interface.
- [x] Detect driver and ethtool support before apply; reject bond aggregates and members.
- [x] Verify effective pause settings and report unsupported interfaces with driver detail.

### Task 12: Add QoS (DSCP)

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define DSCP-to-class and class-to-queue/rate policy shared with the existing adaptive QoS model.
- [x] Apply `tc` classification and queue policy without overriding GameBond tunnel DSCP semantics.
- [x] Report class counters and effective mappings.

### Task 13: Add Storm Control

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define per-port broadcast and multicast thresholds and drop action; generic Linux `tc` cannot classify unknown-unicast based on the bridge FDB, so that class remains unsupported.
- [x] Apply broadcast/multicast policers with `skip_hw` and report software `tc` enforcement.
- [x] Verify configured thresholds and expose drop counters.

### Task 14: Add Multicast and Broadcast Rate Limiting

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define separate per-interface multicast and broadcast rate/burst policies.
- [x] Apply dedicated-priority `tc` policers; reject multicast policing on IGMP-snooping ports and reject overlapping classes with storm control.
- [x] Verify exact filters and drop counters; policers run at `tc` ingress before bridge-family ACL evaluation.

### Task 15: Add IGMP Snooping

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Configure Linux bridge multicast snooping per bridge and VLAN using bridge VLAN global controls where available.
- [x] Report MDB membership, listener ports, and multicast-router ports from effective kernel state; elected-querier presence remains a reporting gap.
- [x] Gate per-VLAN changes on host capability and known live state, with exact rollback; reject unknown or unsupported state.

### Task 16: Add Advanced IGMP Configuration

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Implement Querier, Fast Leave, and Router Port as independently configurable settings.
- [x] Validate that Fast Leave is not enabled on shared downstream segments where multiple listeners can share one port; require explicit non-shared confirmation.
- [x] Verify effective bridge settings and report the detected multicast-router port state.

### Task 17: Add DHCP Snooping and Guarding

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define per-port trusted/untrusted roles and bounded DHCP request rate limits.
- [x] Read the managed Kea memfile lease database into runtime status, using the latest record per IPv4 address and excluding expired, declined, or released leases.
- [ ] Enforce IPv4/MAC/bridge-port tuples on opted-in untrusted ports from an authoritative DHCP ingress source. Kea memfile has no receiving port and learned FDB state is not trusted; requests currently fail closed before host changes.
- [ ] Add configurable binding-table retention after authoritative DHCP ingress metadata is integrated.
- [x] Enforce DHCP server replies only on trusted ports and report unsupported client binding enforcement distinctly.
- [x] Preserve existing Kea DHCP server behavior; do not claim lease bindings are enforced from endpoint-influenced FDB state.

### Task 18: Add 802.1X Control

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

**Provider constraint:** hostapd can act as the wired RADIUS authenticator, but it does not enforce the bridge traffic decision by itself. The feature must include a fail-closed bridge traffic-plane controller driven by authenticated-client events; hostapd status alone is not sufficient evidence of access control. Wired EAPOL forwarding through the Linux bridge must be enabled and verified, and the interaction with the selected STP controller must be tested for the supported kernel/provider matrix before this capability is advertised. The current RHEL wired-auth example sets bridge group-forward-mask `8` and disables STP, so the generic integration must not assume that EAPOL forwarding and the project's STP/RSTP path coexist automatically.

- [x] Select and package the Linux hostapd wired authenticator provider; document its `wired` driver mode, external RADIUS settings, and separate traffic-plane enforcement behavior.
- [x] Define per-port authorization through a fail-closed nftables set, EAPOL-only unauthenticated traffic, reauthentication, and closed failure behavior; reject the unverified STP/RSTP combination.
- [ ] Keep credentials write-only, validate provider-native config before activation, and report supplicant/authenticator state per port. Credentials stay out of management JSON, protected configs are generated from root-only secrets, service health and authorized clients are reported; hostapd has no non-activating native config-check mode, so config rejection is currently detected by transactional service startup and rollback.

### Task 19: Add Voice VLAN

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define voice VLAN membership as a tagged `voice_network` on each bridge port; LLDP-MED network policy identifies the phone-facing voice VLAN.
- [x] Validate it against LLDP-MED application policy and the port's tagged/untagged access network assignments.
- [x] Apply through the reversible bridge VLAN plan and report advertised voice policy plus effective bridge VLAN state.

### Task 20: Add LLDP-MED

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

- [x] Select `lldpd`/`lldpcli` as the Linux provider and document supported application-policy values and provider constraints.
- [x] Configure network policy and voice/application VLAN through the reversible bridge plan and LLDP-MED provider.
- [ ] Probe provider/NIC power-via-MDI support before exposing power fields.
- [x] Report configured advertised policies and bounded, JSON-validated received neighbor data; LLDP input is exposed as data and never used for authorization.

### Task 21: Add STP and RSTP

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

- [x] Report kernel bridge STP state, select STP/RSTP through `mstpd` when requested, and read back root ID/port, per-port role/state, and topology-change state/count.
- [x] Define and apply bridge priority, port priority, path cost, root-block, edge, point-to-point, and BPDU-guard controls with live-state reads and rollback; edge and BPDU-guard settings require the `mstpd` RSTP controller.
- [x] Validate controller ownership before planning: inspect known local STP services and query NetworkManager, systemd-networkd, and Open vSwitch per affected bridge/port; fail closed for managed targets or ambiguous ownership. Arbitrary external agents and remote switches cannot be discovered reliably.

### Task 22: Add Loop Protection

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [ ] Define per-port loop detection, recovery delay, and shutdown/blocked action.
- [ ] Clarify interaction with STP/RSTP and reject conflicting controllers.
- [ ] Report detection, blocked state, recovery timer, and reason.

### Task 23: Add LACP Port Aggregation

**Files:** `gateway/layer2/config.go`, `gateway/layer2/plan.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define dedicated member interfaces, optional system MAC identity, 802.3ad mode, minimum active links, LACP rate, and hash policy.
- [x] Reject members already owned by a WAN, bridge, VLAN, or other bond.
- [x] Create the Linux bond and attach members in reversible order; verify peer system identity and collecting/distributing state before committing.
- [x] Report active member state without claiming a fixed bandwidth increase or single-flow throughput.

### Task 24: Add Redundancy

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define the supported redundancy policy as a health/status coordinator over configured mechanisms such as LACP, STP/RSTP, and VRRP; do not implement a second independent failover protocol.
- [x] Attribute every transition to the mechanism whose health or role changed and reject cross-group overlap on shared bond, bridge, port, and VRRP interface resources.
- [x] Report active/standby state, tracked health, transitions, recovery behavior, and unavailable mechanisms with reasons; recovery guidance remains owned by each underlying mechanism.

### Task 25: Add MC-LAG

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, provider-specific adapter and status files.

- [x] No peer/vendor control protocol is configured, so MC-LAG is not presented as a supported mode.
- [x] No MC-LAG apply path is allowed without a provider capable of peer identity, consistency, and split-brain checks.
- [x] Report MC-LAG unsupported and reject the strict-config `mc_lag` field; do not emulate it with a single-node bond.

### Task 26: Add Shadow Mode (VRRP) Gateway Failover

**Files:** `gateway/layer2/config.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`, provider service packaging.

- [x] Define a non-preempting BACKUP role, virtual IPs, peer addresses, priority, and advertisement interval; explicit virtual-MAC control and tracked health remain open.
- [x] Select Keepalived and validate peer and VIP subnet compatibility against the live interface before apply.
- [x] Apply the provider config transactionally and report MASTER/BACKUP/FAULT from service and local VIP ownership; event history is not yet exposed.
- [x] Document that conntrack/session continuity is unavailable without a separate verified state-sync provider.

### Task 27: Add Port Mirroring

**Files:** `gateway/layer2/config.go`, `gateway/layer2/capabilities_linux.go`, `gateway/layer2/provider_linux.go`, `gateway/layer2/status_linux.go`.

- [x] Define source interfaces/directions, one dedicated destination, tagged VLAN scope, and a TBF capture-rate/burst limit.
- [x] Prove software `tc mirred` support in an isolated veth namespace before apply; force the mirror filters onto the software path, reject non-standalone destinations, and verify effective filters after apply.
- [x] Report effective mirror action and packet/byte counters without retaining packet payloads.

### Tasks 28–35: Add Pro AV profiles one at a time

**Files for each task:** `gateway/layer2/avprofiles/<profile>.go`, matching tests, shared profile registry, config validation, and status output.

For each separate profile (28 Play, 29 Dante, 30 Q-SYS, 31 NDI, 32 SDVoE, 33 Shure, 34 AES67, 35 Crestron):

- [ ] Recheck primary vendor/standards documentation for all eight catalogue entries and confirm every recommendation remains current; profile source URLs and setting-level rationale are recorded in the preset implementations and tests.
- [x] Represent the documented recommendations as named presets and state that they do not imply certification, discovery, or interoperability testing.
- [x] Reconcile required minimum link speeds across every bridge member carrying a selected AV network and validate numeric DSCP/queue recommendations against the final merged Layer 2 plus adaptive QoS map when QoS is active. External switch/endpoint recommendations and optional QoS remain advisory.
- [x] Persist per-network profile selections through the reversible gateway config transaction and expose the complete recommendation catalogue through the authenticated gateway API and portal proxy. Minimum link speed and active numeric QoS requirements are validated; external switch/endpoint controls and recommendations without verified providers remain advisory.
- [x] Add per-profile setting/source assertions, stable catalogue coverage, per-network selection validation, cross-profile conflict tests, and gateway/portal catalogue route tests.

## Completion and Integration

- [x] Run focused gateway and admin portal tests plus the full Server suite and build; all pass. The full Client suite is not green because of existing unrelated `native-edge` compile/runtime failures (`Manager.Sessions`, Linux test missing Windows-only `OpenDevice`, noexec `/tmp`, and a timing-sensitive throughput assertion); `netstack` passes.
- [ ] Run Linux namespace/veth integration checks for bridge, VLAN, ACL, IGMP, DHCP guarding, shaping, LACP where two virtual peers are available, and rollback. Isolated veth, bridge VLAN, multicast snooping, and software mirroring pass; the host kernel rejects nftables bridge-table creation as unsupported, so ACL, DHCP, and 802.1X live checks remain unavailable here.
- [ ] Run a deployment acceptance check proving the existing edge Compose service remains isolated and the host daemon alone owns host interfaces. The optional Compose overlay renders with the edge service on its bridge network, read-only gateway socket mount, and the separate root-owned host service; no live deployment was run.
- [x] Update the admin portal documentation, install guide, capability matrix, and `FEATURES.md` to distinguish available, unsupported, and implemented capabilities.
- [x] Review diffs and stage only Layer 2 integration files; preserve unrelated Client working tree changes and local file-mode noise.
- [x] Commit the Client Layer 2 roadmap change separately and the integrated Server subsystem as a descriptive, reviewable commit.
- [x] Fetch all remotes, rebase the Client commits onto the latest GitHub `main`, then push the Layer 2 Server and Client commits to their respective `main` branches. Verify both remote refs match the pushed commits.
