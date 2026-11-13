# Linux Gateway Foundation and Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a separately supervised Linux gateway control plane that validates desired state, applies reversible host changes through bounded adapters, and reports WAN quality, outages, flows, and bridge MAC occupancy.

**Architecture:** Add a `gateway` package and `cmd/gatewayd` host process in `GameBond.Server`, separate from the existing unprivileged tunnel server container. The daemon reads a versioned gateway config, uses fixed-argument Linux adapters, and exposes a local Unix-socket management API; it does not accept shell commands or expose an unauthenticated network listener.

**Tech Stack:** Go 1.26, Linux, systemd, iproute2 JSON output, Linux conntrack, Linux bridge FDB, Unix domain sockets, existing GameBond admin authentication patterns.

**Spec:** `GameBond.Client/docs/superpowers/specs/2026-11-13-linux-router-capabilities-design.md`

## Global Constraints

- Target a Linux GameBond gateway; do not extend the Windows desktop client for host routing.
- The existing edge server remains in its separate container network namespace; do not change its `network_mode`, capabilities, or firewall behavior in this phase.
- Validate the complete proposed configuration before changing live host state.
- No arbitrary shell strings are accepted from configuration or the API.
- No secrets are returned by management APIs, status documents, or logs.
- Bound flow records and event history by explicit count, time, and storage limits.
- Unsupported host or kernel features fail clearly before apply.
- Reconcile the existing Windows local-network Layer 3 design before later work changes DHCP or interface ownership.

## Review Focus

- **Host/namespace confusion:** the gateway must inspect and modify the host namespace only from its dedicated service; existing container status must not be mistaken for host status.
- **Malformed or oversized configuration:** reject unknown fields, trailing JSON, invalid references, and files over the configured byte limit before any adapter is invoked.
- **Command and socket injection:** every process invocation uses a fixed executable and argv; API permissions derive from the Unix socket owner/group and request bodies have a hard limit.
- **Telemetry cardinality and privacy:** do not retain packet payloads; flow identities and history have hard caps and can be cleared by the operator.
- **Partial apply failure:** preserve the previous known-good config, restore completed stages in reverse order, and expose rollback failure explicitly.

---

## File Map

- Create `gateway/config.go`: versioned desired-state types, strict JSON decode, validation, and normalization.
- Create `gateway/capabilities_linux.go`: read-only kernel/tool/interface capability inventory using fixed argv and bounded calls.
- Create `gateway/runner_linux.go`: the only process adapter; fixed executable allowlist, argv, timeout, output cap, and error normalization.
- Create `gateway/apply.go`: staged apply coordinator with prepare, apply, verify, and rollback interfaces.
- Create `gateway/quality.go`: per-WAN probe scheduling, quality samples, outage transitions, and bounded journal.
- Create `gateway/flows_linux.go`: conntrack event collection and bounded flow aggregation without payload inspection.
- Create `gateway/bridge_linux.go`: Linux bridge FDB inventory, occupancy, configured learned-entry limit capability, and saturation state.
- Create `gateway/api.go`: Unix-socket status/configuration endpoints, request bounds, and local authorization boundary.
- Create `cmd/gatewayd/main.go`: config loading, service startup, signal handling, API socket lifecycle, and JSON status logging.
- Create `tools/gamebond-router.service`: dedicated host systemd unit with restrictive defaults and explicit required capabilities.
- Modify `README.md`: install/run model and clear separation from the current edge container.
- Modify `adminportal/system.go` only if an existing host-status helper can safely be reused without giving the edge container host-network authority; otherwise do not modify the current portal in this phase.

## Interfaces

- `gateway.DecodeConfig(io.Reader) (Config, error)` strictly decodes and validates the versioned config.
- `gateway.Runner.Run(ctx context.Context, executable string, args ...string) (stdout []byte, stderr []byte, err error)` rejects executables outside its fixed allowlist and enforces deadlines/output limits.
- `gateway.CapabilitySource.Snapshot(ctx context.Context) (Capabilities, error)` returns detected host support without changing host state.
- `gateway.Applier.Prepare(ctx context.Context, current, desired Config) (PreparedChange, error)` validates provider-native candidate state without applying it.
- `gateway.PreparedChange.Apply(ctx context.Context) error`, `Verify(ctx context.Context) error`, and `Rollback(ctx context.Context) error` form the reversible transaction boundary.
- `gateway.QualityMonitor.Snapshot() QualitySnapshot` returns per-WAN quality and outage state; it never blocks packet or admin request paths.
- `gateway.FlowCollector.Snapshot() FlowSnapshot` returns bounded aggregate flow records with no payload bytes.
- `gateway.BridgeInventory.Snapshot(ctx context.Context) ([]BridgeSnapshot, error)` reports bridge FDB use and whether an entry ceiling is enforceable on the detected kernel.
- The Unix API exposes only `GET /v1/status`, `GET /v1/config`, `PUT /v1/config`, and `POST /v1/config/validate`; it has no generic command endpoint.

## Task 1: Add strict Linux gateway configuration and host capability inventory

**Files:** `gateway/config.go`, `gateway/capabilities_linux.go`, `gateway/runner_linux.go`, `gateway/config_linux_test.go`, `gateway/capabilities_linux_test.go`.

- [ ] Define versioned config types for named WANs, probe targets, telemetry retention, bridge FDB limits, management socket path, and provider enablement. Use stable IDs, not interface display names, for persistent references.
- [ ] Implement `DecodeConfig` with `DisallowUnknownFields`, a 1 MiB maximum, one JSON value only, and field-specific validation errors.
- [ ] Validate unique IDs, interface ownership, WAN probe target shape, minimum/maximum probe intervals, telemetry caps, MAC limits, and socket path constraints before returning a config.
- [ ] Implement the fixed-argv `Runner` with an executable allowlist (`ip`, `bridge`, `conntrack`, and `nft` only in this phase), context deadlines, and 64 KiB stdout/stderr caps.
- [ ] Implement a read-only capability snapshot that checks kernel release, tool availability, selected interface identities, bridge FDB visibility, conntrack event visibility, and required netlink/sysfs paths.
- [ ] Add tests for unknown/trailing/oversized JSON, duplicate IDs and interface ownership, invalid probe and retention bounds, forbidden executables, argument values containing shell metacharacters, command timeout/output cap, and absent optional tools.

## Task 2: Add reversible apply coordinator and service process boundary

**Files:** `gateway/apply.go`, `gateway/apply_test.go`, `cmd/gatewayd/main.go`, `tools/gamebond-router.service`, `README.md`.

- [ ] Define `PreparedChange` and `Applier`; keep provider validation separate from host mutation so every requested change can be validated before the first live command.
- [ ] Implement transaction order: load current known-good config, prepare every enabled provider, apply prepared changes in dependency order, verify effective state, persist desired config atomically, and report the transaction ID.
- [ ] On any apply/verify/persist error, roll back completed changes in reverse order and preserve the old config; report both the original and rollback errors.
- [ ] Implement `cmd/gatewayd` with explicit config path, status output, graceful signal shutdown, and refusal to start if config permissions or host capability checks fail.
- [ ] Add a systemd unit running the dedicated host daemon with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, private tmp, restricted address families, and only the network capabilities the selected adapters require.
- [ ] Document that this unit is separate from `GameBond.Server/compose.yaml`; do not grant the edge container host networking.
- [ ] Add coordinator tests using an in-memory provider for prepare failure, apply failure, verification failure, reverse-order rollback, rollback error reporting, and interrupted transactions.

## Task 3: Add per-WAN quality and outage reporting

**Files:** `gateway/quality.go`, `gateway/quality_test.go`, `gateway/api.go`.

- [ ] Define probe settings per WAN: target address, interval, timeout, and consecutive-failure thresholds; reject loopback, multicast, unspecified, and malformed targets.
- [ ] Implement bounded ICMP/TCP reachability probes using the WAN interface binding supplied by the Linux adapter; record timestamp, RTT, loss window, and selected probe target.
- [ ] Define outage transitions with hysteresis: one failed probe marks degraded, configured consecutive failures mark outage, and configured consecutive successes close the event.
- [ ] Persist a size-capped outage journal using atomic file replacement; never store credentials or packet contents.
- [ ] Publish current quality, recent samples, outage transitions, and probe errors in the status snapshot.
- [ ] Add tests with fake clock/prober for recovery hysteresis, interface loss, timeout, journal truncation, and stable status while a probe is blocked.
- [ ] Document how this gateway-level view complements the existing client transport/outage status rather than replacing it.

## Task 4: Add bounded all-flow and bridge MAC occupancy reporting

**Files:** `gateway/flows_linux.go`, `gateway/flows_test.go`, `gateway/bridge_linux.go`, `gateway/bridge_test.go`, `gateway/api.go`.

- [ ] Consume conntrack NEW/UPDATE/DESTROY events through the fixed runner or netlink adapter; parse tuple metadata only and never capture payloads.
- [ ] Maintain bounded flow records keyed by network namespace, 5-tuple, and direction; expose first/last seen, protocol, byte/packet counters, WAN/policy attribution when known, and eviction counters.
- [ ] Apply configured history age and maximum-record limits; use deterministic oldest-record eviction and expose whether a flow was evicted or expired.
- [ ] Read bridge FDB state and report learned/dynamic/static counts, configured ceiling, occupancy percentage, and whether the kernel supports enforcing the requested ceiling.
- [ ] Refuse configuration that requests a hard MAC ceiling when the detected bridge/kernel cannot enforce it; do not present a display-only threshold as enforcement.
- [ ] Add tests for malformed and truncated conntrack records, tuple-key isolation, counters, expiration, capacity eviction, bridge static-vs-learned counting, and unsupported enforcement.

## Task 5: Add local Unix-socket management API and deployment guidance

**Files:** `gateway/api.go`, `gateway/api_test.go`, `cmd/gatewayd/main.go`, `tools/gamebond-router.service`, `README.md`.

- [ ] Create the Unix listener with configured owner/group/mode; refuse a pre-existing non-socket path and remove only a socket owned by the daemon.
- [ ] Implement the four versioned endpoints from the Interfaces section with strict methods, content types, body limits, and structured errors.
- [ ] Return effective config with credentials redacted; `PUT` treats omitted secrets as preserve-existing and an explicit null as clear only where the schema allows it.
- [ ] Require socket filesystem permissions for local authorization and bind no TCP listener in this phase.
- [ ] Ensure status combines capability, apply transaction, WAN quality/outages, flow, bridge FDB, and daemon health snapshots without blocking on provider I/O.
- [ ] Add API tests for authorization boundary assumptions, wrong methods, oversized bodies, malformed JSON, redaction, config validation, and unavailable telemetry providers.
- [ ] Document install, config permissions, service startup, status access through the socket, rollback behavior, supported Linux prerequisites, and uninstall.

## Phase 1 completion checks

- `cd GameBond.Server && go test ./gateway ./cmd/gatewayd` passes.
- `cd GameBond.Server && go vet ./gateway ./cmd/gatewayd` passes.
- `cd GameBond.Server && go build ./cmd/gatewayd` succeeds for Linux.
- A non-root invocation with a read-only fixture config reports missing host capabilities and makes no changes.
- A Linux integration run with fake `ip`, `bridge`, `conntrack`, and `nft` executables confirms fixed argv, output caps, config rollback, and no use of the host shell.
- The existing server container still starts with the current Compose file and retains its existing namespace/capability boundary.

## Later plans

Create separate execution plans after this foundation is accepted:

1. Forwarding and policy: DHCP, SNAT/DNAT/masquerade/NAT pools/1-to-1, WAN/VPN policy routing, advanced QoS.
2. Redundancy and aggregation: VRRP shadow/standby, LACP, LTE backup.
3. Dynamic routing: OSPF and BGP, route policy, route visibility.
4. LAN services and identity: mDNS, IGMP proxy, integrated RADIUS, RadSec, virtual-network override.

Use current upstream documentation during each plan's provider selection: [FRRouting](https://docs.frrouting.org/en/latest/), [Keepalived](https://keepalived.org/documentation/), and [ISC Kea](https://kea.readthedocs.io/). Linux bridge, conntrack, and traffic-control feature availability must be checked against the target distribution's shipped kernel and tools.
