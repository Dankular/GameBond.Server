# Advanced Firewall and Traffic Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add advanced zone, region, domain, and application filtering, traffic identification, content/ad filtering, and optional TLS inspection with a hard concurrent-session cap.

**Architecture:** Extend the strict `security` schema and existing manager/API/dashboard. Keep nftables responsible for packet predicates, add a bounded flow classifier for DNS/SNI/protocol metadata, and add a separate opt-in Linux transparent TCP/TLS inspection proxy. DNS filtering remains useful without inspection; URL path decisions require successful interception.

**Tech Stack:** Go 1.26, Linux nftables, `crypto/tls`/`crypto/x509`, existing `golang.org/x/sys/unix`, existing vanilla JavaScript dashboard, Docker Compose.

**Spec:** `GameBond.Server/docs/superpowers/specs/2026-11-13-advanced-firewall-design.md`

## Global Constraints

- All new capabilities default off; current firewall, DNS, and IDS behavior remains unchanged when omitted.
- Unknown application/protocol classification is represented distinctly and can be matched explicitly by policy.
- The TLS inspection CA private key is generated/stored with restrictive permissions and is never returned by the API.
- Session-cap exhaustion follows an explicit configured action (`bypass` or `deny`) and increments a counter.
- Inspection failures, unsupported flows, and classifier uncertainty are observable; no silent claim of inspection is permitted.
- DNS remains independent and usable when TLS inspection is disabled.

## Review Focus

- Flow state exhaustion and idle expiration: bounded tables, explicit eviction, and counters; pin in classifier lifecycle checks.
- DNS/IP correlation with shared hosting and changing addresses: only high-confidence matches may enforce app/domain rules; pin in policy matching checks.
- TLS interception failures after a forged certificate handshake starts: fail closed for inspection-required rules; no unsafe midstream bypass; pin in proxy handshake checks.
- CA loss/rotation and read-only container storage: startup and export state must be explicit; pin in CA lifecycle checks.
- HTTP/2, QUIC, pinning, mutual TLS, encrypted ClientHello: mark unsupported or bypass only before terminating client TLS; pin in compatibility checks.

---

## File Map

- Modify `GameBond.Server/firewall/config.go` and `render.go`: advanced packet-level region/zone conditions and validation/rendering.
- Modify `GameBond.Server/security/settings.go`, `manager.go`, and `manager_test.go`: new settings sections, cross-section checks, manager wiring, overview and catalog.
- Add `GameBond.Server/traffic/`: bounded flow metadata, protocol/application labels, DNS correlation, expiry, confidence, and counters.
- Add `GameBond.Server/inspection/`: CA generation/loading, transparent TCP listener, TLS termination, URL policy, concurrent session accounting, and status.
- Modify `GameBond.Server/cmd/edge/main_linux.go`, `compose.yaml`, and `Dockerfile`: lifecycle wiring, protected persistent CA directory, and inspection listener startup.
- Modify `GameBond.Server/adminportal/portal.go`: authenticated safe CA export/action endpoints if needed; private key is never exposed.
- Modify `GameBond.Client/native-edge/dashboard/widget_security.js` and its related security tests: configuration controls, status and unsupported-flow explanations.
- Modify `GameBond.Server/docs/security.md`, `GameBond.Server/README.md`, and `GameBond.Client/FEATURES.md`: operator requirements, support matrix, and truthful capability descriptions.

## Task 1: Define the additive security schema

**Files:**
- Modify: `GameBond.Server/security/settings.go`
- Modify: `GameBond.Server/firewall/config.go`
- Modify: `GameBond.Server/dnsfilter/config.go`
- Modify: `GameBond.Server/security/manager_test.go`

**Interfaces:**
- Add `traffic` and `inspection` sections to `security.Settings`.
- Add rule match fields using explicit arrays: region codes, domain patterns, and application/protocol labels. Empty arrays mean no condition.
- Add `inspection.max_sessions` (1 to 512), `inspection.enabled`, and `inspection.exhaustion_action` (`bypass` or `deny`). Inspection-dependent policy must be rejected unless inspection is enabled.
- Preserve omitted-field normalization and strict unknown-field rejection.

- [ ] Define limits for each new list and rule count, plus canonical lowercase domain and category/application label forms.
- [ ] Validate that app/domain predicates are not rendered as nftables expressions; they belong to the metadata policy stage.
- [ ] Ensure parsing of current config fixtures produces identical defaults and JSON compatibility.
- [ ] Add migration notes to the security docs for omitted defaults and rejection of invalid combinations.

## Task 2: Add advanced nftables region and zone policy

**Files:**
- Modify: `GameBond.Server/firewall/config.go`
- Modify: `GameBond.Server/firewall/render.go`
- Modify: `GameBond.Server/security/manager.go`
- Modify: `GameBond.Server/security/countries.go`

**Interfaces:**
- Expand `firewall.Rule` with region and zone constraints only where nftables has address-set evidence.
- Keep domain and application conditions out of nft rendering.
- Extend `firewall.Inputs` with normalized region prefix sets resolved by the existing Geo store.

- [ ] Reuse existing country list fetching and validation; add no new third-party feed until provenance/update behavior is reviewed.
- [ ] Render region sets only when loaded; missing data must produce a warning and never accidentally turn a block list into allow-only policy.
- [ ] Preserve rule ordering, established/related handling, counters, and active IPS address blocks.
- [ ] Extend `security.Catalog` with canonical supported regions and rule limits.
- [ ] Update docs with the distinction between country/region address matching and application/domain matching.

## Task 3: Implement bounded traffic identification

**Files:**
- Create: `GameBond.Server/traffic/flow.go`
- Create: `GameBond.Server/traffic/classify.go`
- Create: `GameBond.Server/traffic/flow_test.go`
- Modify: `GameBond.Server/dnsfilter/filter.go`
- Modify: `GameBond.Server/security/manager.go`
- Modify: `GameBond.Server/edge/runtime_linux.go`

**Interfaces:**
- `traffic.Classifier.ObservePacket(fromDevice bool, packet []byte)` records bounded IPv4 5-tuples and supported protocol evidence.
- `traffic.Classifier.ObserveDNS(client netip.Addr, name string, blocked bool)` associates DNS evidence to a tunnel device.
- `traffic.Classifier.Lookup(src, dst netip.Addr, proto uint8, srcPort, dstPort uint16) traffic.Result` returns `Application`, `Protocol`, `Domain`, `Confidence`, and `Evidence`.
- `traffic.Result` uses explicit `unknown` values; DNS/IP correlation has a short TTL and is not treated as certain where IPs are shared.

- [ ] Parse bounded TCP/UDP metadata without retaining packet payloads; reject malformed/truncated packets safely.
- [ ] Add TTL/size limits to flow and DNS maps, deterministic cleanup, and counters for capacity drops/expiry.
- [ ] Identify only maintainable protocol signatures backed by visible metadata (DNS, TLS SNI when visible, HTTP host when cleartext, common transport ports); label port-only guesses as low confidence.
- [ ] Keep QUIC/UDP encrypted application identity unknown unless a future supported parser provides reliable evidence.
- [ ] Feed classifier findings to IDS/IPS only as telemetry initially; no auto-block based on low-confidence labels.

## Task 4: Apply domain/application policy and content categories

**Files:**
- Create: `GameBond.Server/traffic/policy.go`
- Modify: `GameBond.Server/security/settings.go`
- Modify: `GameBond.Server/security/manager.go`
- Modify: `GameBond.Server/dnsfilter/config.go`
- Modify: `GameBond.Server/dnsfilter/filter.go`
- Modify: `GameBond.Server/ids/engine.go`

**Interfaces:**
- `traffic.Policy.Decide(result traffic.Result, device netip.Addr) traffic.Decision` returns allow/deny/log and matching policy ID.
- DNS category checks use the existing filter catalog and decision engine; DNS ad blocking remains active with TLS inspection off.
- Application/domain prevent actions enter IDS/IPS with evidence and confidence; only explicit policy denies a flow.

- [ ] Add domain suffix matching with exact boundary semantics and explicit allow precedence documented in the schema.
- [ ] Add app/protocol category rules and explicit `unknown` matching.
- [ ] Integrate DNS list/category matches without duplicating blocklist parser, storage, or refresh logic.
- [ ] Add safe URL policy structure: hostname-only rules can operate from verified DNS/SNI; path rules require inspected HTTP requests.
- [ ] Surface match reason and evidence source in status/events.

## Task 5: Add policy/status APIs and dashboard controls

**Files:**
- Modify: `GameBond.Server/security/manager.go`
- Modify: `GameBond.Server/adminportal/portal.go`
- Modify: `GameBond.Client/native-edge/dashboard/widget_security.js`
- Modify: `GameBond.Client/native-edge/dashboard/security.go`
- Modify: `GameBond.Client/native-edge/dashboard/security_test.go`

**Interfaces:**
- Extend `/api/security/catalog` with app/protocol categories, rule limits, and inspection capabilities.
- Extend overview with classifier counts, policy matches, and inspection state.
- Keep existing `apply`, `check_domain`, `test_address`, and status actions backward compatible.

- [ ] Add editable zone/region/domain/application rule forms and serialization in the Security page.
- [ ] Add content/ad category controls using current DNS categories.
- [ ] Display unknown/low-confidence traffic without describing it as positively identified.
- [ ] Show inspection off, CA not ready, sessions at limit, unsupported flow, and active/failed states.
- [ ] Persisted settings round-trip through the existing portal config writer without reordering unrelated keys.

## Task 6: Implement inspection CA lifecycle and session limiter

**Files:**
- Create: `GameBond.Server/inspection/ca.go`
- Create: `GameBond.Server/inspection/limiter.go`
- Create: `GameBond.Server/inspection/status.go`
- Modify: `GameBond.Server/compose.yaml`
- Modify: `GameBond.Server/cmd/edge/main_linux.go`
- Modify: `GameBond.Server/edge/config.go`

**Interfaces:**
- `inspection.CA.LoadOrCreate(dir string) (*CA, error)` loads or atomically creates a private CA key/cert with mode `0600` and `0700` directory permissions.
- `inspection.Limiter.Acquire(ctx) (release func(), ok bool)` enforces a hard configured maximum and records rejects.
- `inspection.Status` reports enabled, ready, active, maximum, rejected, bypassed, and errors, never private key material.

- [ ] Add a dedicated persistent bind mount at `/run/secrets/inspection-ca`, configured by `GAMEBOND_INSPECTION_CA_DIR`; require it only when inspection is enabled.
- [ ] Refuse symlinks, group/world-readable private keys, malformed pairs, and partial rotation state; do not silently replace an existing CA.
- [ ] Generate leaf certs only for validated DNS SNI names; apply a short bounded cache and avoid IP wildcard certs.
- [ ] Enforce limit on accepted TLS sessions, release permits on every close/error/cancellation path, and count exhaustion by action.
- [ ] Add authenticated root-certificate export with fingerprint; never export the key. Provide an explicit CA rotation action only after the lifecycle semantics are defined.

## Task 7: Implement transparent supported-flow TLS inspection

**Files:**
- Create: `GameBond.Server/inspection/intercept_linux.go`
- Create: `GameBond.Server/inspection/handler.go`
- Create: `GameBond.Server/inspection/proxy_test.go`
- Modify: `GameBond.Server/firewall/render.go`
- Modify: `GameBond.Server/cmd/edge/main_linux.go`
- Modify: `GameBond.Server/compose.yaml`

**Interfaces:**
- `inspection.Proxy.Run(ctx)` listens on a dedicated local TCP port and receives redirected TCP/443 flows from the tunnel interface.
- The Linux listener recovers the original destination using `SO_ORIGINAL_DST`; the client-facing TLS handshake uses validated SNI and the generated leaf certificate.
- The handler inspects HTTP/1.1 requests and applies URL hostname/path policy before forwarding with a separate verified upstream TLS connection.

- [ ] Research and document exact Linux `REDIRECT` plus `SO_ORIGINAL_DST` behavior for the container kernel before enabling interception by default.
- [ ] Redirect only configured tunnel-device TCP/TLS flows; exempt proxy-originated egress and admin/gateway traffic to prevent loops.
- [ ] Advertise HTTP/1.1 only on the intercepted client TLS side; mark h2-only, QUIC, ECH-hidden, pinning, mutual TLS, and unsupported handshakes as uninspectable.
- [ ] For a policy requiring inspection, fail closed on interception/upstream certificate errors. Bypass is allowed only before terminating client TLS (for declared unsupported categories or session exhaustion configured to bypass).
- [ ] Support configured inspection concurrency without exceeding the limiter; enforce read/write deadlines, response size bounds, and graceful shutdown.
- [ ] On every request, report whether the URL was inspected; URL path rules must never run against metadata-only traffic.

## Task 8: Integrate reliable IDS/IPS signals and operational status

**Files:**
- Modify: `GameBond.Server/ids/engine.go`
- Modify: `GameBond.Server/security/manager.go`
- Modify: `GameBond.Client/native-edge/dashboard/widget_security.js`
- Modify: `GameBond.Server/docs/security.md`

- [ ] Add distinct event kinds for supported protocol anomalies and policy denies, carrying evidence and confidence.
- [ ] Prevent automatic blocks from domain/app labels below the configured confidence threshold.
- [ ] Preserve current detector settings and protected-address exclusions.
- [ ] Show packet/flow table capacity, classifier unknown counts, inspection session pressure, and bypass/error counts.

## Task 9: Operator docs and compatibility review

**Files:**
- Modify: `GameBond.Server/docs/security.md`
- Modify: `GameBond.Server/README.md`
- Modify: `GameBond.Client/FEATURES.md`
- Modify: `GameBond.Server/compose.yaml`

- [ ] Document CA installation on managed devices, private-key backup/rotation, and the trust implications of interception.
- [ ] Publish an explicit support matrix for TCP TLS, HTTP/1.1, h2, QUIC, ECH, certificate pinning, mutual TLS, and unsupported protocols.
- [ ] Explain DNS-only domain/ad filtering versus inspected URL path filtering and make no claim of browser element removal.
- [ ] Document session-cap behavior, exhaustion action, observable counters, and the 1 GiB container memory limit.
- [ ] Confirm default-off behavior and old-config compatibility in docs and generated example configuration.

## Implementation notes

- Ruling: keep the configurable `max_sessions` cap at 512 and its default at 64; the operator has set the server container memory limit to 1 GiB, while the bounded per-session cap still limits TLS/HTTP buffering.
- Do not proceed with interception until the selected `REDIRECT`/`SO_ORIGINAL_DST` path is confirmed against the minimum supported Linux/container environment. If that path cannot be made reliable, stop and revise the spec before choosing a different interception mechanism.
- A TLS handshake that has already presented the GameBond-issued leaf certificate cannot safely fall back to a raw upstream relay. Treat post-handshake inspection failures as deny for inspection-required policy.
- This plan intentionally uses Go's standard TLS/X.509 primitives and existing `x/sys`; adding an external proxy dependency requires a license, maintenance, and resource review.
