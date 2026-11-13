# Advanced Firewall and Traffic Inspection Design

## Goal

Extend GameBond's existing tunnel security system with configurable advanced filtering, traffic identification, and optional TLS inspection. The work should integrate with the server security API and client security dashboard, preserve current defaults, and make enforcement status and limitations visible to administrators.

## Current state

The server has a stateful nftables firewall with ordered IPv4 rules, zones, device segmentation, country filtering, DNS redirection, and connection tracking. The DNS filter supports domain block/allow rules and public lists, including ad and tracker categories. The IDS/IPS observes packet headers, flow behavior, and DNS questions; it does not inspect payloads. Security settings are parsed strictly, applied through one manager, and surfaced through the admin portal API to the desktop dashboard.

There is no generic Layer 7 engine, TLS interception proxy, URL path filter, or application signature database. Adding those requires new components and device setup beyond a rule-list change.

## Scope

1. **Concurrent TLS inspection sessions:** configurable maximum number of simultaneously inspected TLS sessions, bounded by a safe implementation limit. Status must show active sessions, configured limit, and rejection/bypass counts. Inspection is opt-in.
2. **Stateful firewall:** retain established/related connection tracking and existing policy ordering while adding optional advanced predicates.
3. **Application-aware Layer 7 firewall:** identify supported applications from available flow metadata and classify unknown traffic explicitly. Rules can allow, deny, or log matching application categories.
4. **SSL inspection and URL filtering:** an opt-in interception service for eligible TCP/TLS flows, with a locally managed CA that administrators must install and trust on participating devices. URL host/path rules run only after successful inspection.
5. **DPI and traffic identification:** classify supported protocols and applications from flow metadata and, where configured, inspected traffic. Do not claim payload inspection where encryption prevents it.
6. **Advanced zone filtering:** rules can combine source/destination zones with region, domain, and application criteria. Existing IP/CIDR, port, protocol, direction, action, ordering, and counters remain supported.
7. **Content filtering:** domain and URL categories can be blocked or allowed through policy. DNS-based filtering remains available without TLS inspection; URL path filtering requires successful TLS inspection.
8. **IPS/IDS:** retain current behavior detectors and add traffic-identification signals only where reliable. Detection and prevention remain distinct modes; prevention uses the existing timed firewall block mechanism.
9. **Ad blocking:** continue using DNS-based ad lists as the baseline; provide category controls and status in the security UI. HTTPS page-element filtering is out of scope because it would require browser-level content modification.

## Architecture

- Keep nftables as the enforcement point for packet/flow predicates it can express: zones, addresses, countries, transport, ports, connection state, and actions.
- Add an application/protocol classifier as a separate server component. It consumes bounded flow metadata and emits classifications with confidence and provenance; unknown or encrypted flows remain `unknown` rather than being guessed.
- Add a TLS inspection proxy as a separate optional component. The transparent interception path must be explicit, limited to supported TCP/TLS flows, and controlled by the concurrent-session semaphore. QUIC/UDP 443, certificate-pinned clients, mutual TLS, unsupported protocols, and clients that do not trust the configured CA cannot be transparently inspected; policy must define whether these flows are blocked or bypassed.
- Keep DNS filtering independent and useful when inspection is disabled. DNS domain decisions should be shared with the advanced policy layer without duplicating list parsing or category state.
- Extend the existing strict JSON `security` schema with versioned/validated fields. Applying a configuration remains atomic: if validation or firewall installation fails, active settings remain unchanged.
- Expose normalized configuration, catalogs, classifier/inspection status, and counters through the security API. Keep dashboard controls aligned with backend capability and surface unsupported/bypassed states.

## Policy and failure behavior

- All new capabilities default off; current firewall, DNS, and IDS behavior remains unchanged when omitted.
- Unknown application/protocol classification is represented distinctly and can be matched explicitly by policy.
- The TLS inspection CA private key is generated/stored with restrictive permissions and is never returned by the API. The UI exposes a safe certificate export and fingerprint, with clear trust-installation instructions.
- Session-cap exhaustion follows an explicit configured action (`bypass` or `deny`) and increments a counter. Default to deny for rules that require inspection, while unrelated traffic continues according to ordinary firewall policy.
- Inspection failures, unsupported flows, and classifier uncertainty are observable; no silent claim of inspection is permitted.
- Domain and region rules must fail safely on missing/stale data: block-only category lists do not turn into allow-only behavior. Existing country-list behavior is preserved.

## Delivery stages

1. **Policy foundation:** schema, validation, region/domain/application predicates, status/catalog support, and dashboard controls; preserve nftables stateful behavior and existing DNS lists.
2. **Identification and IDS/IPS:** bounded flow classifier, confidence-aware status/counters, rule integration, and detector signals that have reliable evidence.
3. **TLS inspection:** CA lifecycle/export, supported-flow interception, concurrent-session cap, host/path policy, explicit bypass/deny behavior, and operational status.

Each stage is independently deployable and must preserve the existing default-off behavior. The implementation plan should identify exact files, interfaces, migration behavior, and validation for each stage before code changes begin.

## Acceptance criteria

- Existing configurations without new fields parse and behave as before.
- New fields reject unknown, malformed, duplicate, out-of-range, or unsupported combinations.
- Stateful rule order, connection tracking, existing zones/countries, DNS filtering, and IDS/IPS controls remain coherent with added policies.
- Operators can configure and observe each new capability through the existing security workflow.
- TLS inspection reports active/concurrent sessions and all inspection bypass, rejection, and error paths; the configured limit is never exceeded.
- Inspection-dependent URL decisions are applied only when inspection actually succeeded; unsupported traffic follows the configured failure action.
- Tests cover policy validation, rule rendering/integration, classifier uncertainty, concurrency limits, CA handling, and end-to-end supported and unsupported TLS flows.

## Open implementation decisions

- Choose an interception/proxy implementation compatible with the Go server and Linux container constraints; verify HTTP CONNECT/transparent proxy behavior and certificate generation before committing to it.
- Determine whether DNS names can be safely correlated with tunnel client IPs and flows under current resolver behavior; retain DNS-level enforcement as the fallback.
- Select a maintainable application/protocol signature source and document its licensing and update mechanism.
- Define operational storage and rotation for the inspection CA, including what happens when it is rotated or lost.
