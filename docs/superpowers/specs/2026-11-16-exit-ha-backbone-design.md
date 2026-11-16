# Exit HA backbone and gVisor flow anchoring

**Status:** implementation available for configuration  
**Scope:** GameBond.Server exit gateway and its private inter-exit network

## Goal

Keep the GameBond gVisor gateway stateful flows alive when the preferred exit
path fails, and make it possible to compare failover strategies with explicit
configuration. The first failure domain is loss of the preferred upstream exit
or private path while the selected gVisor anchor remains healthy.

The design must not claim zero packet loss or transparent recovery of a failed
gVisor process. It should keep backup paths warm, detect path failure quickly,
retain the flow anchor, and let existing GameBond packet repair handle recoverable
gaps where the packet path supports it.

## Existing seams

- `edge.RunWithSegmentGateway` starts one gVisor gateway for a named segment in
  one edge process. `l2gw.Gateway` owns the TCP/UDP flow counters and live state.
- `l2gw.installForwarders` accepts a device flow and `l2gw.tcpFlow` dials its
  Internet destination through `DialWithECMP`. UDP flows use a live host socket
  in `udpMapping`. The gVisor gateway process is therefore the flow anchor.
- `gateway.DynamicRouting` manages the host gateway. The optional
  `exit_backbone` runtime separately owns per-peer WireGuard interfaces and
  FRR inside the exit container's network namespace; its BGP health feeds the
  gVisor selector.
- A private WireGuard underlay can keep node-to-node paths available, but it
  does not copy gVisor TCP endpoints, userspace proxy streams, UDP sockets, or
  NAT state between processes.

## Recommendation

Keep the gVisor flow anchor on a selected, continuously running exit gateway.
Treat the other exits as redundant upstream paths, not as replicas of the
gateway process. Put path selection behind one `l2gw` egress-path interface;
keep BGP and tunnel setup behind a control-plane adapter. The gateway remains
the sole owner of client-facing TCP and UDP state while the preferred path
changes beneath it.

For the first deployment, use the fastest healthy node as the anchor and keep
its own public egress available. The primary node can be the preferred private
transit when that path is healthy, with the remaining exit as an alternate.
Avoid making the anchor's public source address depend on the primary node: an
established Internet flow can only keep its remote 5-tuple when its public
egress identity and any required translation state remain valid.

## Experiment profiles

Expose an opt-in `l2.bridge.egress_policy` on the gVisor bridge gateway. Keep
the current behavior as the default so existing deployments do not change.

### `local`

Use the anchor's ordinary local routing table for all new egress flows. This is
the control profile for measuring gateway and client behavior without inter-exit
transit.

### `failover`

Select the first healthy configured path and use it for new flows. When
`exit_backbone` is configured, the exit container owns its WireGuard interfaces
and FRR peers. Without it, the edge can read neighbor state from the existing
host gateway's read-only status socket. Existing flows remain anchored in the
same gVisor process. Their continuity depends on whether the alternate preserves
source identity and connection state; new flows use a path after BGP reports
Established.

### `weighted`

Select a stable weighted path among currently healthy configured paths. The
hash is per TCP flow or UDP mapping; a health change affects new flows only.
The legacy behavior for configurations that set `ecmp_paths` without an
`egress_policy` remains static weighted ECMP.

Packet duplication over multiple private tunnels remains a separate experiment
for the GameBond transport. It must not duplicate arbitrary TCP proxy writes to
two Internet destinations, which could execute an application operation twice.

## Configuration model

The path-selection settings stay small and selectable:

```json
{
  "l2": {
    "bridge": {
      "egress_policy": "failover",
      "recovery_hold_down_ms": 3000,
      "ecmp_paths": [
        { "name": "backup-a", "interface": "gb-bka", "weight": 1, "bgp_neighbor_address": "10.79.0.1" },
        { "name": "backup-b", "interface": "gb-bkb", "weight": 1, "bgp_neighbor_address": "10.79.0.5" }
      ]
  },
  "exit_backbone": {
      "router_id": "10.79.255.1",
      "local_as": 4200000101,
      "recovery_hold_down_ms": 3000,
      "transit_source_prefixes": ["10.79.10.0/24"],
      "peers": [
        {
          "id": "backup-a", "interface": "gb-bka", "address": "10.79.0.2/30",
          "peer_address": "10.79.0.1", "listen_port": 51820,
          "private_key_file": "/run/secrets/gamebond-backbone/backup-a.key",
          "public_key": "<base64-public-key>", "endpoint": "198.51.100.10:51820",
          "allowed_ips": ["0.0.0.0/0"],
          "persistent_keepalive_seconds": 25, "remote_as": 4200000102,
          "import_prefixes": ["0.0.0.0/0"], "export_prefixes": ["10.79.10.0/24"]
        },
        {
          "id": "backup-b", "interface": "gb-bkb", "address": "10.79.0.6/30",
          "peer_address": "10.79.0.5", "listen_port": 51821,
          "private_key_file": "/run/secrets/gamebond-backbone/backup-b.key",
          "public_key": "<base64-public-key>", "endpoint": "203.0.113.10:51820",
          "allowed_ips": ["0.0.0.0/0"],
          "persistent_keepalive_seconds": 25, "remote_as": 4200000103,
          "import_prefixes": ["0.0.0.0/0"], "export_prefixes": ["10.79.10.0/24"]
        }
      ]
    }
  }
}
```

`local` uses the ordinary local route. `failover` and `weighted` require
`ecmp_paths`, and each dynamic path's name, interface, and BGP neighbor address
must match one `exit_backbone.peers` entry. Peer private keys are read-only
files under `/run/secrets/gamebond-backbone`; Compose mounts
`GAMEBOND_BACKBONE_KEYS_DIR` there. Compose publishes UDP 51820–51822, so limit
those ports to the peer addresses in the host firewall. Each peer has a
dedicated WireGuard device, explicit AllowedIPs, remote AS, and inbound/outbound
BGP prefix filters. No default route is configured by the program; operators
must explicitly allow `0.0.0.0/0` if they want Internet transit. Add
`transit_source_prefixes` only for private source ranges that must be NATed when
forwarded through this exit. BGP keepalive/hold timers default to 1/3 seconds.
Loss is applied immediately; recovery waits for `recovery_hold_down_ms` (default
3000 ms) before new flows use the recovered path.

The admin snapshot exposes the configured selection mode and current gVisor
egress path health/reason. The backbone runtime does not expose private keys.
Per-path RTT/loss and active-flow migration are not part of this implementation.

## Runtime boundaries

1. `l2gw` now has an `EgressPathSelector` interface for selecting a path for a
   new TCP or UDP mapping and reporting path health. `local` remains the default;
   existing `ECMPPaths` without `egress_policy` retains its legacy behavior.
2. The optional in-container `backbone.Runtime` creates WireGuard devices,
   starts FRR with per-peer filters, and publishes neighbor state to the
   selector. The host-gateway status API remains supported for an already
   provisioned host-owned mesh.
3. Apply route/path changes only to new flows by default. Existing TCP proxy
   streams keep their connected socket; do not silently redial them as that
   changes application semantics. UDP mapping migration is a separately opted-in
   experiment because peer-visible source ports and NAT state can change.
4. Include a bounded packet buffer on the anchor only if measurement shows a
   route-convergence gap that packet repair cannot cover. Keep queue limits,
   expiry, and drop counters explicit.

## Guarantees and limits

- Preferred upstream path failure while the anchor process remains healthy:
  warm route selection can direct new flows to a healthy path. Existing flows
  survive only if their existing socket and public egress identity remain valid.
- Anchor process or host failure: the existing in-memory gVisor endpoints and
  proxy streams are lost. A different node cannot resume them with BGP alone.
- Public egress address changes: Internet TCP sessions may reset. BGP route
  convergence does not transfer external NAT/conntrack state or a public address.
- `duplicate_tunnel` can mask loss of a tunnel copy when packet sequence and
  receiver state are shared; it does not duplicate gVisor gateway process state.

## Rollout and comparison

1. Config parsing, validation, status, and live gVisor path selection are wired
   with `local` as the default.
2. Bring up private tunnel peers and BGP without advertising Internet defaults;
   validate only the dedicated overlay prefixes first.
3. Enable `warm_standby` on a non-production segment. Measure failure detection,
   route selection time, packet loss, TCP resets, UDP mapping changes, and
   recovery hold-down behavior.
4. Compare `duplicate_tunnel` under controlled packet loss on the private
   overlay. Keep Internet proxy traffic single-copy.
5. Promote a profile only after the measurements support its stated guarantee.

## Before live activation

Each exit needs node-specific tunnel addresses, ASNs, interface names, public
keys, endpoint addresses, and explicit route filters. The application code does
not configure live node secrets or advertise routes by itself. Start with only
the dedicated backbone prefix; add a default route only after transit NAT and
failure behavior have been reviewed on a non-production segment.
