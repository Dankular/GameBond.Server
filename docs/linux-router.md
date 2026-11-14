# Linux router gateway

The Linux router gateway is a host service separate from the GameBond tunnel edge
container. The current Compose service keeps its private bridge namespace and does not
receive host networking. The host daemon owns only configured interfaces and bridge
FDB limits. The optional `layer2` configuration manages Linux bridges, VLAN-filtered
virtual networks, port membership, and path MTU through the same transactional apply
coordinator. The daemon reports Layer 2 host capabilities in status and config validation.

## Configuration

Install a root-owned `/etc/gamebond/router.json` with mode `0600`. The file is strict,
versioned JSON. Example:

```json
{
  "version": 1,
  "socket_path": "/run/gamebond/control.sock",
  "socket_group": "gamebond-admin",
  "interfaces": [
    {"id": "wan-main", "name": "enp1s0", "role": "wan"},
    {"id": "lan-main", "name": "br0", "role": "lan"}
  ],
  "wans": [
    {
      "id": "internet-main",
      "interface_id": "wan-main",
      "probe_targets": ["1.1.1.1:443", "9.9.9.9:443"],
      "interval_seconds": 10,
      "timeout_ms": 1500,
      "failure_threshold": 3,
      "recovery_threshold": 2
    }
  ],
  "bridges": [
    {"id": "lan-main-bridge", "interface_name": "br0", "max_learned_entries": 512}
  ],
  "telemetry": {
    "flow_max_records": 10000,
    "flow_retention_hours": 24,
    "outage_retention_days": 30,
    "outage_max_bytes": 1048576
  },
  "features": {"wan_quality": true, "flow_report": true, "mac_limit": true}
}
```

Add Layer 2 state in the optional `layer2` object. Its own interface IDs let bridge
membership refer to physical interfaces by stable ID:

```json
"layer2": {
  "version": 1,
  "interfaces": [{"id": "lan-a", "name": "enp2s0"}],
  "bridges": [{
    "id": "main", "name": "gb-lan0", "vlan_filtering": true,
    "ports": [{"interface": "lan-a", "untagged_network": "users", "tagged_networks": ["voice"]}]
  }],
  "networks": [
    {"id": "users", "bridge": "main", "vlan": 10, "mtu": 1500},
    {"id": "voice", "bridge": "main", "vlan": 20, "mtu": 1500}
  ]
}
```

Voice VLANs are represented as tagged bridge VLAN membership and advertised to
phones through LLDP-MED. The optional `voice_network` on a bridge port must name
one of its `tagged_networks`; it cannot replace the untagged access network. Install
and enable the persistent LLDP-MED policy unit on hosts using this feature:

```sh
sudo install -m 0644 tools/gamebond-lldpmed.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable gamebond-lldpmed.service
```

Explicit application policies can be added per port with the `lldp_med` list. The
provider uses `lldpcli` to load a persistent command file and reports an apply error
if `lldpd` rejects a selected policy. LLDP neighbor advertisements are untrusted
network input and must not be used as authorization evidence. The supported
application values and policy field ranges follow the [lldpd LLDP-MED command
reference](https://lldpd.github.io/usage.html); LLDP-MED power-via-MDI settings are
not exposed until the host can verify provider and NIC support. Status includes
configured advertised policies, received neighbor JSON (capped at 32 KiB per port),
and effective bridge VLAN membership.

Wired 802.1X uses hostapd's `wired` driver with an external RADIUS server. The
hostapd service only authenticates; GameBond's bridge nftables table controls both
traffic to the router and traffic forwarded through the bridge. EAPOL remains
available before authentication, while other traffic is blocked until an EAP
success event authorizes that source MAC on that port. Failure, disconnect, monitor
restart, and monitor shutdown revoke authorization. This integration requires
working `wired` support in the installed hostapd build and the packaged GameBond
event helper. The [RHEL wired-authenticator guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_setting-up-an-802-1x-network-authentication-service-for-lan-clients-using-hostapd-with-freeradius-backend_configuring-and-managing-networking)
documents `driver=wired`, external RADIUS settings, and the fact that hostapd does
not enforce the traffic plane.

Install the two per-port units and the event helper, then reload systemd:

```sh
sudo install -m 0644 tools/gamebond-hostapd@.service /etc/systemd/system/
sudo install -m 0644 tools/gamebond-8021x-events@.service /etc/systemd/system/
go build -o /tmp/gamebond-8021x-event ./cmd/gamebond-8021x-event
sudo install -m 0755 /tmp/gamebond-8021x-event /usr/bin/gamebond-8021x-event
sudo systemctl daemon-reload
```

Provision each referenced `/etc/gamebond/8021x/<interface-id>.secret` out of band
as a root-owned regular file with mode `0600` and a 16..128 character safe ASCII
RADIUS secret. The management API accepts no secret value. `nas_address` must be
an address currently assigned to the managed bridge; `nas_id` must be unique in
the RADIUS server's client scope. Example port policy:

```json
"port_auth": [{
  "interface": "lan-a", "radius_server": "192.0.2.10", "radius_port": 1812,
  "secret_file": "/etc/gamebond/8021x/lan-a.secret",
  "nas_address": "192.0.2.2", "nas_id": "edge-1",
  "reauth_seconds": 3600, "failure_policy": "closed", "exclusive_port": true
}]
```

The daemon enables bridge EAPOL group forwarding and refuses to replace an
unmanaged authorization table. Since EAPOL forwarding compatibility with STP/RSTP
has not been verified across the supported kernel/provider matrix, config validation
rejects 802.1X on bridges with STP/RSTP controls enabled. Runtime status reports the
authenticator, fail-closed event monitor, and authorized MACs separately for each
managed port.

Customizable DHCP is provided by a dedicated Kea DHCPv4 service. Each subnet binds to
one configured LAN interface, has a dynamic pool, router and DNS options, optional
reservations, and raw custom option payloads encoded as lowercase hexadecimal:

```json
{
  "dhcp": {
    "enabled": true,
    "subnets": [{
      "id": "main-lan", "interface_id": "lan-main", "prefix": "192.168.10.0/24",
      "pool_start": "192.168.10.100", "pool_end": "192.168.10.220",
      "router": "192.168.10.1", "dns": ["192.168.10.1", "1.1.1.1"],
      "domain": "home.example", "lease_seconds": 86400,
      "reservations": [{"mac":"02:00:00:00:00:10", "address":"192.168.10.10", "hostname":"nas"}],
      "options": [{"code": 66, "data_hex":"3139322e3136382e31302e32"}]
    }]
  }
}
```

Install Kea DHCPv4 and the dedicated service unit before enabling the feature:

```sh
sudo install -m 0644 tools/gamebond-kea-dhcp4.service /etc/systemd/system/
sudo systemctl daemon-reload
```

The gateway validates the generated Kea configuration before applying it and verifies
the service state afterward. DHCP is stopped when disabled; leases are stored under
`/var/lib/gamebond-kea` and survive service restarts. The service conflicts with the
standard ISC DHCP server units to avoid two DHCP servers answering on the same host.
When Kea is active, gateway status reads its memfile lease database and reports the
latest unexpired, non-declined IPv4 binding per address. If the file cannot be read,
status reports a lease-binding error. DHCP guard blocks server replies on untrusted
ports and can rate-limit DHCP traffic. Client IP/MAC/port binding enforcement is
currently unavailable: Kea's memfile contains address and MAC but not the ingress
port, and the learned bridge FDB is controlled by endpoint traffic, so it is not
trusted for authorization. Configurations that request `validate_bindings: true` are
rejected before host mutation or persistence. Secure binding enforcement requires an
ingress-aware DHCP snooping provider, such as authenticated relay metadata or a
verified DHCP transaction capture provider.

The gateway exposes the documented Pro AV profile catalogue at
`GET /v1/layer2/profiles` and through the authenticated admin-portal proxy at
`/api/gateway/layer2/profiles`. A Layer 2 config can select profiles per managed
network with `pro_av_profiles: [{"profile":"dante","network":"media"}]`.
Selections are saved and rolled back with the gateway config, and validation rejects
unknown profiles, missing networks, duplicate selections, and incompatible values
from profiles selected on the same network. Config validation also checks mandatory
IGMP snooping/querier and MTU requirements against the selected network. The host
checks minimum link speeds on every bridge member carrying a selected profile and,
when QoS is active, validates numeric DSCP and queue-order requirements against the
merged Layer 2 and adaptive QoS map. Other catalogue guidance remains advisory: the
gateway does not configure external switches, endpoint firmware, PoE, EEE, or Linux
controls without a verified provider. Profile selection does not imply certification
or interoperability testing.

## Optional admin-portal access to gatewayd

`gatewayd` listens on the configured Unix socket (normally
`/run/gamebond/control.sock`). It creates the socket as `root:<socket_group>` with mode
`0660`; the parent directory is created with mode `0755`. Create a dedicated host group
and set `socket_group` to that group in `/etc/gamebond/router.json`. The socket grants
its holder the bounded gateway status, validate, plan, apply, and one-step rollback API,
so membership should be limited to the admin portal container's shared group.

The default Compose service does not mount this socket. To opt in, set
`GAMEBOND_GATEWAY_GID` to the numeric host group ID and
`GAMEBOND_GATEWAY_SOCKET_DIR` to the host socket directory (normally `/run/gamebond`),
then start Compose with the optional overlay:

```sh
GAMEBOND_GATEWAY_GID="$(getent group gamebond-admin | cut -d: -f3)" \
GAMEBOND_GATEWAY_SOCKET_DIR=/run/gamebond \
docker compose -f compose.yaml -f compose.gateway.yaml up -d
```

The overlay mounts the host directory at `/run/gamebond-gateway` inside the edge
container, matching `GAMEBOND_GATEWAY_SOCKET`; it is read-only and adds the shared group
to the edge container. The portal still requires its existing login and CSRF token for every
mutating operation. If the socket is missing or unreachable, gateway management is
reported unavailable while the portal and tunnel continue to run. Rollback restores the
last successfully applied configuration held by the running daemon; it is unavailable
until a configuration has been successfully applied after daemon startup.

Shadow-mode high availability uses Keepalived VRRP with this gateway configured as a
non-preempting BACKUP peer. Configure the matching router ID, advertisement interval,
peer address, and shared VIPs on both gateways, with the other peer given the higher
priority. The local VIP ownership and service state appear in `/v1/status`; an absent
VIP means this node is acting as BACKUP, while a partial VIP set is reported as FAULT.
Install the dedicated service unit before enabling VRRP:

```sh
sudo install -m 0644 tools/gamebond-keepalived.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Example configuration:

```json
{
  "vrrp": {
    "enabled": true, "interface_id": "lan-main", "virtual_router_id": 42,
    "priority": 100, "advertisement_interval_seconds": 1,
    "peers": ["192.168.10.2"],
    "virtual_addresses": ["192.168.10.1/24"]
  }
}
```

VRRP does not synchronize connection-tracking state. Existing sessions may reset
when the gateway changes unless a separate conntrack state synchronization provider
is configured and verified.

Optional redundancy groups aggregate status from configured Layer 2 bonds and
bridges, plus the single VRRP instance. They report active/standby role, mechanism
health, degraded cause, and up to 64 observed transitions in `/v1/status`; each
mechanism remains responsible for its own failover and recovery. Transition history
is sampled when status is requested, so short-lived changes between observations may
not appear. The Linux bridge nftables support required by some Layer 2 features must
also be available on the host before those mechanisms can be considered healthy.

mDNS reflection uses a dedicated Avahi instance. Select at least two configured WAN or
LAN interfaces; VPN interfaces are rejected. Optional `reflect_filters` restrict
which DNS-SD service names cross the selected networks. Install the dedicated unit
before enabling the feature:

```sh
sudo install -m 0644 tools/gamebond-avahi.service /etc/systemd/system/
sudo systemctl daemon-reload
```

```json
{
  "mdns": {
    "enabled": true,
    "interface_ids": ["lan-main", "lan-iot"],
    "reflect_filters": ["_airplay._tcp", "_googlecast._tcp"]
  }
}
```

Dynamic routing uses dedicated FRRouting daemons in the `gamebond` pathspace. This
keeps GameBond configuration and control sockets separate from the host's default FRR
instance. OSPFv2 interfaces are passive by default; mark only routed peer links active.
BGP neighbors require explicit import and export prefix lists, and an empty list denies
all routes in that direction. Export prefixes are originated with BGP `network`
statements and must already exist in the kernel routing table. The FRR pathspace still
installs learned routes into the host kernel routing table, so avoid competing with
another routing daemon for the same prefixes.

Install FRRouting and these GameBond service units before enabling either protocol:

```sh
sudo install -m 0644 tools/gamebond-zebra.service tools/gamebond-ospfd.service tools/gamebond-bgpd.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Example OSPF and BGP configuration:

```json
{
  "dynamic_routing": {
    "enabled": true,
    "router_id": "192.0.2.1",
    "ospf": {
      "enabled": true,
      "interfaces": [
        {"interface_id": "lan-main", "area": "0.0.0.0", "passive": true},
        {"interface_id": "transit", "area": "0.0.0.0", "passive": false}
      ]
    },
    "bgp": {
      "enabled": true,
      "local_as": 64512,
      "neighbors": [
        {"id": "upstream", "address": "198.51.100.1", "remote_as": 64496,
         "import_prefixes": ["0.0.0.0/0"], "export_prefixes": ["203.0.113.0/24"]}
      ]
    }
  }
}
```

Daemon activity and FRR neighbor summaries are included in `/v1/status`. Peer
adjacency is not required for configuration apply to succeed; a down peer appears in
the reported protocol summary.

Integrated RADIUS uses FreeRADIUS 3 with locally defined PAP users and address-scoped
RADIUS clients. Client shared secrets and user passwords are provisioned as root-only
files under `/etc/gamebond/radius-secrets`; their contents are never stored in the
gateway JSON config or returned by its API. Each client secret file is named for its
client ID, and each user password is stored in `users/<user-id>`. Password files hold
one supported printable ASCII password of 8–128 characters; client secrets are
16–128 characters.

RadSec is optional and listens on TLS/TCP, with server certificate and private key
files provisioned under `/etc/gamebond/radius-certs`. When client certificate checking
is enabled, provide a CA file and use mutual TLS. Install FreeRADIUS 3 and the GameBond
service unit before enabling RADIUS:

```sh
sudo install -m 0644 tools/gamebond-freeradius.service /etc/systemd/system/
sudo systemctl daemon-reload
```

```json
{
  "radius": {
    "enabled": true,
    "listen_address": "192.168.10.1",
    "auth_port": 1812,
    "accounting_port": 1813,
    "clients": [{"id":"access-points", "network":"192.168.10.0/24"}],
    "users": [{"id":"alice", "username":"alice"}],
    "radsec": {
      "enabled": true,
      "listen_address":"192.168.10.1",
      "port":2083,
      "certificate_file":"server.crt",
      "private_key_file":"server.key",
      "ca_file":"client-ca.crt",
      "require_client_certificate":true
    }
  }
}
```

The gateway validates the generated FreeRADIUS configuration before applying it and
reports daemon state in `/v1/status`. The RADIUS listener accepts PAP authentication;
RadSec protects RADIUS transport with TLS. Install the package's dictionary at
`/usr/share/freeradius/dictionary` and use the `freerad` service account and group.

LACP uses Linux 802.3ad bonding. The bond and its physical members are declared in
the optional Layer 2 `bonds` list; the bond interface can then be assigned to a
bridge or a gateway LAN/WAN role. Members must be dedicated, full-duplex links at
the same reported speed. Configure the switch's corresponding ports in one LACP
group before applying the bond. Apply succeeds only after the kernel reports an
active peer and the requested minimum number of links in synchronized
collecting/distributing state. Link aggregation distributes independent flows by
the selected hash policy; a single flow does not gain the sum of member rates.

```json
{
  "layer2": {
    "version": 1,
    "interfaces": [
      {"id":"lag-main", "name":"bond0"},
      {"id":"lag-member-a", "name":"enp2s0"},
      {"id":"lag-member-b", "name":"enp3s0"}
    ],
    "bonds": [{
      "id":"main-uplink", "interface":"lag-main",
      "members":["lag-member-a", "lag-member-b"],
      "min_links":1, "lacp_rate":"fast", "hash_policy":"layer3+4"
    }]
  }
}
```

Bond mode, membership, negotiation, partner system, and collecting/distributing
members appear in Layer 2 status. Bond settings are immutable while the bond is
managed; remove the bond in one apply before creating a replacement with changed
members or policies.
MC-LAG is unsupported because no compatible multi-chassis peer protocol is
configured. Strict Layer 2 config rejects an `mc_lag` field; a single-node 802.3ad
bond is not treated as an MC-LAG substitute.

IGMP proxying relays IPv4 membership between one configured WAN upstream and one or
more configured LAN downstreams. It supports upstream source prefixes and optional
quick-leave behavior. It is a single-upstream IGMP proxy, not a general multicast
routing protocol. Install the daemon and dedicated service unit:

```sh
sudo install -m 0644 tools/gamebond-igmpproxy.service /etc/systemd/system/
sudo systemctl daemon-reload
```

```json
{
  "igmp_proxy": {
    "enabled": true,
    "upstream_interface_id": "wan-main",
    "downstream_interface_ids": ["lan-main", "lan-media"],
    "allowed_sources": ["198.51.100.0/24"],
    "quick_leave": false
  }
}
```

The gateway checks that upstream and downstream interfaces have non-overlapping
IPv4 subnets, then applies and verifies the service transactionally. `/v1/status`
reports daemon state and kernel multicast routes. The host firewall must permit the
intended multicast forwarding and IGMP control traffic.

The initial provider applies bridge creation, VLAN filtering, port and VLAN membership,
and MTU changes with reverse-order rollback. It refuses to adopt unmanaged bridges or
steal ports from unmanaged masters. Virtual Network Override is available on hosts
with `tc` flower VLAN matching and VLAN push support. It applies only to a configured
access port and assigns listed source MAC addresses to another VLAN on that bridge.
Ingress frames that arrive already tagged are dropped before override matching. Since
Ethernet source MAC addresses can be spoofed, this is a segmentation policy, not a
strong device identity check; use 802.1X when authenticated identity is required.
Effective status is based on the observed bridge VLAN membership and `tc` filters.
Bridge port isolation can be enabled per managed bridge port with `"isolated": true`;
Linux bridge isolation prevents communication between isolated ports while retaining
forwarding to non-isolated ports, including the bridge host port. The gateway reads
the live bridge isolation flag before planning changes and reports it in interface
inventory.
MAC-Based Port Restriction uses Linux bridge locked-port enforcement, a static FDB
allow-list, and the kernel learned-FDB limit. Since Linux applies that learned-FDB
limit to the whole bridge, GameBond accepts this policy only on a bridge with one
managed access port and rejects other topologies. Status reports effective allow-list,
limit, learned devices, and currently locked FDB entries; MAC addresses remain
spoofable without authenticated access control.
MAC Address Blocking is scoped to a managed port and one VLAN-backed network. It uses
an owned nftables bridge table with input, output, and forwarding drop rules and packet
counters. The selected port must carry only that network so untagged traffic cannot
cross the policy boundary; tagged single-network ports match their VLAN ID.
MAC ACLs use ordered terminal allow or deny rules with a source or destination MAC,
direction, managed port, and VLAN-backed network. Duplicate match tuples are rejected;
status reports the configured order and nftables packet/byte counters for each rule.
IP ACLs use ordered terminal allow or deny rules matching IPv4/IPv6 prefixes, protocol,
and an optional TCP/UDP destination port on one managed port and VLAN-backed network.
The bridge VLAN boundary isolates Layer 2 broadcast domains; routed traffic between
those networks must also be constrained by the gateway's routed firewall policy.
Bridge IGMP snooping and querier settings are bridge-wide by default. A network can
set `igmp_snooping` to override snooping for its VLAN; this requires bridge-wide
`igmp_snooping: true`, the host's per-VLAN bridge mode, and readable live VLAN state.
The planner records exact previous mode and VLAN values for rollback and rejects
changes when either value is unknown. Status reports the kernel multicast database,
listener ports, multicast-router ports, and per-VLAN snooping values when requested.
The bridge's querier flag reports local querier configuration; it does not claim to
observe an external querier election. Fast Leave requires
`igmp_shared_downstream: false` on that port, so a shared downstream segment is rejected.
Layer 2 `dhcp_guard` policies can mark bridge ports as trusted DHCP server/relay
paths or untrusted access ports and can rate-limit DHCP requests per ingress port.
Untrusted DHCP server replies are dropped before local delivery or bridge forwarding;
status reports effective rule counters and refuses to overwrite unowned nftables state.
DHCP lease-backed IP/MAC source validation is not advertised as supported until an
authoritative ingress-port source is integrated; `validate_bindings` requests fail
closed before apply.
`storm_control` and `multicast_broadcast_rate_limits` apply independent ingress
broadcast and multicast policers with bounded bursts and drop counters. The
multicast/broadcast policies use dedicated `tc` priorities and reject overlapping
classes with storm control. Multicast policers are rejected on IGMP-snooping ports
so membership and query traffic is not rate-limited. Filters request `skip_hw` and
are reported as software `tc` policers; unknown-unicast storm classification is not
available through this generic Linux provider.
Port mirroring supports one dedicated monitor destination, ingress/egress/both
directions, and optional tagged-VLAN scope on trunk members. Per-VLAN capture requires
software `tc` flower matching; untagged access VLANs cannot be selected independently.
An optional capture rate and burst apply a TBF egress limit to the monitor interface,
which must have an unmanaged-free `noqueue` root qdisc. Status reports effective
source filters and packet/byte counters; mirrored packet payloads are never retained.
Before applying a mirror, the daemon tests software `tc mirred` support on a temporary
veth pair inside a disposable network namespace, then removes that namespace. Mirror
filters use `skip_hw` so the checked software path is the path used on live ports.
QoS (DSCP) policies share the gateway's adaptive HTB root qdisc. Status includes each
class's DSCP, guaranteed rate, ceiling, priority, and observed packet/byte counters.
Port egress rate limits use Linux TBF only when the selected interface has a
`noqueue` root qdisc or the exact previously saved GameBond TBF. Existing queue
disciplines are rejected instead of replaced. Tagged VLANs on trunk ports can have
separate software `tc` police filters attached to `clsact`; access VLANs cannot be
matched after egress untagging, so network-scoped policies are rejected there. VLAN
policing drops excess traffic instead of queueing it. Status reports the observed
qdisc/filter, rate, and burst. VLAN policy uses the reserved `tc` egress priorities
45001 through 49094; a conflicting filter at that priority is rejected.
Ethernet flow control configures `ethtool` RX/TX pause and autonegotiation on a
physical interface only after the driver reports the current values. Bond members
cannot be managed independently. Removing a policy restores autonegotiation with
RX/TX pause enabled; a failed transaction rolls back to the exact observed values.
Layer 2 features without an integrated provider and effective-state check remain
unavailable. A capability listing alone does not mean a feature is configured or active.
VRRP status distinguishes MASTER by local VIP
ownership and FAULT by service/interface/address errors; an active service without
VIPs is reported as BACKUP.

Interface IDs are stable GameBond identifiers; Linux interface names identify the live
kernel object. An interface can be assigned to only one managed role. The bridge must be
listed as a LAN interface. A requested learned-FDB ceiling is rejected unless the running
kernel and `iproute2` report support for it.

WAN probes make TCP connection attempts to the configured address and port, bound to the
specified uplink. They do not send application data. The service records RTT, reachability,
loss over the recent sample window, and outage transitions. The client-side GameBond link
quality and outage view remains separate and continues reporting tunnel-path health.

Flow reporting reads Linux conntrack metadata, with no payload capture. Address, port,
protocol, packet and byte metadata remain local to the gateway API and are bounded by the
configured record count and retention. MAC reporting describes the Linux bridge FDB; it
cannot change a hardware switch's independent table size.

## Service and API

Install `tools/gamebond-router.service` as a systemd unit and the daemon at
`/usr/sbin/gamebond-gatewayd`. The service runs as root with a restricted capability set
because bridge FDB limits and interface-bound probes require host-level access. Check a
config without applying changes with:

```sh
sudo /usr/sbin/gamebond-gatewayd --check --config /etc/gamebond/router.json
```

If `socket_group` is set, create that local group and add only trusted router operators
to it before starting the service. The daemon refuses to start its API if the group does
not exist.

The API listens only on the configured Unix socket, default permissions `root:root
0660`. A configured `socket_group` grants local members access. Endpoints are `GET
/v1/status`, `GET /v1/config`, `POST /v1/config/validate`, and `PUT /v1/config`. There is no
TCP listener or generic shell/command endpoint. Socket path or group changes require a
service restart.

To let the authenticated admin portal reach this API, create the same socket group in
the container with the host group ID and start Compose with the optional overlay:

```sh
GAMEBOND_GATEWAY_GID=<host-socket-group-id> \
GAMEBOND_GATEWAY_SOCKET_DIR=/run/gamebond \
docker compose -f compose.yaml -f compose.gateway.yaml up -d
```

The overlay mounts only the socket directory read-only and adds its group. It does not
enable host networking or add host `NET_ADMIN` to the edge container. The portal
forwards only status, config validation, and config apply requests after its existing
authentication and CSRF checks. The daemon independently validates every request. The
socket still grants its allowlisted host-management API, so only trusted administrators
should belong to its group. If the overlay or socket is absent, the tunnel and portal
continue to run and gateway status reports unavailable.

The service also supports advanced IPv4 NAT through one GameBond-owned nftables table.
It supports SNAT, DNAT, masquerade, address pools, and paired 1:1 source/destination
translation. Example:

```json
{
  "nat": {
    "enabled": true,
    "rules": [
      {"id":"lan-egress", "type":"masquerade", "wan_interface_id":"wan-main"},
      {"id":"web-forward", "type":"dnat", "wan_interface_id":"wan-main", "protocol":"tcp", "destination_port":443, "target_address":"192.168.10.20", "target_port":8443}
    ]
  }
}
```

Policy routing selects a WAN or VPN for a source prefix, with an optional destination
prefix. Each policy owns one table in 10000–19999 and one rule priority in 10000–29999;
WAN policies require an explicit next-hop gateway. Route rules and table defaults are
verified after apply and included in `/v1/status`.

```json
{
  "routing": {
    "enabled": true,
    "policies": [
      {"id":"work-vpn", "source_cidr":"192.168.10.0/24", "destination_cidr":"10.20.0.0/16", "egress_interface_id":"vpn-work", "table":10020, "priority":20020},
      {"id":"guest-wan2", "source_cidr":"192.168.30.0/24", "egress_interface_id":"wan-backup", "gateway":"198.51.100.1", "table":10030, "priority":20030}
    ]
  }
}
```

Advanced QoS applies egress HTB shaping to configured interfaces and classifies IPv4 and
IPv6 packets by DSCP. The configured total is the shaped link rate; class rates are
guarantees and ceilings allow borrowing. The provider reserves its own qdisc handle and
refuses to replace an unidentified root qdisc. It reports effective qdisc state and
traffic counters in `/v1/status`.

```json
{
  "qos": {
    "enabled": true,
    "interfaces": [
      {"interface_id":"wan-main", "total_kbit":100000,
       "classes":[
         {"id":"voice", "dscp":46, "rate_kbit":10000, "ceil_kbit":50000, "priority":0},
         {"id":"interactive", "dscp":34, "rate_kbit":20000, "ceil_kbit":80000, "priority":1}
       ]}
    ]
  }
}
```

Every rule references a configured WAN by stable ID. nftables validates the complete
transaction before apply; table replacement is atomic, and a later apply failure restores
the previous GameBond table. The host must provide nftables. This does not alter the
existing tunnel container's firewall/NAT path. The service also implements configuration
validation, WAN quality/outage reporting, conntrack flow snapshots, Linux bridge FDB
occupancy/learned-entry limits, and the base Linux Layer 2 bridge/VLAN topology provider.
Other Layer 2 providers remain in subsequent delivery phases.

The policy routing implementation uses Linux's routing policy database and dedicated
lookup tables; QoS uses Linux HTB and flower classifiers. See [ip-rule(8)](https://man7.org/linux/man-pages/man8/ip-rule.8.html), [tc-htb(8)](https://man7.org/linux/man-pages/man8/HTB.8.html), and [tc-flower(8)](https://www.man7.org/linux/man-pages/man8/flower.8.html) for kernel tool semantics.
