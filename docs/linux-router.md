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

The initial provider applies bridge creation, VLAN filtering, port and VLAN membership,
and MTU changes with reverse-order rollback. It refuses to adopt unmanaged bridges or
steal ports from unmanaged masters. Virtual Network Override is reported in the
capability inventory but cannot yet be applied; requests containing overrides are
rejected. Other Layer 2 roadmap features remain unavailable until their individual
providers and effective-state checks are integrated. A capability listing alone does
not mean a feature is configured or active.

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

This initial service implements configuration validation, WAN quality/outage reporting,
conntrack flow snapshots, Linux bridge FDB occupancy/learned-entry limits, and the base
Linux Layer 2 bridge/VLAN topology provider. Other Layer 2 providers and DHCP, NAT, policy
routing, QoS, VRRP, LACP, LTE backup, OSPF, BGP, mDNS, IGMP proxy, and RADIUS remain in
subsequent delivery phases.
