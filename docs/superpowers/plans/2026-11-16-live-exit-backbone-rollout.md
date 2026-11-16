# Live three-exit backbone rollout

**Status:** topology and per-node configs are prepared; the live mesh is not activated

## Nodes

The provider ASNs below describe the public IP origins. They are not used as
the private eBGP ASNs.

| Node | Public endpoint | Provider origin ASN | Private BGP ASN | Router ID |
|---|---|---:|---:|---|
| `ionos-exit-01` | `194.164.124.139` | AS8560 | 4200019401 | `10.79.255.1` |
| `apps` | `138.199.201.16` | AS24940 | 4200013801 | `10.79.255.2` |
| `sw01` | `195.154.119.136` | AS12876 | 4200019501 | `10.79.255.3` |

## WireGuard links

Each link is a separate WireGuard interface and eBGP session. Ports are the
container and public UDP ports. The peers use 25-second WireGuard persistent
keepalive; BGP starts with its runtime defaults of 1-second keepalive and
3-second hold time.

| Link | Node A address / port | Node B address / port | UDP endpoints |
|---|---|---|---|
| IONOS to Hetzner | IONOS `10.79.0.1/30`, UDP 51820 | Hetzner `10.79.0.2/30`, UDP 51820 | `194.164.124.139:51820` to `138.199.201.16:51820` |
| IONOS to Scaleway | IONOS `10.79.0.5/30`, UDP 51821 | Scaleway `10.79.0.6/30`, UDP 51820 | `194.164.124.139:51821` to `195.154.119.136:51820` |
| Hetzner to Scaleway | Hetzner `10.79.0.9/30`, UDP 51821 | Scaleway `10.79.0.10/30`, UDP 51821 | `138.199.201.16:51821` to `195.154.119.136:51821` |

Interface names and local secret filenames:

| Node | Peer | Interface | Private key file |
|---|---|---|---|
| IONOS | Hetzner | `gb-hz0` | `gb-hz0.key` |
| IONOS | Scaleway | `gb-sw0` | `gb-sw0.key` |
| Hetzner | IONOS | `gb-ionos` | `gb-ionos.key` |
| Hetzner | Scaleway | `gb-sw0` | `gb-sw0.key` |
| Scaleway | IONOS | `gb-ionos` | `gb-ionos.key` |
| Scaleway | Hetzner | `gb-hz0` | `gb-hz0.key` |

The public keys are generated per interface and exchanged between the nodes;
private keys stay on their owning node in the release's `secrets/backbone`
directory, mounted read-only at `/run/secrets/gamebond-backbone`.

Public keys staged on the nodes:

| Node | Key file / peer link | Public key |
|---|---|---|
| IONOS | `gb-hz0.key` to Hetzner | `w/qLnrA/kTP4MADPPzFEd81OiljZmfqGknOwhHI2Qis=` |
| IONOS | `gb-sw0.key` to Scaleway | `h28bYPny1lJJ3UgRVwsEkfzcQBpagG4Qfg5DEFXVvB4=` |
| Hetzner | `gb-ionos.key` to IONOS | `AKBGWhvywSPQuzxZFDfhYWKsAsxtCZz64NZgeuRFTR4=` |
| Hetzner | `gb-sw0.key` to Scaleway | `9W7PAptm8+sMJK+KIGKKJxS/Rn7ooJm3Uny6cryWGV8=` |
| Scaleway | `gb-ionos.key` to IONOS | `gtrZy9Q/hpQcB3FzgOSNq/0zYLku7fh7PhucK/737Dc=` |
| Scaleway | `gb-hz0.key` to Hetzner | `xzCNly4SyjFJoPp5OzW9qp5zsm8Lc+PkRxDzbSjoxlc=` |

## Initial route policy

The only routes exchanged during warm-mesh bring-up are the three dedicated
link subnets. No client segment, Internet default, or public prefix is
imported or exported. Import/export prefixes are set per neighbor as follows:

| Local node | Neighbor | Import | Export |
|---|---|---|---|
| IONOS | Hetzner | `10.79.0.8/30` | `10.79.0.0/30`, `10.79.0.4/30` |
| IONOS | Scaleway | `10.79.0.8/30` | `10.79.0.0/30`, `10.79.0.4/30` |
| Hetzner | IONOS | `10.79.0.4/30` | `10.79.0.0/30`, `10.79.0.8/30` |
| Hetzner | Scaleway | `10.79.0.4/30` | `10.79.0.0/30`, `10.79.0.8/30` |
| Scaleway | IONOS | `10.79.0.0/30` | `10.79.0.4/30`, `10.79.0.8/30` |
| Scaleway | Hetzner | `10.79.0.0/30` | `10.79.0.4/30`, `10.79.0.8/30` |

Each WireGuard peer's `allowed_ips` must include its BGP peer `/32` and the
prefixes imported from that neighbor. The deployed Compose files do not yet
publish the backbone ports or mount the key directory. The overlay publishes
only UDP 51820-51821 for WireGuard; TCP 51823 remains container-only because
session recovery connects across the private WireGuard interfaces. Restrict the
published UDP ports to the other two exit addresses in each host firewall.

This configuration brings up the encrypted mesh, exchanges only the dedicated
overlay routes, and enables authenticated GameBond session/recovery-state sync
over the peer links. It does not route client traffic through another exit or
migrate gVisor TCP proxy streams, UDP mappings, NAT state, or public egress
identity. Those behaviors require a separately measured transit profile and
explicit source-identity design.

## DHCP authority across exits

DHCP lease state belongs to one gateway service, not to each exit. Exits provide
the L2 path to that authority, whichever exit currently carries the client
session. Do not configure independent lease pools on the exits or copy lease
databases during failover. DHCP state is deliberately excluded from GameBond
packet-recovery snapshots.

The current three nodes each run an exit container, but none runs the separate
`gamebond-gatewayd`/Kea service. Their exit-side L2 gateways have local DHCP
support, so that is not yet the required single-authority deployment. The
gateway owner and its service address must be established before replacing the
working DHCP path; the active-exit transport must reach that same gateway.

## Activation and continuity

The current backbone runtime starts with the GameBond server process. SIGHUP
reloads Layer 2 host and device-policy settings only; it does not start or
reconfigure WireGuard/FRR. Enabling the mesh on a running node therefore
requires a process/container restart with the updated config and secret mount.
The per-node JSON in `tools/backbone/` matches the staged node keys; the public
keys were re-derived from the private key files on each exit. The deployment
script accepts `-EnableBackbone` to merge that config, apply the Compose overlay,
validate Compose, restart one exit at a time, and restore the prior config if a
node fails its health check.

On 2026-11-16, a live check found no WireGuard interfaces, inactive
`gamebond-router.service`, no listeners on 51820–51823, and no
`exit_backbone` config on IONOS, Apps, or sw01. The client was carrying traffic
on Apps at that check. The first activation therefore restarts the active exit
before it has replicated any state; this can briefly interrupt the tunnel and
cannot be described as lossless. The mesh remains inactive until that restart
is authorized.

BGP convergence does not transfer gVisor TCP endpoints, proxy sockets, UDP
mappings, NAT state, or a public source address. The current gateway is a split
TCP proxy. The backbone can keep paths warm and select paths for new flows;
it cannot promise zero packet loss or preserve established Internet flows
through anchor-host failure. The existing GameBond packet-repair mechanisms
recover bounded tunnel gaps while their original session remains alive; they
do not replicate a gateway process to another host.
