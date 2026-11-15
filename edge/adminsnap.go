package edge

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Core/buildinfo"
)

// Version is reported on the admin Status page.
const Version = "0.3.1-go"

// BuildCommit is the git commit this server was built from.
func BuildCommit() string { return buildinfo.Commit }

// AdminSnapshot reshapes the Go engine's stats into the document the admin
// portal's pages read (the shape app.snapshot() produced in Python): version,
// pid, observed_at, transport.paths, packets, queues and a config summary.
// Fields the Go engine does not measure are null, not zero: the per-DSCP
// queue counters and the no-path drop counter have no Go counterpart.
func AdminSnapshot(c Config, stats map[string]any, now time.Time) map[string]any {
	paths := []any{}
	if t, ok := stats["transport"].(map[string]any); ok {
		if ps, ok := t["paths"].([]bond.PathSnapshot); ok {
			for _, p := range ps {
				paths = append(paths, map[string]any{
					"slot": p.Local, "remote": []any{p.Endpoint.Addr().String(), int(p.Endpoint.Port())},
					"healthy": p.Healthy, "available": p.Ready, "rtt_ms": p.RTTMilliseconds, "rtt_jitter_ms": p.JitterMilliseconds,
					"wire_tx_bytes": p.WireTX, "wire_rx_bytes": p.WireRX, "bfd": p.BFD,
					"errors": map[string]any{"probe_lost": p.ProbeLost}})
			}
		}
	}
	packets := map[string]any{"malformed": nil, "wrong_tunnel_address": nil, "no_path_drops": nil}
	if s, ok := stats["packets"].(bond.SessionStats); ok {
		packets = map[string]any{"malformed": s.Malformed, "wrong_tunnel_address": s.WrongSource + s.WrongDestination, "no_path_drops": nil,
			"mtu_drop": s.MTUDrops, "unsupported_ipv6": s.IPv6Unsupported, "outbound_packets": s.OutboundPackets, "inbound_packets": s.InboundPackets}
	}
	queues := map[string]any{"queued_packets": nil, "capacity_packets": nil, "per_dscp_stats": map[string]any{}, "residence_ms": map[string]any{"mean": 0}}
	if q, ok := stats["queues"].(map[string]any); ok {
		if tx, ok := q["transmit"].(bond.TransmitQueueStats); ok {
			queues["queued_packets"] = tx.QueuedPackets
			queues["transmit"] = tx
		}
	}
	bind := [][]any{}
	for _, b := range c.Bind {
		if len(b) == 2 {
			bind = append(bind, []any{rawString(b[0]), rawNumber(b[1])})
		}
	}
	capabilities := map[string]any{
		"vlan_switching":       map[string]any{"state": "implemented", "reason": "Access and trunk membership, per-VLAN learning, flooding and egress tagging are enforced by the frame switch."},
		"vlan_gateway":         map[string]any{"state": "partial", "reason": "The opt-in segment gateway maps VLANs to separate gVisor routers, DHCP pools and device policies. Cross-host gateway attachment and automatic session orchestration are not implemented."},
		"multicast_snooping":   map[string]any{"state": "partial", "reason": "VLAN-scoped IGMPv3/MLDv2 source filtering, periodic general queries, and group-specific last-member queries are implemented. Membership is pruned only after the response window; without a current querier, forwarding falls back to flooding."},
		"segment_fabric":       map[string]any{"state": "partial", "reason": "Linux cmd/edge supports authenticated same-host Unix-socket attachments. Cross-host frames can use the static-peer user-space VXLAN transport or the managed kernel VXLAN/bridge/TAP path with FRR EVPN. Static VXLAN does not authenticate peers; VTEP and session provisioning remain operator-managed. EVPN-MH ESI identity is configured on managed LACP bonds, while two-PE dataplane and designated-forwarder behavior remain unvalidated; this is partial MC-LAG support, not a standalone peer protocol."},
		"dhcp_snooping":        map[string]any{"state": "partial", "reason": "The opt-in segment gateway records DHCPv4 and DHCPv6 leases against authenticated session attachments. IPv4/ARP, optional DHCPv6 IA_NA source enforcement, and validated SLAAC claims tied to trusted autonomous PIO lifetimes are available on guarded ports. Linux deployment and adversarial renewal/conflict validation remain."},
		"dhcp_relay":           map[string]any{"state": "partial", "reason": "Per-VLAN DHCPv4 relay uses Option 82 Circuit-ID; DHCPv6 relay-forward/reply validates the upstream peer, transaction, relay addresses, and Interface-ID tied to the authenticated ingress identity. Multiple upstream servers and failover are not implemented."},
		"dhcpv6":               map[string]any{"state": "partial", "reason": "Stateful IA_NA leasing, IA_PD allocation and delegated-prefix routing, DHCPv6 relay, DUID/IAID plus MAC reservations, and authenticated ingress binding records are available. The broader DHCPv6 option set is not implemented."},
		"dhcpv6_pd":            map[string]any{"state": "partial", "reason": "IA_PD pools, lease expiry/release, combined IA_NA+IA_PD messages, and routes via the requesting router's DHCPv6 link-local address are wired through the gVisor gateway. The delegated client router must advertise its prefix downstream; broader DHCPv6 options and Linux deployment validation remain."},
		"mdns_relay":           map[string]any{"state": "partial", "reason": "An opt-in reflector forwards validated link-local mDNS only between mutually allow-listed VLANs, converts QU questions to multicast-response queries, and returns tracked direct unicast answers only to recorded VLAN/MAC origins. Untracked and expired answers are consumed and counted; Linux deployment validation remains."},
		"lldp_med":             map[string]any{"state": "implemented", "reason": "Configured network-policy TLVs are validated against gateway VLAN membership; the gateway sends periodic advertisements and withdraws them when it closes."},
		"port_mirroring":       map[string]any{"state": "partial", "reason": "Monitor TAP name, directions, and runtime counters are exposed in the admin snapshot. Linux packet-capture behavior still needs deployment validation."},
		"spanning_tree":        map[string]any{"state": "partial", "reason": "The gVisor switch implements single-instance IEEE 802.1w RSTP and bounded IEEE 802.1D version-0 BPDU compatibility, including rootward TCN, TCA, TC propagation, and per-port migration timing with an initial three-second RSTP window and a three-second legacy lock. Configured and received timer bounds/relationships are validated and selected root timers propagate. Full Clause 17 migration/management behavior, dynamic timer management, and MSTP are incomplete; Linux deployment interoperability remains unvalidated. Host Linux bridges can use the separate mstpd provider."},
		"8021x":                map[string]any{"state": "partial", "reason": "Hostapd/RADIUS EAP success and failure events can authorize one station on each MACAuth session through its identity-paired EAPOL TAP and the gateway Unix API. Hostapd and edge must share a network namespace; MAB and in-edge RADIUS are not implemented."},
		"mc_lag":               map[string]any{"state": "partial", "reason": "FRR EVPN-MH ESI identity can be configured on a managed Linux 802.3ad bond through Zebra. The ESID and bond system MAC must be identical on every PE. Two-PE Linux dataplane, MAC synchronization, split-horizon, failover, and DF-election behavior are not yet validated; local mobility groups alone do not provide MC-LAG."},
		"snmp":                 map[string]any{"state": "partial", "reason": "Generic lab nodes can run a configured Net-SNMP agent. The GameBond edge itself does not expose an SNMP agent."},
		"sflow":                map[string]any{"state": "partial", "reason": "Generic lab nodes can export sFlow v5 interface-counter samples. Edge sampled-flow export and NetFlow/IPFIX are unavailable."},
		"tacacs_plus":          map[string]any{"state": "unsupported", "reason": "No TACACS+ client or administrator AAA integration is implemented. RADIUS for wired 802.1X is separate."},
		"pim":                  map[string]any{"state": "unsupported", "reason": "Multicast routing between VLANs is not implemented; the edge provides Layer 2 snooping and constrained mDNS reflection only."},
		"syslog":               map[string]any{"state": "partial", "reason": "Opt-in RFC 5424 export supports best-effort UDP or verified RFC 5425 TLS with optional private CA roots; bounded queue and connection/write losses are counted. Routine stdout status events are not exported."},
		"ntp":                  map[string]any{"state": "partial", "reason": "The admin overview reads NTP enablement and synchronization health from the host gateway status when its local socket and systemd timedatectl are available. GameBond does not configure the host time service."},
		"ra_guard":             map[string]any{"state": "partial", "reason": "Opt-in per-port RA Guard blocks direct and extension-header IPv6 Router Advertisements on configured ingress ports; fragmented, ESP, and malformed extension chains fail closed. Ports without ra_guard remain unfiltered."},
		"ip_source_guard":      map[string]any{"state": "partial", "reason": "Opt-in IPv4/ARP and IPv6 source checks use VLAN-scoped DHCPv4/v6 and static bindings tied to authenticated session ports. Configured IPv6 /64 gateway prefixes enable SAVI-style SLAAC learning after strictly validated DAD, but only while a trusted router port advertises the autonomous prefix. Claims expire with the validated Prefix Information valid lifetime and cannot extend it through traffic; a zero-lifetime withdrawal revokes claims. IPv6 Neighbor Advertisements must target an address bound to the ingress MAC. Linux deployment and adversarial renewal/deprecation validation remain."},
		"mab":                  map[string]any{"state": "unsupported", "reason": "The managed hostapd configuration and event API support EAP outcomes only. MAB needs a wired-hostapd build with an explicit MAC-auth RADIUS fallback (for example, a supported mac_auth option) and a distinct MAB result event before the broker can authorize it; no fallback is configured or inferred."},
		"q_in_q":               map[string]any{"state": "partial", "reason": "Core and the edge VLAN policy support composite outer service-VLAN and inner customer-VLAN admission, forwarding, snooping, tag rewrite, and eight-byte MTU reservation. Q-in-Q-specific session/socket end-to-end and Linux deployment validation remain."},
		"private_vlan":         map[string]any{"state": "partial", "reason": "Standalone tunnel/exit ports and shared segment members can map a primary VLAN to isolated/community secondary VLANs, translate access/trunk egress tags, and apply promiscuous/isolated/community forwarding rules. Standalone roles use l2.tunnel_private_vlan and l2.exit_private_vlan; a single-network gateway can use l2.bridge.private_vlan as the promiscuous primary port. Multi-VLAN broker gateway roles remain broker-managed. Linux interoperability remains unvalidated."},
		"mvr":                  map[string]any{"state": "partial", "reason": "Configured multicast groups can map one multicast VLAN to multiple receiver VLANs; receiver reports are sent to multicast-router ports and snooped traffic is retagged only for joined receiver ports. A trunk may carry only one mapped receiver VLAN for a group; dynamic group-range registration and Linux deployment validation remain."},
		"vxlan_evpn":           map[string]any{"state": "partial", "reason": "The Linux host provider manages a traditional kernel VXLAN device per VNI, bridge VLAN membership, and a persistent TAP; the edge broker pumps frames between the TAP and its VLAN-scoped segment switch. The existing bgpd instance enables FRR L2VPN EVPN; optional EVPN-MH ESI identity is generated by Zebra on managed 802.3ad bonds. VTEP/session provisioning is operator-managed, and two-PE Linux dataplane/DF behavior remains unvalidated. The edge's static user-space VXLAN transport is separate from EVPN."},
		"gateway_bfd":          map[string]any{"state": "partial", "reason": "Keepalived VRRP can track an opt-in BFD session to a separately configured upstream neighbor. Bond path health uses a separate GameBond BFD-like exchange; Linux deployment and peer configuration still require validation."},
		"copp":                 map[string]any{"state": "partial", "reason": "Optional l2.control_plane_pps provides an aggregate limit and l2.control_plane_rates configures independent protocol-class limits on gateway egress. Drops are reported. Host control-plane policing and Linux load validation remain."},
		"ztp":                  map[string]any{"state": "unsupported", "reason": "There is no authenticated discovery, bootstrap enrollment, or remote configuration provisioning flow."},
		"ecmp_policy_routing":  map[string]any{"state": "partial", "reason": "The gVisor gateway can select stable weighted paths and bind sockets to configured Linux interfaces or fwmarks. Host routes, policy rules, health checking, and failover membership remain externally configured."},
		"vrf":                  map[string]any{"state": "partial", "reason": "Each configured VLAN gateway uses an independent gVisor router, which isolates routing by VLAN. Independent VRF objects, route leaking, and VRF-aware BGP/OSPF are not implemented."},
		"macsec":               map[string]any{"state": "unsupported", "reason": "IEEE 802.1AE link-layer encryption and key agreement are not implemented; GameBond tunnel encryption is a separate layer."},
		"ptp":                  map[string]any{"state": "unsupported", "reason": "PTP clock distribution, hardware timestamping, and PTP port health are not implemented. NTP health reporting does not provide PTP."},
		"isis":                 map[string]any{"state": "unsupported", "reason": "The managed FRR integration does not supervise or configure IS-IS."},
		"rpki":                 map[string]any{"state": "unsupported", "reason": "BGP route-origin validation and RPKI RTR cache integration are not implemented."},
		"route_redistribution": map[string]any{"state": "unsupported", "reason": "Managed OSPF, BGP, and static routes have no controlled redistribution policy between protocols."},
		"admin_rbac":           map[string]any{"state": "unsupported", "reason": "Admin authentication has a single permission level; read-only and administrator roles are not implemented."},
	}
	snapshot := map[string]any{"version": Version, "commit": buildinfo.Commit, "pid": os.Getpid(), "observed_at": now.UTC().Format(time.RFC3339Nano),
		"transport": map[string]any{"paths": paths}, "packets": packets, "queues": queues, "qos": stats["qos"],
		"layer2": stats["l2"], "layer2_capabilities": capabilities,
		"config": map[string]any{"lan_tunnel_ips": lanIPs(c), "client_tunnel_ip": c.ClientIP, "game_udp_ports": gamePorts(c),
			"queues": c.Queues, "bonding_mode": c.Bonding, "bind": bind, "mtu": c.MTU, "layer2": layer2ConfigSummary(c.L2)}}
	if relayStats, ok := stats["mdns_relay"]; ok {
		snapshot["mdns_relay_stats"] = relayStats
	}
	return snapshot
}

func layer2ConfigSummary(l2 *L2Config) map[string]any {
	if l2 == nil {
		return map[string]any{"enabled": false}
	}
	vlans := make([]int, 0)
	relay4 := make(map[string]any)
	relay6 := make(map[string]any)
	pd := make(map[string]any)
	if l2.Bridge != nil {
		for _, entry := range l2.Bridge.VLANs {
			vlans = append(vlans, int(entry.VLANID))
			if entry.Gateway != nil {
				id := fmt.Sprint(entry.VLANID)
				if entry.Gateway.DHCPRelay4 != "" {
					relay4[id] = map[string]string{"server": entry.Gateway.DHCPRelay4, "gateway": entry.Gateway.DHCPRelayGateway4}
				}
				if entry.Gateway.DHCPRelay6 != "" {
					relay6[id] = map[string]string{"server": entry.Gateway.DHCPRelay6, "link_address": entry.Gateway.DHCPRelayLink6}
				}
				if entry.Gateway.DHCPv6PDPool != "" {
					pd[id] = map[string]any{"pool": entry.Gateway.DHCPv6PDPool, "prefix_bits": entry.Gateway.DHCPv6PDBits}
				}
			}
		}
		if len(l2.Bridge.VLANs) == 0 && l2.ExitVLAN.AccessVLAN != 0 {
			vlans = append(vlans, int(l2.ExitVLAN.AccessVLAN))
		}
		if len(l2.Bridge.VLANs) == 0 && l2.Bridge.DHCPRelay4 != "" {
			relay4[fmt.Sprint(l2.ExitVLAN.AccessVLAN)] = map[string]string{"server": l2.Bridge.DHCPRelay4, "gateway": l2.Bridge.DHCPRelayGateway4}
		}
		if len(l2.Bridge.VLANs) == 0 && l2.Bridge.DHCPRelay6 != "" {
			relay6[fmt.Sprint(l2.ExitVLAN.AccessVLAN)] = map[string]string{"server": l2.Bridge.DHCPRelay6, "link_address": l2.Bridge.DHCPRelayLink6}
		}
		if len(l2.Bridge.VLANs) == 0 && l2.Bridge.DHCPv6PDPool != "" {
			pd[fmt.Sprint(l2.ExitVLAN.AccessVLAN)] = map[string]any{"pool": l2.Bridge.DHCPv6PDPool, "prefix_bits": l2.Bridge.DHCPv6PDBits}
		}
	}
	var gatewayPrivateVLAN uint16
	if l2.Bridge != nil {
		gatewayPrivateVLAN = l2.Bridge.PrivateVLAN
	}
	return map[string]any{
		"enabled": l2.Enabled, "segment_id": l2.SegmentID, "bridge_gateway": l2.Bridge != nil,
		"tunnel_vlan": l2.TunnelVLAN, "exit_vlan": l2.ExitVLAN, "gateway_vlans": vlans,
		"tunnel_private_vlan": l2.TunnelPrivateVLAN, "exit_private_vlan": l2.ExitPrivateVLAN,
		"gateway_private_vlan": gatewayPrivateVLAN,
		"monitor":              l2.Monitor, "rstp": l2.RSTP, "dhcp_relay4": relay4, "dhcp_relay6": relay6, "dhcpv6_pd": pd, "ra_guard_tunnel": l2.RAGuardTunnel, "ra_guard_exit": l2.RAGuardExit,
		"ipv4_source_guard_tunnel": l2.IPv4SourceGuardTunnel, "ipv6_source_guard_tunnel": l2.IPv6SourceGuardTunnel, "control_plane_pps": l2.ControlPlanePPS, "control_plane_rates": l2.ControlPlaneRates,
	}
}

func gamePorts(c Config) []any {
	out := []any{}
	for _, p := range c.GamePorts {
		out = append(out, int(p))
	}
	return out
}

func rawString(m json.RawMessage) string {
	var s string
	_ = json.Unmarshal(m, &s)
	return s
}

func rawNumber(m json.RawMessage) int {
	var n int
	_ = json.Unmarshal(m, &n)
	return n
}

func lanIPs(c Config) []any {
	out := []any{}
	for _, ip := range c.LanTunnelIPs {
		out = append(out, ip)
	}
	return out
}
