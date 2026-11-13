package avprofiles

const crestronNVXNetworkDesign = "https://docs.crestron.com/en-us/9496/Content/Topics/AV-over-IP_Network-Design.htm"

// Crestron returns the minimum network guidance for a Crestron DM NVX segment.
func Crestron() Profile {
	return Profile{
		ID:   "crestron",
		Name: "Crestron DM NVX",
		Settings: []Setting{
			{Key: "link.minimum-speed", Value: "1-gbps-per-endpoint", Rationale: "Crestron requires a 1 Gbps switch port for every connected DM NVX endpoint.", SourceURL: crestronNVXNetworkDesign},
			{Key: "switch.backplane", Value: "nonblocking", Rationale: "The switch fabric must carry simultaneous bidirectional endpoint traffic without blocking.", SourceURL: crestronNVXNetworkDesign},
			{Key: "switch.layer", Value: "layer-3", Rationale: "Crestron's published minimum switch feature list specifies Layer 3 switching.", SourceURL: crestronNVXNetworkDesign},
			{Key: "vlan.scope", Value: "dedicated-segment", Rationale: "Crestron requires the DM NVX multicast segment to be isolated using separate infrastructure, a VLAN, or MPLS.", SourceURL: crestronNVXNetworkDesign},
			{Key: "igmp.version", Value: "v2", Rationale: "IGMPv2 is the documented DM NVX default and minimum network requirement.", SourceURL: crestronNVXNetworkDesign},
			{Key: "igmp.snooping", Value: "enabled", Rationale: "Snooping limits high-bandwidth multicast streams to intended receivers.", SourceURL: crestronNVXNetworkDesign},
			{Key: "igmp.querier", Value: "one-per-vlan", Rationale: "At least one querier is required to maintain multicast transmitter and receiver membership.", SourceURL: crestronNVXNetworkDesign},
			{Key: "igmp.fast-leave", Value: "enabled", Rationale: "Crestron lists fast leave, also called immediate leave, among the minimum network settings.", SourceURL: crestronNVXNetworkDesign},
			{Key: "qos.classification", Value: "802.1p-with-802.1q", Rationale: "Crestron recommends port-based 802.1P QoS with 802.1Q VLAN tagging throughout the design.", SourceURL: crestronNVXNetworkDesign},
			{Key: "qos.queue.igmp", Value: "highest", Rationale: "Crestron directs the network to give IGMP multicast traffic its highest priority.", SourceURL: crestronNVXNetworkDesign},
		},
		Caveats: []string{
			"This profile is scoped to Crestron DM NVX guidance and is not a generic preset for every Crestron product family.",
			"Allocate interswitch bandwidth for the full 1 Gbps per endpoint that can cross each uplink; endpoint-port speed alone does not prevent uplink oversubscription.",
			"Crestron's 802.1P values 5, 6, and 7 are examples rather than one mandated value, so this preset records relative priority only.",
			"DM NVX supports IGMPv3, but the documented minimum/default is IGMPv2; validate the version consistently across the multicast domain.",
			"PIM sparse mode is required only for large routed DM NVX networks and is not enabled by this generic profile.",
			"The preset does not certify a switch or endpoint for DM NVX interoperability.",
		},
	}
}
