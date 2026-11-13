package avprofiles

const sdvoeSwitchGuide = "https://sdvoe.org/blog/the-four-commandments-of-an-sdvoe-network-switch/"

// SDVoE returns the generic switch requirements published by the SDVoE Alliance.
func SDVoE() Profile {
	return Profile{
		ID:   "sdvoe",
		Name: "SDVoE",
		Settings: []Setting{
			{Key: "link.minimum-speed", Value: "10-gbps-per-endpoint", Rationale: "The Alliance requires one 10-gigabit switch port for each SDVoE endpoint.", SourceURL: sdvoeSwitchGuide},
			{Key: "igmp.version", Value: "v2", Rationale: "The switch must support IGMPv2 for SDVoE multicast membership.", SourceURL: sdvoeSwitchGuide},
			{Key: "igmp.snooping", Value: "enabled", Rationale: "Snooping limits each multicast stream to subscribed receiver ports.", SourceURL: sdvoeSwitchGuide},
			{Key: "igmp.fast-leave", Value: "enabled", Rationale: "Fast leave avoids slow or artifact-prone source changes after a receiver leaves a stream.", SourceURL: sdvoeSwitchGuide},
			{Key: "multicast.unregistered-flooding", Value: "disabled", Rationale: "Filtering unused, unregistered streams prevents them from flooding and overwhelming the network.", SourceURL: sdvoeSwitchGuide},
		},
		Caveats: []string{
			"This is the SDVoE Alliance's generic switch guidance; an endpoint vendor may document additional MTU, PoE, EEE, or topology requirements.",
			"The 10 Gbps value applies to each endpoint-facing port and does not by itself establish sufficient switch-fabric or interswitch-uplink capacity.",
			"The preset describes settings only and does not certify an endpoint, switch, or system as SDVoE interoperable.",
		},
	}
}
