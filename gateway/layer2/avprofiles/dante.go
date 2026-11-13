package avprofiles

// Dante returns Audinate's documented network recommendations for Dante.
func Dante() Profile {
	const source = "https://assets.audinate.com/wp-content/uploads/2022/03/dante-information-for-network-admins.pdf"

	return Profile{
		ID:   "dante",
		Name: "Dante",
		Settings: []Setting{
			{
				Key:       "qos.queueing",
				Value:     "strict-priority",
				Rationale: "Audinate requires strict-priority queueing whenever QoS is used for Dante traffic.",
				SourceURL: source,
			},
			{
				Key:       "qos.dscp.ptp",
				Value:     "56",
				Rationale: "Dante marks time-critical PTP event traffic CS7 (DSCP 56) for the highest priority.",
				SourceURL: source,
			},
			{
				Key:       "qos.dscp.audio-ptpv2",
				Value:     "46",
				Rationale: "Dante marks audio and PTPv2 traffic EF (DSCP 46) for medium priority below time-critical PTP events.",
				SourceURL: source,
			},
			{
				Key:       "qos.dscp.reserved",
				Value:     "8",
				Rationale: "Audinate reserves CS1 (DSCP 8) as the low-priority Dante class.",
				SourceURL: source,
			},
			{
				Key:       "qos.dscp.other",
				Value:     "0",
				Rationale: "Other Dante traffic uses best effort (DSCP 0).",
				SourceURL: source,
			},
			{
				Key:       "igmp.snooping",
				Value:     "enabled-when-needed",
				Rationale: "Use IGMP multicast management on mixed networks, networks sharing IP video, or networks carrying significant multicast audio.",
				SourceURL: source,
			},
			{
				Key:       "igmp.version",
				Value:     "v2-or-v3",
				Rationale: "Dante implements IGMP version 2 or version 3.",
				SourceURL: source,
			},
			{
				Key:       "igmp.querier",
				Value:     "one-per-vlan",
				Rationale: "Audinate directs operators to elect one IGMP querier per VLAN when IGMP is used.",
				SourceURL: source,
			},
			{
				Key:       "energy-efficient-ethernet",
				Value:     "disabled",
				Rationale: "Energy Efficient Ethernet can impair synchronization and cause audio dropouts on Dante ports.",
				SourceURL: source,
			},
		},
		Caveats: []string{
			"QoS is recommended on mixed-use networks, including Dante Video, and required for Dante-audio-only networks only when 100 Mbps or mixed 100 Mbps/1 Gbps infrastructure is used.",
			"IGMP is intended for mixed networks, shared IP-video segments, or significant multicast audio; Dante-audio-only networks with few or no multicast flows do not require it.",
			"The documented DSCP values may be re-marked if time-critical PTP remains above audio and other traffic.",
		},
	}
}
