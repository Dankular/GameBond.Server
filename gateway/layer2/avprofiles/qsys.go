package avprofiles

// QSYS returns Q-SYS's documented Q-LAN network recommendations.
func QSYS() Profile {
	const (
		networkSource   = "https://help.qsys.com/Content/Networking/Switches_Infrastructure.htm"
		checklistSource = "https://www.qsys.com/products-solutions/q-sys/networking/q-sys-networking-solutions/qsc-q-sys-network-support-checklist/"
	)

	return Profile{
		ID:   "qsys",
		Name: "Q-SYS",
		Settings: []Setting{
			{
				Key:       "link.minimum-speed",
				Value:     "1-gbps",
				Rationale: "Interfaces carrying real-time Q-SYS audio or video must operate at 1 Gb/s or faster.",
				SourceURL: networkSource,
			},
			{
				Key:       "qos.classification",
				Value:     "diffserv-dscp",
				Rationale: "Q-SYS requires DSCP classification rather than switch auto-QoS for Q-LAN prioritization.",
				SourceURL: networkSource,
			},
			{
				Key:       "qos.queue.ptpv2",
				Value:     "46:strict-highest",
				Rationale: "Q-SYS PTPv2 uses EF (DSCP 46) and must be placed in the highest strict-priority queue.",
				SourceURL: networkSource,
			},
			{
				Key:       "qos.queue.audio",
				Value:     "34:strict-second-highest",
				Rationale: "Q-LAN audio uses AF41 (DSCP 34) and must be placed in the second-highest strict-priority queue.",
				SourceURL: networkSource,
			},
			{
				Key:       "qos.queue.video",
				Value:     "26:third-highest",
				Rationale: "Q-SYS video uses AF31 (DSCP 26) and belongs in the third-highest queue; strict priority is not required for video.",
				SourceURL: networkSource,
			},
			{
				Key:       "igmp.version",
				Value:     "v2",
				Rationale: "Q-SYS devices implement IGMPv2 for multicast group membership.",
				SourceURL: networkSource,
			},
			{
				Key:       "igmp.snooping",
				Value:     "enabled-for-multicast",
				Rationale: "Q-SYS recommends IGMPv2 snooping to constrain AES67 and video-over-IP multicast traffic.",
				SourceURL: networkSource,
			},
			{
				Key:       "igmp.querier",
				Value:     "one-per-vlan",
				Rationale: "Q-SYS deployments using multicast require a single IGMP querier for each VLAN or subnet.",
				SourceURL: checklistSource,
			},
			{
				Key:       "vlan.endpoint-frames",
				Value:     "untagged",
				Rationale: "Q-SYS endpoints do not support tagged Ethernet frames on their connected switch ports.",
				SourceURL: checklistSource,
			},
			{
				Key:       "jumbo-frames",
				Value:     "disabled",
				Rationale: "Q-SYS does not use jumbo frames, and Q-SYS directs operators not to use them on the same VLAN, subnet, or shared trunks.",
				SourceURL: checklistSource,
			},
		},
		Caveats: []string{
			"QoS is recommended for mixed media or high-data-rate designs; Q-SYS says it is not strictly required on every isolated Q-LAN network.",
			"The IGMP settings are for designs carrying multicast such as AES67 or video over IP; they do not make every Q-SYS stream multicast.",
			"These are Q-LAN-only DSCP values. A Q-SYS design using the Audinate QoS option uses different PTP and audio markings.",
		},
	}
}
