package avprofiles

// NDI returns NDI's documented network and transport recommendations.
func NDI() Profile {
	const (
		configurationSource = "https://docs.ndi.video/all/developing-with-ndi/sdk/configuration-files"
		multicastSource     = "https://docs.ndi.video/all/getting-started/white-paper/multicast"
		layoutSource        = "https://docs.ndi.video/all/getting-started/white-paper/network-layout"
	)

	return Profile{
		ID:   "ndi",
		Name: "NDI",
		Settings: []Setting{
			{
				Key:       "transport.preferred",
				Value:     "reliable-udp",
				Rationale: "NDI 5 and later use Reliable UDP by default and recommend it for most network configurations.",
				SourceURL: configurationSource,
			},
			{
				Key:       "multicast.send",
				Value:     "disabled",
				Rationale: "NDI disables multicast sending by default because an incorrectly configured multicast network can severely affect performance.",
				SourceURL: multicastSource,
			},
			{
				Key:       "igmp.snooping",
				Value:     "required-when-multicast-enabled",
				Rationale: "NDI requires IGMP snooping to keep optional high-bandwidth multicast streams off unsubscribed switch ports.",
				SourceURL: multicastSource,
			},
			{
				Key:       "igmp.querier",
				Value:     "required-when-multicast-enabled",
				Rationale: "NDI requires an IGMP routing querier to manage multicast subscriptions when multicast is enabled.",
				SourceURL: multicastSource,
			},
			{
				Key:       "link.minimum-speed",
				Value:     "1-gbps-full-duplex",
				Rationale: "NDI recommends full-duplex switch ports with at least 1 Gb/s upstream and downstream capacity.",
				SourceURL: layoutSource,
			},
			{
				Key:       "jumbo-frames",
				Value:     "not-required",
				Rationale: "NDI's default UDP packet behavior does not require jumbo frames to be enabled on the network.",
				SourceURL: configurationSource,
			},
		},
		Caveats: []string{
			"NDI discourages multicast for most deployments and prefers Reliable UDP; enable multicast only on a network engineered for high-bandwidth multicast.",
			"Current NDI documentation does not publish a fixed DSCP map or require a dedicated VLAN, so this profile does not invent either setting.",
		},
	}
}
