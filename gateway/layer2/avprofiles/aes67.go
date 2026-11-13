package avprofiles

const aes67Standard = "https://www.aes.org/publications/standards/preview.cfm?ID=96"

// AES67 returns the network traffic-class defaults from AES67-2023.
func AES67() Profile {
	return Profile{
		ID:   "aes67",
		Name: "AES67",
		Settings: []Setting{
			{Key: "timing.ptp-version", Value: "ieee-1588-2008", Rationale: "AES67 synchronization uses the IEEE 1588-2008 Precision Time Protocol profile.", SourceURL: aes67Standard},
			{Key: "qos.dscp.ptp", Value: "46", Rationale: "AES67 marks PTP clock event traffic for Expedited Forwarding (EF).", SourceURL: aes67Standard},
			{Key: "qos.dscp.audio", Value: "34", Rationale: "AES67 marks RTP/RTCP media traffic for AF41 below clock traffic.", SourceURL: aes67Standard},
			{Key: "qos.dscp.other", Value: "0", Rationale: "AES67 leaves PTP management, discovery, and connection-management traffic in Default Forwarding (DF).", SourceURL: aes67Standard},
		},
		Caveats: []string{
			"These are the AES67 standard traffic-class defaults; some endpoint ecosystems, including Dante AES67 implementations, use different markings or make them configurable.",
			"All participating devices must use compatible PTP profile and domain parameters; this preset does not select a grandmaster or a PTP domain.",
			"The preset does not choose a VLAN, MTU, multicast group, packet time, sample rate, or discovery mechanism; validate those choices against every endpoint's AES67 implementation.",
			"Describing AES67 settings does not establish standards conformance or tested interoperability.",
		},
	}
}
