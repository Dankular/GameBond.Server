package avprofiles

const (
	shureSwitchGuide          = "https://service.shure.com/articles/en_US/Knowledge/Dante-Switch-Configuration"
	shureSwitchSelectionGuide = "https://service.shure.com/articles/en_US/Knowledge/selecting-network-switch-for-dante-aes67"
	shureIGMPGuide            = "https://service.shure.com/articles/en_US/Knowledge/dante-networks-and-igmp-snooping"
)

// Shure returns Shure's managed-switch guidance for its Dante/AES67 products.
func Shure() Profile {
	return Profile{
		ID:   "shure",
		Name: "Shure Dante/AES67",
		Settings: []Setting{
			{Key: "link.minimum-speed", Value: "1-gbps", Rationale: "Shure recommends Gigabit switch ports rather than Fast Ethernet for Dante/AES67 endpoints.", SourceURL: shureSwitchGuide},
			{Key: "energy-efficient-ethernet", Value: "disabled", Rationale: "Shure warns that 802.3az sleep behavior can interrupt Dante/AES67 clocking and cause dropouts.", SourceURL: shureSwitchSelectionGuide},
			{Key: "multicast.storm-control", Value: "disabled", Rationale: "Shure's general switch procedure explicitly disables multicast storm control.", SourceURL: shureSwitchGuide},
			{Key: "igmp.version", Value: "v2", Rationale: "Shure's managed-switch procedure configures IGMPv2.", SourceURL: shureSwitchGuide},
			{Key: "igmp.snooping", Value: "enabled", Rationale: "Snooping confines multicast clock, control, and audio traffic to the ports that request it.", SourceURL: shureSwitchGuide},
			{Key: "igmp.querier", Value: "one-per-vlan", Rationale: "A querier maintains multicast group membership; Shure recommends the core switch when several switches are used.", SourceURL: shureSwitchGuide},
			{Key: "igmp.query-interval", Value: "30-seconds", Rationale: "Shure recommends lowering the querier interval to about 30 seconds when the switch permits it.", SourceURL: shureSwitchGuide},
			{Key: "igmp.fast-leave", Value: "enabled", Rationale: "Shure's switch procedure enables fast leave and notes that it is required when video-over-IP is also present.", SourceURL: shureSwitchGuide},
			{Key: "multicast.unregistered-filtering", Value: "disabled", Rationale: "Filtering unregistered multicast can block mDNS, PTP, Dante discovery, and Shure management discovery.", SourceURL: shureIGMPGuide},
			{Key: "qos.classification", Value: "trust-dscp", Rationale: "The switch must trust endpoint DSCP markings before mapping them to priority queues.", SourceURL: shureSwitchGuide},
			{Key: "qos.queue.dscp56", Value: "highest", Rationale: "Shure assigns DSCP 56 clock traffic to the highest-priority queue.", SourceURL: shureSwitchGuide},
			{Key: "qos.queue.dscp46", Value: "second-highest", Rationale: "Shure assigns DSCP 46 audio traffic to the second-highest-priority queue.", SourceURL: shureSwitchGuide},
			{Key: "qos.queue.dscp34", Value: "third-highest", Rationale: "Shure assigns DSCP 34 video or standard AES67 media traffic below clock and primary audio queues.", SourceURL: shureSwitchGuide},
		},
		Caveats: []string{
			"Shure documents different AES67 clock and audio markings for different Dante firmware generations; inspect endpoint markings before applying the queue map.",
			"Small isolated single-switch Dante networks without multicast audio generally do not require IGMP snooping, while enterprise, multi-switch, AES67 multicast, and video deployments do.",
			"Unregistered multicast filtering must remain disabled for Shure discovery traffic; this conflicts with SDVoE's generic instruction to disable unregistered multicast flooding.",
			"PoE requirements are product-specific and are intentionally not selected by this profile.",
			"The preset describes Shure guidance and does not certify Dante/AES67 interoperability.",
		},
	}
}
