package avprofiles

// Play returns the documented network requirement for UniFi Play.
func Play() Profile {
	const source = "https://help.ui.com/hc/en-us/articles/29946699826199-Getting-Started-with-UniFi-Play"

	return Profile{
		ID:   "play",
		Name: "UniFi Play",
		Settings: []Setting{
			{
				Key:       "vlan.scope",
				Value:     "same-vlan",
				Rationale: "Ubiquiti directs the mobile device running UniFi Play and the PowerAmp to use the same VLAN for discovery and control.",
				SourceURL: source,
			},
		},
		Caveats: []string{
			"The requested Play profile is interpreted as Ubiquiti UniFi Play because Ubiquiti lists Play among its Pro AV profiles; Ubiquiti does not publish the preset's underlying QoS, multicast, or MTU rules.",
			"The same-VLAN guidance applies to the mobile device running UniFi Play and PowerAmp; it does not configure device adoption, Bluetooth, or application permissions.",
		},
	}
}
