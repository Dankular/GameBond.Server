package avprofiles

import "sort"

// All returns the supported profile catalogue in stable ID order.
func All() []Profile {
	profiles := []Profile{Play(), Dante(), QSYS(), NDI(), SDVoE(), Shure(), AES67(), Crestron()}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles
}

// Lookup returns a profile by its stable ID.
func Lookup(id string) (Profile, bool) {
	for _, profile := range All() {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}
