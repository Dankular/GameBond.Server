// Package avprofiles contains evidence-backed Pro AV network presets.
// Presets describe settings only; they do not imply certification or tested
// interoperability with a particular endpoint or switch.
package avprofiles

type Setting struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Rationale string `json:"rationale"`
	SourceURL string `json:"source_url"`
}

type Profile struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Settings []Setting `json:"settings"`
	Caveats  []string  `json:"caveats,omitempty"`
}
