package source

import "github.com/anchore/syft/syft/artifact"

// Description represents any static source data that helps describe "what" was cataloged.
type Description struct {
	ID         string      `hash:"ignore"` // the id generated from the parent source struct
	Name       string      `hash:"ignore"`
	Version    string      `hash:"ignore"`
	Supplier   string      `hash:"ignore"`
	ArtifactID artifact.ID `hash:"ignore"` // references a specific artifact this source describes
	Metadata   interface{}
}
