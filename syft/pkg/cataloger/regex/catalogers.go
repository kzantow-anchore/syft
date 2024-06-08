package regex

import (
	"embed"
	"io/fs"

	"github.com/anchore/go-collections"
	"github.com/anchore/syft/syft/pkg"
)

//go:embed rules/*/*.yaml
var embeddedCatalogerRules embed.FS

func EmbeddedCatalogers() []collections.TaggedValue[pkg.Cataloger] {
	fsys, err := fs.Sub(embeddedCatalogerRules, "rules") // remove "rules" directory prefix
	if err != nil {
		panic(err)
	}
	return MakeCatalogers(fsys, ".")
}
