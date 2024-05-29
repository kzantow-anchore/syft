package regex

import (
	"embed"
	"io/fs"

	"github.com/anchore/go-collections"
	"github.com/anchore/syft/syft/pkg"
)

//go:embed dynamic/*/*.yaml
var dynamicCatalogerRules embed.FS

func AllCatalogers() []collections.TaggedValue[pkg.Cataloger] {
	// remove "dynamic"
	fsys, err := fs.Sub(dynamicCatalogerRules, "dynamic")
	if err != nil {
		panic(err)
	}
	return NewCatalogersFromDirs(fsys)
}
