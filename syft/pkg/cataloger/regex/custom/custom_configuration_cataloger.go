package custom

import (
	"embed"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/regex"
)

//go:embed *.yaml
var files embed.FS

func NewCustomConfigurationCataloger() pkg.Cataloger {
	rules, err := regex.ReadAllRules(files)
	if err != nil {
		panic(err)
	}
	return regex.NewCataloger("custom-configuration-cataloger", rules...)
}
