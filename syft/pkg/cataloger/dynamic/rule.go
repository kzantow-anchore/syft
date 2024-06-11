package dynamic

import (
	"errors"
	"io"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
)

type Rule struct {
	Class     string          `yaml:"Class"`
	FileGlob  string          `yaml:"FileGlob"`
	Extractor map[string]any  `yaml:"Extractor"`
	Package   PackageTemplate `yaml:"Package"`
}

type PackageTemplate struct {
	Name    string   `yaml:"Name"`
	Version string   `yaml:"Version"`
	PURL    string   `yaml:"PURL"`
	CPEs    []string `yaml:"CPEs"`
	License string   `yaml:"License"`
}

func ReadRulesInDir(fsys fs.FS) ([]Rule, error) {
	var errs error
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		panic(err)
	}

	var out []Rule
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			log.Debug(err)
			continue
		}
		if info.IsDir() {
			continue
		}

		name := entry.Name()
		if !isRuleDefinition(name) {
			continue
		}
		f, err := fsys.Open(name)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		rule, err := readRule(name, f)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		out = append(out, rule)
	}

	return out, errs
}

func isRuleDefinition(name string) bool {
	return strings.HasSuffix(name, ".yaml")
}

func readRule(name string, rdr io.ReadCloser) (Rule, error) {
	defer internal.CloseAndLogError(rdr, name)
	dec := yaml.NewDecoder(rdr)
	name = strings.TrimSuffix(name, ".yaml")
	rule := Rule{
		Class: name,
	}
	err := dec.Decode(&rule)
	return rule, err
}
