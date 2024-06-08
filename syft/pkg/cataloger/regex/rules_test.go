package regex

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

func Test_allRules(t *testing.T) {
	// can execute a single rule or image test with something like:
	// go test ./syft/pkg/cataloger/regex --run //redmine/
	// go test ./syft/pkg/cataloger/regex --run //redmine/5.1.2
	fsys := os.DirFS("rules")
	testDir(t, fsys, ".")
}

func testDir(t *testing.T, fsys fs.FS, dir string) {
	entries, err := fs.ReadDir(fsys, dir)
	require.NoError(t, err)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if entry.IsDir() {
			t.Run(entry.Name(), func(t *testing.T) {
				testDir(t, fsys, path.Join(dir, entry.Name()))
			})
			continue
		}
		if strings.HasSuffix(entry.Name(), ".yaml") {
			testRule(t, fsys, dir, entry.Name())
			continue
		}
		t.Logf("ignoring file: %s", entry.Name())
	}
}

type ruleTest struct {
	Image    string         `yaml:"Image"`
	Platform string         `yaml:"Platform"`
	Expect   ruleTestExpect `yaml:"Expect"`
}

type ruleTestExpect struct {
	Name    string `yaml:"Name"`
	Version string `yaml:"Version"`
}

func testRule(t *testing.T, fsys fs.FS, dir string, name string) {
	ctx := context.Background()

	fullPath := path.Join(dir, name)
	t.Run(name, func(t *testing.T) {
		t.Parallel()

		ruleFile, err := fsys.Open(fullPath)
		require.NoError(t, err)

		rule, err := readRule(name, ruleFile)
		require.NoError(t, err)

		cataloger := NewCataloger(name, rule)

		var tests []ruleTest
		testPath := strings.ReplaceAll(fullPath, ".yaml", ".test")
		testFile, err := fsys.Open(testPath)
		require.NoError(t, err)

		decoder := yaml.NewDecoder(testFile)
		err = decoder.Decode(&tests)
		require.NoError(t, err)

		for _, test := range tests {
			t.Run(test.Image, func(t *testing.T) {
				t.Parallel()

				var opts []stereoscope.Option
				if test.Platform != "" {
					opts = append(opts, stereoscope.WithPlatform(test.Platform))
				}
				img, err := stereoscope.GetImage(context.TODO(), test.Image, opts...)
				require.NoError(t, err)
				defer func() {
					require.NoError(t, img.Cleanup())
				}()

				s := stereoscopesource.New(img, stereoscopesource.ImageConfig{})

				resolver, err := s.FileResolver(source.SquashedScope)
				require.NoError(t, err)

				pkgs, _, err := cataloger.Catalog(ctx, resolver)
				require.NoError(t, err)

				require.Len(t, pkgs, 1)
				e := test.Expect
				p := pkgs[0]
				if e.Name != "" {
					require.Equal(t, e.Name, p.Name)
				}
				if e.Version != "" {
					require.Equal(t, e.Version, p.Version)
				}
			})
		}
	})
}
