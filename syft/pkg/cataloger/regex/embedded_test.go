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

// You can execute a single rule or image test with something like:
//
//	go test ./syft/pkg/cataloger/regex -run //redmine/5.1.2
//
// Where the run expression is <substr>[/<substr>]* for nested tests like this.
// A full name may look like: Test_allRules/binary/fluent-bit.yaml/fluent/fluent-bit:3.0.2-amd64@sha256:7e6fe8efd...
// and an empty substring for the segment is considered a match, so you could:
// - run all tests for all rules in ruby-apps with: /ruby-apps
// - run all the redmine tests with: //redmine
// - run a single image test with: ////3.0.2 when an org/name is part of the tag or ///5.1.2 when there is no slash in the tag name
func Test_allRules(t *testing.T) {
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

		if len(tests) == 0 {
			t.Errorf("no tests run for: %s", name)
		}

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
