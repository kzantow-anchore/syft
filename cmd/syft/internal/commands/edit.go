package commands

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	editExample = `  {{.appName}} {{.command}} img.syft.json --root pkg:apk/alpine/busybox@1.36 -o syft-json                         extract a root package and output as syft-json
  {{.appName}} {{.command}} img.syft.json --root pkg:apk/alpine/busybox@1.36 --relationships from:dependency-of -o syft-json   extract root with its dependencies
  {{.appName}} {{.command}} - --root <purl-or-id> -o syft-json                                                   read SBOM from stdin
`
)

type EditOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	Root                string   `yaml:"root" mapstructure:"root"`
	Relationships       []string `yaml:"relationships" mapstructure:"relationships"`
}

func (o *EditOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Root, "root", "", "purl or artifact ID of the root package to extract")
	flags.StringArrayVarP(&o.Relationships, "relationships", "", "relationship filter specs: [from:|to:]<relationship-type> (repeatable)")
}

func Edit(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &EditOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		Output:      options.DefaultOutput(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "edit [SOURCE-SBOM] --root [PURL-OR-ID] -o [FORMAT]",
		Short: "Extract a subset of an SBOM rooted at a specific package",
		Long:  "[Experimental] Select a root package from an existing SBOM and produce a focused subset containing only the root and related packages filtered by relationship type and direction.",
		Example: internal.Tprintf(editExample, map[string]interface{}{
			"appName": id.Name,
			"command": "edit",
		}),
		Args:    validateEditArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(_ *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return runEdit(opts, args[0])
		},
	}, opts)
}

func validateEditArgs(cmd *cobra.Command, args []string) error {
	return validateArgs(cmd, args, "an SBOM argument is required")
}

type relFilter struct {
	direction string // "from", "to", or "" (either)
	relType   artifact.RelationshipType
}

func parseRelFilter(spec string) (relFilter, error) {
	var direction string
	rest := spec

	if strings.HasPrefix(spec, "from:") {
		direction = "from"
		rest = strings.TrimPrefix(spec, "from:")
	} else if strings.HasPrefix(spec, "to:") {
		direction = "to"
		rest = strings.TrimPrefix(spec, "to:")
	}

	if rest == "" {
		return relFilter{}, fmt.Errorf("invalid relationship spec %q: missing relationship type", spec)
	}

	return relFilter{
		direction: direction,
		relType:   artifact.RelationshipType(rest),
	}, nil
}

func runEdit(opts *EditOptions, userInput string) error {
	writer, err := opts.SBOMWriter()
	if err != nil {
		return err
	}

	if opts.Root == "" {
		return fmt.Errorf("--root is required")
	}

	// parse relationship filters
	var filters []relFilter
	for _, spec := range opts.Relationships {
		f, err := parseRelFilter(spec)
		if err != nil {
			return err
		}
		filters = append(filters, f)
	}

	// read the SBOM
	var reader io.ReadSeekCloser
	if userInput == "-" {
		reader = internal.NewBufferedSeeker(os.Stdin)
	} else {
		f, err := os.Open(userInput)
		if err != nil {
			return fmt.Errorf("failed to open SBOM file: %w", err)
		}
		defer func() {
			_ = f.Close()
		}()
		reader = f
	}

	s, _, _, err := format.Decode(reader)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}
	if s == nil {
		return fmt.Errorf("no SBOM produced")
	}

	// find the root package
	var rootPkg *pkg.Package
	for _, p := range s.Artifacts.Packages.Sorted() {
		if string(p.ID()) == opts.Root || p.PURL == opts.Root {
			rootPkg = &p
			break
		}
	}
	if rootPkg == nil {
		return fmt.Errorf("root package not found: %s", opts.Root)
	}

	rootID := rootPkg.ID()

	// collect related packages and matching relationships
	includedIDs := map[artifact.ID]struct{}{rootID: {}}
	var matchedRelationships []artifact.Relationship

	for _, rel := range s.Relationships {
		for _, f := range filters {
			if rel.Type != f.relType {
				continue
			}

			fromID := rel.From.ID()
			toID := rel.To.ID()

			switch f.direction {
			case "from":
				if fromID == rootID {
					includedIDs[toID] = struct{}{}
					matchedRelationships = append(matchedRelationships, rel)
				}
			case "to":
				if toID == rootID {
					includedIDs[fromID] = struct{}{}
					matchedRelationships = append(matchedRelationships, rel)
				}
			default:
				if fromID == rootID {
					includedIDs[toID] = struct{}{}
					matchedRelationships = append(matchedRelationships, rel)
				} else if toID == rootID {
					includedIDs[fromID] = struct{}{}
					matchedRelationships = append(matchedRelationships, rel)
				}
			}
		}
	}

	// build output package collection
	newPkgs := pkg.NewCollection()
	for _, p := range s.Artifacts.Packages.Sorted() {
		if _, ok := includedIDs[p.ID()]; ok {
			newPkgs.Add(p)
		}
	}

	// build the output SBOM
	out := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          newPkgs,
			LinuxDistribution: s.Artifacts.LinuxDistribution,
			FileMetadata:      s.Artifacts.FileMetadata,
			FileDigests:       s.Artifacts.FileDigests,
			FileContents:      s.Artifacts.FileContents,
			FileLicenses:      s.Artifacts.FileLicenses,
			Executables:       s.Artifacts.Executables,
			Unknowns:          s.Artifacts.Unknowns,
		},
		Relationships: matchedRelationships,
		Source: source.Description{
			Name:       rootPkg.Name,
			Version:    rootPkg.Version,
			ArtifactID: rootID,
			Metadata:   source.EditMetadata{OriginalSource: s.Source},
		},
		Descriptor: sbom.Descriptor{
			Name:       s.Descriptor.Name,
			Version:    s.Descriptor.Version,
			ArtifactID: rootID,
		},
	}

	if err := writer.Write(out); err != nil {
		return fmt.Errorf("failed to write SBOM: %w", err)
	}

	return nil
}
