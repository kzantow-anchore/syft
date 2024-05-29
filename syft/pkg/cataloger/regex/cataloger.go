package regex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/anchore/go-collections"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func NewCatalogersFromDirs(fsys fs.FS) []collections.TaggedValue[pkg.Cataloger] {
	return catalogersFromDir(fsys, ".")
}

func catalogersFromDir(fsys fs.FS, dirPath string) []collections.TaggedValue[pkg.Cataloger] {
	var out []collections.TaggedValue[pkg.Cataloger]
	_ = fs.WalkDir(fsys, dirPath, func(filePath string, d fs.DirEntry, err error) error {
		if filePath == dirPath {
			return nil // skip the directory entry itself
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			cataloger := catalogerFromDir(fsys, filePath)
			if cataloger != nil {
				out = append(out, collections.NewTaggedValue(cataloger, "image", "installed", "directory", "dynamic", filePath))
			}
		}
		return nil
	})
	return out
}

func catalogerFromDir(fsys fs.FS, dirPath string) pkg.Cataloger {
	subdir, err := fs.Sub(fsys, dirPath)
	if err != nil {
		return nil
	}
	rules, err := ReadAllRules(subdir.(fs.ReadDirFS))
	if err != nil {
		panic(err)
	}
	if len(rules) == 0 {
		return nil
	}
	return NewCataloger(dirPath, rules...)
}

func NewCataloger(name string, rules ...Rule) pkg.Cataloger {
	return &Cataloger{
		name:    name,
		matcher: makeMatchers(rules),
	}
}

type Cataloger struct {
	name    string
	matcher []matcher
}

func (r *Cataloger) WithRules(rules ...Rule) *Cataloger {
	r.matcher = append(r.matcher, makeMatchers(rules)...)
	return r
}

func (r *Cataloger) Name() string {
	return r.name
}

func (r *Cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var errs error
	var pkgs []pkg.Package
	for _, m := range r.matcher {
		locations, err := resolver.FilesByGlob(m.FileGlob)
		if err != nil {
			errs = appendErrs(errs, err)
			continue
		}
		for _, loc := range locations {
			matcherPkgs, err := r.scanLocation(ctx, resolver, loc, m)
			if err != nil {
				errs = appendErrs(errs, err)
				continue
			}
			pkgs = append(pkgs, matcherPkgs...)
		}
	}
	return pkgs, nil, errs
}

func (r *Cataloger) scanLocation(_ context.Context, resolver file.Resolver, loc file.Location, m matcher) ([]pkg.Package, error) {
	rdr, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(rdr, loc.RealPath)

	contents, err := io.ReadAll(rdr)
	if err != nil {
		return nil, err
	}

	matched := m.Extractor(contents)
	if matched != nil {
		name := execTemplate(m.Package.Name, matched)
		version := execTemplate(m.Package.Version, matched)
		purl := execTemplate(m.Package.PURL, matched)
		if purl != "" {
			p, err := packageurl.FromString(purl)
			if err == nil {
				p.Version = version
				purl = p.String()
			}
		}
		var cpes []cpe.CPE
		for _, cpeTemplate := range m.Package.CPEs {
			cpeTemplate = execTemplate(cpeTemplate, matched)
			c, err := cpe.New(cpeTemplate, cpe.DeclaredSource)
			if err == nil {
				c.Attributes.Version = version
				cpes = append(cpes, c)
			}
		}
		p := pkg.Package{
			Name:    name,
			Version: version,
			Type:    pkg.Type(r.name), // FIXME ??
			FoundBy: r.name,
			Metadata: pkg.BinarySignature{
				Matches: []pkg.ClassifierMatch{
					{
						Classifier: m.Class,
						Location:   loc,
					},
				},
			},
			Locations: file.NewLocationSet(loc),
			Licenses:  toSyftLicenses(m.Package.License),
			PURL:      purl,
			CPEs:      cpes,
		}
		p.SetID()

		return []pkg.Package{p}, nil
	}

	// TODO known unknown
	return nil, nil
}

func appendErrs(err error, errs ...error) error {
	if len(errs) == 0 {
		return err
	}
	// note: errors.Join handles eliminating nil errors
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		return errors.Join(append(joined.Unwrap(), errs...)...)
	}
	if err != nil {
		return errors.Join(append([]error{err}, errs...)...)
	}
	return errors.Join(errs...)
}

type contentExtractor func(contents []byte) map[string]string

type matcher struct {
	Class     string
	FileGlob  string
	Extractor contentExtractor
	Package   PackageTemplate
}

func makeMatchers(rules []Rule) []matcher {
	var out []matcher
	for _, r := range rules {
		out = append(out, matcher{
			Class:     r.Class,
			FileGlob:  r.FileGlob,
			Extractor: makeExtractor(r.Extractor),
			Package:   r.Package,
		})
	}
	return out
}

func makeExtractor(matcher map[string]any) contentExtractor {
	for k, v := range matcher {
		switch k {
		case regexGroupExtractorKey:
			v, ok := v.(string)
			if !ok {
				panic(fmt.Errorf("invalid value for %s: %v", regexGroupExtractorKey, v))
			}
			return regexGroupExtractor(v)
		case extractAllKey:
			var args []contentExtractor
			switch v := v.(type) {
			case map[string]any:
				args = append(args, makeExtractor(v))
			case []any:
				for _, e := range v {
					if e, ok := e.(map[string]any); ok {
						args = append(args, makeExtractor(e))
					} else {
						panic(fmt.Errorf("invalid value for %s: %v", extractAllKey, v))
					}
				}
			default:
				panic(fmt.Errorf("invalid value for %s: %v", extractAllKey, v))
			}
			return extractAll(args...)
		default:
			panic(fmt.Errorf("invalid extractor: %s", k))
		}
	}
	return nil
}

func toSyftLicenses(license string) pkg.LicenseSet {
	if license != "" {
		return pkg.NewLicenseSet(pkg.NewLicense(license))
	}
	return pkg.LicenseSet{}
}
