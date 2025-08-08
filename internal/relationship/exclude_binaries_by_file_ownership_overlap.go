package relationship

import (
	"reflect"
	"slices"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/sbom"
)

var (
	osCatalogerTypes = []pkg.Type{
		pkg.AlpmPkg,
		pkg.ApkPkg,
		pkg.DebPkg,
		pkg.NixPkg,
		pkg.PortagePkg,
		pkg.RpmPkg,
	}
	binaryCatalogerTypes = []pkg.Type{
		pkg.BinaryPkg,
	}
	bitnamiCatalogerTypes = []pkg.Type{
		pkg.BitnamiPkg,
	}
	binaryMetadataTypes = []string{
		reflect.TypeOf(pkg.ELFBinaryPackageNoteJSONPayload{}).Name(),
		reflect.TypeOf(pkg.BinarySignature{}).Name(),
		reflect.TypeOf(pkg.JavaVMInstallation{}).Name(),
	}
)

func ExcludeBinariesByFileOwnershipOverlap(accessor sbomsync.Accessor) {
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		for _, r := range s.Relationships {
			if idToRemove := excludeByFileOwnershipOverlap(r, s.Artifacts.Packages); idToRemove != "" {
				s.Artifacts.Packages.Delete(idToRemove)
				s.Relationships = RemoveRelationshipsByID(s.Relationships, idToRemove)
			}
		}
	})
}

func ReplaceUnknownVersionsWithKnownBinaryVersions(accessor sbomsync.Accessor) {
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		classifierName := binary.NewClassifierCataloger(binary.ClassifierCatalogerConfig{}).Name()
		for _, p := range s.Artifacts.Packages.Sorted() { // use Sorted to get a copy
			if p.FoundBy != classifierName && isUnknownVersion(p.Version) {
				for _, matching := range s.Artifacts.Packages.PackagesByName(p.Name) {
					if matching.FoundBy == classifierName && matching.Type == p.Type && !isUnknownVersion(matching.Version) {
						// update the matching versionless package
						p.Version = matching.Version
						s.Artifacts.Packages.Delete(p.ID())
						s.Artifacts.Packages.Add(p)

						// remove the  binary package
						id := matching.ID()
						s.Artifacts.Packages.Delete(id)
						s.Relationships = RemoveRelationshipsByID(s.Relationships, id)
						break
					}
				}
			}
		}
	})
}

// excludeByFileOwnershipOverlap will remove packages that should be overridden by a more authoritative package,
// such as an OS package or a package from a cataloger with more specific information being raised up.
func excludeByFileOwnershipOverlap(r artifact.Relationship, c *pkg.Collection) artifact.ID {
	if artifact.OwnershipByFileOverlapRelationship != r.Type {
		return ""
	}

	parent := c.Package(r.From.ID())
	if parent == nil {
		return ""
	}

	child := c.Package(r.To.ID())
	if child == nil {
		return ""
	}

	if idToRemove := identifyOverlappingOSRelationship(parent, child); idToRemove != "" {
		return idToRemove
	}

	if idToRemove := identifyOverlappingJVMRelationship(parent, child); idToRemove != "" {
		return idToRemove
	}

	if idToRemove := identifyOverlappingBitnamiRelationship(parent, child); idToRemove != "" {
		return idToRemove
	}

	return ""
}

// identifyOverlappingJVMRelationship indicates the package to remove if this is a binary -> binary pkg relationship
// with a java binary signature package and a more authoritative JVM release package.
func identifyOverlappingJVMRelationship(parent *pkg.Package, child *pkg.Package) artifact.ID {
	if !slices.Contains(binaryCatalogerTypes, parent.Type) {
		return ""
	}

	if !slices.Contains(binaryCatalogerTypes, child.Type) {
		return ""
	}

	if child.Metadata == nil {
		return ""
	}

	var (
		foundJVM   bool
		idToRemove artifact.ID
	)
	for _, p := range []*pkg.Package{parent, child} {
		switch p.Metadata.(type) {
		case pkg.JavaVMInstallation:
			foundJVM = true
		default:
			idToRemove = p.ID()
		}
	}

	if foundJVM {
		return idToRemove
	}

	return ""
}

// identifyOverlappingOSRelationship indicates the package ID to remove if this is an OS pkg -> bin pkg relationship.
// This was implemented as a way to help resolve: https://github.com/anchore/syft/issues/931
func identifyOverlappingOSRelationship(parent *pkg.Package, child *pkg.Package) artifact.ID {
	if !slices.Contains(osCatalogerTypes, parent.Type) {
		return ""
	}

	if slices.Contains(binaryCatalogerTypes, child.Type) {
		return child.ID()
	}

	if child.Metadata == nil {
		return ""
	}

	if !slices.Contains(binaryMetadataTypes, reflect.TypeOf(child.Metadata).Name()) {
		return ""
	}

	return child.ID()
}

// identifyOverlappingBitnamiRelationship indicates the package ID to remove if this is a Bitnami pkg -> bin pkg relationship.
func identifyOverlappingBitnamiRelationship(parent *pkg.Package, child *pkg.Package) artifact.ID {
	if !slices.Contains(bitnamiCatalogerTypes, parent.Type) {
		return ""
	}

	if slices.Contains(binaryCatalogerTypes, child.Type) {
		return child.ID()
	}

	if child.Metadata == nil {
		return ""
	}

	if !slices.Contains(binaryMetadataTypes, reflect.TypeOf(child.Metadata).Name()) {
		return ""
	}

	return child.ID()
}

func isUnknownVersion(version string) bool {
	return version == "" || version == cataloging.UnknownStubValue
}
