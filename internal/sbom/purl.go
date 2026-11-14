package sbom

import "strings"

// Ecosystems are the OSV identifiers used by internal/osv. They are repeated
// here because the originals are unexported.
const (
	ecosystemNPM       = "npm"
	ecosystemPyPI      = "PyPI"
	ecosystemGo        = "Go"
	ecosystemCrates    = "crates.io"
	ecosystemRubyGems  = "RubyGems"
	ecosystemMaven     = "Maven"
	ecosystemPackagist = "Packagist"
	ecosystemNuGet     = "NuGet"
)

// purl types as defined by the package URL specification.
const (
	purlTypeNPM      = "npm"
	purlTypePyPI     = "pypi"
	purlTypeGolang   = "golang"
	purlTypeCargo    = "cargo"
	purlTypeGem      = "gem"
	purlTypeMaven    = "maven"
	purlTypeComposer = "composer"
	purlTypeNuGet    = "nuget"
)

// purlFor maps an ecosystem coordinate to a package URL, or "" when the
// ecosystem has no mapping. Pub packages have no purl here, so they are exported
// without one instead of with a guessed type.
func purlFor(ecosystem, name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return ""
	}
	switch ecosystem {
	case ecosystemNPM:
		return purl(purlTypeNPM, encodePURLPath(name), version)
	case ecosystemPyPI:
		// The purl pypi type requires PEP 503 normalisation. Most manifests are
		// already normalised, but lockfiles may carry the published casing.
		return purl(purlTypePyPI, encodePURLPath(pypiPURLName(name)), version)
	case ecosystemGo:
		return purl(purlTypeGolang, encodePURLPath(name), version)
	case ecosystemCrates:
		return purl(purlTypeCargo, encodePURLPath(name), version)
	case ecosystemRubyGems:
		return purl(purlTypeGem, encodePURLPath(name), version)
	case ecosystemMaven:
		group, artifact, ok := strings.Cut(name, ":")
		if !ok || group == "" || artifact == "" {
			return ""
		}
		return purl(purlTypeMaven, encodePURLPath(group)+"/"+encodePURLPath(artifact), version)
	case ecosystemPackagist:
		return purl(purlTypeComposer, encodePURLPath(name), version)
	case ecosystemNuGet:
		return purl(purlTypeNuGet, encodePURLPath(name), version)
	default:
		return ""
	}
}

func purl(typ, path, version string) string {
	return "pkg:" + typ + "/" + path + "@" + encodePURLSegment(version)
}

// encodePURLPath percent-encodes each slash-separated segment of a namespace and
// name. It turns an npm scope "@scope/pkg" into "%40scope/pkg" as the purl
// specification requires, and a Maven group/artifact pair is joined with "/"
// by the caller before reaching this function.
func encodePURLPath(value string) string {
	segments := strings.Split(value, "/")
	for i, segment := range segments {
		segments[i] = encodePURLSegment(segment)
	}
	return strings.Join(segments, "/")
}

// encodePURLSegment percent-encodes everything outside the RFC 3986 unreserved
// set. Purl consumers decode it, so encoding is always safe; leaving "@" or "+"
// raw would change the meaning of the URL.
func encodePURLSegment(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isPURLUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

func isPURLUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	default:
		return false
	}
}

// pypiPURLName applies PEP 503 normalisation, which the purl pypi type requires:
// lowercase with runs of "-", "_" and "." collapsed to a single dash.
func pypiPURLName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	b.Grow(len(name))
	lastDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return b.String()
}
