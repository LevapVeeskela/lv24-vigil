// Package sbom builds a software bill of materials from the dependency
// manifests already understood by the OSV scanner and renders it as CycloneDX
// 1.6 or SPDX 2.3 JSON.
//
// Build is offline: it reuses osv.CollectPackagesWithExcludes instead of
// querying an advisory service. Rendering is reproducible: the same tree always
// produces the same bytes, including the CycloneDX serial number and the SPDX
// document namespace, which are derived from a hash of the package content
// rather than from a random UUID or the current time.
package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/osv"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

const (
	// ToolName is the producer recorded in both formats.
	ToolName = "Vigil"
	// DefaultDocumentName names the generated document. It is fixed rather than
	// derived from the scan root so the same tree scanned from a different path
	// renders identically and no filesystem path reaches the output.
	DefaultDocumentName = "vigil-sbom"
	// maxPackages bounds the inventory. It matches the OSV scanner default so an
	// SBOM never grows beyond what one scan can reasonably audit.
	maxPackages = osv.DefaultMaxPackages

	dependencyScopeProperty = "vigil:dependency:scope"
	warningProperty         = "vigil:inventory:warning"
	scopeDevelopment        = "development"
	scopeProduction         = "production"
)

// Format is a supported SBOM serialisation.
type Format string

const (
	// FormatCycloneDXJSON is CycloneDX 1.6 JSON.
	FormatCycloneDXJSON Format = "cyclonedx+json"
	// FormatSPDXJSON is SPDX 2.3 JSON.
	FormatSPDXJSON Format = "spdx+json"
)

// Valid reports whether f is a supported format.
func (f Format) Valid() bool {
	switch f {
	case FormatCycloneDXJSON, FormatSPDXJSON:
		return true
	default:
		return false
	}
}

// Package is one dependency coordinate included in a document. PURL is empty
// when the ecosystem has no purl mapping (for example Pub).
type Package struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
	Dev       bool
}

// Document is a format-neutral bill of materials. Build produces one, then
// Render serialises it.
type Document struct {
	// Name is the document name. Empty renders as DefaultDocumentName.
	Name string
	// Tool and ToolVersion identify the producing engine.
	Tool        string
	ToolVersion string
	// Created is the document timestamp. Build reads SOURCE_DATE_EPOCH and falls
	// back to the Unix epoch so output stays reproducible.
	Created time.Time
	// Packages is the inventory. Rendering orders it by name, version and
	// ecosystem regardless of the slice order.
	Packages []Package
	// Warnings lists coverage gaps found while collecting the inventory: an
	// unparseable manifest, a walk limit or a package count truncated at
	// maxPackages. They are rendered into the document so a consumer cannot
	// mistake a partial inventory for a complete one.
	Warnings []string
}

// buildOptions is the resolved Build configuration.
type buildOptions struct {
	excludes []string
}

// Option customises Build without changing existing callers.
type Option func(*buildOptions)

// WithExcludes skips dependency manifests matching any of the slash-separated
// globs. The syntax and semantics are the scanner's exclude list: "**" crosses
// directories, "*" and "?" stay within one segment, a pattern without a slash
// matches a base name at any depth and a matching directory is pruned. A nil
// list inventories the whole tree.
func WithExcludes(excludes []string) Option {
	return func(o *buildOptions) {
		o.excludes = append([]string(nil), excludes...)
	}
}

// Build walks root, collects the dependencies declared by its manifests and
// returns a document. includeDev keeps development dependencies and marks them;
// when false they are omitted. The package count is capped at maxPackages (the
// OSV scanner default) and no network access is performed.
//
// Excludes are opt-in through WithExcludes so existing callers keep the current
// whole-tree inventory. Coverage warnings, including a truncated inventory, are
// recorded on the document.
func Build(ctx context.Context, root string, includeDev bool, opts ...Option) (*Document, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var settings buildOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&settings)
		}
	}

	collected, warnings, err := osv.CollectPackagesWithExcludes(ctx, root, includeDev, maxPackages, settings.excludes)
	if err != nil {
		return nil, fmt.Errorf("sbom: collect packages: %w", err)
	}

	pkgs := make([]Package, 0, len(collected))
	for _, p := range collected {
		pkgs = append(pkgs, Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem,
			PURL:      purlFor(p.Ecosystem, p.Name, p.Version),
			Dev:       p.Dev,
		})
	}
	sortPackages(pkgs)

	return &Document{
		Name:        DefaultDocumentName,
		Tool:        ToolName,
		ToolVersion: version.Version,
		Created:     creationTime(),
		Packages:    pkgs,
		Warnings:    append([]string(nil), warnings...),
	}, nil
}

// orderedWarnings returns the coverage warnings in a stable order. Build already
// emits them deterministically, but a hand-built Document must render the same
// bytes twice.
func (d *Document) orderedWarnings() []string {
	if len(d.Warnings) == 0 {
		return nil
	}
	out := make([]string, len(d.Warnings))
	copy(out, d.Warnings)
	sort.Strings(out)
	return out
}

// Render serialises the document in the requested format. The result is stable
// for a given document: no clock, random value or map iteration reaches it.
func (d *Document) Render(format Format) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("sbom: render: nil document")
	}
	switch format {
	case FormatCycloneDXJSON:
		return d.renderCycloneDX()
	case FormatSPDXJSON:
		return d.renderSPDX()
	default:
		return nil, fmt.Errorf("sbom: unsupported format %q", string(format))
	}
}

// creationTime returns the timestamp written to both formats. SOURCE_DATE_EPOCH
// (seconds since the Unix epoch) lets a reproducible-build pipeline pin it;
// otherwise the epoch itself is used so two builds of one tree match byte for
// byte.
func creationTime() time.Time {
	raw := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH"))
	if raw != "" {
		if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Unix(secs, 0).UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

// created returns the document timestamp, defaulting to the epoch.
func (d *Document) created() time.Time {
	if d.Created.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return d.Created.UTC()
}

// timestamp renders the creation time as RFC 3339, as both specs require.
func (d *Document) timestamp() string {
	return d.created().Format(time.RFC3339)
}

func (d *Document) documentName() string {
	if strings.TrimSpace(d.Name) == "" {
		return DefaultDocumentName
	}
	return d.Name
}

func (d *Document) toolName() string {
	if strings.TrimSpace(d.Tool) == "" {
		return ToolName
	}
	return d.Tool
}

// orderedPackages returns the inventory sorted by package name, then version,
// then ecosystem. Build already sorts, but renderers sort a copy so a hand-built
// Document still produces deterministic output.
func (d *Document) orderedPackages() []Package {
	pkgs := make([]Package, len(d.Packages))
	copy(pkgs, d.Packages)
	sortPackages(pkgs)
	return pkgs
}

func sortPackages(pkgs []Package) {
	sort.SliceStable(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Ecosystem < b.Ecosystem
	})
}

// digest hashes everything the renderers emit about the inventory, excluding
// timestamps and filesystem paths, so it identifies the document rather than one
// build of it.
func (d *Document) digest() [sha256.Size]byte {
	var b strings.Builder
	writeHashField(&b, d.documentName())
	writeHashField(&b, d.toolName())
	writeHashField(&b, d.ToolVersion)
	for _, warning := range d.orderedWarnings() {
		writeHashField(&b, warning)
	}
	for _, p := range d.orderedPackages() {
		writeHashField(&b, p.Name)
		writeHashField(&b, p.Version)
		writeHashField(&b, p.Ecosystem)
		writeHashField(&b, p.PURL)
		if p.Dev {
			writeHashField(&b, scopeDevelopment)
		} else {
			writeHashField(&b, scopeProduction)
		}
	}
	return sha256.Sum256([]byte(b.String()))
}

// writeHashField writes a length-prefixed field so concatenation cannot make two
// different inventories hash alike.
func writeHashField(b *strings.Builder, value string) {
	b.WriteString(strconv.Itoa(len(value)))
	b.WriteByte(':')
	b.WriteString(value)
	b.WriteByte('\n')
}

// serialNumber returns the CycloneDX serial number. The payload is a UUID-shaped
// (version 5 layout) rendering of the content hash: deterministic, unique per
// inventory and never random.
func (d *Document) serialNumber() string {
	sum := d.digest()
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = u[6]&0x0f | 0x50 // version 5, name-based UUID layout
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// documentNamespace returns the SPDX document namespace: the content hash under
// the project's repository URL. Content addressing keeps the namespace unique
// without a clock or random value.
func (d *Document) documentNamespace() string {
	base := strings.TrimRight(version.BuildRepo, "/")
	base = strings.TrimPrefix(base, "https://")
	base = strings.TrimPrefix(base, "http://")
	if base == "" {
		base = "sbom.invalid/vigil"
	}
	sum := d.digest()
	return "https://" + base + "/sbom/" + hex.EncodeToString(sum[:])
}
