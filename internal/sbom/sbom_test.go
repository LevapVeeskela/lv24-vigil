package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/version"
)

const (
	fixturePackageLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture-app",
      "dependencies": {"lodash": "^4.17.20"},
      "devDependencies": {"jest": "^29.0.0"}
    },
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/@scope/pkg": {"version": "1.0.0"},
    "node_modules/jest": {"version": "29.5.0", "dev": true}
  }
}`
	fixtureRequirements = "requests==2.31.0\nurllib3==2.0.7\n"
	fixtureGoMod        = "module example.com/fixture\n\ngo 1.22\n\nrequire github.com/stretchr/testify v1.9.0\n"
)

// fixturePURLs is the purl each fixture package must carry.
var fixturePURLs = map[string]string{
	"@scope/pkg":                  "pkg:npm/%40scope/pkg@1.0.0",
	"github.com/stretchr/testify": "pkg:golang/github.com/stretchr/testify@v1.9.0",
	"jest":                        "pkg:npm/jest@29.5.0",
	"lodash":                      "pkg:npm/lodash@4.17.21",
	"requests":                    "pkg:pypi/requests@2.31.0",
	"urllib3":                     "pkg:pypi/urllib3@2.0.7",
}

// fixtureOrder is the inventory sorted by name then version.
var fixtureOrder = []string{
	"@scope/pkg",
	"github.com/stretchr/testify",
	"jest",
	"lodash",
	"requests",
	"urllib3",
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func fixtureTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"package-lock.json": fixturePackageLock,
		"requirements.txt":  fixtureRequirements,
		"go.mod":            fixtureGoMod,
	})
}

func buildDoc(t *testing.T, dir string, includeDev bool) *Document {
	t.Helper()
	doc, err := Build(context.Background(), dir, includeDev)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return doc
}

func mustRender(t *testing.T, doc *Document, format Format) []byte {
	t.Helper()
	out, err := doc.Render(format)
	if err != nil {
		t.Fatalf("Render(%s): %v", format, err)
	}
	return out
}

func indexByName(pkgs []Package) map[string]Package {
	out := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		out[p.Name] = p
	}
	return out
}

func TestBuildFixturePackages(t *testing.T) {
	doc := buildDoc(t, fixtureTree(t), true)

	if doc.Name != DefaultDocumentName {
		t.Errorf("Name = %q, want %q", doc.Name, DefaultDocumentName)
	}
	if doc.Tool != ToolName {
		t.Errorf("Tool = %q, want %q", doc.Tool, ToolName)
	}
	if doc.ToolVersion != version.Version {
		t.Errorf("ToolVersion = %q, want %q", doc.ToolVersion, version.Version)
	}
	if len(doc.Packages) != len(fixtureOrder) {
		t.Fatalf("packages = %d, want %d", len(doc.Packages), len(fixtureOrder))
	}
	for i, want := range fixtureOrder {
		if got := doc.Packages[i].Name; got != want {
			t.Fatalf("packages[%d].Name = %q, want %q", i, got, want)
		}
	}

	idx := indexByName(doc.Packages)
	for name, purl := range fixturePURLs {
		p, ok := idx[name]
		if !ok {
			t.Fatalf("package %q missing from document", name)
		}
		if p.PURL != purl {
			t.Errorf("%s purl = %q, want %q", name, p.PURL, purl)
		}
		if p.Ecosystem == "" || p.Version == "" {
			t.Errorf("%s lost ecosystem or version: %+v", name, p)
		}
	}
	if !idx["jest"].Dev {
		t.Error("jest must be marked as a development dependency")
	}
	if idx["lodash"].Dev {
		t.Error("lodash must be a production dependency")
	}
}

func TestBuildOmitsDevWhenNotIncluded(t *testing.T) {
	doc := buildDoc(t, fixtureTree(t), false)

	idx := indexByName(doc.Packages)
	if _, ok := idx["jest"]; ok {
		t.Fatal("jest must be omitted when includeDev is false")
	}
	if len(doc.Packages) != len(fixtureOrder)-1 {
		t.Fatalf("packages = %d, want %d", len(doc.Packages), len(fixtureOrder)-1)
	}
	for _, p := range doc.Packages {
		if p.Dev {
			t.Errorf("package %q is marked dev although dev packages were excluded", p.Name)
		}
	}
}

func TestCycloneDXDocument(t *testing.T) {
	doc := buildDoc(t, fixtureTree(t), true)
	raw := mustRender(t, doc, FormatCycloneDXJSON)

	var out struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Tools     struct {
				Components []struct {
					Type    string `json:"type"`
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"components"`
			} `json:"tools"`
		} `json:"metadata"`
		Components []struct {
			Type       string `json:"type"`
			Name       string `json:"name"`
			Version    string `json:"version"`
			PURL       string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, raw)
	}

	if out.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q", out.BOMFormat)
	}
	if out.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", out.SpecVersion)
	}
	if out.Version != 1 {
		t.Errorf("version = %d, want 1", out.Version)
	}
	if !uuidURNPrefix.MatchString(out.SerialNumber) {
		t.Errorf("serialNumber = %q, want a content-derived UUID URN", out.SerialNumber)
	}

	if _, err := time.Parse(time.RFC3339, out.Metadata.Timestamp); err != nil {
		t.Errorf("metadata.timestamp = %q: %v", out.Metadata.Timestamp, err)
	}
	if len(out.Metadata.Tools.Components) != 1 {
		t.Fatalf("metadata.tools.components = %d, want 1", len(out.Metadata.Tools.Components))
	}
	tool := out.Metadata.Tools.Components[0]
	if tool.Name != ToolName || tool.Type != "application" {
		t.Errorf("metadata tool = %+v", tool)
	}
	if tool.Version != version.Version {
		t.Errorf("metadata tool version = %q, want %q", tool.Version, version.Version)
	}

	if len(out.Components) != len(fixtureOrder) {
		t.Fatalf("components = %d, want %d", len(out.Components), len(fixtureOrder))
	}
	for i, comp := range out.Components {
		if comp.Name != fixtureOrder[i] {
			t.Errorf("components[%d].Name = %q, want %q", i, comp.Name, fixtureOrder[i])
		}
		if comp.Type != "library" {
			t.Errorf("%s type = %q, want library", comp.Name, comp.Type)
		}
		if want := fixturePURLs[comp.Name]; comp.PURL != want {
			t.Errorf("%s purl = %q, want %q", comp.Name, comp.PURL, want)
		}
		if len(comp.Properties) != 1 {
			t.Errorf("%s properties = %d, want 1 scope property", comp.Name, len(comp.Properties))
			continue
		}
		wantScope := scopeProduction
		if comp.Name == "jest" {
			wantScope = scopeDevelopment
		}
		if comp.Properties[0].Name != dependencyScopeProperty || comp.Properties[0].Value != wantScope {
			t.Errorf("%s scope property = %+v, want %q", comp.Name, comp.Properties[0], wantScope)
		}
	}
}

func TestSPDXDocument(t *testing.T) {
	doc := buildDoc(t, fixtureTree(t), true)
	raw := mustRender(t, doc, FormatSPDXJSON)

	var out struct {
		SPDXID       string `json:"SPDXID"`
		SPDXVersion  string `json:"spdxVersion"`
		Name         string `json:"name"`
		DataLicense  string `json:"dataLicense"`
		Namespace    string `json:"documentNamespace"`
		CreationInfo struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			SPDXID           string `json:"SPDXID"`
			Name             string `json:"name"`
			VersionInfo      string `json:"versionInfo"`
			DownloadLocation string `json:"downloadLocation"`
			FilesAnalyzed    bool   `json:"filesAnalyzed"`
			LicenseConcluded string `json:"licenseConcluded"`
			ExternalRefs     []struct {
				Category string `json:"referenceCategory"`
				Type     string `json:"referenceType"`
				Locator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, raw)
	}

	if out.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want SPDX-2.3", out.SPDXVersion)
	}
	if out.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q", out.SPDXID)
	}
	if out.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q", out.DataLicense)
	}
	if out.Name != DefaultDocumentName {
		t.Errorf("name = %q, want %q", out.Name, DefaultDocumentName)
	}
	if !spdxNamespace.MatchString(out.Namespace) {
		t.Errorf("documentNamespace = %q, want a stable https URL ending in a content hash", out.Namespace)
	}
	if _, err := time.Parse(time.RFC3339, out.CreationInfo.Created); err != nil {
		t.Errorf("creationInfo.created = %q: %v", out.CreationInfo.Created, err)
	}
	wantCreator := "Tool: " + ToolName + "-" + version.Version
	if len(out.CreationInfo.Creators) != 1 || out.CreationInfo.Creators[0] != wantCreator {
		t.Errorf("creationInfo.creators = %v, want %q", out.CreationInfo.Creators, wantCreator)
	}

	if len(out.Packages) != len(fixtureOrder) {
		t.Fatalf("packages = %d, want %d", len(out.Packages), len(fixtureOrder))
	}
	for i, pkg := range out.Packages {
		if want := "SPDXRef-Package-" + strconv.Itoa(i+1); pkg.SPDXID != want {
			t.Errorf("packages[%d].SPDXID = %q, want %q", i, pkg.SPDXID, want)
		}
		if pkg.Name != fixtureOrder[i] {
			t.Errorf("packages[%d].Name = %q, want %q", i, pkg.Name, fixtureOrder[i])
		}
		if pkg.DownloadLocation != "NOASSERTION" || pkg.LicenseConcluded != "NOASSERTION" {
			t.Errorf("%s download/license = %q/%q, want NOASSERTION", pkg.Name, pkg.DownloadLocation, pkg.LicenseConcluded)
		}
		if pkg.FilesAnalyzed {
			t.Errorf("%s filesAnalyzed = true, want false", pkg.Name)
		}
		if len(pkg.ExternalRefs) != 1 {
			t.Errorf("%s externalRefs = %d, want 1", pkg.Name, len(pkg.ExternalRefs))
			continue
		}
		ref := pkg.ExternalRefs[0]
		if ref.Category != "PACKAGE-MANAGER" || ref.Type != "purl" || ref.Locator != fixturePURLs[pkg.Name] {
			t.Errorf("%s external ref = %+v", pkg.Name, ref)
		}
	}
}

func TestRenderIsByteIdenticalAcrossRuns(t *testing.T) {
	dir := fixtureTree(t)
	formats := []Format{FormatCycloneDXJSON, FormatSPDXJSON}

	for _, format := range formats {
		first := mustRender(t, buildDoc(t, dir, true), format)
		second := mustRender(t, buildDoc(t, dir, true), format)
		if string(first) != string(second) {
			t.Fatalf("%s output differs between two builds of the same tree", format)
		}

		doc := buildDoc(t, dir, true)
		if a, b := mustRender(t, doc, format), mustRender(t, doc, format); string(a) != string(b) {
			t.Fatalf("%s output differs between two renders of the same document", format)
		}
		if !strings.HasSuffix(string(first), "\n") {
			t.Errorf("%s output has no trailing newline", format)
		}
	}
}

func TestIdentifiersAreContentAddressed(t *testing.T) {
	files := map[string]string{
		"package-lock.json": fixturePackageLock,
		"requirements.txt":  fixtureRequirements,
		"go.mod":            fixtureGoMod,
	}
	first := buildDoc(t, writeTree(t, files), true)
	second := buildDoc(t, writeTree(t, files), true)

	if a, b := first.serialNumber(), second.serialNumber(); a != b {
		t.Errorf("serial numbers differ for the same inventory: %q vs %q", a, b)
	}
	if a, b := first.documentNamespace(), second.documentNamespace(); a != b {
		t.Errorf("namespaces differ for the same inventory: %q vs %q", a, b)
	}

	changed := map[string]string{
		"package-lock.json": fixturePackageLock,
		"requirements.txt":  fixtureRequirements + "idna==3.6\n",
		"go.mod":            fixtureGoMod,
	}
	third := buildDoc(t, writeTree(t, changed), true)
	if first.serialNumber() == third.serialNumber() {
		t.Error("serial number did not change with the inventory")
	}
	if first.documentNamespace() == third.documentNamespace() {
		t.Error("document namespace did not change with the inventory")
	}
}

func TestEmptyTreeProducesValidDocuments(t *testing.T) {
	dir := t.TempDir()

	for _, format := range []Format{FormatCycloneDXJSON, FormatSPDXJSON} {
		doc := buildDoc(t, dir, true)
		if len(doc.Packages) != 0 {
			t.Fatalf("%s: packages = %d, want 0", format, len(doc.Packages))
		}
		raw := mustRender(t, doc, format)

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("%s: json.Unmarshal: %v\n%s", format, err, raw)
		}
		switch format {
		case FormatCycloneDXJSON:
			if got := strings.TrimSpace(string(fields["components"])); got != "[]" {
				t.Errorf("components = %s, want []", got)
			}
			var serial string
			if err := json.Unmarshal(fields["serialNumber"], &serial); err != nil {
				t.Fatalf("serialNumber: %v", err)
			}
			if !uuidURNPrefix.MatchString(serial) {
				t.Errorf("serialNumber = %q", serial)
			}
		case FormatSPDXJSON:
			if got := strings.TrimSpace(string(fields["packages"])); got != "[]" {
				t.Errorf("packages = %s, want []", got)
			}
		}
	}
}

func TestUnmappedEcosystemHasNoPURL(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pubspec.lock": `packages:
  vector_math:
    dependency: "direct main"
    description:
      name: vector_math
      url: "https://pub.dev"
    source: hosted
    version: "2.1.4"
`,
	})
	doc := buildDoc(t, dir, true)
	if len(doc.Packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(doc.Packages))
	}
	if doc.Packages[0].PURL != "" {
		t.Errorf("purl = %q, want none for Pub", doc.Packages[0].PURL)
	}

	var cdx struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(mustRender(t, doc, FormatCycloneDXJSON), &cdx); err != nil {
		t.Fatal(err)
	}
	if cdx.Components[0].PURL != "" {
		t.Errorf("CycloneDX purl = %q, want omitted", cdx.Components[0].PURL)
	}

	var spdx struct {
		Packages []struct {
			ExternalRefs []struct{} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(mustRender(t, doc, FormatSPDXJSON), &spdx); err != nil {
		t.Fatal(err)
	}
	if len(spdx.Packages[0].ExternalRefs) != 0 {
		t.Errorf("SPDX externalRefs = %d, want 0", len(spdx.Packages[0].ExternalRefs))
	}
}

func TestOutputContainsNoFilesystemPaths(t *testing.T) {
	dir := fixtureTree(t)
	doc := buildDoc(t, dir, true)

	escaped, err := json.Marshal(dir)
	if err != nil {
		t.Fatalf("json.Marshal(dir): %v", err)
	}
	leaks := []string{
		dir,
		filepath.ToSlash(dir),
		string(escaped[1 : len(escaped)-1]),
	}
	for _, format := range []Format{FormatCycloneDXJSON, FormatSPDXJSON} {
		out := string(mustRender(t, doc, format))
		for _, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Errorf("%s output leaks the scan root %q", format, leak)
			}
		}
	}
}

func TestRenderRejectsUnsupportedFormat(t *testing.T) {
	doc := buildDoc(t, t.TempDir(), true)
	if !FormatCycloneDXJSON.Valid() || !FormatSPDXJSON.Valid() || Format("kotlinx").Valid() {
		t.Fatal("Format.Valid returned the wrong result")
	}
	if _, err := doc.Render(Format("kotlinx")); err == nil {
		t.Fatal("Render accepted an unsupported format")
	}
	var nilDoc *Document
	if _, err := nilDoc.Render(FormatSPDXJSON); err == nil {
		t.Fatal("Render accepted a nil document")
	}
}

func TestBuildHonoursCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, fixtureTree(t), true); err == nil {
		t.Fatal("Build ignored a canceled context")
	}
}

func TestPURLMapping(t *testing.T) {
	cases := []struct {
		ecosystem string
		name      string
		version   string
		want      string
	}{
		{"npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{"npm", "@scope/pkg", "1.0.0", "pkg:npm/%40scope/pkg@1.0.0"},
		{"npm", "build-meta", "1.0.0+build.5", "pkg:npm/build-meta@1.0.0%2Bbuild.5"},
		{"PyPI", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
		{"PyPI", "Flask", "3.0.0", "pkg:pypi/flask@3.0.0"},
		{"PyPI", "zope.interface", "6.1", "pkg:pypi/zope-interface@6.1"},
		{"Go", "github.com/x/mod", "v0.20.0", "pkg:golang/github.com/x/mod@v0.20.0"},
		{"crates.io", "serde", "1.0.196", "pkg:cargo/serde@1.0.196"},
		{"RubyGems", "rails", "7.1.3", "pkg:gem/rails@7.1.3"},
		{"Maven", "org.slf4j:slf4j-api", "2.0.11", "pkg:maven/org.slf4j/slf4j-api@2.0.11"},
		{"Packagist", "monolog/monolog", "3.5.0", "pkg:composer/monolog/monolog@3.5.0"},
		{"NuGet", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{"Maven", "no-artifact", "1.0.0", ""},
		{"Pub", "vector_math", "2.1.4", ""},
		{"unknown", "thing", "1.0.0", ""},
		{"npm", "", "1.0.0", ""},
		{"npm", "thing", "", ""},
	}
	for _, tc := range cases {
		if got := purlFor(tc.ecosystem, tc.name, tc.version); got != tc.want {
			t.Errorf("purlFor(%q, %q, %q) = %q, want %q", tc.ecosystem, tc.name, tc.version, got, tc.want)
		}
	}
}

func TestBuildHonoursExcludes(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"app/package-lock.json":     fixturePackageLock,
		"ideas/x/package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/left-pad":{"version":"1.3.0"}}}`,
	})

	whole := buildDoc(t, dir, true)
	if _, ok := indexByName(whole.Packages)["left-pad"]; !ok {
		t.Fatalf("without excludes the research clone must be inventoried: %v", whole.Packages)
	}

	doc, err := Build(context.Background(), dir, true, WithExcludes([]string{"ideas/**"}))
	if err != nil {
		t.Fatalf("Build with excludes: %v", err)
	}
	idx := indexByName(doc.Packages)
	if _, ok := idx["left-pad"]; ok {
		t.Error("WithExcludes(ideas/**) still inventoried the research clone")
	}
	if len(doc.Packages) != 3 {
		t.Fatalf("packages = %d, want the 3 app packages: %v", len(doc.Packages), doc.Packages)
	}
	for _, name := range []string{"@scope/pkg", "jest", "lodash"} {
		if _, ok := idx[name]; !ok {
			t.Errorf("app package %q is missing after excluding ideas/**", name)
		}
	}
	if len(doc.Warnings) != 0 {
		t.Errorf("warnings = %v, want none for a clean tree", doc.Warnings)
	}

	var cdx struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(mustRender(t, doc, FormatCycloneDXJSON), &cdx); err != nil {
		t.Fatal(err)
	}
	if len(cdx.Metadata.Properties) != 0 {
		t.Errorf("metadata.properties = %+v, want none without warnings", cdx.Metadata.Properties)
	}
	var spdx struct {
		DocumentComment string `json:"documentComment"`
	}
	if err := json.Unmarshal(mustRender(t, doc, FormatSPDXJSON), &spdx); err != nil {
		t.Fatal(err)
	}
	if spdx.DocumentComment != "" {
		t.Errorf("documentComment = %q, want none without warnings", spdx.DocumentComment)
	}
}

func TestBuildTruncationWarningIsRendered(t *testing.T) {
	dir := writeTree(t, map[string]string{"package-lock.json": npmLockWithPackages(201)})

	doc := buildDoc(t, dir, true)
	if len(doc.Packages) != maxPackages {
		t.Fatalf("packages = %d, want the %d cap", len(doc.Packages), maxPackages)
	}
	joined := strings.Join(doc.Warnings, "\n")
	for _, want := range []string{"inventory truncated", strconv.Itoa(maxPackages) + " package cap", "found 201 packages"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}

	var cdx struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(mustRender(t, doc, FormatCycloneDXJSON), &cdx); err != nil {
		t.Fatal(err)
	}
	if len(cdx.Metadata.Properties) != len(doc.Warnings) {
		t.Fatalf("metadata.properties = %d, want %d", len(cdx.Metadata.Properties), len(doc.Warnings))
	}
	for _, prop := range cdx.Metadata.Properties {
		if prop.Name != warningProperty || !strings.Contains(prop.Value, "inventory truncated") {
			t.Errorf("warning property = %+v", prop)
		}
	}

	var spdx struct {
		DocumentComment string `json:"documentComment"`
	}
	if err := json.Unmarshal(mustRender(t, doc, FormatSPDXJSON), &spdx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spdx.DocumentComment, "inventory truncated") {
		t.Errorf("documentComment = %q, want the truncation warning", spdx.DocumentComment)
	}
}

// npmLockWithPackages returns a package-lock.json with n pinned dependencies, so
// a test can cross the inventory cap.
func npmLockWithPackages(n int) string {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{}`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `,"node_modules/pkg-%03d":{"version":"1.0.%d"}`, i, i)
	}
	b.WriteString("}}")
	return b.String()
}

var (
	uuidURNPrefix = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	spdxNamespace = regexp.MustCompile(`^https://[^ \t]+/sbom/[0-9a-f]{64}$`)
)
