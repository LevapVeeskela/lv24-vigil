package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

// prepareSBOMTest keeps a developer's real ~/vigil/config.yaml out of the SBOM
// tests: config.Load resolves it through VIGIL_CONFIG.
func prepareSBOMTest(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("VIGIL_CONFIG", filepath.Join(dir, "missing-config.yaml"))
}

// writeSBOMFixture writes a fixture file, creating parent directories.
func writeSBOMFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// sbomNpmLock is a minimal package-lock.json that pins one dependency.
func sbomNpmLock(name, version string) string {
	return fmt.Sprintf(`{"lockfileVersion":3,"packages":{"":{},"node_modules/%s":{"version":"%s"}}}`, name, version)
}

// sbomLargeNpmLock returns a package-lock.json with n pinned dependencies.
func sbomLargeNpmLock(n int) string {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{}`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `,"node_modules/pkg-%03d":{"version":"1.0.%d"}`, i, i)
	}
	b.WriteString("}}")
	return b.String()
}

func TestSBOMCycloneDXDefault(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)
	writeTestFile(t, dir, "requirements.txt", "requests==2.31.0\nurllib3==2.0.7\n")

	out, stderr, err := runCLI(t, "sbom", dir)
	if err != nil {
		t.Fatalf("sbom: %v\nstderr:\n%s", err, stderr)
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("sbom is not valid JSON: %v\n%s", err, out)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" {
		t.Errorf("bom = %s %s, want CycloneDX 1.6", bom.BOMFormat, bom.SpecVersion)
	}
	if len(bom.Components) != 2 {
		t.Fatalf("components = %d, want 2\n%s", len(bom.Components), out)
	}
	if bom.Components[0].Name != "requests" || bom.Components[0].PURL != "pkg:pypi/requests@2.31.0" {
		t.Errorf("first component = %+v", bom.Components[0])
	}
}

func TestSBOMSPDXAndOutputFile(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)
	writeTestFile(t, dir, "go.mod", "module example.com/demo\n\ngo 1.22\n\nrequire github.com/stretchr/testify v1.9.0\n")
	docPath := filepath.Join(dir, "sbom.spdx.json")

	out, stderr, err := runCLI(t, "sbom", dir, "--format", "spdx", "--output", docPath)
	if err != nil {
		t.Fatalf("sbom --format spdx: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(out, "wrote "+docPath) {
		t.Errorf("missing output confirmation: %s", out)
	}
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		SPDXID      string `json:"SPDXID"`
		Packages    []struct {
			Name string `json:"name"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("spdx is not valid JSON: %v\n%s", err, data)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("spdx header = %+v", doc)
	}
	if len(doc.Packages) != 1 || doc.Packages[0].Name != "github.com/stretchr/testify" {
		t.Fatalf("packages = %+v", doc.Packages)
	}
}

func TestSBOMEmptyTreeIsValid(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)

	out, stderr, err := runCLI(t, "sbom", dir)
	if err != nil {
		t.Fatalf("sbom on an empty tree: %v\nstderr:\n%s", err, stderr)
	}
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []any  `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("empty sbom is not valid JSON: %v\n%s", err, out)
	}
	if bom.BOMFormat != "CycloneDX" || len(bom.Components) != 0 {
		t.Errorf("empty bom = %+v", bom)
	}
}

func TestSBOMIncludeDev(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)
	writeTestFile(t, dir, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture", "dependencies": {"lodash": "^4.17.20"}, "devDependencies": {"jest": "^29.0.0"}},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/jest": {"version": "29.5.0", "dev": true}
  }
}
`)

	out, stderr, err := runCLI(t, "sbom", dir)
	if err != nil {
		t.Fatalf("sbom: %v\nstderr:\n%s", err, stderr)
	}
	if strings.Contains(out, `"jest"`) {
		t.Errorf("default sbom included a dev dependency:\n%s", out)
	}

	out, stderr, err = runCLI(t, "sbom", dir, "--include-dev")
	if err != nil {
		t.Fatalf("sbom --include-dev: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(out, `"jest"`) {
		t.Errorf("--include-dev did not include jest:\n%s", out)
	}
}

func TestSBOMRejectsUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)
	if _, _, err := runCLI(t, "sbom", dir, "--format", "swid"); err == nil {
		t.Error("an unknown sbom format was accepted")
	}
}

func TestSBOMExcludesResearchClonesAndHonoursFlags(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)
	writeTestFile(t, dir, ".vigil.yaml", "scan:\n  exclude:\n    - ideas/**\n")
	writeSBOMFixture(t, dir, "ideas/x/package-lock.json", sbomNpmLock("left-pad", "1.3.0"))
	writeSBOMFixture(t, dir, "legacy/package-lock.json", sbomNpmLock("old-pkg", "0.1.0"))
	writeSBOMFixture(t, dir, "app/package-lock.json", sbomNpmLock("lodash", "4.17.21"))

	out, stderr, err := runCLI(t, "sbom", dir, "--exclude", "legacy/**")
	if err != nil {
		t.Fatalf("sbom: %v\nstderr:\n%s", err, stderr)
	}

	var bom struct {
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("sbom is not valid JSON: %v\n%s", err, out)
	}
	if len(bom.Components) != 1 || bom.Components[0].Name != "lodash" {
		t.Fatalf("components = %+v, want only the app dependency", bom.Components)
	}
	for _, gone := range []string{"left-pad", "old-pkg"} {
		if strings.Contains(out, `"`+gone+`"`) {
			t.Errorf("excluded package %q is still in the document:\n%s", gone, out)
		}
	}
}

func TestSBOMExcludesFromConfigKeepDirectoriesOnly(t *testing.T) {
	cfg := config.Config{
		Scan: config.ScanConfig{Exclude: []string{
			"ideas/**", "go.sum", "package-lock.json", "*.lock", "docs/**", "**/testdata/**", "vendor/",
		}},
		Sources: map[string]string{"scan.exclude": ".vigil.yaml"},
	}

	got := sbomExcludes(cfg, stringList{"*.lock", "legacy/**"})
	want := []string{"ideas/**", "docs/**", "**/testdata/**", "vendor/", "*.lock", "legacy/**"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sbomExcludes = %v, want %v", got, want)
	}

	// Without an explicit config list the built-in scanner defaults must not
	// become SBOM excludes.
	unset := config.Config{
		Scan:    config.ScanConfig{Exclude: []string{"*.lock", "package-lock.json", "go.sum"}},
		Sources: map[string]string{},
	}
	if got := sbomExcludes(unset, nil); len(got) != 0 {
		t.Errorf("built-in scan defaults leaked into SBOM excludes: %v", got)
	}
}

func TestSBOMConfigExcludesDoNotHideLockfiles(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)
	writeTestFile(t, dir, ".vigil.yaml", `scan:
  exclude:
    - ideas/**
    - go.sum
    - package-lock.json
    - "*.lock"
    - docs/**
`)
	writeSBOMFixture(t, dir, "ideas/research/package-lock.json", sbomNpmLock("idea-pkg", "1.0.0"))
	writeSBOMFixture(t, dir, "docs/examples/package-lock.json", sbomNpmLock("docs-pkg", "3.0.0"))
	writeSBOMFixture(t, dir, "go.mod", "module example.com/app\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n")
	writeSBOMFixture(t, dir, "go.sum", "github.com/foo/bar v1.2.3 h1:abc123=\n")
	writeSBOMFixture(t, dir, "package-lock.json", sbomNpmLock("lodash", "4.17.21"))
	writeSBOMFixture(t, dir, "Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n")

	out, stderr, err := runCLI(t, "sbom", dir)
	if err != nil {
		t.Fatalf("sbom: %v\nstderr:\n%s", err, stderr)
	}

	var bom struct {
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("sbom is not valid JSON: %v\n%s", err, out)
	}
	names := make(map[string]bool, len(bom.Components))
	for _, c := range bom.Components {
		names[c.Name] = true
	}
	for _, want := range []string{"github.com/foo/bar", "lodash", "serde"} {
		if !names[want] {
			t.Errorf("component %q is missing: %v", want, names)
		}
	}
	for _, gone := range []string{"idea-pkg", "docs-pkg"} {
		if names[gone] {
			t.Errorf("excluded package %q is still in the document:\n%s", gone, out)
		}
	}
}

func TestSBOMTruncationWarningIsVisible(t *testing.T) {
	dir := t.TempDir()
	prepareSBOMTest(t, dir)
	writeTestFile(t, dir, "package-lock.json", sbomLargeNpmLock(201))

	out, stderr, err := runCLI(t, "sbom", dir)
	if err != nil {
		t.Fatalf("sbom: %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{"inventory truncated", "200 package cap"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}

	var bom struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("sbom is not valid JSON: %v\n%s", err, out)
	}
	if len(bom.Components) != 200 {
		t.Errorf("components = %d, want the 200 cap", len(bom.Components))
	}
	if len(bom.Metadata.Properties) == 0 || !strings.Contains(bom.Metadata.Properties[0].Value, "inventory truncated") {
		t.Errorf("document does not record the truncation: %+v", bom.Metadata.Properties)
	}
}

func TestSBOMHelp(t *testing.T) {
	out, _, err := runCLI(t, "sbom", "--help")
	if err != nil {
		t.Fatalf("sbom --help: %v", err)
	}
	for _, want := range []string{"Usage: vigil sbom", "directory-oriented", "--format cyclonedx|spdx", "--include-dev", "--exclude GLOB", "--output"} {
		if !strings.Contains(out, want) {
			t.Errorf("sbom help missing %q:\n%s", want, out)
		}
	}
}
