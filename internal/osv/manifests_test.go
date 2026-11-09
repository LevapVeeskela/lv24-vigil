package osv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func indexPackages(pkgs []Package) map[string]Package {
	out := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		out[p.Name] = p
	}
	return out
}

func requirePackage(t *testing.T, idx map[string]Package, name, version string) Package {
	t.Helper()
	p, ok := idx[name]
	if !ok {
		t.Fatalf("package %q not found; got %v", name, packageNames(idx))
	}
	if p.Version != version {
		t.Fatalf("package %q version = %q, want %q", name, p.Version, version)
	}
	return p
}

func packageNames(idx map[string]Package) []string {
	out := make([]string, 0, len(idx))
	for name := range idx {
		out = append(out, name)
	}
	return out
}

func collectForTest(t *testing.T, dir string, includeDev bool) []Package {
	t.Helper()
	pkgs, err := collectPackages(context.Background(), dir, includeDev, DefaultMaxPackages)
	if err != nil {
		t.Fatalf("collectPackages: %v", err)
	}
	return pkgs
}

func TestCollectPackagesPackageLockPreferred(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "package.json", `{
	  "dependencies": {"lodash": "^4.17.20", "only-in-pkg-json": "^2.0.0"},
	  "devDependencies": {"jest": "^29.0.0"}
	}`)
	writeFixture(t, dir, "package-lock.json", `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "dependencies": {"lodash": "^4.17.20"}, "devDependencies": {"jest": "^29.0.0"}},
	    "node_modules/lodash": {"version": "4.17.21"},
	    "node_modules/jest": {"version": "29.5.0", "dev": true},
	    "node_modules/@scope/pkg": {"version": "1.0.0"},
	    "node_modules/lodash/node_modules/nested": {"version": "3.0.0"},
	    "packages/workspace": {"name": "@app/workspace", "version": "0.0.1"}
	  }
	}`)

	idx := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, idx, "lodash", "4.17.21")
	requirePackage(t, idx, "nested", "3.0.0")
	requirePackage(t, idx, "@scope/pkg", "1.0.0")

	if _, ok := idx["only-in-pkg-json"]; ok {
		t.Error("package.json must be ignored when a usable lockfile exists")
	}
	if _, ok := idx["@app/workspace"]; ok {
		t.Error("workspace link entries are not published packages")
	}
	if !idx["jest"].Dev {
		t.Error("jest should be marked as a dev dependency")
	}
}

func TestCollectPackagesPackageJSONFallback(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "package.json", `{
	  "dependencies": {
	    "lodash": "^4.17.20",
	    "exact": "1.2.3",
	    "wild": "*",
	    "gitdep": "git+https://example.test/x.git",
	    "nested": ">=2.0.0 <3.0.0",
	    "alias": "npm:other@^1.5.0"
	  },
	  "devDependencies": {"jest": "~29.0.0"}
	}`)

	idx := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, idx, "lodash", "4.17.20")
	requirePackage(t, idx, "exact", "1.2.3")
	requirePackage(t, idx, "nested", "2.0.0")
	requirePackage(t, idx, "other", "1.5.0")
	if !idx["jest"].Dev {
		t.Error("jest should be marked as a dev dependency")
	}
	for _, name := range []string{"wild", "gitdep", "alias"} {
		if _, ok := idx[name]; ok {
			t.Errorf("%q must be skipped: it has no concrete version", name)
		}
	}
}

func TestCollectPackagesFallsBackOnMalformedLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "package.json", `{"dependencies": {"left-pad": "^1.3.0"}}`)
	writeFixture(t, dir, "package-lock.json", `{not json`)

	idx := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, idx, "left-pad", "1.3.0")
}

func TestCollectPackagesRequirements(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", `# pinned dependencies
-r base.txt
-e git+https://example.test/repo#egg=thing
Django[bcrypt]==3.2.4
requests==2.31.0 ; python_version >= "3.8"
Flask
numpy==1.24.0 --hash=sha256:deadbeef
pkg.name_x==2.0.0
weird==1.*
`)

	idx := indexPackages(collectForTest(t, dir, true))
	django := requirePackage(t, idx, "django", "3.2.4")
	requirePackage(t, idx, "requests", "2.31.0")
	requirePackage(t, idx, "numpy", "1.24.0")
	requirePackage(t, idx, "pkg-name-x", "2.0.0")

	if django.Ecosystem != ecosystemPyPI {
		t.Errorf("django ecosystem = %q, want %q", django.Ecosystem, ecosystemPyPI)
	}
	if django.Line != 4 {
		t.Errorf("django line = %d, want 4", django.Line)
	}
	for _, name := range []string{"flask", "weird"} {
		if _, ok := idx[name]; ok {
			t.Errorf("%q must be skipped", name)
		}
	}
}

func TestCollectPackagesGoMod(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "go.mod", `module example.com/app

go 1.22

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.4.0 // indirect
)

require github.com/single/dep v2.0.0+incompatible

replace github.com/baz/qux => github.com/baz/qux v0.5.0
`)

	idx := indexPackages(collectForTest(t, dir, true))
	bar := requirePackage(t, idx, "github.com/foo/bar", "v1.2.3")
	requirePackage(t, idx, "github.com/single/dep", "v2.0.0+incompatible")

	if bar.Ecosystem != ecosystemGo {
		t.Errorf("bar ecosystem = %q, want %q", bar.Ecosystem, ecosystemGo)
	}
	if bar.Line != 6 {
		t.Errorf("bar line = %d, want 6", bar.Line)
	}
	if _, ok := idx["github.com/baz/qux"]; ok {
		t.Error("replaced modules must be skipped: their declared version is not resolved")
	}
}

func TestCollectPackagesGemfileLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "Gemfile.lock", `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      activesupport (= 7.0.4)
    nokogiri (1.13.8-x86_64-linux)
    rack (2.2.4)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rack
`)

	idx := indexPackages(collectForTest(t, dir, true))
	actionpack := requirePackage(t, idx, "actionpack", "7.0.4")
	requirePackage(t, idx, "nokogiri", "1.13.8")
	requirePackage(t, idx, "rack", "2.2.4")

	if actionpack.Line != 4 {
		t.Errorf("actionpack line = %d, want 4", actionpack.Line)
	}
	if _, ok := idx["activesupport"]; ok {
		t.Error("nested dependency constraints are not installed specs")
	}
}

func TestCollectPackagesCargoLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "Cargo.lock", `version = 3

[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "app"
version = "0.1.0"

[metadata]
checksum = "ignored"
`)

	idx := indexPackages(collectForTest(t, dir, true))
	serde := requirePackage(t, idx, "serde", "1.0.188")
	requirePackage(t, idx, "app", "0.1.0")

	if serde.Ecosystem != ecosystemCrates {
		t.Errorf("serde ecosystem = %q, want %q", serde.Ecosystem, ecosystemCrates)
	}
	if serde.Line != 4 {
		t.Errorf("serde line = %d, want 4", serde.Line)
	}
}

func TestCollectPackagesComposerLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "composer.lock", `{
	  "packages": [
	    {"name": "monolog/monolog", "version": "2.9.1"},
	    {"name": "branch/pkg", "version": "dev-master"}
	  ],
	  "packages-dev": [
	    {"name": "phpunit/phpunit", "version": "v9.6.0"}
	  ]
	}`)

	withDev := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, withDev, "monolog/monolog", "2.9.1")
	phpunit := requirePackage(t, withDev, "phpunit/phpunit", "9.6.0")
	if !phpunit.Dev {
		t.Error("phpunit should be marked as a dev dependency")
	}
	if _, ok := withDev["branch/pkg"]; ok {
		t.Error("branch aliases have no OSV version and must be skipped")
	}

	withoutDev := indexPackages(collectForTest(t, dir, false))
	if _, ok := withoutDev["phpunit/phpunit"]; ok {
		t.Error("dev packages must be excluded when IncludeDev is false")
	}
	requirePackage(t, withoutDev, "monolog/monolog", "2.9.1")
}

func TestCollectPackagesPomXML(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "pom.xml", `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>props</artifactId>
      <version>${props.version}</version>
    </dependency>
  </dependencies>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
`)

	withDev := indexPackages(collectForTest(t, dir, true))
	log4j := requirePackage(t, withDev, "org.apache.logging.log4j:log4j-core", "2.14.1")
	requirePackage(t, withDev, "com.fasterxml.jackson.core:jackson-databind", "2.15.0")
	if !withDev["junit:junit"].Dev {
		t.Error("test-scoped Maven dependencies should be marked dev")
	}
	if log4j.Ecosystem != ecosystemMaven {
		t.Errorf("log4j ecosystem = %q, want %q", log4j.Ecosystem, ecosystemMaven)
	}
	if _, ok := withDev["com.example:props"]; ok {
		t.Error("property placeholders must be skipped")
	}

	withoutDev := indexPackages(collectForTest(t, dir, false))
	if _, ok := withoutDev["junit:junit"]; ok {
		t.Error("test-scoped dependencies must be excluded when IncludeDev is false")
	}
}

func TestCollectPackagesDeduplicates(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.31.0\nrequests==2.31.0\nurllib3==2.0.0\n")

	pkgs := collectForTest(t, dir, true)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %v", len(pkgs), packageNames(indexPackages(pkgs)))
	}
}

func TestCollectPackagesCapsMax(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "aaa==1.0.0\nbbb==1.0.0\nccc==1.0.0\nddd==1.0.0\neee==1.0.0\n")

	pkgs, err := collectPackages(context.Background(), dir, true, 2)
	if err != nil {
		t.Fatalf("collectPackages: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "aaa" || pkgs[1].Name != "bbb" {
		t.Fatalf("unexpected packages: %v", packageNames(indexPackages(pkgs)))
	}
}

func TestCollectPackagesSkipsInstallDirsAndLargeFiles(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "app/requirements.txt", "requests==2.31.0\n")
	for _, skip := range []string{"node_modules", "vendor", "dist", "build", ".venv", ".git"} {
		writeFixture(t, dir, skip+"/requirements.txt", "skipped==1.0.0\n")
	}
	writeFixture(t, dir, "big/requirements.txt", strings.Repeat("#", maxManifestBytes+1))
	writeFixture(t, dir, strings.Repeat("deep/", maxManifestDepth+5)+"requirements.txt", "toodeep==1.0.0\n")

	idx := indexPackages(collectForTest(t, dir, true))
	if len(idx) != 1 {
		t.Fatalf("got %d packages, want 1: %v", len(idx), packageNames(idx))
	}
	requirePackage(t, idx, "requests", "2.31.0")
}

func TestNpmNameFromPath(t *testing.T) {
	tests := map[string]string{
		"node_modules/lodash":                     "lodash",
		"node_modules/@scope/pkg":                 "@scope/pkg",
		"node_modules/a/node_modules/b":           "b",
		"node_modules/@scope/a/node_modules/@x/y": "@x/y",
		"packages/workspace":                      "",
		"":                                        "",
	}
	for in, want := range tests {
		if got := npmNameFromPath(in); got != want {
			t.Errorf("npmNameFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConcreteNPMVersion(t *testing.T) {
	tests := map[string]string{
		"1.2.3":            "1.2.3",
		"^1.2.3":           "1.2.3",
		"~1.2.3":           "1.2.3",
		">=1.2.3":          "1.2.3",
		">=1.2.3 <2.0.0":   "1.2.3",
		">= 1.2.3":         "1.2.3",
		"1.2.3 || 2.0.0":   "1.2.3",
		"workspace:^1.2.3": "1.2.3",
		"*":                "",
		"latest":           "",
		"1.x":              "",
		"git+https://x":    "",
		"file:../local":    "",
	}
	for in, want := range tests {
		if got := concreteNPMVersion(in); got != want {
			t.Errorf("concreteNPMVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
