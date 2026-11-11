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
	pkgs, err := CollectPackages(context.Background(), dir, includeDev, DefaultMaxPackages)
	if err != nil {
		t.Fatalf("CollectPackages: %v", err)
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

	pkgs, err := CollectPackages(context.Background(), dir, true, 2)
	if err != nil {
		t.Fatalf("CollectPackages: %v", err)
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

func TestCollectPackagesPNPMLockV9(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "package.json", `{"dependencies": {"only-in-pkg-json": "^1.0.0"}}`)
	writeFixture(t, dir, "pnpm-lock.yaml", `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
    devDependencies:
      jest:
        specifier: ^29.0.0
        version: 29.5.0

  packages/web:
    dependencies:
      react:
        specifier: ^18.2.0
        version: 18.2.0

packages:

  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-scope}

  lodash@4.17.21:
    resolution: {integrity: sha512-lodash}

  jest@29.5.0:
    resolution: {integrity: sha512-jest}

  react@18.2.0:
    resolution: {integrity: sha512-react}

  with-peer@2.0.0(react@18.2.0):
    resolution: {integrity: sha512-peer}

snapshots:

  lodash@4.17.21: {}
`)

	idx := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, idx, "lodash", "4.17.21")
	scoped := requirePackage(t, idx, "@scope/pkg", "1.2.3")
	requirePackage(t, idx, "jest", "29.5.0")
	requirePackage(t, idx, "react", "18.2.0")
	requirePackage(t, idx, "with-peer", "2.0.0")

	if scoped.Ecosystem != ecosystemNPM {
		t.Errorf("scoped ecosystem = %q, want %q", scoped.Ecosystem, ecosystemNPM)
	}
	if !idx["jest"].Dev {
		t.Error("jest is an importer devDependency and should be marked dev")
	}
	if idx["react"].Dev {
		t.Error("a dependency of a second importer must not inherit the previous dev section")
	}
	if _, ok := idx["only-in-pkg-json"]; ok {
		t.Error("package.json must be ignored when a pnpm lockfile exists")
	}
	if _, ok := idx["snapshots"]; ok {
		t.Error("the snapshots section must not be parsed as packages")
	}
}

func TestCollectPackagesPNPMLockV6(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "pnpm-lock.yaml", `lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21

packages:

  /@scope/pkg@1.2.3:
    resolution: {integrity: sha512-scope}
    dev: false

  /lodash@4.17.21:
    resolution: {integrity: sha512-lodash}
    dev: false

  /dev-only@1.0.0:
    resolution: {integrity: sha512-dev}
    dev: true
`)

	idx := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, idx, "@scope/pkg", "1.2.3")
	requirePackage(t, idx, "lodash", "4.17.21")
	requirePackage(t, idx, "dev-only", "1.0.0")
	if !idx["dev-only"].Dev {
		t.Error("pnpm v6 dev: true entries should be marked dev")
	}

	withoutDev := indexPackages(collectForTest(t, dir, false))
	if _, ok := withoutDev["dev-only"]; ok {
		t.Error("dev packages must be excluded when IncludeDev is false")
	}
}

func TestCollectPackagesYarnLockV1(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "package.json", `{"dependencies": {"only-in-pkg-json": "^1.0.0"}}`)
	writeFixture(t, dir, "yarn.lock", `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

lodash@^4.17.20, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-lodash

"@scope/pkg@^1.0.0":
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.0.0.tgz"
`)

	idx := indexPackages(collectForTest(t, dir, true))
	lodash := requirePackage(t, idx, "lodash", "4.17.21")
	requirePackage(t, idx, "@scope/pkg", "1.0.0")

	if lodash.Line != 4 {
		t.Errorf("lodash line = %d, want the block header line 4", lodash.Line)
	}
	if _, ok := idx["only-in-pkg-json"]; ok {
		t.Error("package.json must be ignored when a yarn lockfile exists")
	}
}

func TestCollectPackagesYarnLockBerry(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "yarn.lock", `__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: deadbeef

"@scope/pkg@npm:^1.0.0":
  version: 1.0.0
  resolution: "@scope/pkg@npm:1.0.0"
`)

	idx := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, idx, "lodash", "4.17.21")
	requirePackage(t, idx, "@scope/pkg", "1.0.0")
	if _, ok := idx["__metadata"]; ok {
		t.Error("__metadata is not a package")
	}
}

func TestCollectPackagesPipfileLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "Pipfile.lock", `{
	  "_meta": {"hash": {"sha256": "deadbeef"}},
	  "default": {
	    "Django": {"version": "==3.2.4"},
	    "requests": {"version": "==2.31.0", "markers": "python_version >= '3.8'"},
	    "local-pkg": {"path": ".", "editable": true}
	  },
	  "develop": {
	    "pytest": {"version": "==7.4.0"},
	    "unpinned": {"version": "*"}
	  }
	}`)

	idx := indexPackages(collectForTest(t, dir, true))
	django := requirePackage(t, idx, "django", "3.2.4")
	requirePackage(t, idx, "requests", "2.31.0")
	requirePackage(t, idx, "pytest", "7.4.0")

	if django.Ecosystem != ecosystemPyPI {
		t.Errorf("django ecosystem = %q, want %q", django.Ecosystem, ecosystemPyPI)
	}
	if !idx["pytest"].Dev {
		t.Error("develop entries should be marked dev")
	}
	if idx["django"].Dev {
		t.Error("default entries are production dependencies")
	}
	for _, name := range []string{"local-pkg", "unpinned"} {
		if _, ok := idx[name]; ok {
			t.Errorf("%q must be skipped: it has no pinned version", name)
		}
	}
}

func TestCollectPackagesPoetryLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "poetry.lock", `[[package]]
name = "certifi"
version = "2023.7.22"
description = "CA bundle"
optional = false
python-versions = ">=3.6"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"

[package.dependencies]
iniconfig = "*"

[[package]]
name = "black"
version = "23.7.0"
groups = ["dev", "lint"]

[[package]]
name = "requests"
version = "2.31.0"
groups = ["main"]

[metadata]
lock-version = "2.0"
python-versions = "^3.10"
content-hash = "deadbeef"
`)

	idx := indexPackages(collectForTest(t, dir, true))
	requirePackage(t, idx, "certifi", "2023.7.22")
	requirePackage(t, idx, "requests", "2.31.0")
	requirePackage(t, idx, "pytest", "7.4.0")
	requirePackage(t, idx, "black", "23.7.0")

	if !idx["pytest"].Dev {
		t.Error("category = dev should mark a Poetry package dev")
	}
	if !idx["black"].Dev {
		t.Error("a groups list without main should mark a Poetry package dev")
	}
	if idx["requests"].Dev {
		t.Error("a groups list containing main is a production dependency")
	}
	if idx["certifi"].Dev {
		t.Error("a package without category or groups is a production dependency")
	}
	if _, ok := idx["iniconfig"]; ok {
		t.Error("[package.dependencies] entries are not locked packages")
	}
}

func TestCollectPackagesUVLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "uv.lock", `version = 1
revision = 1
requires-python = ">=3.12"

[[package]]
name = "anyio"
version = "4.3.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "my-app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "local-lib"
version = "0.0.0"
source = { virtual = "." }
`)

	idx := indexPackages(collectForTest(t, dir, true))
	anyio := requirePackage(t, idx, "anyio", "4.3.0")
	if anyio.Ecosystem != ecosystemPyPI {
		t.Errorf("anyio ecosystem = %q, want %q", anyio.Ecosystem, ecosystemPyPI)
	}
	for _, name := range []string{"my-app", "local-lib"} {
		if _, ok := idx[name]; ok {
			t.Errorf("%q is a local project and must be skipped", name)
		}
	}
}

func TestCollectPackagesPubspecLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "pubspec.lock", `packages:
  async:
    dependency: transitive
    description:
      name: async
      sha256: "abc"
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "def"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.1"
  test:
    dependency: "direct dev"
    description:
      name: test
      sha256: "ghi"
      url: "https://pub.dev"
    source: hosted
    version: "1.24.0"
  flutter_test:
    dependency: "direct dev"
    description:
      name: flutter_test
      url: "https://pub.dev"
    source: sdk
    version: "0.0.0"
  my_app:
    dependency: "direct main"
    description:
      path: "."
      relative: true
    source: path
    version: "1.0.0+1"
sdks:
  dart: ">=3.3.0 <4.0.0"
`)

	idx := indexPackages(collectForTest(t, dir, true))
	async := requirePackage(t, idx, "async", "2.11.0")
	requirePackage(t, idx, "http", "1.2.1")
	requirePackage(t, idx, "test", "1.24.0")

	if async.Ecosystem != ecosystemPub {
		t.Errorf("async ecosystem = %q, want %q", async.Ecosystem, ecosystemPub)
	}
	if async.Dev || idx["http"].Dev {
		t.Error("transitive and direct main packages are not dev dependencies")
	}
	if !idx["test"].Dev {
		t.Error("direct dev packages should be marked dev")
	}
	for _, name := range []string{"flutter_test", "my_app"} {
		if _, ok := idx[name]; ok {
			t.Errorf("%q is not a pub.dev package and must be skipped", name)
		}
	}

	withoutDev := indexPackages(collectForTest(t, dir, false))
	if _, ok := withoutDev["test"]; ok {
		t.Error("dev packages must be excluded when IncludeDev is false")
	}
	requirePackage(t, withoutDev, "http", "1.2.1")
}

func TestCollectPackagesGradleLockfile(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "gradle.lockfile", `# This is a Gradle generated file for dependency locking.
com.fasterxml.jackson.core:jackson-databind:2.15.0=compileClasspath,runtimeClasspath
org.jetbrains.kotlin:kotlin-stdlib:1.9.0=compileClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor
`)

	idx := indexPackages(collectForTest(t, dir, true))
	jackson := requirePackage(t, idx, "com.fasterxml.jackson.core:jackson-databind", "2.15.0")
	requirePackage(t, idx, "org.jetbrains.kotlin:kotlin-stdlib", "1.9.0")
	requirePackage(t, idx, "junit:junit", "4.13.2")

	if jackson.Ecosystem != ecosystemMaven {
		t.Errorf("jackson ecosystem = %q, want %q", jackson.Ecosystem, ecosystemMaven)
	}
	if !idx["junit:junit"].Dev {
		t.Error("test-only configurations should be marked dev")
	}
	if idx["com.fasterxml.jackson.core:jackson-databind"].Dev {
		t.Error("compile configurations are production dependencies")
	}
	if _, ok := idx["empty"]; ok {
		t.Error("the empty configuration line is not a dependency")
	}

	withoutDev := indexPackages(collectForTest(t, dir, false))
	if _, ok := withoutDev["junit:junit"]; ok {
		t.Error("test-only dependencies must be excluded when IncludeDev is false")
	}
}

func TestCollectPackagesNuGetLock(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "packages.lock.json", `{
	  "version": 1,
	  "dependencies": {
	    "net8.0": {
	      "Newtonsoft.Json": {
	        "type": "Direct",
	        "requested": "[13.0.3, )",
	        "resolved": "13.0.3",
	        "contentHash": "abc"
	      },
	      "System.Text.Json": {
	        "type": "Transitive",
	        "resolved": "8.0.4"
	      },
	      "My.App": {
	        "type": "Project",
	        "resolved": "1.0.0"
	      }
	    },
	    "net8.0/win-x64": {
	      "Newtonsoft.Json": {
	        "type": "Direct",
	        "resolved": "13.0.3"
	      },
	      "System.Security.Cryptography.ProtectedData": {
	        "type": "Transitive",
	        "resolved": "8.0.0"
	      }
	    }
	  }
	}`)

	pkgs := collectForTest(t, dir, true)
	idx := indexPackages(pkgs)
	newtonsoft := requirePackage(t, idx, "Newtonsoft.Json", "13.0.3")
	requirePackage(t, idx, "System.Text.Json", "8.0.4")
	requirePackage(t, idx, "System.Security.Cryptography.ProtectedData", "8.0.0")

	if newtonsoft.Ecosystem != ecosystemNuGet {
		t.Errorf("Newtonsoft.Json ecosystem = %q, want %q", newtonsoft.Ecosystem, ecosystemNuGet)
	}
	if _, ok := idx["My.App"]; ok {
		t.Error("Project entries are local references and must be skipped")
	}
	count := 0
	for _, p := range pkgs {
		if p.Name == "Newtonsoft.Json" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Newtonsoft.Json appears %d times, want one entry after dedupe", count)
	}
}

func TestCollectPackagesExported(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.31.0\nurllib3==2.0.0\n")

	pkgs, err := CollectPackages(context.Background(), dir, true, 1)
	if err != nil {
		t.Fatalf("CollectPackages: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want the max cap of 1", len(pkgs))
	}
	if pkgs[0].Name != "requests" {
		t.Errorf("package = %q, want requests", pkgs[0].Name)
	}
}
