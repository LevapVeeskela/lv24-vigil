package osv

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Ecosystems are the OSV API identifiers used in this package.
const (
	ecosystemNPM       = "npm"
	ecosystemPyPI      = "PyPI"
	ecosystemGo        = "Go"
	ecosystemRubyGems  = "RubyGems"
	ecosystemCrates    = "crates.io"
	ecosystemPackagist = "Packagist"
	ecosystemMaven     = "Maven"
	ecosystemPub       = "Pub"
	ecosystemNuGet     = "NuGet"
)

const (
	// maxManifestBytes is the per-file limit. Dependency manifests are small;
	// anything larger is not a manifest worth parsing.
	maxManifestBytes = 2 << 20
	// maxManifestFiles bounds how many manifests one scan parses.
	maxManifestFiles = 1000
	// maxManifestDepth bounds directory recursion for pathological trees.
	maxManifestDepth = 24
	// maxCollectedPackages bounds intermediate memory before the MaxPackages
	// cap is applied.
	maxCollectedPackages = 50_000
)

// Package is one exact dependency coordinate found in a manifest.
type Package struct {
	Name      string
	Version   string
	Ecosystem string
	Manifest  string // slash-separated path relative to the scan root
	Line      int    // 1-based line of the entry, or 1 when unknown
	Dev       bool   // devDependency, composer packages-dev, Maven test scope
}

type manifestKind int

const (
	kindPackageJSON manifestKind = iota
	kindPackageLock
	kindRequirements
	kindGoMod
	kindGemfileLock
	kindCargoLock
	kindComposerLock
	kindPomXML
	kindPNPMLock
	kindYarnLock
	kindPipfileLock
	kindPoetryLock
	kindUVLock
	kindPubspecLock
	kindGradleLockfile
	kindNuGetLock
)

type manifestFile struct {
	abs  string
	rel  string
	kind manifestKind
}

// skipManifestDirs are directories that contain installed or generated copies
// of dependencies rather than the repository's own manifests.
var skipManifestDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	".venv":        true,
}

// CollectPackages walks root, parses every supported manifest and returns the
// deduplicated, sorted package list capped at max.
//
// Lockfiles are parsed before manifests: a package.json is only used when its
// directory has no usable npm-family lockfile (package-lock.json, pnpm-lock.yaml
// or yarn.lock). A malformed lockfile deliberately falls back to the semver
// ranges in package.json.
//
// The walk is bounded by maxManifestFiles and maxManifestDepth, each file by
// maxManifestBytes and the intermediate list by maxCollectedPackages.
func CollectPackages(ctx context.Context, root string, includeDev bool, max int) ([]Package, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("osv: resolve scan root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("osv: scan root %s: %w", absRoot, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("osv: scan root %s is not a directory", absRoot)
	}
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolved
	}

	var files []manifestFile
	walkErr := filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if p == absRoot {
				return walkErr
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(absRoot, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if p == absRoot {
				return nil
			}
			if skipManifestDirs[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			if strings.Count(rel, "/") >= maxManifestDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		kind, ok := manifestKindFor(d.Name())
		if !ok {
			return nil
		}
		if fi, err := d.Info(); err != nil || fi.Size() > maxManifestBytes {
			return nil
		}
		if len(files) >= maxManifestFiles {
			return filepath.SkipAll
		}
		files = append(files, manifestFile{abs: p, rel: rel, kind: kind})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("osv: walk %s: %w", absRoot, walkErr)
	}
	if len(files) == 0 {
		return nil, nil
	}

	// Parse lockfiles first so a manifest is only used when its directory has
	// no usable lockfile.
	var packages []Package
	lockDirs := make(map[string]bool)
	for _, f := range files {
		if !isLockfileKind(f.kind) {
			continue
		}
		parsed, err := parseManifestFile(f)
		if err != nil {
			continue
		}
		if suppressesPackageJSON(f.kind) {
			lockDirs[path.Dir(f.rel)] = true
		}
		packages = append(packages, parsed...)
		if len(packages) >= maxCollectedPackages {
			break
		}
	}
	for _, f := range files {
		if isLockfileKind(f.kind) {
			continue
		}
		if f.kind == kindPackageJSON && lockDirs[path.Dir(f.rel)] {
			continue
		}
		parsed, err := parseManifestFile(f)
		if err != nil {
			continue
		}
		packages = append(packages, parsed...)
		if len(packages) >= maxCollectedPackages {
			break
		}
	}

	packages = dedupePackages(packages)
	if !includeDev {
		kept := packages[:0]
		for _, p := range packages {
			if p.Dev {
				continue
			}
			kept = append(kept, p)
		}
		packages = kept
	}
	return capPackages(packages, max), nil
}

// isLockfileKind reports whether a manifest pins the full dependency graph.
// Lockfiles are parsed before manifests so a coarse manifest in the same
// directory does not duplicate or dilute them.
func isLockfileKind(kind manifestKind) bool {
	switch kind {
	case kindPackageLock, kindPNPMLock, kindYarnLock, kindPipfileLock,
		kindPoetryLock, kindUVLock, kindPubspecLock, kindGradleLockfile,
		kindNuGetLock:
		return true
	default:
		return false
	}
}

// suppressesPackageJSON reports whether a lockfile makes the package.json in
// the same directory redundant. Non-npm lockfiles do not, because a repository
// may legitimately keep a Python lockfile next to a JS manifest.
func suppressesPackageJSON(kind manifestKind) bool {
	switch kind {
	case kindPackageLock, kindPNPMLock, kindYarnLock:
		return true
	default:
		return false
	}
}

func manifestKindFor(name string) (manifestKind, bool) {
	switch strings.ToLower(name) {
	case "package.json":
		return kindPackageJSON, true
	case "package-lock.json":
		return kindPackageLock, true
	case "pnpm-lock.yaml":
		return kindPNPMLock, true
	case "yarn.lock":
		return kindYarnLock, true
	case "pipfile.lock":
		return kindPipfileLock, true
	case "poetry.lock":
		return kindPoetryLock, true
	case "uv.lock":
		return kindUVLock, true
	case "pubspec.lock":
		return kindPubspecLock, true
	case "gradle.lockfile":
		return kindGradleLockfile, true
	case "packages.lock.json":
		return kindNuGetLock, true
	case "requirements.txt":
		return kindRequirements, true
	case "go.mod":
		return kindGoMod, true
	case "gemfile.lock":
		return kindGemfileLock, true
	case "cargo.lock":
		return kindCargoLock, true
	case "composer.lock":
		return kindComposerLock, true
	case "pom.xml":
		return kindPomXML, true
	default:
		return 0, false
	}
}

func parseManifestFile(f manifestFile) ([]Package, error) {
	data, err := os.ReadFile(f.abs)
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", maxManifestBytes)
	}
	switch f.kind {
	case kindPackageJSON:
		return parsePackageJSON(f.rel, data)
	case kindPackageLock:
		return parsePackageLock(f.rel, data)
	case kindPNPMLock:
		return parsePNPMLock(f.rel, data)
	case kindYarnLock:
		return parseYarnLock(f.rel, data)
	case kindPipfileLock:
		return parsePipfileLock(f.rel, data)
	case kindPoetryLock:
		return parsePoetryLock(f.rel, data)
	case kindUVLock:
		return parseUVLock(f.rel, data)
	case kindPubspecLock:
		return parsePubspecLock(f.rel, data)
	case kindGradleLockfile:
		return parseGradleLockfile(f.rel, data)
	case kindNuGetLock:
		return parseNuGetLock(f.rel, data)
	case kindRequirements:
		return parseRequirementsTxt(f.rel, data)
	case kindGoMod:
		return parseGoMod(f.rel, data)
	case kindGemfileLock:
		return parseGemfileLock(f.rel, data)
	case kindCargoLock:
		return parseCargoLock(f.rel, data)
	case kindComposerLock:
		return parseComposerLock(f.rel, data)
	case kindPomXML:
		return parsePomXML(f.rel, data)
	default:
		return nil, nil
	}
}

// dedupePackages sorts packages deterministically and removes duplicates by
// ecosystem+name+version. When the same coordinate appears in a production and
// a dev context it is treated as production.
func dedupePackages(pkgs []Package) []Package {
	for i := range pkgs {
		pkgs[i].Name = strings.TrimSpace(pkgs[i].Name)
		pkgs[i].Version = strings.TrimSpace(pkgs[i].Version)
		pkgs[i].Manifest = filepath.ToSlash(pkgs[i].Manifest)
		if pkgs[i].Line <= 0 {
			pkgs[i].Line = 1
		}
	}
	sort.SliceStable(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Manifest < b.Manifest
	})

	out := make([]Package, 0, len(pkgs))
	index := make(map[string]int, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" || p.Ecosystem == "" {
			continue
		}
		key := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version
		if i, ok := index[key]; ok {
			if out[i].Dev && !p.Dev {
				out[i].Dev = false
			}
			continue
		}
		index[key] = len(out)
		out = append(out, p)
	}
	return out
}

func capPackages(pkgs []Package, max int) []Package {
	if max > 0 && len(pkgs) > max {
		return pkgs[:max]
	}
	return pkgs
}

func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

// --- npm -------------------------------------------------------------------

type npmLockEntry struct {
	Version         string            `json:"version"`
	Dev             bool              `json:"dev"`
	Link            bool              `json:"link"`
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type npmLockDependency struct {
	Version      string                       `json:"version"`
	Dev          bool                         `json:"dev"`
	Dependencies map[string]npmLockDependency `json:"dependencies"`
}

type npmLockFile struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string]npmLockEntry      `json:"packages"`
	Dependencies    map[string]npmLockDependency `json:"dependencies"`
}

func parsePackageLock(rel string, data []byte) ([]Package, error) {
	var doc npmLockFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	devNames := make(map[string]bool)
	if root, ok := doc.Packages[""]; ok {
		for name := range root.DevDependencies {
			devNames[name] = true
		}
	}

	var out []Package
	for key, entry := range doc.Packages {
		if key == "" {
			continue
		}
		name := npmNameFromPath(key)
		if name == "" || entry.Version == "" || entry.Link {
			continue
		}
		out = append(out, Package{
			Name:      name,
			Version:   entry.Version,
			Ecosystem: ecosystemNPM,
			Manifest:  rel,
			Line:      1,
			Dev:       entry.Dev || devNames[name],
		})
	}

	// Lockfile v1 stores a nested dependency tree instead of "packages".
	var walk func(deps map[string]npmLockDependency)
	walk = func(deps map[string]npmLockDependency) {
		for name, dep := range deps {
			if dep.Version != "" {
				out = append(out, Package{
					Name:      name,
					Version:   dep.Version,
					Ecosystem: ecosystemNPM,
					Manifest:  rel,
					Line:      1,
					Dev:       dep.Dev,
				})
			}
			walk(dep.Dependencies)
		}
	}
	walk(doc.Dependencies)
	return out, nil
}

// npmNameFromPath extracts the package name from a lockfile path key such as
// "node_modules/@scope/pkg" or "node_modules/a/node_modules/b".
func npmNameFromPath(key string) string {
	key = strings.TrimSuffix(key, "/")
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	name := key[i+len(marker):]
	if name == "" {
		return ""
	}
	if strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
		return ""
	}
	return name
}

var npmVersionRe = regexp.MustCompile(`^\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.\-+]+)?$`)

// npmAliasTarget resolves an npm alias ("alias": "npm:real-package@^1.2.3") to
// the real package name, because the alias itself is not a published package.
func npmAliasTarget(name, spec string) (string, string) {
	s := strings.TrimSpace(spec)
	if !strings.HasPrefix(strings.ToLower(s), "npm:") {
		return name, spec
	}
	rest := s[len("npm:"):]
	i := strings.LastIndex(rest, "@")
	if i <= 0 {
		return name, spec
	}
	target := strings.TrimSpace(rest[:i])
	if target == "" {
		return name, spec
	}
	return target, rest[i+1:]
}

// concreteNPMVersion turns a package.json semver range into the lowest concrete
// version it admits. OSV needs exact versions, so "*", "latest", git and file
// specs are skipped rather than queried blindly.
func concreteNPMVersion(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)

	if strings.HasPrefix(lower, "npm:") {
		i := strings.LastIndex(s, "@")
		if i <= len("npm:") {
			return ""
		}
		s = s[i+1:]
		lower = strings.ToLower(s)
	}
	if strings.HasPrefix(lower, "workspace:") {
		s = strings.TrimSpace(s[len("workspace:"):])
		if s == "" || s == "*" {
			return ""
		}
		lower = strings.ToLower(s)
	}
	for _, prefix := range []string{
		"file:", "link:", "portal:", "patch:", "git+", "git:", "github:",
		"http:", "https:", "catalog:",
	} {
		if strings.HasPrefix(lower, prefix) {
			return ""
		}
	}

	if i := strings.Index(s, "||"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	s = strings.TrimLeft(s, "^~><= ")
	if i := strings.IndexAny(s, " \t,"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if !npmVersionRe.MatchString(s) {
		return ""
	}
	return s
}

func parsePackageJSON(rel string, data []byte) ([]Package, error) {
	var doc struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Package
	appendDeps := func(deps map[string]string, dev bool) {
		for name, spec := range deps {
			name, spec = npmAliasTarget(name, spec)
			version := concreteNPMVersion(spec)
			if version == "" {
				continue
			}
			out = append(out, Package{
				Name:      name,
				Version:   version,
				Ecosystem: ecosystemNPM,
				Manifest:  rel,
				Line:      1,
				Dev:       dev,
			})
		}
	}
	appendDeps(doc.Dependencies, false)
	appendDeps(doc.DevDependencies, true)
	return out, nil
}

// --- PyPI ------------------------------------------------------------------

var requirementsRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)`)

func parseRequirementsTxt(rel string, data []byte) ([]Package, error) {
	var out []Package
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Environment markers are irrelevant to the installed version.
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		m := requirementsRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		version := strings.TrimSpace(m[2])
		if !validPyPIVersion(version) {
			continue
		}
		out = append(out, Package{
			Name:      normalizePyPIName(m[1]),
			Version:   version,
			Ecosystem: ecosystemPyPI,
			Manifest:  rel,
			Line:      i + 1,
		})
	}
	return out, nil
}

// validPyPIVersion rejects requirement specs that only look like versions
// after a range wildcard was truncated (for example "1.*" becoming "1.").
func validPyPIVersion(version string) bool {
	if version == "" || version[0] < '0' || version[0] > '9' {
		return false
	}
	if strings.ContainsAny(version, "*$") {
		return false
	}
	switch version[len(version)-1] {
	case '.', '-', '+', '!':
		return false
	}
	return true
}

// normalizePyPIName applies PEP 503 normalisation, which is what OSV stores.
func normalizePyPIName(name string) string {
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

// --- Go --------------------------------------------------------------------

type goRequire struct {
	name    string
	version string
	line    int
}

func parseGoMod(rel string, data []byte) ([]Package, error) {
	lines := splitLines(data)
	var requires []goRequire
	replaced := make(map[string]bool)
	mode := ""

	for i, raw := range lines {
		line := strings.TrimSpace(stripGoComment(raw))
		switch {
		case line == "":
			continue
		case line == ")":
			mode = ""
		case strings.HasPrefix(line, "require ("):
			mode = "require"
		case strings.HasPrefix(line, "replace ("):
			mode = "replace"
		case strings.HasPrefix(line, "require "):
			addGoRequire(strings.TrimSpace(strings.TrimPrefix(line, "require ")), i+1, &requires)
		case strings.HasPrefix(line, "replace "):
			addGoReplace(strings.TrimSpace(strings.TrimPrefix(line, "replace ")), replaced)
		case mode == "require":
			addGoRequire(line, i+1, &requires)
		case mode == "replace":
			addGoReplace(line, replaced)
		}
	}

	var out []Package
	for _, req := range requires {
		if replaced[req.name] {
			// A replaced module is no longer resolved from its declared
			// version, so querying that version would be misleading.
			continue
		}
		out = append(out, Package{
			Name:      req.name,
			Version:   req.version,
			Ecosystem: ecosystemGo,
			Manifest:  rel,
			Line:      req.line,
		})
	}
	return out, nil
}

// stripGoComment removes a trailing "// indirect" style comment. Go module
// paths cannot contain "//", so a plain index is safe here.
func stripGoComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

func addGoRequire(fields string, line int, out *[]goRequire) {
	parts := strings.Fields(fields)
	if len(parts) < 2 {
		return
	}
	name, version := parts[0], parts[1]
	if !strings.HasPrefix(version, "v") || strings.Contains(name, "=>") {
		return
	}
	*out = append(*out, goRequire{name: name, version: version, line: line})
}

func addGoReplace(fields string, out map[string]bool) {
	left := fields
	if i := strings.Index(left, "=>"); i >= 0 {
		left = left[:i]
	}
	parts := strings.Fields(left)
	if len(parts) == 0 {
		return
	}
	out[parts[0]] = true
}

// --- RubyGems --------------------------------------------------------------

var (
	gemSpecRe     = regexp.MustCompile(`^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)$`)
	gemPlatformRe = regexp.MustCompile(`-(?:x86_64|x64|arm64|aarch64|arm|universal|java|mswin|mingw)[^)]*$`)
)

func parseGemfileLock(rel string, data []byte) ([]Package, error) {
	var out []Package
	section := ""
	inSpecs := false

	for i, raw := range splitLines(data) {
		line := strings.TrimRight(raw, " \t")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section = strings.TrimSpace(line)
			inSpecs = false
			continue
		}
		if section != "GEM" {
			continue
		}
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		m := gemSpecRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		version := strings.TrimSpace(gemPlatformRe.ReplaceAllString(m[2], ""))
		if version == "" {
			continue
		}
		out = append(out, Package{
			Name:      m[1],
			Version:   version,
			Ecosystem: ecosystemRubyGems,
			Manifest:  rel,
			Line:      i + 1,
		})
	}
	return out, nil
}

// --- crates.io -------------------------------------------------------------

func parseCargoLock(rel string, data []byte) ([]Package, error) {
	var out []Package
	name, version, line := "", "", 0

	flush := func() {
		if name != "" && version != "" {
			if line <= 0 {
				line = 1
			}
			out = append(out, Package{
				Name:      name,
				Version:   version,
				Ecosystem: ecosystemCrates,
				Manifest:  rel,
				Line:      line,
			})
		}
		name, version, line = "", "", 0
	}

	for i, raw := range splitLines(data) {
		t := strings.TrimSpace(raw)
		switch {
		case t == "[[package]]":
			flush()
		case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
			// A new table (for example [metadata]) ends the current package.
			flush()
		default:
			key, value, ok := cargoKeyValue(t)
			if !ok {
				continue
			}
			switch key {
			case "name":
				name = value
				if line == 0 {
					line = i + 1
				}
			case "version":
				version = value
			}
		}
	}
	flush()
	return out, nil
}

func cargoKeyValue(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
	}
	return key, value, key != "" && value != ""
}

// --- Packagist -------------------------------------------------------------

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseComposerLock(rel string, data []byte) ([]Package, error) {
	var doc struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Package
	appendPackages := func(list []composerPackage, dev bool) {
		for _, p := range list {
			version := concreteComposerVersion(p.Version)
			if p.Name == "" || version == "" {
				continue
			}
			out = append(out, Package{
				Name:      p.Name,
				Version:   version,
				Ecosystem: ecosystemPackagist,
				Manifest:  rel,
				Line:      1,
				Dev:       dev,
			})
		}
	}
	appendPackages(doc.Packages, false)
	appendPackages(doc.PackagesDev, true)
	return out, nil
}

// concreteComposerVersion strips the leading "v" Composer accepts and skips
// branch aliases such as "dev-master" or "1.0.x-dev", which have no OSV match.
func concreteComposerVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "dev-") || strings.HasSuffix(lower, "-dev") {
		return ""
	}
	v = strings.TrimPrefix(v, "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return ""
	}
	return v
}

// --- Maven -----------------------------------------------------------------

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomProject struct {
	Dependencies        []pomDependency `xml:"dependencies>dependency"`
	ManagedDependencies []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
}

func parsePomXML(rel string, data []byte) ([]Package, error) {
	var doc pomProject
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Package
	appendDeps := func(deps []pomDependency) {
		for _, dep := range deps {
			group := strings.TrimSpace(dep.GroupID)
			artifact := strings.TrimSpace(dep.ArtifactID)
			version := strings.TrimSpace(dep.Version)
			if group == "" || artifact == "" || version == "" {
				continue
			}
			// Property placeholders and version ranges cannot be queried as an
			// exact OSV version.
			if strings.Contains(version, "${") || strings.HasPrefix(version, "[") || strings.HasPrefix(version, "(") {
				continue
			}
			out = append(out, Package{
				Name:      group + ":" + artifact,
				Version:   version,
				Ecosystem: ecosystemMaven,
				Manifest:  rel,
				Line:      1,
				Dev:       strings.EqualFold(strings.TrimSpace(dep.Scope), "test"),
			})
		}
	}
	appendDeps(doc.Dependencies)
	appendDeps(doc.ManagedDependencies)
	return out, nil
}

// --- shared helpers --------------------------------------------------------

// isConcreteVersion reports whether a lockfile value is an exact published
// version that OSV can match. Ranges, wildcards, git refs and local paths are
// not queryable.
func isConcreteVersion(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	return !strings.ContainsAny(v, "*$ \t/\\")
}

// sortedKeys returns the map keys in deterministic order so parsers that walk
// JSON objects emit a stable package list.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// yamlKeyValue splits one "key: value" YAML line. It is intentionally shallow:
// the lockfiles parsed here only need scalar properties.
func yamlKeyValue(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return key, value, key != "" && value != ""
}

// --- pnpm ------------------------------------------------------------------

// parsePNPMLock reads pnpm-lock.yaml (v6 and v9) without a YAML dependency.
// v6 keys look like "/pkg@1.2.3:" and v9 keys like "pkg@1.2.3:"; scoped names
// keep their leading "@". A pnpm v5 "/pkg/1.2.3:" key is also accepted.
func parsePNPMLock(rel string, data []byte) ([]Package, error) {
	var out []Package
	devNames := make(map[string]bool)
	prodNames := make(map[string]bool)
	section := ""
	importerSection := ""
	current := -1

	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))

		if indent == 0 {
			current = -1
			importerSection = ""
			switch key := strings.TrimSuffix(line, ":"); key {
			case "packages", "importers", "snapshots":
				section = key
			default:
				section = ""
			}
			continue
		}

		switch section {
		case "importers":
			// Direct dev dependencies are listed per importer; the packages
			// section itself carries no reliable dev flag in lockfile v9.
			if indent == 2 {
				importerSection = ""
				continue
			}
			if indent == 4 && strings.HasSuffix(line, ":") {
				switch strings.TrimSuffix(line, ":") {
				case "devDependencies":
					importerSection = "dev"
				case "dependencies", "optionalDependencies":
					importerSection = "prod"
				default:
					importerSection = ""
				}
				continue
			}
			if indent == 6 && importerSection != "" {
				if name := pnpmDependencyName(line); name != "" {
					if importerSection == "dev" {
						devNames[name] = true
					} else {
						prodNames[name] = true
					}
				}
			}
		case "packages":
			if indent == 2 && strings.HasSuffix(line, ":") {
				current = -1
				name, version, ok := parsePNPMKey(strings.TrimSuffix(line, ":"))
				if !ok {
					continue
				}
				out = append(out, Package{
					Name:      name,
					Version:   version,
					Ecosystem: ecosystemNPM,
					Manifest:  rel,
					Line:      i + 1,
				})
				current = len(out) - 1
				continue
			}
			// v6 records a dev flag on the resolved entry.
			if indent == 4 && current >= 0 && line == "dev: true" {
				out[current].Dev = true
			}
		}
	}

	for i := range out {
		if devNames[out[i].Name] && !prodNames[out[i].Name] {
			out[i].Dev = true
		}
	}
	return out, nil
}

func pnpmDependencyName(line string) string {
	if !strings.HasSuffix(line, ":") {
		return ""
	}
	name := strings.Trim(strings.TrimSuffix(line, ":"), `'"`)
	if name == "" || strings.ContainsAny(name, " \t") {
		return ""
	}
	return name
}

// parsePNPMKey extracts name and version from a packages-section key.
func parsePNPMKey(raw string) (string, string, bool) {
	key := strings.TrimSpace(raw)
	key = strings.TrimSuffix(key, ":")
	key = strings.Trim(key, `'"`)
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", "", false
	}
	for _, prefix := range []string{"link:", "file:", "workspace:"} {
		if strings.HasPrefix(key, prefix) {
			return "", "", false
		}
	}
	// Drop a peer-dependency suffix such as "pkg@1.2.3(react@18.2.0)".
	if i := strings.Index(key, "("); i > 0 {
		key = key[:i]
	}
	if i := strings.LastIndex(key, "@"); i > 0 {
		name, version := key[:i], key[i+1:]
		if name != "" && isConcreteVersion(version) {
			return name, version, true
		}
	}
	// pnpm v5 used "/pkg/1.2.3" and "/@scope/pkg/1.2.3".
	if i := strings.LastIndex(key, "/"); i > 0 {
		name, version := key[:i], key[i+1:]
		if name != "" && isConcreteVersion(version) {
			return name, version, true
		}
	}
	return "", "", false
}

// --- yarn ------------------------------------------------------------------

// parseYarnLock reads yarn.lock in both the v1 ("version \"1.2.3\"") and the
// Berry ("version: 1.2.3") format. Yarn does not record dev status in the
// lockfile, so every entry is production.
func parseYarnLock(rel string, data []byte) ([]Package, error) {
	var out []Package
	header := ""
	headerLine := 0
	emitted := false

	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))

		if indent == 0 {
			header, headerLine, emitted = "", 0, false
			if !strings.HasSuffix(line, ":") {
				continue
			}
			header = strings.TrimSuffix(line, ":")
			headerLine = i + 1
			continue
		}
		if header == "" || emitted || header == "__metadata" {
			continue
		}
		version, ok := yarnVersionValue(line)
		if !ok || !isConcreteVersion(version) {
			continue
		}
		name, ok := yarnSelectorName(header)
		if !ok {
			continue
		}
		out = append(out, Package{
			Name:      name,
			Version:   version,
			Ecosystem: ecosystemNPM,
			Manifest:  rel,
			Line:      headerLine,
		})
		emitted = true
	}
	return out, nil
}

func yarnVersionValue(line string) (string, bool) {
	switch {
	case strings.HasPrefix(line, "version "):
		return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version ")), `"'`), true
	case strings.HasPrefix(line, "version:"):
		return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version:")), `"'`), true
	default:
		return "", false
	}
}

// yarnSelectorName extracts the package name from a yarn block header such as
// "lodash@^4.17.20, lodash@^4.17.21" or "\"@scope/pkg@npm:^1.0.0\"".
func yarnSelectorName(header string) (string, bool) {
	first := header
	if i := strings.Index(first, ", "); i >= 0 {
		first = first[:i]
	}
	sel := strings.Trim(strings.TrimSpace(first), `"'`)
	if sel == "" {
		return "", false
	}
	i := strings.LastIndex(sel, "@")
	if i <= 0 {
		return "", false
	}
	name := sel[:i]
	// Berry aliases resolve to "alias@npm:real-package@^1.0.0".
	if j := strings.Index(name, "@npm:"); j > 0 {
		name = name[j+len("@npm:"):]
	}
	if name == "" || strings.ContainsAny(name, ":%") {
		return "", false
	}
	return name, true
}

// --- Pipfile.lock ----------------------------------------------------------

type pipfileEntry struct {
	Version string `json:"version"`
	Git     string `json:"git"`
	Path    string `json:"path"`
	File    string `json:"file"`
}

// parsePipfileLock reads the JSON lockfile written by Pipenv. Only pinned
// "==x.y.z" entries are usable; git, path and file requirements have no OSV
// version.
func parsePipfileLock(rel string, data []byte) ([]Package, error) {
	var doc struct {
		Default map[string]pipfileEntry `json:"default"`
		Develop map[string]pipfileEntry `json:"develop"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Package
	appendSection := func(deps map[string]pipfileEntry, dev bool) {
		for _, name := range sortedKeys(deps) {
			entry := deps[name]
			if entry.Git != "" || entry.Path != "" || entry.File != "" {
				continue
			}
			version := strings.TrimSpace(entry.Version)
			version = strings.TrimSpace(strings.TrimPrefix(version, "=="))
			if !validPyPIVersion(version) {
				continue
			}
			out = append(out, Package{
				Name:      normalizePyPIName(name),
				Version:   version,
				Ecosystem: ecosystemPyPI,
				Manifest:  rel,
				Line:      1,
				Dev:       dev,
			})
		}
	}
	appendSection(doc.Default, false)
	appendSection(doc.Develop, true)
	return out, nil
}

// --- poetry.lock -----------------------------------------------------------

// parsePoetryLock reads the TOML [[package]] tables line by line. Poetry 1.x
// marks dev packages with category = "dev"; Poetry 2.x uses groups, where a
// package is a dev dependency when "main" is not among its groups.
func parsePoetryLock(rel string, data []byte) ([]Package, error) {
	var out []Package
	name, version, line := "", "", 0
	dev := false

	flush := func() {
		if name != "" && isConcreteVersion(version) {
			out = append(out, Package{
				Name:      name,
				Version:   version,
				Ecosystem: ecosystemPyPI,
				Manifest:  rel,
				Line:      line,
				Dev:       dev,
			})
		}
		name, version, line, dev = "", "", 0, false
	}

	for i, raw := range splitLines(data) {
		t := strings.TrimSpace(raw)
		switch {
		case t == "[[package]]":
			flush()
		case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
			// Nested tables ([package.dependencies], [package.extras]) belong
			// to the current package; only [[package]] starts a new one.
		default:
			key, value, ok := cargoKeyValue(t)
			if !ok {
				continue
			}
			switch key {
			case "name":
				if name == "" {
					name = value
					if line == 0 {
						line = i + 1
					}
				}
			case "version":
				if version == "" {
					version = value
				}
			case "category":
				dev = strings.EqualFold(value, "dev")
			case "groups":
				if groups := parseTOMLStringArray(value); len(groups) > 0 {
					dev = true
					for _, group := range groups {
						if group == "main" {
							dev = false
						}
					}
				}
			}
		}
	}
	flush()
	return out, nil
}

// parseTOMLStringArray reads a simple inline TOML array such as
// ["main", "dev"] without a TOML dependency.
func parseTOMLStringArray(value string) []string {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// --- uv.lock ---------------------------------------------------------------

// parseUVLock reads the TOML [[package]] tables written by uv. Editable and
// virtual entries are the project itself, not published packages.
func parseUVLock(rel string, data []byte) ([]Package, error) {
	var out []Package
	name, version, source, line := "", "", "", 0

	flush := func() {
		if name != "" && isConcreteVersion(version) && !isLocalPythonSource(source) {
			out = append(out, Package{
				Name:      name,
				Version:   version,
				Ecosystem: ecosystemPyPI,
				Manifest:  rel,
				Line:      line,
			})
		}
		name, version, source, line = "", "", "", 0
	}

	for i, raw := range splitLines(data) {
		t := strings.TrimSpace(raw)
		switch {
		case t == "[[package]]":
			flush()
		case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
		default:
			key, value, ok := cargoKeyValue(t)
			if !ok {
				continue
			}
			switch key {
			case "name":
				if name == "" {
					name = value
					if line == 0 {
						line = i + 1
					}
				}
			case "version":
				if version == "" {
					version = value
				}
			case "source":
				if source == "" {
					source = value
				}
			}
		}
	}
	flush()
	return out, nil
}

func isLocalPythonSource(source string) bool {
	s := strings.ToLower(source)
	return strings.Contains(s, "editable") ||
		strings.Contains(s, "virtual") ||
		strings.Contains(s, "directory")
}

// --- pubspec.lock ----------------------------------------------------------

// parsePubspecLock reads the YAML lockfile written by Dart and Flutter. Path,
// git and SDK dependencies are local or non-registry, so they are skipped.
func parsePubspecLock(rel string, data []byte) ([]Package, error) {
	var out []Package
	inPackages := false
	name, version, dependency, source, line := "", "", "", "", 0

	flush := func() {
		dev := dependency == "direct dev"
		hosted := source == "" || source == "hosted"
		if name != "" && hosted && isConcreteVersion(version) {
			out = append(out, Package{
				Name:      name,
				Version:   version,
				Ecosystem: ecosystemPub,
				Manifest:  rel,
				Line:      line,
				Dev:       dev,
			})
		}
		name, version, dependency, source, line = "", "", "", "", 0
	}

	for i, raw := range splitLines(data) {
		lineText := strings.TrimSpace(raw)
		if lineText == "" || strings.HasPrefix(lineText, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))

		if indent == 0 {
			flush()
			inPackages = strings.HasSuffix(lineText, ":") &&
				strings.TrimSuffix(lineText, ":") == "packages"
			continue
		}
		if !inPackages {
			continue
		}
		if indent == 2 && strings.HasSuffix(lineText, ":") {
			flush()
			name = strings.Trim(strings.TrimSuffix(lineText, ":"), `'"`)
			line = i + 1
			continue
		}
		if indent != 4 {
			continue
		}
		key, value, ok := yamlKeyValue(lineText)
		if !ok {
			continue
		}
		switch key {
		case "dependency":
			dependency = value
		case "source":
			source = value
		case "version":
			version = value
		}
	}
	flush()
	return out, nil
}

// --- Gradle ----------------------------------------------------------------

// parseGradleLockfile reads the flat "group:artifact:version=configurations"
// format produced by Gradle dependency locking. A dependency is treated as dev
// when every locked configuration is test-only.
func parseGradleLockfile(rel string, data []byte) ([]Package, error) {
	var out []Package
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		left, configurations, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		left = strings.TrimSpace(left)
		if left == "" || left == "empty" {
			continue
		}
		parts := strings.Split(left, ":")
		if len(parts) != 3 {
			continue
		}
		group := strings.TrimSpace(parts[0])
		artifact := strings.TrimSpace(parts[1])
		version := strings.TrimSpace(parts[2])
		if group == "" || artifact == "" || !isConcreteVersion(version) {
			continue
		}
		out = append(out, Package{
			Name:      group + ":" + artifact,
			Version:   version,
			Ecosystem: ecosystemMaven,
			Manifest:  rel,
			Line:      i + 1,
			Dev:       allTestConfigurations(configurations),
		})
	}
	return out, nil
}

func allTestConfigurations(list string) bool {
	seen := false
	for _, configuration := range strings.Split(list, ",") {
		configuration = strings.TrimSpace(configuration)
		if configuration == "" {
			continue
		}
		seen = true
		if !strings.Contains(strings.ToLower(configuration), "test") {
			return false
		}
	}
	return seen
}

// --- NuGet -----------------------------------------------------------------

type nugetLockEntry struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// parseNuGetLock reads packages.lock.json. Dependencies are grouped by target
// framework, so the same package may appear under "net8.0" and
// "net8.0/win-x64"; dedupePackages collapses identical coordinates.
func parseNuGetLock(rel string, data []byte) ([]Package, error) {
	var doc struct {
		Dependencies map[string]map[string]nugetLockEntry `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Package
	for _, framework := range sortedKeys(doc.Dependencies) {
		packages := doc.Dependencies[framework]
		for _, name := range sortedKeys(packages) {
			entry := packages[name]
			if strings.EqualFold(entry.Type, "Project") {
				continue
			}
			if !isConcreteVersion(entry.Resolved) {
				continue
			}
			out = append(out, Package{
				Name:      name,
				Version:   entry.Resolved,
				Ecosystem: ecosystemNuGet,
				Manifest:  rel,
				Line:      1,
			})
		}
	}
	return out, nil
}
