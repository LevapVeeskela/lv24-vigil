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

// collectPackages walks root, parses every supported manifest and returns the
// deduplicated, sorted package list capped at max.
func collectPackages(ctx context.Context, root string, includeDev bool, max int) ([]Package, error) {
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

	// Parse lockfiles first so package.json is only used when its directory has
	// no usable lockfile. A malformed lockfile deliberately falls back to the
	// semver ranges in package.json.
	var packages []Package
	lockDirs := make(map[string]bool)
	for _, f := range files {
		if f.kind != kindPackageLock {
			continue
		}
		parsed, err := parseManifestFile(f)
		if err != nil {
			continue
		}
		lockDirs[path.Dir(f.rel)] = true
		packages = append(packages, parsed...)
		if len(packages) >= maxCollectedPackages {
			break
		}
	}
	for _, f := range files {
		if f.kind == kindPackageLock {
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

func manifestKindFor(name string) (manifestKind, bool) {
	switch strings.ToLower(name) {
	case "package.json":
		return kindPackageJSON, true
	case "package-lock.json":
		return kindPackageLock, true
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
