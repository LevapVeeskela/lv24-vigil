package osv

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/levapveeskela/lv24-vigil/internal/safepath"
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
	// maxRequirementsIncludeDepth bounds -r/--requirement chains.
	maxRequirementsIncludeDepth = 8
	// maxRequirementsIncludes bounds how many distinct files one requirements
	// tree may pull in.
	maxRequirementsIncludes = 200
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
	kindPyProject
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

// manifestExcludePattern is one compiled exclude glob. The semantics
// deliberately mirror the scanner's include/exclude list
// (internal/scanner/ignore.go) so one .vigil.yaml selects the same tree for
// `vigil scan` and `vigil sbom`. The scanner package cannot be imported here
// without an import cycle, so the small glob translator is repeated.
type manifestExcludePattern struct {
	re      *regexp.Regexp
	dirOnly bool
}

// manifestExcludes is a compiled, nil-safe set of exclude patterns.
type manifestExcludes struct {
	patterns []manifestExcludePattern
}

// newManifestExcludes compiles raw patterns. Invalid or empty patterns are
// dropped, and an empty result is nil so callers take the fast path.
func newManifestExcludes(raw []string) *manifestExcludes {
	if len(raw) == 0 {
		return nil
	}
	set := &manifestExcludes{}
	for _, pattern := range raw {
		if compiled := compileManifestExclude(pattern); compiled != nil {
			set.patterns = append(set.patterns, *compiled)
		}
	}
	if len(set.patterns) == 0 {
		return nil
	}
	return set
}

// excludes reports whether rel (slash-separated, relative to the scan root) is
// excluded. A file also inherits the exclude of a parent directory, which keeps
// directory patterns effective for paths resolved outside the walk (requirements
// includes).
func (s *manifestExcludes) excludes(rel string, isDir bool) bool {
	if s == nil {
		return false
	}
	for i := range s.patterns {
		if s.patterns[i].matches(rel, isDir) {
			return true
		}
		if isDir {
			continue
		}
		for dir := path.Dir(rel); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if s.patterns[i].matches(dir, true) {
				return true
			}
		}
	}
	return false
}

func (g *manifestExcludePattern) matches(rel string, isDir bool) bool {
	if g.dirOnly && !isDir {
		return false
	}
	if g.re.MatchString(rel) {
		return true
	}
	return isDir && g.re.MatchString(rel+"/")
}

// compileManifestExclude translates one pattern into an anchored regular
// expression. "**" crosses directories, "*" and "?" stay within one segment and
// every other character is literal, so a pattern such as "x[1].txt" keeps its
// brackets.
func compileManifestExclude(raw string) *manifestExcludePattern {
	p := strings.TrimSpace(raw)
	if p == "" {
		return nil
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}

	baseOnly := !strings.Contains(p, "/")
	expr := manifestGlobRegexp(p)
	if baseOnly {
		expr = `(?:.*/)?` + expr
	}
	re, err := regexp.Compile(`^` + expr + `$`)
	if err != nil {
		return nil
	}
	return &manifestExcludePattern{re: re, dirOnly: dirOnly}
}

func manifestGlobRegexp(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); {
		switch p[i] {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				i += 2
				if i < len(p) && p[i] == '/' {
					b.WriteString(`(?:.*/)?`)
					i++
				} else {
					b.WriteString(`.*`)
				}
				continue
			}
			b.WriteString(`[^/]*`)
			i++
		case '?':
			b.WriteString(`[^/]`)
			i++
		default:
			j := i
			for j < len(p) && p[j] != '*' && p[j] != '?' {
				j++
			}
			b.WriteString(regexp.QuoteMeta(p[i:j]))
			i = j
		}
	}
	return b.String()
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
	pkgs, _, err := collectPackages(ctx, root, includeDev, max)
	return pkgs, err
}

// CollectPackagesWithExcludes is CollectPackages with an exclude list and the
// coverage warnings the cap and skipped manifests produce.
//
// excludes are slash-separated globs relative to root that follow the scanner's
// exclude semantics: "**" crosses directory boundaries, "*" and "?" do not, a
// pattern without a slash matches a base name at any depth (for example
// "*.lock"), and a matching directory is pruned entirely. A nil or empty list
// collects the whole tree.
//
// The warnings are what CollectPackages has always dropped: manifests that could
// not be parsed, walk and requirements limits that were hit and an inventory
// truncated by max. They must be shown, because a truncated or partial
// inventory otherwise looks complete.
func CollectPackagesWithExcludes(ctx context.Context, root string, includeDev bool, max int, excludes []string) ([]Package, []string, error) {
	return collectPackagesExcluding(ctx, root, includeDev, max, newManifestExcludes(excludes))
}

// collectPackages is CollectPackages plus coverage warnings: manifests that
// were skipped (oversized or unparseable), walk limits that were hit and an
// inventory truncated by max. A skipped manifest must never look like a
// clean result, so callers surface these next to query errors.
func collectPackages(ctx context.Context, root string, includeDev bool, max int) ([]Package, []string, error) {
	return collectPackagesExcluding(ctx, root, includeDev, max, nil)
}

// collectPackagesExcluding is collectPackages with an optional exclude set; a
// nil set walks the whole tree.
func collectPackagesExcluding(ctx context.Context, root string, includeDev bool, max int, excludes *manifestExcludes) ([]Package, []string, error) {
	var warnings []string
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, fmt.Errorf("osv: resolve scan root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("osv: scan root %s: %w", absRoot, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("osv: scan root %s is not a directory", absRoot)
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
			if excludes.excludes(rel, true) {
				return filepath.SkipDir
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
		if excludes.excludes(rel, false) {
			return nil
		}
		kind, ok := manifestKindFor(d.Name())
		if !ok {
			return nil
		}
		if fi, err := d.Info(); err != nil || fi.Size() > maxManifestBytes {
			warnings = append(warnings, fmt.Sprintf("osv: skipped %s: larger than %d bytes or unreadable", rel, maxManifestBytes))
			return nil
		}
		if len(files) >= maxManifestFiles {
			warnings = append(warnings, fmt.Sprintf("osv: stopped after %d manifests; the rest of the tree was not read", maxManifestFiles))
			return filepath.SkipAll
		}
		files = append(files, manifestFile{abs: p, rel: rel, kind: kind})
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("osv: walk %s: %w", absRoot, walkErr)
	}
	if len(files) == 0 {
		return nil, warnings, nil
	}

	// Parse lockfiles first so a manifest is only used when its directory has
	// no usable lockfile. Requirements includes must honour the same excludes
	// as the walk: an include may name a file the walk refused to enter.
	reqBudget := newRequirementsParseBudget(ctx, absRoot)
	reqBudget.excludes = excludes
	var packages []Package
	lockDirs := make(map[string]bool)
	for _, f := range files {
		if !isLockfileKind(f.kind) {
			continue
		}
		parsed, fileWarnings, err := parseManifestFile(absRoot, f, reqBudget)
		warnings = append(warnings, fileWarnings...)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("osv: skipped %s: %s", f.rel, boundedError(err)))
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
		parsed, fileWarnings, err := parseManifestFile(absRoot, f, reqBudget)
		warnings = append(warnings, fileWarnings...)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("osv: skipped %s: %s", f.rel, boundedError(err)))
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
	if max > 0 && len(packages) > max {
		warnings = append(warnings, fmt.Sprintf("osv: inventory truncated at the %d package cap: found %d packages but only the first %d (sorted by ecosystem and name) were kept; raise the package limit for full coverage", max, len(packages), max))
	}
	return capPackages(packages, max), warnings, nil
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
	lower := strings.ToLower(name)
	// pip requirement files are often split by purpose: requirements-dev.txt,
	// requirements_prod.txt or requirements.prod.txt. The exact requirements.txt
	// is covered by the same prefix/suffix check.
	if strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt") {
		return kindRequirements, true
	}
	switch lower {
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
	case "pyproject.toml":
		return kindPyProject, true
	case "packages.lock.json":
		return kindNuGetLock, true
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

// parseManifestFile parses one discovered manifest. The returned warnings are
// per-file coverage gaps (for example an unreadable requirements include) that
// must not be mistaken for a clean parse. reqBudget is shared by every
// requirements file of one scan; other kinds ignore it.
func parseManifestFile(root string, f manifestFile, reqBudget *requirementsParseBudget) ([]Package, []string, error) {
	data, err := os.ReadFile(f.abs)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, nil, fmt.Errorf("manifest exceeds %d bytes", maxManifestBytes)
	}
	switch f.kind {
	case kindPackageJSON:
		pkgs, err := parsePackageJSON(f.rel, data)
		return pkgs, nil, err
	case kindPackageLock:
		pkgs, err := parsePackageLock(f.rel, data)
		return pkgs, nil, err
	case kindPNPMLock:
		pkgs, err := parsePNPMLock(f.rel, data)
		return pkgs, nil, err
	case kindYarnLock:
		pkgs, err := parseYarnLock(f.rel, data)
		return pkgs, nil, err
	case kindPipfileLock:
		pkgs, err := parsePipfileLock(f.rel, data)
		return pkgs, nil, err
	case kindPoetryLock:
		pkgs, err := parsePoetryLock(f.rel, data)
		return pkgs, nil, err
	case kindUVLock:
		pkgs, err := parseUVLock(f.rel, data)
		return pkgs, nil, err
	case kindPubspecLock:
		pkgs, err := parsePubspecLock(f.rel, data)
		return pkgs, nil, err
	case kindGradleLockfile:
		pkgs, err := parseGradleLockfile(f.rel, data)
		return pkgs, nil, err
	case kindNuGetLock:
		pkgs, err := parseNuGetLock(f.rel, data)
		return pkgs, nil, err
	case kindRequirements:
		pkgs, warnings := parseRequirementsFile(root, f, data, reqBudget)
		return pkgs, warnings, nil
	case kindPyProject:
		pkgs, warnings := parsePyProject(f.rel, data)
		return pkgs, warnings, nil
	case kindGoMod:
		pkgs, err := parseGoMod(f.rel, data)
		return pkgs, nil, err
	case kindGemfileLock:
		pkgs, err := parseGemfileLock(f.rel, data)
		return pkgs, nil, err
	case kindCargoLock:
		pkgs, err := parseCargoLock(f.rel, data)
		return pkgs, nil, err
	case kindComposerLock:
		pkgs, err := parseComposerLock(f.rel, data)
		return pkgs, nil, err
	case kindPomXML:
		pkgs, err := parsePomXML(f.rel, data)
		return pkgs, nil, err
	default:
		return nil, nil, nil
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
		installed := npmNameFromPath(key)
		if installed == "" || entry.Link {
			continue
		}
		// An aliased install ("alias": "npm:real@1.0.0") lives under the alias
		// path and records the published package in "name".
		name := installed
		if real := strings.TrimSpace(entry.Name); real != "" {
			name = real
		}
		version, ok := npmRegistryVersion(entry.Version)
		if !ok {
			continue
		}
		out = append(out, Package{
			Name:      name,
			Version:   version,
			Ecosystem: ecosystemNPM,
			Manifest:  rel,
			Line:      1,
			Dev:       entry.Dev || devNames[installed],
		})
	}

	// Lockfile v1 stores a nested dependency tree instead of "packages". Its
	// "version" holds the spec for anything that is not a registry install: a
	// git or tarball URL (which can carry a credential), a file path, or an
	// "npm:real@1.0.0" alias. Only a registry version may leave this parser.
	var walk func(deps map[string]npmLockDependency)
	walk = func(deps map[string]npmLockDependency) {
		for name, dep := range deps {
			real, spec := npmAliasTarget(name, dep.Version)
			if version, ok := npmRegistryVersion(spec); ok {
				out = append(out, Package{
					Name:      real,
					Version:   version,
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

// npmRegistryVersion reports whether a lockfile "version" is a published
// registry version. Git, tarball, file and alias specs are rejected: OSV cannot
// match them, and they would otherwise be sent to the API and written to an
// SBOM verbatim.
func npmRegistryVersion(raw string) (string, bool) {
	version := strings.TrimSpace(raw)
	if !npmVersionRe.MatchString(version) {
		return "", false
	}
	return version, true
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
// specs, and ranges without an inclusive lower bound, are skipped rather than
// queried blindly.
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
	// "<2.0.0", "<=2.0.0" and ">1.0.0" name a version the range does not have
	// as its lowest member, so there is nothing concrete to query.
	if strings.HasPrefix(s, "<") || (strings.HasPrefix(s, ">") && !strings.HasPrefix(s, ">=")) {
		return ""
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

// parsePyPIRequirement extracts an exact name==version pin from one PEP 508
// requirement string. Ranges, direct references and unpinned names are skipped
// because OSV needs a concrete installed version.
func parsePyPIRequirement(raw string) (string, string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
		return "", "", false
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
		return "", "", false
	}
	version := strings.TrimSpace(m[2])
	if !validPyPIVersion(version) {
		return "", "", false
	}
	return normalizePyPIName(m[1]), version, true
}

// requirementsParseBudget is shared by every requirements file of one scan. A
// crafted repository can discover many requirements*.txt roots, and each root
// could otherwise re-parse the same include tree with a fresh depth, include
// and package budget; this type makes those limits scan-wide. It also carries
// the audit context so cancellation stops parsing promptly.
type requirementsParseBudget struct {
	ctx         context.Context
	root        string
	excludes    *manifestExcludes
	visited     map[string]bool
	includes    int
	maxIncludes int
	packages    int
	maxPackages int
	packageWarn bool
	includeWarn bool
	ctxWarn     bool
}

func newRequirementsParseBudget(ctx context.Context, root string) *requirementsParseBudget {
	if ctx == nil {
		ctx = context.Background()
	}
	return &requirementsParseBudget{
		ctx:         ctx,
		root:        root,
		visited:     make(map[string]bool),
		maxIncludes: maxRequirementsIncludes,
		maxPackages: maxCollectedPackages,
	}
}

// halted reports whether parsing must stop. It emits at most one warning per
// cause so a huge tree does not produce a warning per line.
func (s *requirementsParseBudget) halted(warnings *[]string) bool {
	if err := s.ctx.Err(); err != nil {
		if !s.ctxWarn {
			s.ctxWarn = true
			*warnings = append(*warnings, fmt.Sprintf("osv: requirements parsing stopped: %s", boundedError(err)))
		}
		return true
	}
	if s.packages >= s.maxPackages {
		if !s.packageWarn {
			s.packageWarn = true
			*warnings = append(*warnings, fmt.Sprintf("osv: requirements parsing stopped after %d packages; the rest of the requirements tree was not read", s.maxPackages))
		}
		return true
	}
	return false
}

func (s *requirementsParseBudget) includeLimitReached(warnings *[]string) bool {
	if s.includes < s.maxIncludes {
		return false
	}
	if !s.includeWarn {
		s.includeWarn = true
		*warnings = append(*warnings, fmt.Sprintf("osv: requirements includes stopped after %d files", s.maxIncludes))
	}
	return true
}

func parseRequirementsFile(root string, f manifestFile, data []byte, budget *requirementsParseBudget) ([]Package, []string) {
	if budget == nil {
		budget = newRequirementsParseBudget(nil, root)
	}
	// Each root gets its own visited set: the same include may be reachable
	// from a production and a dev root, and the dev marker must stay correct
	// per tree. The scan-wide budget (counts and context) is still shared.
	budget.visited = map[string]bool{canonicalManifestPath(f.abs): true}
	var out []Package
	var warnings []string
	budget.parse(f.abs, f.rel, data, 0, false, &out, &warnings)
	return out, warnings
}

// parse walks one requirements file. dev is inherited by includes so the whole
// tree of a requirements-dev.txt is treated as development dependencies.
func (s *requirementsParseBudget) parse(abs, rel string, data []byte, depth int, dev bool, out *[]Package, warnings *[]string) {
	dev = dev || isDevRequirementsFile(rel)
	for i, raw := range splitLines(decodeRequirementsText(data)) {
		if s.halted(warnings) {
			return
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if include, ok := requirementsIncludePath(line); ok {
			s.include(abs, rel, include, depth, dev, out, warnings)
			continue
		}
		// Other pip options (-e, -c, --hash, --index-url) do not name an
		// installed dependency.
		if strings.HasPrefix(line, "-") {
			continue
		}
		name, version, ok := parsePyPIRequirement(line)
		if !ok {
			continue
		}
		s.packages++
		*out = append(*out, Package{
			Name:      name,
			Version:   version,
			Ecosystem: ecosystemPyPI,
			Manifest:  rel,
			Line:      i + 1,
			Dev:       dev,
		})
	}
}

func (s *requirementsParseBudget) include(abs, rel, target string, depth int, dev bool, out *[]Package, warnings *[]string) {
	if isRemoteRequirementsInclude(target) {
		*warnings = append(*warnings, fmt.Sprintf("osv: %s: remote requirements include %q was not fetched", rel, target))
		return
	}
	if s.halted(warnings) {
		return
	}
	if depth >= maxRequirementsIncludeDepth {
		*warnings = append(*warnings, fmt.Sprintf("osv: %s: requirements include %q exceeds the depth limit of %d", rel, target, maxRequirementsIncludeDepth))
		return
	}
	if s.includeLimitReached(warnings) {
		return
	}

	targetAbs := target
	if !filepath.IsAbs(targetAbs) {
		targetAbs = filepath.Join(filepath.Dir(abs), filepath.FromSlash(target))
	}
	targetAbs = filepath.Clean(targetAbs)

	targetRel, ok := s.relativeToRoot(rel, targetAbs, target, warnings)
	if !ok {
		return
	}
	if dir := skippedManifestDir(targetRel); dir != "" {
		*warnings = append(*warnings, fmt.Sprintf("osv: %s: requirements include %q is inside the skipped directory %q", rel, target, dir))
		return
	}
	if s.excludes.excludes(targetRel, false) {
		*warnings = append(*warnings, fmt.Sprintf("osv: %s: requirements include %q is excluded by the scan exclude list", rel, target))
		return
	}
	// relativeToRoot is lexical. Reading follows symlinks and junctions, so an
	// include through a link could still leave the scan root.
	if s.root != "" {
		if _, err := safepath.Resolve(s.root, targetRel); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("osv: %s: requirements include %q is outside the scan root", rel, target))
			return
		}
	}

	key := canonicalManifestPath(targetAbs)
	if s.visited[key] {
		// Already parsed, or a cycle; either way parsing it again adds nothing.
		return
	}
	s.visited[key] = true

	data, err := readManifestBytes(targetAbs)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("osv: %s: requirements include %q: %s", rel, target, pathlessError(err)))
		return
	}
	s.includes++
	s.parse(targetAbs, targetRel, data, depth+1, dev, out, warnings)
}

// relativeToRoot resolves an include to a slash path under the scan root and
// rejects includes that escape it.
func (s *requirementsParseBudget) relativeToRoot(rel, targetAbs, target string, warnings *[]string) (string, bool) {
	if s.root == "" {
		return filepath.ToSlash(targetAbs), true
	}
	relFromRoot, err := filepath.Rel(s.root, targetAbs)
	if err != nil || relFromRoot == ".." || strings.HasPrefix(relFromRoot, ".."+string(filepath.Separator)) {
		*warnings = append(*warnings, fmt.Sprintf("osv: %s: requirements include %q is outside the scan root", rel, target))
		return "", false
	}
	return filepath.ToSlash(relFromRoot), true
}

// skippedManifestDir reports the first skipped directory segment of rel, or ""
// when the path is collectable. Includes must honour the same directories the
// walk refuses to enter (installed and generated copies).
func skippedManifestDir(rel string) string {
	for _, segment := range strings.Split(filepath.ToSlash(rel), "/") {
		if skipManifestDirs[strings.ToLower(segment)] {
			return segment
		}
	}
	return ""
}

// isDevRequirementsFile reports whether a requirements file name marks a
// development or test dependency set, matching the dev semantics used for npm
// devDependencies, composer packages-dev and Maven test scope.
func isDevRequirementsFile(rel string) bool {
	name := strings.ToLower(path.Base(filepath.ToSlash(rel)))
	name = strings.TrimPrefix(name, "requirements")
	name = strings.TrimSuffix(name, ".txt")
	for _, token := range strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	}) {
		switch token {
		case "dev", "development", "test", "tests", "testing":
			return true
		}
	}
	return false
}

// requirementsIncludePath recognises -r and --requirement directives, including
// the "=", attached and quoted forms.
func requirementsIncludePath(line string) (string, bool) {
	line = strings.TrimSpace(line)
	var rest string
	switch {
	case strings.HasPrefix(line, "--requirement"):
		rest = strings.TrimPrefix(line, "--requirement")
		if strings.HasPrefix(rest, "=") {
			rest = rest[1:]
		} else if rest != "" && !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "\t") {
			return "", false
		}
	case strings.HasPrefix(line, "-r"):
		rest = strings.TrimPrefix(line, "-r")
	default:
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if idx := strings.Index(rest, " #"); idx >= 0 {
		rest = strings.TrimSpace(rest[:idx])
	}
	rest = strings.Trim(rest, `"'`)
	if rest == "" {
		return "", false
	}
	return rest, true
}

func isRemoteRequirementsInclude(target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	for _, prefix := range []string{"http://", "https://", "git+", "ssh://", "file://"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// canonicalManifestPath normalises a path for cycle detection. Windows paths are
// case-insensitive, so they are folded; on other systems a case difference can
// name a different file.
func canonicalManifestPath(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// pathlessError describes a file error without the absolute path the operating
// system puts in it. Warnings are copied into scan results and SBOM
// properties, where a local path is both a leak and a source of
// machine-dependent output.
func pathlessError(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		if errors.Is(err, fs.ErrNotExist) {
			return "file not found"
		}
		return boundedError(pathErr.Err)
	}
	return boundedError(err)
}

// decodeRequirementsText returns requirements data as UTF-8 text. pip accepts a
// UTF-8 byte-order mark and UTF-16 files (what "pip freeze > requirements.txt"
// writes in Windows PowerShell 5.1); without decoding, the first pin or the
// whole file would be dropped silently.
func decodeRequirementsText(data []byte) []byte {
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		return data[3:]
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		return decodeUTF16(data[2:], binary.LittleEndian)
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		return decodeUTF16(data[2:], binary.BigEndian)
	default:
		return data
	}
}

func decodeUTF16(data []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, order.Uint16(data[i:]))
	}
	return []byte(string(utf16.Decode(units)))
}

// readManifestBytes reads one manifest or include with the same size bound as a
// discovered manifest.
func readManifestBytes(abs string) ([]byte, error) {
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", maxManifestBytes)
	}
	return os.ReadFile(abs)
}

// parsePyProject collects PEP 621 [project].dependencies. The project may
// declare dependencies as dynamic, in which case the build backend owns the
// real list and guessing it here would be wrong.
//
// A UTF-8 BOM is stripped first: Windows editors add one and it would hide the
// first table header. Arrays containing triple-quoted (multi-line) strings are
// skipped with a warning, because a line-based scanner cannot read them
// without misparsing the rest of the array.
func parsePyProject(rel string, data []byte) ([]Package, []string) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	lines := splitLines(data)
	var out []Package
	var warnings []string
	section := ""
	dynamic := false

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			header := line
			if idx := strings.Index(header, "#"); idx >= 0 {
				header = strings.TrimSpace(header[:idx])
			}
			if strings.HasSuffix(header, "]") {
				section = strings.TrimSpace(header[1 : len(header)-1])
				continue
			}
		}
		if section != "project" {
			continue
		}
		key, value, ok := cargoKeyValue(line)
		if !ok || !strings.HasPrefix(value, "[") {
			continue
		}
		switch key {
		case "dependencies":
			elements, last, skipped := scanTOMLArrayStrings(lines, i, value)
			i = last
			if skipped {
				warnings = append(warnings, fmt.Sprintf("osv: %s: [project].dependencies uses a triple-quoted (multi-line) string; the array was skipped", rel))
				continue
			}
			for _, element := range elements {
				name, version, ok := parsePyPIRequirement(element.value)
				if !ok {
					continue
				}
				out = append(out, Package{
					Name:      name,
					Version:   version,
					Ecosystem: ecosystemPyPI,
					Manifest:  rel,
					Line:      element.line,
				})
			}
		case "dynamic":
			elements, last, _ := scanTOMLArrayStrings(lines, i, value)
			i = last
			for _, element := range elements {
				if strings.TrimSpace(element.value) == "dependencies" {
					dynamic = true
				}
			}
		default:
			// Consume unrelated arrays so their contents cannot be mistaken
			// for [project] keys.
			_, last, _ := scanTOMLArrayStrings(lines, i, value)
			i = last
		}
	}
	if dynamic {
		return nil, warnings
	}
	return out, warnings
}

type tomlArrayString struct {
	value string
	line  int
}

// scanTOMLArrayStrings reads the quoted strings of a TOML array that starts on
// start and may continue on following lines. It returns the last consumed line
// and whether the array contained a triple-quoted string, in which case the
// returned elements are incomplete and the caller must skip the array.
func scanTOMLArrayStrings(lines []string, start int, first string) ([]tomlArrayString, int, bool) {
	var out []tomlArrayString
	var scanner tomlArrayScanner
	index := start
	line := first
	for {
		scanner.feed(line, index+1, &out)
		if scanner.complete {
			return out, index, scanner.triple
		}
		index++
		if index >= len(lines) {
			return out, index - 1, scanner.triple
		}
		line = lines[index]
	}
}

// tomlArrayScanner is a bounded, quote-aware scanner for one TOML array.
type tomlArrayScanner struct {
	depth      int
	started    bool
	complete   bool
	inString   bool
	quote      byte
	escaped    bool
	inMulti    bool
	multiQuote byte
	triple     bool
	buf        strings.Builder
	elemLine   int
}

func (p *tomlArrayScanner) feed(line string, lineNo int, out *[]tomlArrayString) {
	for i := 0; i < len(line); i++ {
		if p.inMulti {
			idx := strings.Index(line[i:], strings.Repeat(string(p.multiQuote), 3))
			if idx < 0 {
				return
			}
			i += idx + 2 // the loop increment lands after the closing delimiter
			p.inMulti = false
			continue
		}
		ch := line[i]
		if p.inString {
			if p.quote == '"' && p.escaped {
				p.buf.WriteByte(ch)
				p.escaped = false
				continue
			}
			if p.quote == '"' && ch == '\\' {
				p.buf.WriteByte(ch)
				p.escaped = true
				continue
			}
			if ch == p.quote {
				*out = append(*out, tomlArrayString{value: p.stringValue(), line: p.elemLine})
				p.inString = false
				p.buf.Reset()
				continue
			}
			p.buf.WriteByte(ch)
			continue
		}
		switch ch {
		case '#':
			return
		case '"', '\'':
			if i+2 < len(line) && line[i+1] == ch && line[i+2] == ch {
				// A triple-quoted string makes the array unparsable line by
				// line; remember that and skip to the closing delimiter so
				// the array end (and the rest of the file) is still found.
				p.triple = true
				closing := strings.Repeat(string(ch), 3)
				if idx := strings.Index(line[i+3:], closing); idx >= 0 {
					i += idx + 5 // loop increment lands after the closing delimiter
					continue
				}
				p.inMulti = true
				p.multiQuote = ch
				return
			}
			p.inString = true
			p.quote = ch
			p.elemLine = lineNo
			p.escaped = false
			p.buf.Reset()
		case '[':
			p.depth++
			p.started = true
		case ']':
			if p.started {
				p.depth--
				if p.depth <= 0 {
					p.complete = true
					return
				}
			}
		}
	}
	// A basic TOML string cannot contain a raw newline. Dropping an
	// unterminated fragment keeps the parser bounded instead of treating the
	// next line as a continuation.
	if p.inString {
		p.inString = false
		p.buf.Reset()
	}
}

func (p *tomlArrayScanner) stringValue() string {
	raw := p.buf.String()
	if p.quote == '"' {
		if unquoted, err := strconv.Unquote(`"` + raw + `"`); err == nil {
			return unquoted
		}
	}
	return raw
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
