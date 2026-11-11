package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	pbDepSectionRe = regexp.MustCompile(`^\s*"(dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{`)
	pbDepEntryRe   = regexp.MustCompile(`^\s*"([^"]+)"\s*:\s*"([^"]*)"`)
	pbGitDepRe     = regexp.MustCompile(`^\s*"([^"]+)"\s*:\s*"((?:git\+|git://|http://|https://)[^"]*)"`)
	pbLocalReplace = regexp.MustCompile(`(?i)=>\s*(?:\./|\.\./|/|[A-Za-z]:[\\/])`)
	pbStrictSSLRe  = regexp.MustCompile(`(?i)^\s*strict-ssl\s*=\s*false\s*$`)
	pbTrustedHost  = regexp.MustCompile(`(?i)--trusted-host|^\s*trusted-host\s*=`)

	pbComposerTLSRe = regexp.MustCompile(`(?i)"(secure-http|disable-tls)"\s*:\s*(true|false)`)

	pbYarnBerrySSLRe = regexp.MustCompile(`^\s*enableStrictSsl\s*:\s*false\s*(?:#.*)?$`)

	pbYarnClassicSSLRe = regexp.MustCompile(`^\s*strict-ssl\s*(?:=|\s)\s*false\s*$`)

	pbGoInsecureRe = regexp.MustCompile(`(?i)\bGOINSECURE\s*=\s*["']?([^\s"'#]+)`)

	pbGoSumDBOffRe = regexp.MustCompile(`(?i)\bGOSUMDB\s*=\s*["']?off\b`)

	pbComposerTLSRefs = []string{
		"https://getcomposer.org/doc/06-config.md#secure-http",
		"https://getcomposer.org/doc/06-config.md#disable-tls",
	}

	pbYarnSSLRefs = []string{
		"https://yarnpkg.com/configuration/yarnrc#enableStrictSsl",
		"https://classic.yarnpkg.com/lang/en/docs/cli/config/",
	}

	pbGoChecksumRefs = []string{
		"https://go.dev/ref/mod#checksum-database",
		"https://pkg.go.dev/cmd/go#hdr-Environment_variables",
	}
)

// DependencyRules returns the dependency and package-manager rules. These are
// configuration-level checks only; vulnerability lookups happen elsewhere.
func DependencyRules() []Rule {
	return []Rule{
		New(model.RuleMeta{
			ID:          "VGL-DEP-001",
			Title:       "package.json has no lockfile",
			Description: "Without package-lock.json, yarn.lock or pnpm-lock.yaml every install can resolve different transitive versions, enabling dependency confusion and unreviewed updates.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryDependency,
			Languages:   []string{"json"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"npm", "supply-chain"},
		}, pbPackageLockRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-002",
			Title:       "Dependency uses a wildcard or latest version",
			Description: "A wildcard or latest range accepts any future release, including a compromised one. Pin a minimum compatible version and review upgrades.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryDependency,
			Languages:   []string{"json"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"npm", "supply-chain"},
		}, pbWildcardVersionRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-003",
			Title:       "Dependency installed from a git or HTTP source",
			Description: "Installing from a branch or tarball URL bypasses registry review and can change without a version bump. Prefer a published, integrity-checked release.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-829"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"dependency", "supply-chain"},
		}, pbGitDependencyRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-004",
			Title:       "pip installs an artifact URL without a hash",
			Description: "An artifact fetched from a URL has no registry integrity check. Pin a version and verify --hash, or use a private index with hashes enabled.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"pip", "supply-chain"},
		}, pbPipURLRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-005",
			Title:       "go.mod replace points to a local path",
			Description: "A local replace makes the build depend on an unversioned directory and is usually a development leftover. Remove it before release or point to a versioned module.",
			Severity:    model.SeverityInfo,
			Category:    model.CategoryDependency,
			Languages:   []string{"go"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"go", "dependency"},
		}, pbGoModReplaceRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-006",
			Title:       "npm TLS verification disabled",
			Description: "strict-ssl=false disables certificate validation for every npm request, enabling registry and proxy interception. Remove it and fix the certificate chain.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"npm", "tls"},
		}, pbStrictSSLRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-007",
			Title:       "pip trusted-host bypasses TLS verification",
			Description: "--trusted-host disables TLS verification for that index, allowing a network attacker to serve a malicious package. Install the index CA certificate instead.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"pip", "tls"},
		}, pbPipTrustedHostRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-013",
			Title:       "Composer secure-http or TLS requirement disabled",
			Description: "Composer's secure-http defaults to true. Disabling it (or setting disable-tls) allows http:// package metadata and dist downloads, so a network attacker can serve a malicious package or a tampered lockfile source.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryDependency,
			Languages:   []string{"json"},
			CWE:         []string{"CWE-319", "CWE-494"},
			OWASP:       []string{"A02:2021", "A08:2021"},
			Tags:        []string{"composer", "php", "tls"},
			References:  pbComposerTLSRefs,
		}, pbComposerTLSRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-014",
			Title:       "Yarn strict SSL disabled",
			Description: "enableStrictSsl/strict-ssl false disables certificate validation for package downloads. A MITM or a compromised registry can then serve a tampered tarball that Yarn installs.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021", "A08:2021"},
			Tags:        []string{"yarn", "tls"},
			References:  pbYarnSSLRefs,
		}, pbYarnStrictSSLRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-015",
			Title:       "Go module checksum verification disabled",
			Description: "GOINSECURE permits HTTP/insecure VCS for matching module paths, and GOSUMDB=off disables the checksum database entirely. Either lets a tampered module be accepted without the normal integrity check.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-494", "CWE-345"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"go", "supply-chain"},
			References:  pbGoChecksumRefs,
		}, pbGoChecksumRule),
	}
}

func pbIsPackageJSON(f *File) bool {
	return pbBaseLower(f.Path) == "package.json"
}

func pbDependencyFile(f *File) bool {
	base := pbBaseLower(f.Path)
	switch {
	case base == "package.json", base == ".npmrc", base == "pipfile", base == "pyproject.toml", base == "gemfile":
		return true
	case strings.HasPrefix(base, "requirements"):
		return true
	case pbIsDockerfile(f):
		return true
	case f.Language == "shell":
		return true
	default:
		return false
	}
}

func pbPackageLockRule(f *File) []model.Finding {
	if !pbIsPackageJSON(f) || f.AbsPath == "" || !filepath.IsAbs(f.AbsPath) {
		return nil
	}
	if pbHasAnyFold(f.Path, "/test/", "/tests/", "/fixtures/", "/examples/") {
		return nil
	}
	content := string(f.Content)
	if !pbHasAny(content, `"dependencies"`, `"devDependencies"`, `"optionalDependencies"`) {
		return nil
	}
	dir := filepath.Dir(f.AbsPath)
	for _, name := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return nil
		}
	}
	line := 1
	for i, l := range f.Lines {
		if pbHasAny(l, `"dependencies"`, `"devDependencies"`, `"optionalDependencies"`) {
			line = i + 1
			break
		}
	}
	fd := pbFinding(f, line, "package.json without package-lock.json, yarn.lock or pnpm-lock.yaml")
	fd.Severity = pbSev(f, model.SeverityLow)
	fd.Confidence = model.ConfidenceMedium
	return []model.Finding{fd}
}

func pbWildcardVersionRule(f *File) []model.Finding {
	if !pbIsPackageJSON(f) {
		return nil
	}
	var out []model.Finding
	inDeps := false
	depth := 0
	for i, line := range f.Lines {
		if m := pbDepSectionRe.FindStringSubmatch(line); m != nil {
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			inDeps = depth > 0
			continue
		}
		if !inDeps {
			continue
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if m := pbDepEntryRe.FindStringSubmatch(line); m != nil {
			version := strings.TrimSpace(m[2])
			weak := version == "" || version == "*" || version == "latest" ||
				strings.EqualFold(version, "x") || strings.HasPrefix(version, ">=")
			if weak {
				fd := pbFinding(f, i+1, line)
				fd.Severity = pbSev(f, model.SeverityLow)
				fd.Confidence = model.ConfidenceHigh
				out = append(out, fd)
			}
		}
		if depth <= 0 {
			inDeps = false
		}
	}
	return out
}

func pbGitDependencyRule(f *File) []model.Finding {
	if !pbDependencyFile(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		lower := strings.ToLower(line)
		var hit bool
		if pbIsPackageJSON(f) {
			// Only dependency entries, not repository URLs or scripts.
			hit = pbGitDepRe.MatchString(line)
		} else {
			hit = strings.Contains(lower, "git+") || strings.Contains(lower, "git://")
			if !hit && (strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) {
				hit = strings.Contains(lower, "#egg=")
			}
		}
		if !hit {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbPipURLRule(f *File) []model.Finding {
	if !pbDependencyFile(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "git+") {
			continue
		}
		if !strings.Contains(lower, "http://") && !strings.Contains(lower, "https://") {
			continue
		}
		if !pbHasAny(lower, ".whl", ".tar.gz", ".tgz") {
			continue
		}
		if pbHasAny(lower, "#sha256=", "--hash=") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbGoModReplaceRule(f *File) []model.Finding {
	if pbBaseLower(f.Path) != "go.mod" {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbLocalReplace.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityInfo)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbStrictSSLRule(f *File) []model.Finding {
	if pbBaseLower(f.Path) != ".npmrc" {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbStrictSSLRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbPipTrustedHostRule(f *File) []model.Finding {
	if !pbDependencyFile(f) && pbBaseLower(f.Path) != "pip.conf" && pbBaseLower(f.Path) != "pip.ini" {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbTrustedHost.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbComposerTLSRule(f *File) []model.Finding {
	if pbBaseLower(f.Path) != "composer.json" {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		for _, m := range pbComposerTLSRe.FindAllStringSubmatch(line, -1) {
			key, value := strings.ToLower(m[1]), strings.ToLower(m[2])
			unsafe := (key == "secure-http" && value == "false") ||
				(key == "disable-tls" && value == "true")
			if !unsafe {
				continue
			}
			fd := pbFinding(f, i+1, strings.TrimSpace(line))
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			fd.References = append([]string(nil), pbComposerTLSRefs...)
			fd.Remediation = "Remove secure-http=false / disable-tls=true, keep Composer's TLS verification enabled, and fix the CA chain or use a trusted mirror instead."
			out = append(out, fd)
		}
	}
	return out
}

func pbYarnStrictSSLRule(f *File) []model.Finding {
	var re *regexp.Regexp
	switch pbBaseLower(f.Path) {
	case ".yarnrc.yml":
		re = pbYarnBerrySSLRe
	case ".yarnrc":
		re = pbYarnClassicSSLRe
	default:
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !re.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.References = append([]string(nil), pbYarnSSLRefs...)
		fd.Remediation = "Re-enable certificate validation (enableStrictSsl: true / strict-ssl true), fix the registry certificate chain, and rotate any packages installed while verification was off."
		out = append(out, fd)
	}
	return out
}

func pbGoChecksumRule(f *File) []model.Finding {
	if !pbGoEnvScan(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbGoEnvComment(f, line) {
			continue
		}
		if m := pbGoInsecureRe.FindStringSubmatch(line); m != nil && pbGoInsecureValue(m[1]) {
			fd := pbFinding(f, i+1, strings.TrimSpace(line))
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			fd.References = append([]string(nil), pbGoChecksumRefs...)
			fd.Remediation = "Remove GOINSECURE, serve modules over HTTPS, and use GOPRIVATE/GONOSUMDB only for genuinely private modules that still verify checksums."
			out = append(out, fd)
		}
		if pbGoSumDBOffRe.MatchString(line) {
			fd := pbFinding(f, i+1, strings.TrimSpace(line))
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			fd.References = append([]string(nil), pbGoChecksumRefs...)
			fd.Remediation = "Remove GOSUMDB=off and let the public checksum database verify modules. Use GONOSUMDB/GOPRIVATE for private module paths instead of disabling verification globally."
			out = append(out, fd)
		}
	}
	return out
}

// pbGoEnvScan limits the Go checksum rule to non-documentation files. The
// settings can appear in Dockerfiles, CI YAML, shell scripts, Makefiles, .env
// files and source code, so only prose documentation is excluded.
func pbGoEnvScan(f *File) bool {
	if f == nil || pbDocsPath(f.Path) {
		return false
	}
	switch pbBaseLower(f.Path) {
	case "readme", "changelog", "license", "contributing", "notice", "authors":
		return false
	}
	return true
}

// pbGoEnvComment extends comment detection to formats whose comment marker is
// "#" but whose language label is not shell/yaml (Dockerfile, Makefile, .env,
// TOML/INI and other config files).
func pbGoEnvComment(f *File, line string) bool {
	if pbComment(f, line) {
		return true
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "#") {
		return false
	}
	return f.Language == "dockerfile" || f.Language == "other"
}

// pbGoInsecureValue reports whether a GOINSECURE value is a literal module
// pattern rather than an empty value or an environment interpolation.
func pbGoInsecureValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || LooksLikePlaceholder(v) {
		return false
	}
	return !strings.ContainsAny(v, "$%{}")
}
