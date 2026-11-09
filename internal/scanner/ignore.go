package scanner

import (
	"path"
	"regexp"
	"strings"
)

// globPattern is one compiled include/exclude pattern. Patterns are matched
// against slash-separated paths relative to the scan root. A pattern without a
// slash matches a base name at any depth, which mirrors the way people write
// ignore lists (for example "*.lock").
type globPattern struct {
	re      *regexp.Regexp
	dirOnly bool
}

// ignoreMatcher applies exclude patterns and an optional include allowlist.
type ignoreMatcher struct {
	exclude []globPattern
	include []globPattern
}

func newIgnoreMatcher(exclude, include []string) *ignoreMatcher {
	m := &ignoreMatcher{}
	for _, raw := range exclude {
		if p := compileGlob(raw); p != nil {
			m.exclude = append(m.exclude, *p)
		}
	}
	for _, raw := range include {
		if p := compileGlob(raw); p != nil {
			m.include = append(m.include, *p)
		}
	}
	return m
}

// ignored reports whether rel is excluded. Directories are tested both with
// and without a trailing slash so that patterns such as "vendor/**" prune the
// directory itself instead of walking every file below it. Files also inherit
// an exclude that matches one of their parent directories, which keeps
// directory-style patterns working when there is no directory walk (diff mode).
func (m *ignoreMatcher) ignored(rel string, isDir bool) bool {
	if m == nil {
		return false
	}
	for i := range m.exclude {
		if m.exclude[i].matches(rel, isDir) {
			return true
		}
		if isDir {
			continue
		}
		for dir := path.Dir(rel); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if m.exclude[i].matches(dir, true) {
				return true
			}
		}
	}
	return false
}

// included reports whether rel passes the include allowlist. An empty
// allowlist accepts everything. A pattern that names a parent directory (for
// example "src") includes every file below it.
func (m *ignoreMatcher) included(rel string) bool {
	if m == nil || len(m.include) == 0 {
		return true
	}
	for i := range m.include {
		if m.include[i].matches(rel, false) {
			return true
		}
		for dir := path.Dir(rel); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if m.include[i].matches(dir, true) {
				return true
			}
		}
	}
	return false
}

func (g *globPattern) matches(rel string, isDir bool) bool {
	if g.dirOnly && !isDir {
		return false
	}
	if g.re.MatchString(rel) {
		return true
	}
	return isDir && g.re.MatchString(rel+"/")
}

// compileGlob translates the supported glob syntax (** , * and ?) into a
// regular expression. All other characters are matched literally. Invalid or
// empty patterns are dropped rather than aborting a scan.
func compileGlob(raw string) *globPattern {
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
	expr := globToRegexp(p)
	if baseOnly {
		expr = `(?:.*/)?` + expr
	}
	re, err := regexp.Compile(`^` + expr + `$`)
	if err != nil {
		return nil
	}
	return &globPattern{re: re, dirOnly: dirOnly}
}

func globToRegexp(p string) string {
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
