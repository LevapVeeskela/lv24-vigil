package rules

import (
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func sortMetas(metas []model.RuleMeta) {
	sort.Slice(metas, func(i, j int) bool { return metas[i].ID < metas[j].ID })
}

// FindLine returns the 1-based line number of the first regex match, or 0.
func FindLine(re *regexp.Regexp, lines []string) int {
	for i, line := range lines {
		if re.MatchString(line) {
			return i + 1
		}
	}
	return 0
}

// AllLines returns every 1-based line number matching re.
func AllLines(re *regexp.Regexp, lines []string) []int {
	var out []int
	for i, line := range lines {
		if re.MatchString(line) {
			out = append(out, i+1)
		}
	}
	return out
}

// Entropy returns the Shannon entropy (bits per character) of s.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// LooksLikePlaceholder reports whether a candidate secret is obviously a
// placeholder, documentation value or test fixture. Keeping this central means
// every secret rule suppresses the same noise.
func LooksLikePlaceholder(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if len(v) < 8 {
		return true
	}
	placeholders := []string{
		"example", "sample", "dummy", "placeholder", "changeme", "change-me",
		"your_", "your-", "xxx", "redacted", "replace", "todo", "fixme",
		"<", ">", "${", "{{", "}}", "insert_", "insert-", "notreal",
		"test_key", "test-key", "test_token", "test-token", "fake", "mock", "lorem", "abcdefgh",
		"0000000000", "1111111111", "1234567890",
	}
	for _, p := range placeholders {
		if strings.Contains(v, p) {
			return true
		}
	}
	// A value made of one repeated character is never a real credential.
	uniq := map[rune]bool{}
	for _, r := range v {
		uniq[r] = true
	}
	return len(uniq) <= 3
}

// IsCommentLine reports whether a line looks like a comment in the given
// language. Used to downgrade or skip documentation hits.
func IsCommentLine(line, language string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	switch language {
	case "python", "ruby", "shell", "yaml", "terraform":
		return strings.HasPrefix(t, "#")
	case "sql":
		return strings.HasPrefix(t, "--") || strings.HasPrefix(t, "/*")
	case "html":
		return strings.HasPrefix(t, "<!--")
	default:
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
	}
}

// SeverityForLanguage caps a base severity for non-production paths. Test
// fixtures and documentation are still reported, but a hardcoded key in
// `docs/` is not the same emergency as one in `src/`.
//
// The cap is absolute rather than a one-notch downgrade, and applying the
// function twice returns the same value: a fixture can never be lowered past
// MEDIUM and documentation can never be lowered past LOW.
func SeverityForLanguage(base model.Severity, path string) model.Severity {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if isDocsPath(p) {
		return capSeverity(base, model.SeverityLow)
	}
	if isTestPath(p) {
		return capSeverity(base, model.SeverityMedium)
	}
	return base
}

// capSeverity returns base unless it is more severe than max.
func capSeverity(base, max model.Severity) model.Severity {
	if base.Rank() > max.Rank() {
		return max
	}
	return base
}

// isDocsPath reports whether path is prose documentation. The argument must be
// lower-cased and slash-separated.
func isDocsPath(p string) bool {
	return strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".markdown") ||
		strings.HasSuffix(p, ".mdx") || strings.HasSuffix(p, ".rst") ||
		strings.Contains(p, "/docs/") || strings.HasPrefix(p, "docs/") ||
		strings.Contains(p, "/documentation/") || strings.HasPrefix(p, "documentation/")
}

// isTestPath reports whether path belongs to tests, fixtures or examples. The
// argument must be lower-cased and slash-separated.
func isTestPath(p string) bool {
	for _, marker := range []string{
		"/test/", "/tests/", "/__tests__/", "/testdata/", "/spec/", "/specs/",
		"/fixtures/", "/fixture/", "/examples/", "/example/", "/e2e/",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	for _, prefix := range []string{"test/", "tests/", "spec/", "fixtures/", "examples/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	for _, marker := range []string{"_test.", ".test.", "_spec.", ".spec."} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py")
}

// codeContextAt reports whether pos (a byte offset) in line falls inside a
// quoted string literal or a comment. It is a deliberately small scanner: the
// rules use it to keep prose in DTO descriptions from looking like code.
func codeContextAt(line string, pos int) (inString, inComment bool) {
	if pos < 0 {
		pos = 0
	}
	if pos > len(line) {
		pos = len(line)
	}
	var quote byte
	escaped := false
	block := false
	for i := 0; i < pos; i++ {
		c := line[i]
		if block {
			if c == '*' && i+1 < pos && line[i+1] == '/' {
				block = false
				i++
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '/':
			if i+1 < pos {
				switch line[i+1] {
				case '/':
					return false, true
				case '*':
					block = true
					i++
				}
			}
		}
	}
	return quote != 0, false
}

// IsInsideStringLiteral reports whether pos in line is inside a quoted string.
func IsInsideStringLiteral(line string, pos int) bool {
	inString, _ := codeContextAt(line, pos)
	return inString
}

// Truncate shortens s to n characters, appending an ellipsis.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// MaskSecret keeps a short prefix so a human can identify the credential
// without the report becoming a second leak.
func MaskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + strings.Repeat("*", 8) + s[len(s)-2:]
}

// Snippet returns a bounded, trimmed snippet around line n.
func Snippet(f *File, n, radius int) string {
	return strings.TrimSpace(f.Window(n, radius))
}
