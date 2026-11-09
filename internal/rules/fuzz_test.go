package rules

import (
	"path/filepath"
	"strings"
	"testing"
)

// fuzzRuleMaxContent keeps one fuzz iteration bounded: every default rule runs
// over the same content, so a multi-megabyte input would multiply the cost by
// the size of the registry.
const fuzzRuleMaxContent = 16 << 10

// fuzzRuleLanguages mirrors the File.Language contract in types.go.
var fuzzRuleLanguages = []string{
	"go", "python", "javascript", "typescript", "java", "php", "ruby",
	"csharp", "rust", "sql", "yaml", "json", "dockerfile", "terraform",
	"shell", "html", "other",
}

// FuzzRuleCheck runs every default rule over arbitrary content, paths and
// languages. Rules are pure, so the fuzz target asserts the contract:
//
//   - Check never panics;
//   - Check never mutates the input File;
//   - every finding has a non-empty RuleID, a known severity, a non-empty path
//     and a 1-based line range (EndLine >= StartLine >= 1).
//
// Path is forced to a non-empty value because the scanner only hands rules real
// files; a finding that drops the path would otherwise be untestable.
//
// The seed corpus stays deliberately boring (configuration mistakes, not
// exploit payloads) so endpoint protection does not quarantine this test file;
// the fuzzer itself still explores arbitrary bytes.
func FuzzRuleCheck(f *testing.F) {
	seeds := []struct {
		path    string
		content string
		lang    int
	}{
		{"cmd/server/main.go", "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n", 0},
		{"app.py", "def main():\n    print('hello')\n", 1},
		{"src/index.js", "console.log('hello');\n", 2},
		{"package.json", "{\n  \"name\": \"demo\",\n  \"dependencies\": {\"left-pad\": \"*\"}\n}\n", 11},
		{"Dockerfile", "FROM ubuntu:latest\nUSER root\n", 12},
		{".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n", 10},
		{"deploy/nginx.conf", "server {\n  autoindex on;\n}\n", 16},
		{"infra/main.tf", "resource \"aws_security_group\" \"open\" {\n  ingress {\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n", 13},
		{"config/prod.yaml", "server:\n  ssl: false\n", 10},
		{"index.html", "<div>hello</div>\n", 15},
		{"weird", "line one\r\nline two\r\n\tline three\r\n", 16},
		{"", "", 16},
		{"deep/../escape.go", strings.Repeat("A", 4096), 0},
	}
	for _, s := range seeds {
		f.Add(s.path, s.content, s.lang)
	}

	reg := Default()
	f.Fuzz(func(t *testing.T, path, content string, langIdx int) {
		if len(content) > fuzzRuleMaxContent || len(path) > 1024 {
			return
		}
		if path == "" {
			path = "fuzz/app.go"
		}
		lang := fuzzRuleLanguages[modIndex(langIdx, len(fuzzRuleLanguages))]

		// Shared immutable input: a rule that mutates it is caught by the
		// comparison after Check, before the next rule runs.
		contentBytes := []byte(content)
		lines := strings.Split(content, "\n")
		absPath := filepath.Join("vigil-fuzz-no-such-dir", filepath.FromSlash(path))

		for _, rule := range reg.All() {
			meta := rule.Meta()
			file := &File{
				Path:     path,
				AbsPath:  absPath,
				Content:  contentBytes,
				Lines:    lines,
				Language: lang,
				Size:     len(contentBytes),
			}

			findings := rule.Check(file)

			if file.Path != path || string(file.Content) != content || strings.Join(file.Lines, "\n") != content {
				t.Fatalf("rule %s mutated its input file (path=%q language=%q content=%q)",
					meta.ID, path, lang, content)
			}

			for i, fd := range findings {
				if fd.RuleID == "" {
					t.Fatalf("rule %s finding %d has an empty RuleID: %+v", meta.ID, i, fd)
				}
				if fd.RuleID != meta.ID {
					t.Fatalf("rule %s finding %d has RuleID %q", meta.ID, i, fd.RuleID)
				}
				if fd.Severity.Rank() == 0 {
					t.Fatalf("rule %s finding %d has invalid severity %q", meta.ID, i, fd.Severity)
				}
				if fd.Location.Path == "" {
					t.Fatalf("rule %s finding %d has an empty path: %+v", meta.ID, i, fd)
				}
				if fd.Location.StartLine < 1 {
					t.Fatalf("rule %s finding %d has StartLine %d, want >= 1 (path %q)",
						meta.ID, i, fd.Location.StartLine, path)
				}
				if fd.Location.EndLine < fd.Location.StartLine {
					t.Fatalf("rule %s finding %d has EndLine %d < StartLine %d",
						meta.ID, i, fd.Location.EndLine, fd.Location.StartLine)
				}
			}
		}
	})
}

// modIndex returns a non-negative index for any int, including MinInt.
func modIndex(v, n int) int {
	if n <= 0 {
		return 0
	}
	i := v % n
	if i < 0 {
		i += n
	}
	return i
}
