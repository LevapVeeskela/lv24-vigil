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
func FuzzRuleCheck(f *testing.F) {
	seeds := []struct {
		path    string
		content string
		lang    int
	}{
		{"cmd/server/main.go", "package main\n\nvar key = \"AKIAZ7Q2LMN4RSTUVWXY\"\nfunc main() { exec.Command(\"sh\", \"-c\", \"ls \" + dir) }\n", 0},
		{"app.py", "import pickle, yaml\nkey = \"AKIAZ7Q2LMN4RSTUVWXY\"\neval(request.args[\"x\"])\npickle.loads(blob)\nyaml.load(blob)\nsubprocess.call(cmd, shell=True)\n", 1},
		{"src/index.js", "const x = eval(req.body.code);\nchild_process.exec(cmd);\nel.innerHTML = req.query.q;\nconst proto = JSON.parse(body);\n", 2},
		{"api/web.php", "<?php\neval($_GET['code']);\n$q = \"SELECT * FROM users WHERE id = \" . $_GET['id'];\nmysql_query($q);\n", 5},
		{"package.json", "{\n  \"name\": \"demo\",\n  \"dependencies\": {\"left-pad\": \"*\", \"express\": \"^4.0.0\"}\n}\n", 11},
		{"Dockerfile", "FROM ubuntu:latest\nUSER root\nADD . /app\nRUN apt-get update && apt-get install -y curl\n", 12},
		{".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n      - run: echo ${{ github.event.pull_request.title }}\n", 10},
		{"deploy/nginx.conf", "server {\n  autoindex on;\n  ssl_protocols TLSv1 TLSv1.1;\n  add_header Access-Control-Allow-Origin *;\n}\n", 16},
		{".env", "AWS_ACCESS_KEY_ID=AKIAZ7Q2LMN4RSTUVWXY\nDB_PASSWORD=Sup3rS3cretValue!2024\n", 16},
		{"config/prod.yaml", "database:\n  password: Sup3rS3cretValue!2024\n  ssl: false\n", 10},
		{"infra/main.tf", "resource \"aws_security_group\" \"open\" {\n  ingress {\n    cidr_blocks = [\"0.0.0.0/0\"]\n    from_port = 22\n  }\n}\n", 13},
		{"scripts/deploy.sh", "#!/bin/sh\ncurl -fsSL https://example.test/install.sh | bash\neval \"$USER_INPUT\"\n", 15},
		{"src/Main.java", "class Main {\n  void run(String cmd) throws Exception {\n    Runtime.getRuntime().exec(cmd);\n  }\n}\n", 4},
		{"query.sql", "SELECT * FROM users WHERE name = '\" + name + \"';\n", 9},
		{"index.html", "<div id=\"out\"></div>\n<script>document.getElementById('out').innerHTML = location.hash;</script>\n", 15},
		{"docs/readme.md", "# Notes\naws_access_key_id = AKIAZ7Q2LMN4RSTUVWXY\n", 16},
		{"weird", "password = \"AKIAZ7Q2LMN4RSTUVWXY\"\r\napi_key: sk-live-0123456789abcdef\r\n", 16},
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
