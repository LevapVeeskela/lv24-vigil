package rules

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func secJoin(parts ...string) string {
	return strings.Join(parts, "")
}

func secTestFile(p, content string) *File {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return &File{
		Path:     p,
		Content:  []byte(content),
		Lines:    lines,
		Language: secTestLanguage(p),
		Size:     len(content),
	}
}

func secTestLanguage(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	base := path.Base(p)
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."):
		return "dockerfile"
	case strings.HasSuffix(p, ".tf"), strings.HasSuffix(p, ".tfvars"), strings.HasSuffix(p, ".hcl"):
		return "terraform"
	}
	switch path.Ext(p) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".java":
		return "java"
	case ".php":
		return "php"
	case ".rb":
		return "ruby"
	case ".cs":
		return "csharp"
	case ".rs":
		return "rust"
	case ".sql":
		return "sql"
	case ".sh", ".bash":
		return "shell"
	case ".html", ".htm":
		return "html"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	default:
		return "other"
	}
}

func secRulesByID(t *testing.T) map[string]Rule {
	t.Helper()
	out := make(map[string]Rule, len(SecretsRules()))
	for _, r := range SecretsRules() {
		id := r.Meta().ID
		if _, exists := out[id]; exists {
			t.Fatalf("duplicate secret rule id %q", id)
		}
		out[id] = r
	}
	return out
}

func TestSecretsRuleMetadata(t *testing.T) {
	rules := SecretsRules()
	if len(rules) != 29 {
		t.Fatalf("SecretsRules() = %d rules, want 29", len(rules))
	}
	idRe := regexp.MustCompile(`^VGL-SEC-\d{3}$`)
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		m := r.Meta()
		if !idRe.MatchString(m.ID) {
			t.Errorf("rule id %q does not match VGL-SEC-NNN", m.ID)
		}
		if seen[m.ID] {
			t.Errorf("duplicate rule id %q", m.ID)
		}
		seen[m.ID] = true
		if m.Title == "" {
			t.Errorf("%s: empty title", m.ID)
		}
		if m.Description == "" {
			t.Errorf("%s: empty description", m.ID)
		}
		if m.Severity == "" {
			t.Errorf("%s: empty severity", m.ID)
		}
		if m.Category != model.CategorySecrets {
			t.Errorf("%s: category = %q, want %q", m.ID, m.Category, model.CategorySecrets)
		}
		if len(m.CWE) == 0 {
			t.Errorf("%s: no CWE", m.ID)
		}
		if len(m.References) == 0 {
			t.Errorf("%s: no references", m.ID)
		}
	}
	for i := 1; i <= 24; i++ {
		id := fmt.Sprintf("VGL-SEC-%03d", i)
		if !seen[id] {
			t.Errorf("missing rule id %q", id)
		}
	}
}

func TestSecretsRulesPositive(t *testing.T) {
	byID := secRulesByID(t)
	cases := []struct {
		name      string
		ruleID    string
		path      string
		content   string
		wantLines []int
		secret    string
	}{
		{
			name:      "aws access key id",
			ruleID:    "VGL-SEC-001",
			path:      "src/config.js",
			content:   secJoin(`const AWS_KEY = "AK`, `IAZ7Q2XJ4M5N6P7R8S";`),
			wantLines: []int{1},
			secret:    secJoin("AK", "IAZ7Q2XJ4M5N6P7R8S"),
		},
		{
			name:      "aws secret access key",
			ruleID:    "VGL-SEC-002",
			path:      "src/settings.py",
			content:   secJoin(`aws_secret_access_key = "kR9dQ2mX4pL7`, `vN1sT6wZ8bC3hJ5fG0aY2eU4iO7r"`),
			wantLines: []int{1},
			secret:    secJoin("kR9dQ2mX4pL7", "vN1sT6wZ8bC3hJ5fG0aY2eU4iO7r"),
		},
		{
			name:      "github token",
			ruleID:    "VGL-SEC-003",
			path:      "src/deploy.sh",
			content:   secJoin("export GITHUB_TOKEN=gh", "p_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
			wantLines: []int{1},
			secret:    secJoin("gh", "p_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
		},
		{
			name:      "gitlab token",
			ruleID:    "VGL-SEC-004",
			path:      ".gitlab-ci.yml",
			content:   secJoin("GITLAB_TOKEN=gl", "pat-Ab3dEf6hIj9kLm2nOp5q"),
			wantLines: []int{1},
			secret:    secJoin("gl", "pat-Ab3dEf6hIj9kLm2nOp5q"),
		},
		{
			name:      "slack token",
			ruleID:    "VGL-SEC-005",
			path:      "src/notify.py",
			content:   secJoin(`slack_token = "xox`, `b-984201337744-771203998541-Wq7Rt2Yp9Lm4Kd8Ns6Bv3Xz5"`),
			wantLines: []int{1},
			secret:    secJoin("xox", "b-984201337744-771203998541-Wq7Rt2Yp9Lm4Kd8Ns6Bv3Xz5"),
		},
		{
			name:      "slack webhook",
			ruleID:    "VGL-SEC-006",
			path:      "src/notify.ts",
			content:   secJoin(`const WEBHOOK = "https://hooks.slack.com/`, `services/T9K2M4P7Q/B8R3S5T1U/Wq7Rt2Yp9Lm4Kd8Ns6Bv3Xz5";`),
			wantLines: []int{1},
			secret:    secJoin("https://hooks.slack.com/", "services/T9K2M4P7Q/B8R3S5T1U/Wq7Rt2Yp9Lm4Kd8Ns6Bv3Xz5"),
		},
		{
			name:      "stripe live key",
			ruleID:    "VGL-SEC-007",
			path:      "src/payments.py",
			content:   secJoin("STRIPE_KEY=sk_", "live_51H8xYzWq7Rt2Yp9Lm4Kd8Ns"),
			wantLines: []int{1},
			secret:    secJoin("sk_", "live_51H8xYzWq7Rt2Yp9Lm4Kd8Ns"),
		},
		{
			name:      "google api key",
			ruleID:    "VGL-SEC-008",
			path:      "src/maps.js",
			content:   secJoin(`const key = "AI`, `zaSyD9kLm3Np7Qr2St6Uv8Wx1Yz4Ab5Cd6Ef7";`),
			wantLines: []int{1},
			secret:    secJoin("AI", "zaSyD9kLm3Np7Qr2St6Uv8Wx1Yz4Ab5Cd6Ef7"),
		},
		{
			name:      "openai key",
			ruleID:    "VGL-SEC-009",
			path:      "src/ai.py",
			content:   secJoin("OPENAI_API_KEY=sk-", "proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ"),
			wantLines: []int{1},
			secret:    secJoin("sk-", "proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ"),
		},
		{
			name:      "anthropic key",
			ruleID:    "VGL-SEC-010",
			path:      "src/ai.py",
			content:   secJoin("ANTHROPIC_API_KEY=sk-", "ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ7aB6cD5eF"),
			wantLines: []int{1},
			secret:    secJoin("sk-", "ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ7aB6cD5eF"),
		},
		{
			name:   "private key block",
			ruleID: "VGL-SEC-011",
			path:   "certs/server.pem",
			content: secJoin("-----BEGIN RSA ", "PRIVATE KEY-----\n",
				"MIIEowIBAAKCAQEAx7Q2mK9pL4vN8sT1wZ6bC3hJ5fG0aY2eU4iO7r\n",
				"-----END RSA ", "PRIVATE KEY-----"),
			wantLines: []int{1},
			secret:    "MIIEowIBAAKCAQEAx7Q2mK9pL4vN8sT1wZ6bC3hJ5fG0aY2eU4iO7r",
		},
		{
			name:   "jwt literal",
			ruleID: "VGL-SEC-012",
			path:   "src/auth.ts",
			content: secJoin(`const token = "`, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".",
				"eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIn0", ".",
				"9xQ2mK7pL4vN8sT1wZ6bC3hJ5fG0aY2eU4iO7r", `";`),
			wantLines: []int{1},
			secret: secJoin("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".",
				"eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIn0", ".",
				"9xQ2mK7pL4vN8sT1wZ6bC3hJ5fG0aY2eU4iO7r"),
		},
		{
			name:      "basic auth url",
			ruleID:    "VGL-SEC-013",
			path:      "src/client.py",
			content:   secJoin(`url = "https://deploy:`, "Zx9Qm2Lp7Rt4", `@internal.acme-corp.io/health"`),
			wantLines: []int{1},
			secret:    "Zx9Qm2Lp7Rt4",
		},
		{
			name:      "generic password assignment",
			ruleID:    "VGL-SEC-014",
			path:      "src/config.py",
			content:   `DB_PASSWORD = "Qz7!mK2pL9vN4sT8"`,
			wantLines: []int{1},
			secret:    "Qz7!mK2pL9vN4sT8",
		},
		{
			name:      "connection string",
			ruleID:    "VGL-SEC-015",
			path:      "src/db.ts",
			content:   `DATABASE_URL=postgres://svc_user:R7kL9mN2pQ4sT6vW@db.internal:5432/app`,
			wantLines: []int{1},
			secret:    "R7kL9mN2pQ4sT6vW",
		},
		{
			name:      "redis connection string without username",
			ruleID:    "VGL-SEC-015",
			path:      "src/cache.py",
			content:   `REDIS_URL=redis://:R7kL9mN2pQ4sT6vW@cache.internal:6379/0`,
			wantLines: []int{1},
			secret:    "R7kL9mN2pQ4sT6vW",
		},
		{
			name:      "npm auth token",
			ruleID:    "VGL-SEC-016",
			path:      ".npmrc",
			content:   secJoin("//registry.npmjs.org/:_authToken=np", "m_Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ"),
			wantLines: []int{1},
			secret:    secJoin("np", "m_Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ"),
		},
		{
			name:      "env file value",
			ruleID:    "VGL-SEC-017",
			path:      ".env.production",
			content:   `DATABASE_PASSWORD=Qz7mK2pL9vN4sT8x`,
			wantLines: []int{1},
			secret:    "Qz7mK2pL9vN4sT8x",
		},
		{
			name:      "heroku key",
			ruleID:    "VGL-SEC-018",
			path:      "src/release.py",
			content:   `HEROKU_API_KEY=8f3c2a91-7b4d-4e6a-9c1d-2f5b8a3e7d10`,
			wantLines: []int{1},
			secret:    "8f3c2a91-7b4d-4e6a-9c1d-2f5b8a3e7d10",
		},
		{
			name:      "digitalocean token",
			ruleID:    "VGL-SEC-019",
			path:      "infra/deploy.tf",
			content:   secJoin("DO_TOKEN=do", "p_v1_9f3c2a917b4d4e6a9c1d2f5b8a3e7d109f3c2a917b4d4e6a9c1d2f5b8a3e7d10"),
			wantLines: []int{1},
			secret:    secJoin("do", "p_v1_9f3c2a917b4d4e6a9c1d2f5b8a3e7d109f3c2a917b4d4e6a9c1d2f5b8a3e7d10"),
		},
		{
			name:      "twilio auth token",
			ruleID:    "VGL-SEC-020",
			path:      "src/sms.py",
			content:   `TWILIO_AUTH_TOKEN=9f3c2a917b4d4e6a9c1d2f5b8a3e7d10`,
			wantLines: []int{1},
			secret:    "9f3c2a917b4d4e6a9c1d2f5b8a3e7d10",
		},
		{
			name:      "sendgrid key",
			ruleID:    "VGL-SEC-021",
			path:      "src/mail.ts",
			content:   secJoin("SENDGRID_API_KEY=S", "G.Ab3dEf6hIj9kLm2nOp5qRs.Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ7aB6cD5eF"),
			wantLines: []int{1},
			secret:    secJoin("S", "G.Ab3dEf6hIj9kLm2nOp5qRs.Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ7aB6cD5eF"),
		},
		{
			name:      "azure storage key",
			ruleID:    "VGL-SEC-022",
			path:      "src/storage.cs",
			content:   secJoin("AccountKey=", "Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ7aB6cD5eF8gH9iJ0kL1mN2oP3qR4sT5uV6wX7yZ8aB9cD0eF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0yZ"),
			wantLines: []int{1},
			secret:    secJoin("Ab3dEf6hIj9kLm2nOp5qRs8tUv1Wx4yZ7aB6cD5eF8gH9iJ0kL1mN2oP3qR4sT5uV6wX7yZ8aB9cD0eF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0yZ"),
		},
		{
			name:      "terraform secret",
			ruleID:    "VGL-SEC-023",
			path:      "infra/main.tf",
			content:   `password = "Qz7mK2pL9vN4sT8x"`,
			wantLines: []int{1},
			secret:    "Qz7mK2pL9vN4sT8x",
		},
		{
			name:   "docker registry auth",
			ruleID: "VGL-SEC-024",
			path:   ".docker/config.json",
			content: "{\n" +
				"  \"auths\": {\n" +
				"    \"registry.internal\": {\n" +
				"      \"auth\": \"" + secJoin("c3ZjX3VzZXI6UjdrTDltTjJwUTRzVDZ2Vw", "==\"\n") +
				"    }\n" +
				"  }\n" +
				"}",
			wantLines: []int{4},
			secret:    secJoin("c3ZjX3VzZXI6UjdrTDltTjJwUTRzVDZ2Vw", "=="),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := byID[tc.ruleID]
			if rule == nil {
				t.Fatalf("rule %s not registered", tc.ruleID)
			}
			f := secTestFile(tc.path, tc.content)
			got := rule.Check(f)
			lines := make([]int, 0, len(got))
			for _, fd := range got {
				lines = append(lines, fd.Location.StartLine)
			}
			if !slices.Equal(lines, tc.wantLines) {
				t.Fatalf("lines = %v, want %v (findings: %+v)", lines, tc.wantLines, got)
			}
			for _, fd := range got {
				if fd.RuleID != tc.ruleID {
					t.Errorf("RuleID = %q, want %q", fd.RuleID, tc.ruleID)
				}
				if fd.Severity != rule.Meta().Severity {
					t.Errorf("Severity = %q, want meta severity %q", fd.Severity, rule.Meta().Severity)
				}
				if len(fd.References) == 0 {
					t.Error("empty references")
				}
				if fd.Category != model.CategorySecrets {
					t.Errorf("Category = %q, want %q", fd.Category, model.CategorySecrets)
				}
				if fd.Source != model.SourceRule {
					t.Errorf("Source = %q, want %q", fd.Source, model.SourceRule)
				}
				if fd.Confidence == "" {
					t.Error("empty confidence")
				}
				if fd.Remediation == "" {
					t.Error("empty remediation")
				}
				if fd.Evidence == "" {
					t.Error("empty evidence")
				}
				if fd.ID == "" {
					t.Error("empty finding id")
				}
				if fd.Location.EndLine != fd.Location.StartLine {
					t.Errorf("EndLine = %d, want %d", fd.Location.EndLine, fd.Location.StartLine)
				}
				if tc.secret != "" {
					if strings.Contains(fd.Evidence, tc.secret) {
						t.Errorf("raw secret leaked in evidence: %q", fd.Evidence)
					}
					if strings.Contains(fd.Location.Snippet, tc.secret) {
						t.Errorf("raw secret leaked in snippet: %q", fd.Location.Snippet)
					}
				}
			}
		})
	}
}

func TestSecretsPlaceholdersIgnored(t *testing.T) {
	f := secTestFile("config/settings.py", `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
password = "changeme"
api_key = "your_api_key_here"
DATABASE_URL = "postgres://user:password@localhost:5432/db"`)
	for _, r := range SecretsRules() {
		if got := r.Check(f); len(got) != 0 {
			t.Errorf("%s fired on placeholders: %+v", r.Meta().ID, got)
		}
	}
}

func TestSecretsNegatives(t *testing.T) {
	byID := secRulesByID(t)
	cases := []struct {
		name    string
		ruleID  string
		path    string
		content string
	}{
		{
			name:    "comment only",
			ruleID:  "VGL-SEC-014",
			path:    "src/app.js",
			content: `// password = "Qz7mK2pL9vN4sT8x"`,
		},
		{
			name:    "env example",
			ruleID:  "VGL-SEC-017",
			path:    ".env.example",
			content: `DATABASE_PASSWORD=Qz7mK2pL9vN4sT8x`,
		},
		{
			name:    "npm token from environment",
			ruleID:  "VGL-SEC-016",
			path:    ".npmrc",
			content: `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`,
		},
		{
			name:    "jwt.io documentation token",
			ruleID:  "VGL-SEC-012",
			path:    "docs/auth.md",
			content: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
		},
		{
			name:    "docker config without userinfo",
			ruleID:  "VGL-SEC-024",
			path:    ".docker/config.json",
			content: `{"auths":{"registry.internal":{"auth":"qwertyuiopasdfgh"}}}`,
		},
		{
			name:    "weak basic auth password",
			ruleID:  "VGL-SEC-013",
			path:    "src/client.py",
			content: `url = "https://admin:password@example.com/x"`,
		},
		{
			name:    "openai test key",
			ruleID:  "VGL-SEC-009",
			path:    "src/ai.py",
			content: `OPENAI_API_KEY=sk-test-abcdefghijklmnopqrstuvwx`,
		},
		{
			name:    "docs placeholder password",
			ruleID:  "VGL-SEC-014",
			path:    "docs/setup.md",
			content: `password = "example-password-123"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := byID[tc.ruleID]
			if rule == nil {
				t.Fatalf("rule %s not registered", tc.ruleID)
			}
			if got := rule.Check(secTestFile(tc.path, tc.content)); len(got) != 0 {
				t.Fatalf("expected no findings, got %+v", got)
			}
		})
	}
}

func TestSecretsSeverityDowngrade(t *testing.T) {
	byID := secRulesByID(t)
	rule := byID["VGL-SEC-014"]
	if rule == nil {
		t.Fatal("VGL-SEC-014 not registered")
	}
	content := `token = "Qz7mK2pL9vN4sT8x"`

	src := rule.Check(secTestFile("src/config.py", content))
	if len(src) != 1 || src[0].Severity != model.SeverityHigh {
		t.Fatalf("source findings = %+v, want one high finding", src)
	}

	fixture := rule.Check(secTestFile("internal/rules/secrets_test.go", content))
	if len(fixture) != 1 {
		t.Fatalf("fixture findings = %+v, want one finding", fixture)
	}
	if fixture[0].Severity != model.SeverityMedium {
		t.Errorf("fixture severity = %q, want %q", fixture[0].Severity, model.SeverityMedium)
	}

	docs := rule.Check(secTestFile("docs/setup.md", content))
	if len(docs) != 1 {
		t.Fatalf("docs findings = %+v, want one finding", docs)
	}
	if docs[0].Severity != model.SeverityLow {
		t.Errorf("docs severity = %q, want %q", docs[0].Severity, model.SeverityLow)
	}
}

func TestSecretsRulesHandleNilFile(t *testing.T) {
	for _, r := range SecretsRules() {
		if got := r.Check(nil); len(got) != 0 {
			t.Errorf("%s: nil file produced %d findings", r.Meta().ID, len(got))
		}
	}
}

func TestSecMaskURL(t *testing.T) {
	got := secMaskURL("postgres://user:supersecret@db.internal:5432/app")
	if strings.Contains(got, "supersecret") {
		t.Errorf("masked URL still contains the password: %q", got)
	}
	if !strings.Contains(got, "db.internal") {
		t.Errorf("masked URL lost the host: %q", got)
	}
}

func TestSecretsSnippetDoesNotLeakNeighbouringSecret(t *testing.T) {
	rule := secRulesByID(t)["VGL-SEC-017"]
	if rule == nil {
		t.Fatal("VGL-SEC-017 not registered")
	}
	const first = "Qz7mK2pL9vN4sT8x"
	const second = "Rk4mN8pQ2sT6vW9y"
	f := secTestFile(".env.production", "DB_PASSWORD="+first+"\nAPI_TOKEN="+second)
	got := rule.Check(f)
	if len(got) != 2 {
		t.Fatalf("findings = %+v, want 2", got)
	}
	for _, fd := range got {
		if strings.Contains(fd.Location.Snippet, first) || strings.Contains(fd.Location.Snippet, second) {
			t.Errorf("neighbouring secret leaked in snippet: %q", fd.Location.Snippet)
		}
	}
}
