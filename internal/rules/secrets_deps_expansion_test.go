package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Fixtures for the secrets/dependencies expansion (VGL-SEC-025..030 and
// VGL-DEP-013..015). The values are synthetic but keep the real provider
// structure so the detectors are exercised end to end.
const (
	sdeTelegramToken = "8123456789:" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"
	sdeVaultToken    = "hvs." + "Ca3sI9j2K8l4M6n0P5q7R1t3V8w2X9y4Z6a0B7c5D1e8F3g9H2i4J6k0L5m7N1o3P8q2R9s4T6u0V7w5X1y8Z3a9B2c4D6e0F5g7"
	sdeNPMToken      = "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	sdeGitLabToken   = "glrt-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"
	sdeAzureSBKey    = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2="
)

var sdeVaultBatchToken = "hvb." + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6", 3)

func sdeRules(t *testing.T) map[string]Rule {
	t.Helper()
	out := make(map[string]Rule)
	for _, r := range append(SecretsRules(), DependencyRules()...) {
		out[r.Meta().ID] = r
	}
	return out
}

func sdeRule(t *testing.T, id string) Rule {
	t.Helper()
	r := sdeRules(t)[id]
	if r == nil {
		t.Fatalf("rule %s not registered", id)
	}
	return r
}

func TestSecretsDepsExpansionPositive(t *testing.T) {
	cases := []struct {
		name      string
		ruleID    string
		path      string
		content   string
		wantLines []int
		secret    string
	}{
		{
			name:      "telegram bot token",
			ruleID:    "VGL-SEC-025",
			path:      "src/notify/bot.ts",
			content:   "const bot = new Telegraf('" + sdeTelegramToken + "');",
			wantLines: []int{1},
			secret:    sdeTelegramToken,
		},
		{
			name:      "vault service token",
			ruleID:    "VGL-SEC-026",
			path:      "deploy/vault-agent.sh",
			content:   "export VAULT_TOKEN=" + sdeVaultToken,
			wantLines: []int{1},
			secret:    sdeVaultToken,
		},
		{
			name:   "vault batch token",
			ruleID: "VGL-SEC-026",
			path:   "ci/secrets.yaml",
			content: "env:\n" +
				"  VAULT_BATCH_TOKEN: " + sdeVaultBatchToken + "\n",
			wantLines: []int{2},
			secret:    sdeVaultBatchToken,
		},
		{
			name:   "npm token outside npmrc",
			ruleID: "VGL-SEC-028",
			path:   "ci/publish.yml",
			content: "env:\n" +
				"  NPM_TOKEN: " + sdeNPMToken + "\n",
			wantLines: []int{2},
			secret:    sdeNPMToken,
		},
		{
			name:   "gitlab deploy token",
			ruleID: "VGL-SEC-029",
			path:   "ci/.gitlab-ci.yml",
			content: "variables:\n" +
				"  CI_DEPLOY_TOKEN: " + sdeGitLabToken + "\n",
			wantLines: []int{2},
			secret:    sdeGitLabToken,
		},
		{
			name:      "azure service bus connection string",
			ruleID:    "VGL-SEC-030",
			path:      "src/appsettings.json",
			content:   `{ "ServiceBus": "Endpoint=sb://lv24.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=` + sdeAzureSBKey + `" }`,
			wantLines: []int{1},
			secret:    sdeAzureSBKey,
		},
		{
			name:   "azure service bus folded connection string",
			ruleID: "VGL-SEC-030",
			path:   "deploy/servicebus.yaml",
			content: "connectionString: >-\n" +
				"  Endpoint=sb://lv24.servicebus.windows.net/;\n" +
				"  SharedAccessKeyName=app;\n" +
				"  SharedAccessKey=" + sdeAzureSBKey + "\n",
			wantLines: []int{4},
			secret:    sdeAzureSBKey,
		},
		{
			name:      "composer secure-http disabled",
			ruleID:    "VGL-DEP-013",
			path:      "composer.json",
			content:   `{ "config": { "secure-http": false } }`,
			wantLines: []int{1},
		},
		{
			name:   "composer disable-tls enabled",
			ruleID: "VGL-DEP-013",
			path:   "composer.json",
			content: "{\n" +
				"  \"config\": {\n" +
				"    \"disable-tls\": true\n" +
				"  }\n" +
				"}\n",
			wantLines: []int{3},
		},
		{
			name:      "yarn berry strict ssl disabled",
			ruleID:    "VGL-DEP-014",
			path:      ".yarnrc.yml",
			content:   "enableStrictSsl: false\n",
			wantLines: []int{1},
		},
		{
			name:      "yarn classic strict ssl disabled",
			ruleID:    "VGL-DEP-014",
			path:      ".yarnrc",
			content:   "strict-ssl false\n",
			wantLines: []int{1},
		},
		{
			name:   "go insecure and checksum database off",
			ruleID: "VGL-DEP-015",
			path:   "Dockerfile",
			content: "FROM golang:1.22\n" +
				"ENV GOINSECURE=modules.lv24.by\n" +
				"RUN GOSUMDB=off go build ./...\n",
			wantLines: []int{2, 3},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := sdeRule(t, tc.ruleID)
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
				if fd.Confidence == "" {
					t.Error("empty confidence")
				}
				if fd.Remediation == "" {
					t.Error("empty remediation")
				}
				if len(fd.References) == 0 {
					t.Error("empty references")
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

func TestSecretsDepsExpansionNegative(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		path    string
		content string
	}{
		{
			name:    "telegram token from environment",
			ruleID:  "VGL-SEC-025",
			path:    "src/notify/bot.ts",
			content: `const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN!);`,
		},
		{
			name:    "telegram token in comment",
			ruleID:  "VGL-SEC-025",
			path:    "src/notify/bot.ts",
			content: "// const bot = new Telegraf('" + sdeTelegramToken + "');",
		},
		{
			name:    "telegram placeholder bot id",
			ruleID:  "VGL-SEC-025",
			path:    "src/notify/bot.ts",
			content: `const bot = new Telegraf('0000000000:A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r');`,
		},
		{
			name:    "vault token from approle login",
			ruleID:  "VGL-SEC-026",
			path:    "deploy/vault-agent.sh",
			content: `export VAULT_TOKEN="$(vault write -field=token auth/approle/login role_id="$ROLE" secret_id="$SECRET")"`,
		},
		{
			name:    "npm token from ci secrets",
			ruleID:  "VGL-SEC-028",
			path:    "ci/publish.yml",
			content: "env:\n  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
		},
		{
			name:    "npm token owned by npmrc rule",
			ruleID:  "VGL-SEC-028",
			path:    ".npmrc",
			content: "//registry.npmjs.org/:_authToken=" + sdeNPMToken + "\n",
		},
		{
			name:    "gitlab token from masked variable",
			ruleID:  "VGL-SEC-029",
			path:    "ci/.gitlab-ci.yml",
			content: "variables:\n  CI_DEPLOY_TOKEN: $CI_DEPLOY_TOKEN\n",
		},
		{
			name:    "gitlab personal token owned by sec 004",
			ruleID:  "VGL-SEC-029",
			path:    "ci/.gitlab-ci.yml",
			content: "variables:\n  GITLAB_TOKEN: " + "glpat-" + "A1b2C3d4E5f6G7h8I9j0K1l2" + "\n",
		},
		{
			name:    "azure connection string from environment",
			ruleID:  "VGL-SEC-030",
			path:    "src/appsettings.json",
			content: `{ "ServiceBus": "Endpoint=sb://lv24.servicebus.windows.net/;SharedAccessKeyName=app;SharedAccessKey=${SERVICEBUS_KEY}" }`,
		},
		{
			name:    "azure key name without a key",
			ruleID:  "VGL-SEC-030",
			path:    "src/appsettings.json",
			content: `{ "ServiceBus": "Endpoint=sb://lv24.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey" }`,
		},
		{
			name:    "composer secure http enabled",
			ruleID:  "VGL-DEP-013",
			path:    "composer.json",
			content: `{ "config": { "secure-http": true, "disable-tls": false } }`,
		},
		{
			name:    "yarn berry strict ssl enabled",
			ruleID:  "VGL-DEP-014",
			path:    ".yarnrc.yml",
			content: "enableStrictSsl: true\n",
		},
		{
			name:    "yarn classic strict ssl enabled",
			ruleID:  "VGL-DEP-014",
			path:    ".yarnrc",
			content: "strict-ssl true\n",
		},
		{
			name:    "go private modules",
			ruleID:  "VGL-DEP-015",
			path:    "Dockerfile",
			content: "FROM golang:1.22\nENV GOPRIVATE=git.lv24.by\nRUN go build ./...\n",
		},
		{
			name:    "go insecure from environment",
			ruleID:  "VGL-DEP-015",
			path:    "Dockerfile",
			content: "FROM golang:1.22\nENV GOINSECURE=${GO_INSECURE}\n",
		},
		{
			name:    "go checksum database enabled",
			ruleID:  "VGL-DEP-015",
			path:    "ci/build.yml",
			content: "env:\n  GOSUMDB: sum.golang.org\n",
		},
		{
			name:    "go checksum setting in documentation",
			ruleID:  "VGL-DEP-015",
			path:    "docs/build.md",
			content: "Run with `GOSUMDB=off` only if you must.\n",
		},
		{
			name:    "go checksum setting in comment",
			ruleID:  "VGL-DEP-015",
			path:    "Dockerfile",
			content: "FROM golang:1.22\n# GOSUMDB=off\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := sdeRule(t, tc.ruleID)
			if got := rule.Check(secTestFile(tc.path, tc.content)); len(got) != 0 {
				t.Fatalf("expected no findings, got %+v", got)
			}
		})
	}
}

func TestSecretsDepsExpansionMetadata(t *testing.T) {
	want := map[string]struct {
		category model.Category
		severity model.Severity
	}{
		"VGL-SEC-025": {model.CategorySecrets, model.SeverityCritical},
		"VGL-SEC-026": {model.CategorySecrets, model.SeverityCritical},
		"VGL-SEC-028": {model.CategorySecrets, model.SeverityHigh},
		"VGL-SEC-029": {model.CategorySecrets, model.SeverityHigh},
		"VGL-SEC-030": {model.CategorySecrets, model.SeverityCritical},
		"VGL-DEP-013": {model.CategoryDependency, model.SeverityHigh},
		"VGL-DEP-014": {model.CategoryDependency, model.SeverityHigh},
		"VGL-DEP-015": {model.CategoryDependency, model.SeverityHigh},
	}
	rules := sdeRules(t)
	for id, exp := range want {
		r := rules[id]
		if r == nil {
			t.Errorf("missing rule %s", id)
			continue
		}
		m := r.Meta()
		if m.Title == "" || m.Description == "" {
			t.Errorf("%s: empty title or description", id)
		}
		if m.Category != exp.category {
			t.Errorf("%s: category = %q, want %q", id, m.Category, exp.category)
		}
		if m.Severity != exp.severity {
			t.Errorf("%s: severity = %q, want %q", id, m.Severity, exp.severity)
		}
		if len(m.CWE) == 0 {
			t.Errorf("%s: no CWE", id)
		}
		if len(m.OWASP) == 0 {
			t.Errorf("%s: no OWASP", id)
		}
		if len(m.Tags) == 0 {
			t.Errorf("%s: no tags", id)
		}
		if len(m.References) == 0 {
			t.Errorf("%s: no references", id)
		}
	}
}
