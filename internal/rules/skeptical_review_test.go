package rules

import (
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func mcpCompactConfig(args string) string {
	return `{"mcpServers":{"s":{"command":"npx","args":[` + args + `]}}}`
}

// Regression: any "@<text>" other than "latest" counted as pinned, so a range,
// a wildcard or a moving dist-tag passed the "pin an exact version" rule.
func TestMCPUnpinnedRangesAndDistTags(t *testing.T) {
	rule := mcpTestRule(t, "VGL-MCP-001")
	unpinned := []string{
		`"-y","pkg@*"`,
		`"-y","pkg@x"`,
		`"-y","pkg@next"`,
		`"-y","pkg@beta"`,
		`"-y","pkg@^1.0.0"`,
		`"-y","pkg@~1.2.3"`,
		`"-y","pkg@>=1.0.0"`,
		`"-y","pkg@1"`,
		`"-y","pkg@1.2"`,
		`"-y","pkg@1.x"`,
		`"-y","@scope/pkg@^2.0.0"`,
		`"-y","pkg@LATEST"`,
	}
	for _, args := range unpinned {
		if got := rule.Check(mcpTestFile(".mcp.json", mcpCompactConfig(args))); len(got) == 0 {
			t.Errorf("args [%s]: no VGL-MCP-001 finding, want one", args)
		}
	}
	pinned := []string{
		`"-y","pkg@1.2.3"`,
		`"-y","@scope/pkg@1.2.3"`,
		`"-y","pkg@1.2.3-beta.1"`,
		`"-y","pkg@v1.2.3"`,
		`"-y","pkg@0.0.1+build.5"`,
	}
	for _, args := range pinned {
		if got := rule.Check(mcpTestFile(".mcp.json", mcpCompactConfig(args))); len(got) != 0 {
			t.Errorf("args [%s]: unexpected VGL-MCP-001 finding %q", args, got[0].Evidence)
		}
	}

	uvx := func(spec string) string {
		return `{"mcpServers":{"s":{"command":"uvx","args":["` + spec + `"]}}}`
	}
	for _, spec := range []string{"pkg==1.*", "pkg==latest"} {
		if got := rule.Check(mcpTestFile(".mcp.json", uvx(spec))); len(got) == 0 {
			t.Errorf("uvx %s: no VGL-MCP-001 finding, want one", spec)
		}
	}
	for _, spec := range []string{"pkg==1.2.3", "pkg==2024.10", "pkg@1.2.3"} {
		if got := rule.Check(mcpTestFile(".mcp.json", uvx(spec))); len(got) != 0 {
			t.Errorf("uvx %s: unexpected VGL-MCP-001 finding %q", spec, got[0].Evidence)
		}
	}
}

// Regression: OpenCode resolves "{env:VAR}" and "{file:path}" at runtime. The
// reference check stripped an "env:" prefix but the value starts with a brace,
// so a correct config was reported as a critical literal secret.
func TestMCPLiteralSecretIgnoresOpenCodeReferences(t *testing.T) {
	rule := mcpTestRule(t, "VGL-MCP-002")
	for _, value := range []string{"{env:MY_SERVICE_TOKEN}", "{file:~/.secrets/service-token}", "{ENV:MY_SERVICE_TOKEN}"} {
		cfg := `{"mcp":{"s":{"type":"local","command":["npx","-y","pkg@1.2.3"],"environment":{"SERVICE_TOKEN":"` + value + `"}}}}`
		if got := rule.Check(mcpTestFile("opencode.json", cfg)); len(got) != 0 {
			t.Errorf("value %s: unexpected finding %q", value, got[0].Evidence)
		}
	}
	cfg := `{"mcp":{"s":{"type":"local","command":["npx","-y","pkg@1.2.3"],"environment":{"SERVICE_TOKEN":"q8Zr2LmP0vXy7Tn4Kb9WfD3s"}}}}`
	if got := rule.Check(mcpTestFile("opencode.json", cfg)); len(got) == 0 {
		t.Error("a literal token next to the reference syntax must still be reported")
	}
}

// Regression: MCP-002 skipped values longer than 200 characters, values under
// a *_PASS / *_PWD key and "Authorization: Bearer <token>" (the value has a
// space), and the shared redaction missed URL userinfo. Any other finding on
// the same line then printed those values verbatim.
func TestMCPDetectsAndRedactsMoreSecretShapes(t *testing.T) {
	const (
		longToken = "Zk3" + "Qw9eRt7yUi1oPa5sDf2gHj6kLz8xCv4bNm0" // repeated below to pass 200 chars
		passValue = "LiteralPassVal99x"
		bearer    = "q8Zr2LmP0vXy7Tn4Kb9W"
		userinfo  = "Sup3rSecretPw9"
	)
	long := strings.Repeat(longToken, 7)
	if len(long) <= 200 {
		t.Fatalf("fixture token is %d characters, want more than 200", len(long))
	}
	cfg := strings.Join([]string{
		`{"mcpServers": {`,
		`"a": {"command": "npx", "args": ["-y", "pkg-a"], "env": {"DATABASE_URL": "postgres://alice:` + userinfo + `@db.example.com/x", "DB_PASS": "` + passValue + `"}},`,
		`"b": {"command": "npx", "args": ["-y", "pkg-b"], "env": {"API_TOKEN": "` + long + `"}},`,
		`"c": {"command": "npx", "args": ["-y", "pkg-c"], "headers": {"Authorization": "Bearer ` + bearer + `"}}`,
		`}}`,
	}, "\n")
	file := mcpTestFile(".mcp.json", cfg)

	var all []model.Finding
	for _, r := range MCPRules() {
		all = append(all, r.Check(file)...)
	}
	if len(all) == 0 {
		t.Fatal("fixture produced no MCP findings")
	}
	for _, f := range all {
		for name, value := range map[string]string{"long token": long, "DB_PASS": passValue, "bearer": bearer, "userinfo": userinfo} {
			if strings.Contains(f.Evidence, value) || strings.Contains(f.Location.Snippet, value) {
				t.Errorf("%s line %d prints the raw %s value", f.RuleID, f.Location.StartLine, name)
			}
		}
	}

	literal := map[int]bool{}
	for _, f := range mcpTestRule(t, "VGL-MCP-002").Check(file) {
		literal[f.Location.StartLine] = true
	}
	for line, what := range map[int]string{2: "DB_PASS / URL password", 3: "long API token", 4: "bearer header"} {
		if !literal[line] {
			t.Errorf("VGL-MCP-002 does not report the %s on line %d", what, line)
		}
	}
}

// Regression: the Rails helper is usually written without parentheses
// ("raw params[:q]"), which the rule did not match.
func TestRubyRawWithoutParentheses(t *testing.T) {
	rule := wave2Rule(t, InjectionRules(), "VGL-INJ-065")
	erb := "app/views/search/show.html.erb"

	cawCheck(t, rule, erb, "other", `<%= raw params[:q] %>`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, erb, "other", `<%= raw @user.bio %>`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, erb, "other", `<%= raw request.query_parameters["q"] %>`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, erb, "other", `<%= raw cookies[:banner] %>`,
		cawWant{line: 1, sev: model.SeverityHigh})

	// Safe: prose and literals are not the helper call.
	cawCheck(t, rule, erb, "other", `<p>Send the raw request body to support.</p>`)
	cawCheck(t, rule, erb, "other", `<p>We never store raw session data.</p>`)
	cawCheck(t, rule, erb, "other", `<%= raw "<b>static</b>" %>`)
	cawCheck(t, rule, erb, "other", `<%= raw sanitize(params[:q]) %>`)
}
