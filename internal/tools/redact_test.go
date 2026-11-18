package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// scanPayloadInto decodes structuredContent back into scanPayload. result
// round-trips the payload through JSON, so concrete Go types are not preserved
// and tests must decode the JSON shape instead of type-asserting it.
func scanPayloadInto(t *testing.T, res *mcp.CallToolResult) scanPayload {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatalf("tool result has no structuredContent")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("re-encode structuredContent: %v", err)
	}
	var out scanPayload
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structuredContent: %v", err)
	}
	return out
}

// redactTest fixtures are assembled at runtime so this file never contains a
// contiguous live-looking credential.
const (
	redactTestAPIKey = "cfg-local-api-key-9f2b"
	redactTestAWSKey = "AKIA" + "Z7Q2LMN4RSTUVWXY"
	redactTestGitHub = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUvWxYz1Bc2D"
)

var redactTestJWT = strings.Join([]string{
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	"eyJzdWIiOiIxMjM0NTY3ODkwIn0",
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
}, ".")

func redactTestDeps() Deps {
	return Deps{App: &app.App{Config: config.Config{APIKey: redactTestAPIKey}}}
}

// TestRedactStructuredMasksValuesOnly walks nested maps and slices and checks
// that only secret-looking values are masked: keys, ordinary strings and
// scalars keep their value so the decoded JSON shape stays usable.
func TestRedactStructuredMasksValuesOnly(t *testing.T) {
	in := map[string]any{
		"apiKey": redactTestAPIKey,
		"nested": map[string]any{
			"aws":    redactTestAWSKey,
			"github": redactTestGitHub,
			"list":   []any{redactTestGitHub, "plain text", float64(7), true, nil},
		},
	}

	got := redactStructured(redactTestDeps(), in)
	out, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("redactStructured returned %T, want map[string]any", got)
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested = %T, want map[string]any", out["nested"])
	}
	if len(out) != 2 || len(nested) != 3 {
		t.Fatalf("shape changed: top=%d nested=%d, want 2 and 3", len(out), len(nested))
	}
	if got := out["apiKey"]; got != "***" {
		t.Errorf("configured API key = %v, want ***", got)
	}
	if got := nested["aws"]; got != rules.MaskSecret(redactTestAWSKey) {
		t.Errorf("AWS key = %v, want %q", got, rules.MaskSecret(redactTestAWSKey))
	}
	if got := nested["github"]; got != rules.MaskSecret(redactTestGitHub) {
		t.Errorf("GitHub token = %v, want %q", got, rules.MaskSecret(redactTestGitHub))
	}

	list, ok := nested["list"].([]any)
	if !ok {
		t.Fatalf("list = %T, want []any", nested["list"])
	}
	if len(list) != 5 {
		t.Fatalf("list length = %d, want 5", len(list))
	}
	if list[0] != rules.MaskSecret(redactTestGitHub) {
		t.Errorf("list[0] = %v, want the masked GitHub token", list[0])
	}
	if list[1] != "plain text" || list[2] != float64(7) || list[3] != true || list[4] != nil {
		t.Errorf("non-string scalars changed: %#v", list[1:])
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal redacted value: %v", err)
	}
	for _, secret := range []string{redactTestAPIKey, redactTestAWSKey, redactTestGitHub} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("redacted value still contains %q: %s", secret, raw)
		}
	}
}

// TestResultRedactsStructuredContent: result applies redaction to the text and
// the structured payload while keeping the JSON shape clients decode.
func TestResultRedactsStructuredContent(t *testing.T) {
	payload := &scanPayload{ScanResult: &model.ScanResult{
		ID:   "scan-redact",
		Root: "/repo",
		Findings: []model.Finding{{
			ID:     "VGL-TEST-1",
			RuleID: "VGL-SEC-001",
			Location: model.Location{
				Path:      "a.py",
				StartLine: 2,
				Snippet:   "aws = " + redactTestAWSKey,
			},
		}},
	}}

	res := result(redactTestDeps(), "text "+redactTestAWSKey, payload)

	if text := res.Content[0].Text; strings.Contains(text, redactTestAWSKey) {
		t.Errorf("text leaked the raw AWS key: %s", text)
	}
	if _, ok := res.StructuredContent.(map[string]any); !ok {
		t.Fatalf("structuredContent = %T, want the JSON-decoded map", res.StructuredContent)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structuredContent: %v", err)
	}
	if strings.Contains(string(raw), redactTestAWSKey) {
		t.Fatalf("structuredContent leaked the raw AWS key: %s", raw)
	}

	var decoded struct {
		ID       string `json:"id"`
		Root     string `json:"root"`
		Findings []struct {
			ID       string `json:"id"`
			RuleID   string `json:"ruleId"`
			Location struct {
				Path      string `json:"path"`
				StartLine int    `json:"startLine"`
				Snippet   string `json:"snippet"`
			} `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode structuredContent: %v", err)
	}
	if decoded.ID != "scan-redact" || decoded.Root != "/repo" {
		t.Errorf("top-level shape changed: %+v", decoded)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(decoded.Findings))
	}
	f := decoded.Findings[0]
	if f.ID != "VGL-TEST-1" || f.RuleID != "VGL-SEC-001" {
		t.Errorf("finding identity changed: %+v", f)
	}
	if f.Location.Path != "a.py" || f.Location.StartLine != 2 {
		t.Errorf("finding location changed: %+v", f.Location)
	}
	if want := rules.MaskSecret(redactTestAWSKey); !strings.Contains(f.Location.Snippet, want) {
		t.Errorf("snippet = %q, want it to contain %q", f.Location.Snippet, want)
	}
}

// redactTestApp builds a hermetic app with a configured API key, so the scan
// path really applies the configured-key redactor to its output.
func redactTestApp(t *testing.T) (*app.App, string) {
	t.Helper()
	t.Setenv("VIGIL_NO_LLM", "1")
	t.Setenv("VIGIL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("VIGIL_API_KEY", redactTestAPIKey)
	for _, env := range []string{
		"VIGIL_PROVIDER", "VIGIL_MODEL", "VIGIL_BASE_URL", "VIGIL_USE_LLM",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
		"OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY",
		"XAI_API_KEY", "OLLAMA_HOST",
	} {
		t.Setenv(env, "")
	}
	dir := t.TempDir()
	a, err := app.New(dir, nil)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, dir
}

// TestScanStructuredContentRedactsSnippetTokens: a token that no secret rule
// reports on its own (the canonical jwt.io example is a documented sample, so
// VGL-SEC-012 skips it) still appears in a non-secret finding's raw snippet.
// The hard redactor must remove it from structuredContent without touching the
// finding identity or location.
func TestScanStructuredContentRedactsSnippetTokens(t *testing.T) {
	a, dir := redactTestApp(t)
	src := "signature = hashlib.md5(" + redactTestJWT + ".encode()).hexdigest()\n"
	if err := os.WriteFile(filepath.Join(dir, "weak_hash.py"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	res, err := handleScan(context.Background(), Deps{App: a}, json.RawMessage(`{"mode":"quick","noBaseline":true}`))
	if err != nil {
		t.Fatalf("handleScan: %v", err)
	}
	if res.IsError {
		t.Fatalf("scan failed: %s", res.Content[0].Text)
	}
	if text := res.Content[0].Text; strings.Contains(text, redactTestJWT) {
		t.Errorf("scan text leaked the raw JWT:\n%s", text)
	}

	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structuredContent: %v", err)
	}
	if strings.Contains(string(raw), redactTestJWT) {
		t.Fatalf("structuredContent leaked the raw JWT")
	}

	scan := scanPayloadInto(t, res)
	found := false
	for _, f := range scan.Findings {
		if f.RuleID != "VGL-CRY-001" {
			continue
		}
		found = true
		if f.ID == "" {
			t.Errorf("weak-hash finding lost its ID")
		}
		if f.Location.Path != "weak_hash.py" || f.Location.StartLine < 1 {
			t.Errorf("weak-hash location changed: %+v", f.Location)
		}
		if want := rules.MaskSecret(redactTestJWT); !strings.Contains(f.Location.Snippet, want) {
			t.Errorf("weak-hash snippet = %q, want it to contain %q", f.Location.Snippet, want)
		}
	}
	if !found {
		t.Fatalf("fixture did not produce a VGL-CRY-001 finding: %+v", scan.Findings)
	}
}
