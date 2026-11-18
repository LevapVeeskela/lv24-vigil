package tools_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
	"github.com/levapveeskela/lv24-vigil/internal/tools"
)

const (
	fixOriginalLine    = `aws_access_key_id = "` + awsKey + `"`
	fixReplacementLine = `aws_access_key_id = os.environ["AWS_ACCESS_KEY_ID"]`
	fixApprovalAPIKey  = "sk-fix-approval-key"
)

// fixTestDiff is a valid one-line diff against the harness config.py.
var fixTestDiff = "diff --git a/config.py b/config.py\n" +
	"--- a/config.py\n" +
	"+++ b/config.py\n" +
	"@@ -1 +1 @@\n" +
	"-" + fixOriginalLine + "\n" +
	"+" + fixReplacementLine + "\n"

type fixHarness struct {
	h       *harness
	app     *app.App
	finding model.Finding
	client  *rpcClient
	calls   *atomic.Int32
}

type fixProposalPayload struct {
	ScanID       string            `json:"scanId"`
	FindingID    string            `json:"findingId"`
	Mode         string            `json:"mode"`
	FixID        string            `json:"fixId"`
	DiffSHA256   string            `json:"diffSha256"`
	DiffRedacted bool              `json:"diffRedacted"`
	ExpiresAt    time.Time         `json:"expiresAt"`
	Targets      map[string]string `json:"targets"`
	Applied      bool              `json:"applied"`
	Fix          *model.Fix        `json:"fix"`
}

type fixApplyPayload struct {
	ScanID          string   `json:"scanId"`
	FindingID       string   `json:"findingId"`
	Applied         bool     `json:"applied"`
	FixID           string   `json:"fixId"`
	DiffSHA256      string   `json:"diffSha256"`
	VerifiedTargets []string `json:"verifiedTargets"`
	Warning         string   `json:"warning"`
}

// newFixHarness scans deterministically, then rebuilds the app with a fake
// OpenAI-compatible model so vigil_fix can propose a known diff.
func newFixHarness(t *testing.T, unsafeUnbound bool) *fixHarness {
	t.Helper()
	h := newHarness(t)
	initGitRepo(t, h.repo)
	scan := h.scan()
	finding := firstFindingOn(t, scan, "config.py")

	srv, calls := fakeFixModel(t)
	t.Setenv("VIGIL_NO_LLM", "")
	t.Setenv("VIGIL_PROVIDER", "openai")
	t.Setenv("VIGIL_MODEL", "test-model")
	t.Setenv("VIGIL_BASE_URL", srv.URL+"/v1")
	t.Setenv("VIGIL_API_KEY", fixApprovalAPIKey)

	a, err := app.New(h.repo, nil)
	if err != nil {
		t.Fatalf("app.New with fake model: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if !a.LLM {
		t.Fatalf("fake model was not configured: %+v", a.Warnings)
	}
	return &fixHarness{
		h:       h,
		app:     a,
		finding: finding,
		client:  newFixClient(t, a, false, unsafeUnbound),
		calls:   calls,
	}
}

func newFixClient(t *testing.T, a *app.App, readOnly, unsafeUnbound bool) *rpcClient {
	t.Helper()
	srv := mcp.NewServer("vigil", "test", "Vigil")
	tools.Register(srv, tools.Deps{
		App:              a,
		Version:          "test",
		ReadOnly:         readOnly,
		UnsafeUnboundFix: unsafeUnbound,
	})
	if readOnly {
		srv.HideTools("vigil_fix")
	}
	return startServer(t, srv)
}

func initGitRepo(t *testing.T, repo string) {
	t.Helper()
	cmd := exec.Command("git", "init", "--quiet", repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
}

func firstFindingOn(t *testing.T, scan model.ScanResult, path string) model.Finding {
	t.Helper()
	for _, f := range scan.Findings {
		if f.Location.Path == path {
			return f
		}
	}
	t.Fatalf("scan found no finding on %s", path)
	return model.Finding{}
}

// fakeFixModel returns the canned diff for every chat-completions request and
// counts how often it was called.
func fakeFixModel(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("fake model method = %s, want POST", r.Method)
		}
		content, err := json.Marshal(map[string]string{
			"diff":        fixTestDiff,
			"description": "Read the access key from the environment.",
		})
		if err != nil {
			t.Errorf("encode fake response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "test-model",
			"choices": []any{map[string]any{
				"message":       map[string]any{"role": "assistant", "content": string(content)},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 1},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func (h *fixHarness) propose(t *testing.T) (fixProposalPayload, string) {
	t.Helper()
	res := callTool(t, h.client, "vigil_fix", map[string]any{"findingId": h.finding.ID})
	if res.IsError {
		t.Fatalf("propose failed: %s", textOf(t, res))
	}
	return structuredInto[fixProposalPayload](t, res), textOf(t, res)
}

func readFixSource(t *testing.T, repo string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, "config.py"))
	if err != nil {
		t.Fatalf("read config.py: %v", err)
	}
	// git apply honours core.autocrlf on Windows; compare content, not the
	// checkout's line-ending policy.
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func pendingFile(repo, fixID string) string {
	return filepath.Join(repo, ".vigil", "pending", fixID+".json")
}

// rewriteProposal edits the stored JSON so tests can force expiry without
// waiting fifteen minutes.
func rewriteProposal(t *testing.T, repo, fixID string, mutate func(map[string]any)) {
	t.Helper()
	path := pendingFile(repo, fixID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read proposal: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode proposal: %v", err)
	}
	mutate(payload)
	updated, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("encode proposal: %v", err)
	}
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		t.Fatalf("write proposal: %v", err)
	}
}

func TestFixApplyRequiresReviewedProposal(t *testing.T) {
	h := newFixHarness(t, false)
	before := readFixSource(t, h.h.repo)

	res := callTool(t, h.client, "vigil_fix", map[string]any{"findingId": h.finding.ID, "apply": true})
	if code := toolErrorCode(t, res); code != tools.CodeFixUnbound {
		t.Fatalf("unbound apply code = %q, want %q", code, tools.CodeFixUnbound)
	}
	if text := textOf(t, res); !strings.Contains(text, "mode=propose") {
		t.Errorf("refusal does not explain how to propose first: %q", text)
	}
	if got := h.calls.Load(); got != 0 {
		t.Errorf("unbound apply called the model %d time(s), want 0", got)
	}
	if got := readFixSource(t, h.h.repo); got != before {
		t.Errorf("unbound apply changed the source:\n%s", got)
	}
	if entries, err := os.ReadDir(filepath.Join(h.h.repo, ".vigil", "pending")); err == nil && len(entries) != 0 {
		t.Errorf("unbound apply stored %d proposal file(s)", len(entries))
	}

	if _, err := os.Stat(filepath.Join(h.h.repo, ".vigil", "pending")); !os.IsNotExist(err) {
		t.Errorf("unbound apply created the pending directory")
	}
}

func TestFixProposeThenApplyExactReviewedDiff(t *testing.T) {
	h := newFixHarness(t, false)
	original := readFixSource(t, h.h.repo)

	p, text := h.propose(t)
	if p.Mode != "propose" {
		t.Errorf("mode = %q, want propose", p.Mode)
	}
	if !strings.HasPrefix(p.FixID, "fx_") || len(p.FixID) != 19 {
		t.Errorf("fixId = %q, want fx_ plus 16 hex characters", p.FixID)
	}
	if len(p.DiffSHA256) != 64 {
		t.Errorf("diffSha256 = %q, want 64 hex characters", p.DiffSHA256)
	}
	if p.Applied {
		t.Error("propose reports the fix as applied")
	}
	// Tool output applies the hard redactor to every string, including a diff
	// that quotes the credential, so the reviewed diff is the redacted form.
	if p.Fix == nil || p.Fix.Diff != rules.RedactSecrets(fixTestDiff, nil) {
		t.Errorf("propose did not return the diff: %+v", p.Fix)
	}
	if !p.DiffRedacted {
		t.Error("propose did not flag the redacted diff")
	}
	if !strings.Contains(text, "credential-shaped text") {
		t.Errorf("propose text does not explain the masked diff:\n%s", text)
	}
	// diffSha256 binds the stored unmasked proposal, which is what apply uses.
	rawSum := sha256.Sum256([]byte(fixTestDiff))
	if p.DiffSHA256 != hex.EncodeToString(rawSum[:]) {
		t.Errorf("diffSha256 = %q, want the stored diff hash", p.DiffSHA256)
	}
	sum := sha256.Sum256([]byte(original))
	if p.Targets["config.py"] != hex.EncodeToString(sum[:]) {
		t.Errorf("target hash = %q, want the pre-image hash", p.Targets["config.py"])
	}
	if ttl := time.Until(p.ExpiresAt); ttl <= 0 || ttl > 15*time.Minute+time.Minute {
		t.Errorf("expiresAt is %v away, want about 15 minutes", ttl)
	}
	if got := readFixSource(t, h.h.repo); got != original {
		t.Errorf("propose wrote the source file")
	}
	if _, err := os.Stat(pendingFile(h.h.repo, p.FixID)); err != nil {
		t.Errorf("proposal not stored: %v", err)
	}
	if !strings.Contains(text, p.FixID) || !strings.Contains(text, p.DiffSHA256) {
		t.Errorf("proposal text does not carry the review handle:\n%s", text)
	}
	if got := h.calls.Load(); got != 1 {
		t.Errorf("model called %d times for one proposal, want 1", got)
	}

	applyRes := callTool(t, h.client, "vigil_fix", map[string]any{
		"findingId":  h.finding.ID,
		"mode":       "apply",
		"fixId":      p.FixID,
		"diffSha256": p.DiffSHA256,
	})
	if applyRes.IsError {
		t.Fatalf("apply failed: %s", textOf(t, applyRes))
	}
	applied := structuredInto[fixApplyPayload](t, applyRes)
	if !applied.Applied || applied.FixID != p.FixID || applied.DiffSHA256 != p.DiffSHA256 {
		t.Errorf("apply payload = %+v", applied)
	}
	if len(applied.VerifiedTargets) != 1 || applied.VerifiedTargets[0] != "config.py" {
		t.Errorf("verifiedTargets = %v, want [config.py]", applied.VerifiedTargets)
	}
	if applied.Warning != "" {
		t.Errorf("bound apply carries a warning: %q", applied.Warning)
	}
	if got := readFixSource(t, h.h.repo); got != fixReplacementLine+"\n" {
		t.Errorf("source = %q, want the replacement line", got)
	}
	if got := h.calls.Load(); got != 1 {
		t.Errorf("apply called the model (%d calls); the stored diff must be applied", got)
	}

	replay := callTool(t, h.client, "vigil_fix", map[string]any{
		"findingId":  h.finding.ID,
		"mode":       "apply",
		"fixId":      p.FixID,
		"diffSha256": p.DiffSHA256,
	})
	if code := toolErrorCode(t, replay); code != tools.CodeFixConsumed {
		t.Errorf("replay code = %q, want %q", code, tools.CodeFixConsumed)
	}
}

func TestFixApplyRejectsUnknownOrMismatchedProposal(t *testing.T) {
	h := newFixHarness(t, false)
	p, _ := h.propose(t)

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{
			name: "missing diff hash",
			args: map[string]any{"mode": "apply", "fixId": p.FixID},
			want: tools.CodeFixUnbound,
		},
		{
			name: "unknown fix id",
			args: map[string]any{"mode": "apply", "fixId": "fx_0000000000000000", "diffSha256": p.DiffSHA256},
			want: tools.CodeFixNotFound,
		},
		{
			name: "traversal fix id",
			args: map[string]any{"mode": "apply", "fixId": "../escape", "diffSha256": p.DiffSHA256},
			want: tools.CodeFixNotFound,
		},
		{
			name: "wrong diff hash",
			args: map[string]any{"mode": "apply", "fixId": p.FixID, "diffSha256": strings.Repeat("0", 64)},
			want: tools.CodeFixMismatch,
		},
		{
			name: "wrong scan",
			args: map[string]any{"mode": "apply", "scanId": "scan-other", "fixId": p.FixID, "diffSha256": p.DiffSHA256},
			want: tools.CodeFixMismatch,
		},
		{
			name: "conflicting mode and apply flag",
			args: map[string]any{"findingId": h.finding.ID, "mode": "propose", "apply": true},
			want: tools.CodeArgs,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := callTool(t, h.client, "vigil_fix", tc.args)
			if code := toolErrorCode(t, res); code != tc.want {
				t.Errorf("code = %q, want %q (message: %s)", code, tc.want, textOf(t, res))
			}
		})
	}
	if got := readFixSource(t, h.h.repo); got != fixOriginalLine+"\n" {
		t.Errorf("a rejected apply changed the source: %q", got)
	}
}

func TestFixApplyRejectsExpiredProposal(t *testing.T) {
	h := newFixHarness(t, false)
	p, _ := h.propose(t)
	// Move the server clock past the 15-minute TTL instead of editing the
	// signed proposal: tampering must be rejected as unauthentic, not expired.
	restore := tools.SetPendingClockForTest(func() time.Time { return time.Now().Add(16 * time.Minute) })
	defer restore()

	res := callTool(t, h.client, "vigil_fix", map[string]any{
		"mode":       "apply",
		"fixId":      p.FixID,
		"diffSha256": p.DiffSHA256,
	})
	if code := toolErrorCode(t, res); code != tools.CodeFixExpired {
		t.Fatalf("code = %q, want %q", code, tools.CodeFixExpired)
	}
	if got := readFixSource(t, h.h.repo); got != fixOriginalLine+"\n" {
		t.Errorf("expired apply changed the source: %q", got)
	}
}

func TestFixApplyRejectsChangedTarget(t *testing.T) {
	h := newFixHarness(t, false)
	p, _ := h.propose(t)

	writeRepoFile(t, h.h.repo, "config.py", fixOriginalLine+"\n# edited after the proposal\n")
	res := callTool(t, h.client, "vigil_fix", map[string]any{
		"mode":       "apply",
		"fixId":      p.FixID,
		"diffSha256": p.DiffSHA256,
	})
	if code := toolErrorCode(t, res); code != tools.CodeFileChanged {
		t.Fatalf("code = %q, want %q", code, tools.CodeFileChanged)
	}

	// The failed target check must not consume the proposal: restoring the
	// reviewed pre-image makes the same proposal applicable again.
	writeRepoFile(t, h.h.repo, "config.py", fixOriginalLine+"\n")
	res = callTool(t, h.client, "vigil_fix", map[string]any{
		"mode":       "apply",
		"fixId":      p.FixID,
		"diffSha256": p.DiffSHA256,
	})
	if res.IsError {
		t.Fatalf("restored proposal did not apply: %s", textOf(t, res))
	}
	if got := readFixSource(t, h.h.repo); got != fixReplacementLine+"\n" {
		t.Errorf("source after restored apply = %q", got)
	}
}

func TestFixReadOnlyRejectsBeforeProposal(t *testing.T) {
	h := newFixHarness(t, false)
	readOnly := newFixClient(t, h.app, true, false)

	for _, args := range []map[string]any{
		{"findingId": h.finding.ID},
		{"findingId": h.finding.ID, "mode": "apply", "fixId": "fx_0000000000000000", "diffSha256": strings.Repeat("0", 64)},
	} {
		res := callTool(t, readOnly, "vigil_fix", args)
		if code := toolErrorCode(t, res); code != tools.CodeReadOnly {
			t.Errorf("read-only code = %q, want %q", code, tools.CodeReadOnly)
		}
	}
	if got := h.calls.Load(); got != 0 {
		t.Errorf("read-only server called the model %d time(s)", got)
	}
	if _, err := os.Stat(filepath.Join(h.h.repo, ".vigil", "pending")); !os.IsNotExist(err) {
		t.Errorf("read-only server stored a proposal")
	}
	if got := readFixSource(t, h.h.repo); got != fixOriginalLine+"\n" {
		t.Errorf("read-only server changed the source: %q", got)
	}
}

func TestFixUnsafeUnboundAppliesWithWarning(t *testing.T) {
	h := newFixHarness(t, true)

	res := callTool(t, h.client, "vigil_fix", map[string]any{"findingId": h.finding.ID, "apply": true})
	if res.IsError {
		t.Fatalf("unsafe unbound apply failed: %s", textOf(t, res))
	}
	payload := structuredInto[fixApplyPayload](t, res)
	if !payload.Applied {
		t.Error("unsafe unbound apply did not report applied")
	}
	if !strings.Contains(payload.Warning, "unsafe unbound") {
		t.Errorf("warning = %q, want the unsafe-unbound warning", payload.Warning)
	}
	if !strings.Contains(textOf(t, res), "Warning") {
		t.Errorf("text does not carry the warning:\n%s", textOf(t, res))
	}
	if got := readFixSource(t, h.h.repo); got != fixReplacementLine+"\n" {
		t.Errorf("source = %q, want the replacement line", got)
	}
	if _, err := os.Stat(filepath.Join(h.h.repo, ".vigil", "pending")); !os.IsNotExist(err) {
		t.Errorf("unsafe unbound apply stored a proposal")
	}
}

func TestFixRefusesModelOnlyFindingWithoutCorroboration(t *testing.T) {
	h := newHarness(t)

	llmOnly := craftedFinding("LLM-ONLY-001", "config.py", 1, 1)
	llmOnly.Source = model.SourceLLM
	saveCraftedScan(t, h, []model.Finding{llmOnly}, nil)

	res := callTool(t, h.client, "vigil_fix", map[string]any{"findingId": llmOnly.ID})
	if code := toolErrorCode(t, res); code != tools.CodeFixNondeterministic {
		t.Fatalf("code = %q, want %q", code, tools.CodeFixNondeterministic)
	}
	text := textOf(t, res)
	if !strings.Contains(text, "model only") || !strings.Contains(text, "deterministic") {
		t.Errorf("refusal is not honest about model-only evidence: %s", text)
	}

	// A deterministic rule on an overlapping line is corroboration, so the
	// gate passes and the missing model becomes the reported problem.
	llmWithRule := craftedFinding("LLM-ONLY-002", "config.py", 5, 6)
	llmWithRule.Source = model.SourceLLM
	corroborating := craftedFinding("VGL-TEST-002", "config.py", 6, 8)
	saveCraftedScan(t, h, []model.Finding{llmWithRule, corroborating}, nil)

	res = callTool(t, h.client, "vigil_fix", map[string]any{"findingId": llmWithRule.ID})
	text = textOf(t, res)
	if strings.Contains(text, tools.CodeFixNondeterministic) {
		t.Fatalf("corroborated finding was refused as model-only: %s", text)
	}
	if !strings.Contains(text, "needs a model") {
		t.Fatalf("corroborated finding did not reach the model check: %s", text)
	}
}
