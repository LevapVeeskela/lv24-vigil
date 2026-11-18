package tools_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/tools"
)

const (
	snippetCanary  = "SNIPPET-LEAK-CANARY"
	evidenceCanary = "EVIDENCE-LEAK-CANARY"
)

// errorEnvelope decodes the stable structured error shape.
type errorEnvelope struct {
	Error struct {
		Code       string            `json:"code"`
		Message    string            `json:"message"`
		Candidates []tools.Candidate `json:"candidates"`
	} `json:"error"`
}

func errorDetails(t *testing.T, res mcp.CallToolResult) errorEnvelope {
	t.Helper()
	if !res.IsError {
		t.Fatalf("result is not an error: %s", textOf(t, res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structuredContent: %v", err)
	}
	var env errorEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode structuredContent: %v", err)
	}
	if env.Error.Code == "" {
		t.Fatalf("typed error has no code: %s", raw)
	}
	return env
}

type resolutionPayload struct {
	MatchedBy string `json:"matchedBy"`
	Path      string `json:"path"`
	Line      int    `json:"line"`
}

type explainedPayload struct {
	Finding    model.Finding     `json:"finding"`
	Resolution resolutionPayload `json:"resolution"`
}

// craftedFinding builds a stored finding with a stable ID and fingerprint.
// EndLine is kept as given so legacy zero-EndLine scans stay testable.
func craftedFinding(rule, path string, start, end int) model.Finding {
	f := model.Finding{
		RuleID:     rule,
		Title:      rule + " finding",
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		Source:     model.SourceRule,
		Location: model.Location{
			Path:      path,
			StartLine: start,
			EndLine:   end,
			Snippet:   snippetCanary,
		},
		Evidence: evidenceCanary + "-" + rule,
	}
	f.ID = f.ComputeID()
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

func saveCraftedScan(t *testing.T, h *harness, findings, suppressed []model.Finding) model.ScanResult {
	t.Helper()
	res := model.ScanResult{
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Root:       h.repo,
		Mode:       "quick",
		Findings:   findings,
		Suppressed: suppressed,
		Engine:     "test",
		Version:    "test",
	}
	if err := h.app.Store.Save(&res); err != nil {
		t.Fatalf("save crafted scan: %v", err)
	}
	return res
}

// uniquePrefix returns the shortest prefix of id (at least 4 characters) that
// no other identity in the scan starts with.
func uniquePrefix(t *testing.T, id string, identities []string) string {
	t.Helper()
	for n := 4; n <= len(id); n++ {
		prefix := strings.ToLower(id[:n])
		unique := true
		for _, other := range identities {
			if other == id {
				continue
			}
			if strings.HasPrefix(strings.ToLower(other), prefix) {
				unique = false
				break
			}
		}
		if unique {
			return id[:n]
		}
	}
	t.Fatalf("no unique prefix for %q", id)
	return ""
}

func TestLookupByIDFingerprintAndUniquePrefix(t *testing.T) {
	h := newHarness(t)
	scan := saveCraftedScan(t, h, []model.Finding{
		craftedFinding("VGL-TEST-101", "a.py", 10, 10),
		craftedFinding("VGL-TEST-102", "b.py", 20, 20),
		craftedFinding("VGL-TEST-103", "c.py", 30, 30),
	}, nil)
	a := scan.Findings[0]
	identities := make([]string, 0, 2*len(scan.Findings))
	for _, f := range scan.Findings {
		identities = append(identities, f.ID, f.Fingerprint)
	}

	exact := h.client.tool("vigil_explain", map[string]any{"findingId": a.ID})
	if exact.IsError {
		t.Fatalf("exact ID did not resolve: %s", textOf(t, exact))
	}
	if got := structuredInto[explainedPayload](t, exact).Resolution.MatchedBy; got != "id" {
		t.Errorf("exact ID matchedBy = %q, want id", got)
	}

	fpPrefix := uniquePrefix(t, a.Fingerprint, identities)
	byFP := h.client.tool("vigil_explain", map[string]any{"findingId": fpPrefix})
	if byFP.IsError {
		t.Fatalf("unique fingerprint prefix %q did not resolve: %s", fpPrefix, textOf(t, byFP))
	}
	if got := structuredInto[explainedPayload](t, byFP).Finding.ID; got != a.ID {
		t.Errorf("fingerprint prefix resolved %q, want %q", got, a.ID)
	}
	if got := structuredInto[explainedPayload](t, byFP).Resolution.MatchedBy; got != "fingerprint" {
		t.Errorf("fingerprint prefix matchedBy = %q, want fingerprint", got)
	}

	idPrefix := uniquePrefix(t, a.ID, identities)
	byID := h.client.tool("vigil_explain", map[string]any{"findingId": idPrefix})
	if byID.IsError {
		t.Fatalf("unique ID prefix %q did not resolve: %s", idPrefix, textOf(t, byID))
	}
	if got := structuredInto[explainedPayload](t, byID).Finding.ID; got != a.ID {
		t.Errorf("ID prefix resolved %q, want %q", got, a.ID)
	}

	short := h.client.tool("vigil_explain", map[string]any{"findingId": "VGL"})
	if got := toolErrorCode(t, short); got != "VGL-NOT-FOUND" {
		t.Errorf("3-character prefix code = %q, want VGL-NOT-FOUND", got)
	}
}

func TestAmbiguousPrefixReturnsCandidates(t *testing.T) {
	h := newHarness(t)
	// A second file with a hardcoded secret gives the scan two real findings.
	if err := os.WriteFile(filepath.Join(h.repo, "secrets.py"),
		[]byte("aws_access_key_id = \"AKIAQ3W5ERTY7UIOPASD\"\n"), 0o644); err != nil {
		t.Fatalf("write secrets.py: %v", err)
	}
	scan := h.scan()
	if len(scan.Findings) < 2 {
		t.Fatalf("scan returned %d findings, want at least 2", len(scan.Findings))
	}

	res := h.client.tool("vigil_explain", map[string]any{"findingId": "VGL-"})
	if got := toolErrorCode(t, res); got != "VGL-AMBIGUOUS" {
		t.Fatalf("VGL- prefix code = %q, want VGL-AMBIGUOUS: %s", got, textOf(t, res))
	}
	env := errorDetails(t, res)
	if len(env.Error.Candidates) == 0 {
		t.Error("ambiguous error has no candidates")
	}
	if len(env.Error.Candidates) > 10 {
		t.Errorf("ambiguous error has %d candidates, want at most 10", len(env.Error.Candidates))
	}
	for _, c := range env.Error.Candidates {
		if c.FindingID == "" || c.Location == "" {
			t.Errorf("candidate is incomplete: %+v", c)
		}
	}
}

func TestErrorCandidatesHideEvidence(t *testing.T) {
	h := newHarness(t)
	saveCraftedScan(t, h, []model.Finding{
		craftedFinding("VGL-CANARY-001", "one.py", 1, 1),
		craftedFinding("VGL-CANARY-002", "two.py", 2, 2),
	}, nil)

	noMatch := h.client.tool("vigil_explain", map[string]any{"findingId": "VGL-NO-SUCH-FINDING"})
	if got := toolErrorCode(t, noMatch); got != "VGL-NOT-FOUND" {
		t.Errorf("missing finding code = %q, want VGL-NOT-FOUND", got)
	}
	if env := errorDetails(t, noMatch); len(env.Error.Candidates) == 0 {
		t.Error("not-found error has no candidates")
	}

	ambiguous := h.client.tool("vigil_explain", map[string]any{"findingId": "VGL-"})
	if got := toolErrorCode(t, ambiguous); got != "VGL-AMBIGUOUS" {
		t.Errorf("ambiguous prefix code = %q, want VGL-AMBIGUOUS", got)
	}

	for name, res := range map[string]mcp.CallToolResult{
		"not found": noMatch,
		"ambiguous": ambiguous,
	} {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("%s: marshal structuredContent: %v", name, err)
		}
		combined := textOf(t, res) + string(raw)
		for _, canary := range []string{snippetCanary, evidenceCanary} {
			if strings.Contains(combined, canary) {
				t.Errorf("%s error leaked %q: %s", name, canary, combined)
			}
		}
	}
}

func TestResolveFindingByLocation(t *testing.T) {
	h := newHarness(t)
	scan := saveCraftedScan(t, h, []model.Finding{
		craftedFinding("VGL-LOC-001", "src/app.py", 10, 14),
		craftedFinding("VGL-LOC-002", "src/app.py", 30, 30),
		craftedFinding("VGL-LOC-003", "src/other.py", 5, 0),
		craftedFinding("VGL-LOC-004", "src/other.py", 25, 0),
		craftedFinding("VGL-LOC-005", "src/only.py", 7, 0),
	}, nil)
	appFirst, appSecond := scan.Findings[0], scan.Findings[1]
	only := scan.Findings[4]

	success := []struct {
		name   string
		args   map[string]any
		wantID string
		wantBy string
	}{
		{"exact line", map[string]any{"path": "src/app.py", "line": 10}, appFirst.ID, "location"},
		{"inside range", map[string]any{"path": "src/app.py", "line": 12}, appFirst.ID, "location"},
		{"range end", map[string]any{"path": "src/app.py", "line": 14}, appFirst.ID, "location"},
		{"nearest line", map[string]any{"path": "src/app.py", "line": 27}, appSecond.ID, "location-nearest"},
		{"only finding on path", map[string]any{"path": "src/only.py"}, only.ID, "location"},
		{"absolute path inside root", map[string]any{
			"path": filepath.Join(h.repo, "src", "app.py"), "line": 10,
		}, appFirst.ID, "location"},
	}
	for _, tc := range success {
		t.Run(tc.name, func(t *testing.T) {
			res := h.client.tool("vigil_explain", tc.args)
			if res.IsError {
				t.Fatalf("%s: %s", tc.name, textOf(t, res))
			}
			payload := structuredInto[explainedPayload](t, res)
			if payload.Finding.ID != tc.wantID {
				t.Errorf("resolved %q, want %q", payload.Finding.ID, tc.wantID)
			}
			if payload.Resolution.MatchedBy != tc.wantBy {
				t.Errorf("matchedBy = %q, want %q", payload.Resolution.MatchedBy, tc.wantBy)
			}
			if payload.Resolution.Path == "" || payload.Resolution.Line != payload.Finding.Location.StartLine {
				t.Errorf("resolution location = %+v, want the finding location", payload.Resolution)
			}
			if tc.wantBy != "location" && tc.wantBy != "location-nearest" {
				return
			}
			if !strings.Contains(textOf(t, res), "Resolved finding "+tc.wantID+" at ") {
				t.Errorf("text does not announce the resolution:\n%s", textOf(t, res))
			}
		})
	}

	if runtime.GOOS == "windows" {
		res := h.client.tool("vigil_explain", map[string]any{"path": `src\app.py`, "line": 10})
		if res.IsError {
			t.Fatalf("backslash path did not resolve: %s", textOf(t, res))
		}
		if got := structuredInto[explainedPayload](t, res).Finding.ID; got != appFirst.ID {
			t.Errorf("backslash path resolved %q, want %q", got, appFirst.ID)
		}
	}

	t.Run("equidistant tie", func(t *testing.T) {
		res := h.client.tool("vigil_explain", map[string]any{"path": "src/app.py", "line": 20})
		if got := toolErrorCode(t, res); got != "VGL-AMBIGUOUS" {
			t.Fatalf("tie code = %q, want VGL-AMBIGUOUS: %s", got, textOf(t, res))
		}
		if env := errorDetails(t, res); len(env.Error.Candidates) != 2 {
			t.Errorf("tie candidates = %d, want 2", len(env.Error.Candidates))
		}
	})

	t.Run("wrong path", func(t *testing.T) {
		res := h.client.tool("vigil_explain", map[string]any{"path": "src/missing.py"})
		if got := toolErrorCode(t, res); got != "VGL-NOT-FOUND" {
			t.Fatalf("wrong path code = %q, want VGL-NOT-FOUND: %s", got, textOf(t, res))
		}
		if env := errorDetails(t, res); len(env.Error.Candidates) == 0 {
			t.Error("wrong path did not list scan candidates")
		}
	})

	t.Run("path with several findings", func(t *testing.T) {
		res := h.client.tool("vigil_explain", map[string]any{"path": "src/app.py"})
		if got := toolErrorCode(t, res); got != "VGL-AMBIGUOUS" {
			t.Fatalf("path-only code = %q, want VGL-AMBIGUOUS: %s", got, textOf(t, res))
		}
	})

	t.Run("absolute path outside root", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "app.py")
		res := h.client.tool("vigil_explain", map[string]any{"path": outside, "line": 10})
		if got := toolErrorCode(t, res); got != "VGL-ARGS" {
			t.Fatalf("escape code = %q, want VGL-ARGS: %s", got, textOf(t, res))
		}
	})
}

func TestResolutionRejectsConflictingAddresses(t *testing.T) {
	h := newHarness(t)
	scan := saveCraftedScan(t, h, []model.Finding{
		craftedFinding("VGL-ARGS-001", "one.py", 1, 1),
	}, nil)

	both := h.client.tool("vigil_explain", map[string]any{
		"findingId": scan.Findings[0].ID,
		"path":      "one.py",
		"line":      1,
	})
	if got := toolErrorCode(t, both); got != "VGL-ARGS" {
		t.Errorf("both addresses code = %q, want VGL-ARGS", got)
	}

	neither := h.client.tool("vigil_explain", map[string]any{})
	if got := toolErrorCode(t, neither); got != "VGL-ARGS" {
		t.Errorf("missing address code = %q, want VGL-ARGS", got)
	}
	if msg := errorDetails(t, neither).Error.Message; !strings.Contains(msg, "findingId or path is required") {
		t.Errorf("missing address message = %q", msg)
	}
}

func TestLookupPrefersActiveOverSuppressedDuplicate(t *testing.T) {
	h := newHarness(t)
	active := craftedFinding("VGL-DUP-001", "dup.py", 10, 10)
	suppressed := active
	suppressed.Location.StartLine = 99
	suppressed.Location.EndLine = 99
	suppressed.Fingerprint = suppressed.ComputeFingerprint()
	suppressed.ID = suppressed.ComputeID()
	suppressed.Suppressed = true
	saveCraftedScan(t, h, []model.Finding{active}, []model.Finding{suppressed})

	// The active and suppressed copies share a fingerprint, so a prefix that
	// matches both must still resolve to exactly one finding.
	byPrefix := h.client.tool("vigil_explain", map[string]any{"findingId": "VGL-"})
	if byPrefix.IsError {
		t.Fatalf("active/suppressed duplicate stayed ambiguous: %s", textOf(t, byPrefix))
	}
	if got := structuredInto[explainedPayload](t, byPrefix).Finding.ID; got != active.ID {
		t.Errorf("prefix resolved %q, want active %q", got, active.ID)
	}

	byLocation := h.client.tool("vigil_explain", map[string]any{"path": "dup.py", "line": 10})
	if byLocation.IsError {
		t.Fatalf("active/suppressed duplicate broke location lookup: %s", textOf(t, byLocation))
	}
	if got := structuredInto[explainedPayload](t, byLocation).Finding.ID; got != active.ID {
		t.Errorf("location resolved %q, want active %q", got, active.ID)
	}
}

func TestVerifyResolvesByLocation(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	f := scan.Findings[0]

	res := h.client.mustTool("vigil_verify", map[string]any{
		"path": f.Location.Path,
		"line": f.Location.StartLine,
	})
	type verifyResolution struct {
		FindingID    string            `json:"findingId"`
		Resolution   resolutionPayload `json:"resolution"`
		StillPresent bool              `json:"stillPresent"`
	}
	payload := structuredInto[verifyResolution](t, res)
	if payload.FindingID != f.ID {
		t.Errorf("verified %q, want %q", payload.FindingID, f.ID)
	}
	if payload.Resolution.MatchedBy != "location" {
		t.Errorf("matchedBy = %q, want location", payload.Resolution.MatchedBy)
	}
	if !payload.StillPresent {
		t.Errorf("verification did not find the unchanged finding: %s", textOf(t, res))
	}

	both := h.client.tool("vigil_verify", map[string]any{
		"findingId": f.ID,
		"path":      f.Location.Path,
	})
	if got := toolErrorCode(t, both); got != "VGL-ARGS" {
		t.Errorf("verify with both addresses code = %q, want VGL-ARGS", got)
	}
}
