package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/llm"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// triageJSON builds a model-style JSON array of judgements for the given ids.
func triageJSON(verdict string, ids ...string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf(`{"id":%q,"verdict":%q,"confidence":0.8}`, id, verdict))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// scriptedTriageClient answers successive triage requests from a fixed script
// and records each request so tests can assert on retry prompts.
func scriptedTriageClient(t *testing.T, responses ...string) (*Analyzer, *fakeClient, *[]llm.Request) {
	t.Helper()
	reqs := make([]llm.Request, 0, len(responses))
	fn := func(_ context.Context, req llm.Request) (llm.Response, error) {
		reqs = append(reqs, req)
		i := len(reqs) - 1
		if i >= len(responses) {
			t.Fatalf("unexpected LLM call %d; script has %d responses", i+1, len(responses))
		}
		return llm.Response{Text: responses[i], Model: "fake-model"}, nil
	}
	a, fc := newTestAnalyzer(fn)
	return a, fc, &reqs
}

func TestTriageHappyPath(t *testing.T) {
	f1 := testFinding("VGL-AAA", "auth/login.go", 10, "SQL injection", `db.Query("SELECT * FROM users WHERE name = '" + user + "'")`)
	f2 := testFinding("VGL-BBB", "auth/session.go", 20, "Hardcoded secret", `password := "hunter2"`)

	a, fc := newTestAnalyzer(func(_ context.Context, req llm.Request) (llm.Response, error) {
		if !req.JSON {
			t.Fatal("triage request must ask for JSON")
		}
		return llm.Response{Text: "Sure:\n```json\n" + `[
			{"id":"VGL-AAA","verdict":"true_positive","severity":"critical","confidence":0.92,"reasoning":"user input reaches the query","exploitScenario":"send a quote","remediation":"use parameters"},
			{"id":"VGL-UNKNOWN","verdict":"true_positive","severity":"critical","confidence":0.99},
			{"id":"VGL-BBB","verdict":"false_positive","severity":"low","confidence":1.7,"reasoning":"documentation fixture"}
		]` + "\n```", Model: "fake-model"}, nil
	})

	out, stats, err := a.TriageWithStats(context.Background(), []model.Finding{f1, f2}, "/repo")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("Triage returned %d findings, want 2", len(out))
	}
	if want := (TriageStats{Batches: 1, Judged: 2}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}

	if out[0].LLM == nil {
		t.Fatal("first finding has no judgement")
	}
	if out[0].LLM.Verdict != verdictTruePositive {
		t.Errorf("verdict = %q", out[0].LLM.Verdict)
	}
	if out[0].LLM.Severity != model.SeverityCritical {
		t.Errorf("severity = %q", out[0].LLM.Severity)
	}
	if out[0].LLM.Confidence != 0.92 {
		t.Errorf("confidence = %v", out[0].LLM.Confidence)
	}
	if out[0].LLM.Model != "fake-model" {
		t.Errorf("model = %q", out[0].LLM.Model)
	}
	if out[0].LLM.Exploit != "send a quote" || out[0].LLM.Remediation != "use parameters" {
		t.Errorf("judgement fields missing: %+v", out[0].LLM)
	}

	if out[1].LLM == nil || out[1].LLM.Verdict != verdictFalsePositive {
		t.Fatalf("false positive judgement missing: %+v", out[1].LLM)
	}
	if out[1].LLM.Confidence != 1 {
		t.Errorf("confidence not clamped: %v", out[1].LLM.Confidence)
	}
	if out[1].Confidence != model.ConfidenceLow {
		t.Errorf("false positive did not lower finding confidence: %q", out[1].Confidence)
	}
	if out[1].Evidence != f2.Evidence {
		t.Errorf("false positive changed deterministic evidence: %q", out[1].Evidence)
	}
	if out[1].Severity != f2.Severity {
		t.Errorf("false positive changed deterministic severity: %q", out[1].Severity)
	}

	if fc.calls != 1 {
		t.Errorf("calls = %d, want 1", fc.calls)
	}
	prompt := fc.last.Messages[0].Content
	for _, want := range []string{"VGL-AAA", "VGL-BBB", "SELECT", "hunter2", "<untrusted_code"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestTriageRetryJudgesOmittedIDs(t *testing.T) {
	fs := []model.Finding{
		testFinding("VGL-AAA", "a.go", 1, "SQL injection", `db.Query("SELECT * FROM users WHERE name = '" + user + "'")`),
		testFinding("VGL-BBB", "b.go", 2, "Hardcoded secret", `password := "hunter2"`),
		testFinding("VGL-CCC", "c.go", 3, "Path traversal", `os.Open(userPath)`),
	}
	a, fc, reqs := scriptedTriageClient(t,
		triageJSON(verdictTruePositive, "VGL-AAA"),
		`[{"id":"VGL-BBB","verdict":"uncertain","confidence":0.5},{"id":"VGL-CCC","verdict":"false_positive","severity":"low","confidence":0.7}]`,
	)

	out, stats, err := a.TriageWithStats(context.Background(), fs, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if want := (TriageStats{Batches: 1, Retries: 1, Judged: 3}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if fc.calls != 2 || len(*reqs) != 2 {
		t.Fatalf("calls = %d, want 1 batch + 1 retry", fc.calls)
	}
	for i := range out {
		if out[i].LLM == nil {
			t.Fatalf("finding %s has no judgement", out[i].ID)
		}
	}
	if out[2].Confidence != model.ConfidenceLow {
		t.Errorf("false positive verdict did not lower confidence: %q", out[2].Confidence)
	}

	retry := (*reqs)[1].Messages[0].Content
	if !strings.Contains(retry, "Return exactly one object for each of these IDs") {
		t.Errorf("retry prompt lacks the explicit one-object-per-id instruction: %q", retry)
	}
	for _, want := range []string{"VGL-BBB", "VGL-CCC", "hunter2", "os.Open(userPath)", "<untrusted_code"} {
		if !strings.Contains(retry, want) {
			t.Errorf("retry prompt missing %q", want)
		}
	}
	if strings.Contains(retry, "VGL-AAA") {
		t.Error("retry prompt resent an already judged id")
	}
	if (*reqs)[1].System != systemTriage {
		t.Error("retry did not keep the triage system prompt")
	}
	if !strings.Contains((*reqs)[1].System, "untrusted data") {
		t.Error("retry system prompt lost the untrusted-data instruction")
	}
}

func TestTriageRetryStillMissingKeepsFindings(t *testing.T) {
	fs := []model.Finding{
		testFinding("VGL-AAA", "a.go", 1, "SQL injection", "evidence-a"),
		testFinding("VGL-BBB", "b.go", 2, "Hardcoded secret", "evidence-b"),
		testFinding("VGL-CCC", "c.go", 3, "Path traversal", "evidence-c"),
	}
	a, fc, _ := scriptedTriageClient(t,
		triageJSON(verdictTruePositive, "VGL-AAA"),
		triageJSON(verdictUncertain, "VGL-BBB"),
	)

	out, stats, err := a.TriageWithStats(context.Background(), fs, "")
	if err != nil {
		t.Fatalf("partial retry must not return an error: %v", err)
	}
	if want := (TriageStats{Batches: 1, Retries: 1, Judged: 2, Missing: 1}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if fc.calls != 2 {
		t.Errorf("calls = %d, want 2", fc.calls)
	}
	if out[0].LLM == nil || out[1].LLM == nil {
		t.Fatalf("judged findings lost their judgement: %+v / %+v", out[0].LLM, out[1].LLM)
	}
	if out[2].LLM != nil {
		t.Error("unjudged finding received an invented judgement")
	}
	if out[2].Evidence != fs[2].Evidence {
		t.Errorf("unjudged finding evidence changed: %q", out[2].Evidence)
	}
	if out[2].Confidence != fs[2].Confidence || out[2].Severity != fs[2].Severity {
		t.Errorf("unjudged finding was modified: %+v", out[2])
	}
}

func TestTriageFalsePositiveKeepsFinding(t *testing.T) {
	f := testFinding("VGL-1", "auth.go", 7, "Hardcoded password", `var password = "hunter2"`)
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: `[{"id":"VGL-1","verdict":"false_positive","severity":"low","confidence":0.8,"reasoning":"test fixture"}]`}, nil
	})
	out, stats, err := a.TriageWithStats(context.Background(), []model.Finding{f}, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if want := (TriageStats{Batches: 1, Judged: 1}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if len(out) != 1 {
		t.Fatalf("finding was deleted: %d", len(out))
	}
	if out[0].LLM == nil || out[0].LLM.Verdict != verdictFalsePositive {
		t.Fatalf("verdict missing: %+v", out[0].LLM)
	}
	if out[0].Confidence != model.ConfidenceLow {
		t.Errorf("confidence = %q, want low", out[0].Confidence)
	}
	if out[0].Evidence != f.Evidence {
		t.Errorf("evidence changed: %q", out[0].Evidence)
	}
	if out[0].Severity != f.Severity {
		t.Errorf("severity changed: %q", out[0].Severity)
	}
}

func TestTriageUnknownIDsAreIgnored(t *testing.T) {
	f := testFinding("VGL-KNOWN", "a.go", 1, "issue", "evidence")
	a, fc := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: `[{"id":"VGL-OTHER","verdict":"false_positive","confidence":0.9}]`}, nil
	})
	out, stats, err := a.TriageWithStats(context.Background(), []model.Finding{f}, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if want := (TriageStats{Batches: 1, Retries: 1, Missing: 1}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if fc.calls != 2 {
		t.Errorf("calls = %d, want one retry for the omitted id", fc.calls)
	}
	if out[0].LLM != nil || out[0].Confidence != f.Confidence {
		t.Fatalf("unknown id changed the finding: %+v", out[0])
	}
}

func TestTriageReasoningIsCapped(t *testing.T) {
	f := testFinding("VGL-1", "a.go", 1, "issue", "evidence")
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: fmt.Sprintf(`[{"id":"VGL-1","verdict":"true_positive","confidence":0.5,"reasoning":%q,"exploitScenario":%q}]`,
			strings.Repeat("r", 5000), strings.Repeat("e", 5000))}, nil
	})
	out, err := a.Triage(context.Background(), []model.Finding{f}, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if len(out[0].LLM.Reasoning) > maxReasoningBytes || len(out[0].LLM.Exploit) > maxReasoningBytes {
		t.Fatalf("reasoning not capped: %d / %d", len(out[0].LLM.Reasoning), len(out[0].LLM.Exploit))
	}
}

func TestTriageBatchFailureFailsOpen(t *testing.T) {
	findings := make([]model.Finding, 11)
	for i := range findings {
		findings[i] = testFinding(fmt.Sprintf("VGL-%03d", i), "f.go", i+1, fmt.Sprintf("issue %d", i), "evidence")
	}

	call := 0
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		call++
		if call == 1 {
			return llm.Response{}, errors.New("network down")
		}
		return llm.Response{Text: `[{"id":"VGL-010","verdict":"true_positive","severity":"high","confidence":0.9}]`}, nil
	})

	out, stats, err := a.TriageWithStats(context.Background(), findings, "")
	if err != nil {
		t.Fatalf("partial failure returned an error: %v", err)
	}
	if want := (TriageStats{Batches: 2, Failed: 1, Judged: 1, Missing: 10}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if len(out) != len(findings) {
		t.Fatalf("lost findings on partial failure: %d", len(out))
	}
	for i := 0; i < 10; i++ {
		if out[i].LLM != nil {
			t.Errorf("failed batch %d was modified", i)
		}
	}
	if out[10].LLM == nil || out[10].LLM.Verdict != verdictTruePositive {
		t.Errorf("successful batch was not applied: %+v", out[10].LLM)
	}
	if call != 2 {
		t.Errorf("calls = %d, want 2 batches of at most 10", call)
	}
}

func TestTriageAllBatchesFail(t *testing.T) {
	findings := make([]model.Finding, 11)
	for i := range findings {
		findings[i] = testFinding(fmt.Sprintf("VGL-%03d", i), "f.go", i+1, "issue", "evidence")
	}
	a, fc := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{}, errors.New("down")
	})
	out, stats, err := a.TriageWithStats(context.Background(), findings, "")
	if err == nil {
		t.Fatal("expected an aggregate error")
	}
	if !strings.Contains(err.Error(), "all 2 batches failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := (TriageStats{Batches: 2, Failed: 2, Missing: 11}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if fc.calls != 2 {
		t.Errorf("calls = %d, want no retry after a failed request", fc.calls)
	}
	if len(out) != len(findings) {
		t.Fatalf("findings lost: %d", len(out))
	}
	for i := range out {
		if out[i].LLM != nil {
			t.Errorf("finding %d was modified after a failed batch", i)
		}
		if out[i].Evidence != findings[i].Evidence {
			t.Errorf("finding %d evidence changed", i)
		}
	}
}

func TestParseTriageResponseSingleObject(t *testing.T) {
	items, err := parseTriageResponse(`{"id":"VGL-1","verdict":"true_positive","confidence":0.8}`)
	if err != nil {
		t.Fatalf("parseTriageResponse: %v", err)
	}
	if len(items) != 1 || items[0].ID != "VGL-1" {
		t.Fatalf("unexpected items: %+v", items)
	}
}

func TestTriageMalformedResponseFailsOpen(t *testing.T) {
	fs := []model.Finding{
		testFinding("VGL-1", "a.go", 1, "issue", "evidence"),
		testFinding("VGL-2", "b.go", 2, "issue", "evidence"),
	}
	a, fc := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: "this is not json"}, nil
	})
	out, stats, err := a.TriageWithStats(context.Background(), fs, "")
	if err == nil {
		t.Fatal("expected an error when the only batch is malformed")
	}
	if fc.calls != 1 {
		t.Errorf("calls = %d, want no retry after a parse failure", fc.calls)
	}
	if want := (TriageStats{Batches: 1, Failed: 1, Missing: 2}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	for i := range out {
		if out[i].LLM != nil {
			t.Fatalf("malformed response mutated finding %d", i)
		}
		if out[i].Evidence != fs[i].Evidence {
			t.Errorf("malformed response changed evidence of finding %d", i)
		}
	}
}

func TestTriageStatsCounts(t *testing.T) {
	const total = 12
	findings := make([]model.Finding, total)
	ids := make([]string, total)
	for i := range findings {
		ids[i] = fmt.Sprintf("VGL-%03d", i)
		findings[i] = testFinding(ids[i], "f.go", i+1, fmt.Sprintf("issue %d", i), "evidence")
	}

	a, fc, reqs := scriptedTriageClient(t,
		triageJSON(verdictTruePositive, ids[:10]...),
		triageJSON(verdictUncertain, ids[10]),
		triageJSON(verdictTruePositive, ids[11]),
	)

	out, stats, err := a.TriageWithStats(context.Background(), findings, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if want := (TriageStats{Batches: 2, Retries: 1, Judged: total}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if fc.calls != 3 || len(*reqs) != 3 {
		t.Fatalf("calls = %d, want 2 batches + 1 retry", fc.calls)
	}
	for i := range out {
		if out[i].LLM == nil {
			t.Fatalf("finding %s has no judgement", out[i].ID)
		}
	}

	retry := (*reqs)[2].Messages[0].Content
	if !strings.Contains(retry, ids[11]) {
		t.Errorf("retry prompt missing the omitted id %s", ids[11])
	}
	if strings.Contains(retry, ids[10]) {
		t.Errorf("retry prompt resent the judged id %s", ids[10])
	}
	if strings.Contains(retry, ids[0]) {
		t.Errorf("retry prompt resent the first batch id %s", ids[0])
	}
}
