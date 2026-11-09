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

	out, err := a.Triage(context.Background(), []model.Finding{f1, f2}, "/repo")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("Triage returned %d findings, want 2", len(out))
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

func TestTriageFalsePositiveKeepsFinding(t *testing.T) {
	f := testFinding("VGL-1", "auth.go", 7, "Hardcoded password", `var password = "hunter2"`)
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: `[{"id":"VGL-1","verdict":"false_positive","severity":"low","confidence":0.8,"reasoning":"test fixture"}]`}, nil
	})
	out, err := a.Triage(context.Background(), []model.Finding{f}, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
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
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: `[{"id":"VGL-OTHER","verdict":"false_positive","confidence":0.9}]`}, nil
	})
	out, err := a.Triage(context.Background(), []model.Finding{f}, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
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

	out, err := a.Triage(context.Background(), findings, "")
	if err != nil {
		t.Fatalf("partial failure returned an error: %v", err)
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
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{}, errors.New("down")
	})
	out, err := a.Triage(context.Background(), findings, "")
	if err == nil {
		t.Fatal("expected an aggregate error")
	}
	if !strings.Contains(err.Error(), "all 2 batches failed") {
		t.Fatalf("unexpected error: %v", err)
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
	f := testFinding("VGL-1", "a.go", 1, "issue", "evidence")
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: "this is not json"}, nil
	})
	out, err := a.Triage(context.Background(), []model.Finding{f}, "")
	if err == nil {
		t.Fatal("expected an error when the only batch is malformed")
	}
	if out[0].LLM != nil {
		t.Fatal("malformed response mutated the finding")
	}
}
