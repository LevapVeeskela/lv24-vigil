package report

import (
	"encoding/json"
	"testing"
)

func TestJSONEnvelope(t *testing.T) {
	out, err := renderJSON(sampleResult())
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		ID            string `json:"id"`
		Findings      []struct {
			ID         string `json:"id"`
			RuleID     string `json:"ruleId"`
			Suppressed bool   `json:"suppressed"`
			Fix        *struct {
				Diff string `json:"diff"`
			} `json:"fix"`
			LLM *struct {
				Verdict string `json:"verdict"`
			} `json:"llm"`
		} `json:"findings"`
		Suppressed []struct {
			ID               string `json:"id"`
			Suppressed       bool   `json:"suppressed"`
			SuppressedReason string `json:"suppressedReason"`
		} `json:"suppressed"`
		Stats struct {
			FilesScanned int            `json:"filesScanned"`
			BySeverity   map[string]int `json:"bySeverity"`
		} `json:"stats"`
		Errors []string `json:"errors"`
		Model  *struct {
			Provider string `json:"provider"`
			Model    string `json:"model"`
		} `json:"model"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, out)
	}

	if doc.SchemaVersion != "1" {
		t.Fatalf("schemaVersion = %q, want 1", doc.SchemaVersion)
	}
	if doc.ID != "scan-test-1" {
		t.Fatalf("id = %q", doc.ID)
	}
	if len(doc.Findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(doc.Findings))
	}
	if len(doc.Suppressed) != 1 {
		t.Fatalf("suppressed = %d, want 1", len(doc.Suppressed))
	}
	if !doc.Suppressed[0].Suppressed {
		t.Error("suppressed finding lost its suppressed flag")
	}
	if doc.Suppressed[0].SuppressedReason != "baseline: known test fixture" {
		t.Errorf("suppressedReason = %q", doc.Suppressed[0].SuppressedReason)
	}
	if doc.Findings[0].Fix == nil || doc.Findings[0].Fix.Diff == "" {
		t.Error("finding fix missing from JSON")
	}
	if doc.Findings[0].LLM == nil || doc.Findings[0].LLM.Verdict != "true_positive" {
		t.Error("LLM judgement missing from JSON")
	}
	if doc.Stats.FilesScanned != 12 {
		t.Errorf("filesScanned = %d", doc.Stats.FilesScanned)
	}
	if doc.Stats.BySeverity["critical"] != 1 {
		t.Errorf("bySeverity.critical = %d", doc.Stats.BySeverity["critical"])
	}
	if len(doc.Errors) != 1 {
		t.Errorf("errors = %v", doc.Errors)
	}
	if doc.Model == nil || doc.Model.Provider != "openai" {
		t.Error("model info missing from JSON")
	}
}

func TestJSONStable(t *testing.T) {
	first, err := renderJSON(sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderJSON(sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("JSON output is not deterministic")
	}
}

func TestJSONEmptyArrays(t *testing.T) {
	out, err := renderJSON(emptyResult())
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, key := range []string{"findings", "suppressed", "errors"} {
		raw, ok := doc[key]
		if !ok {
			t.Fatalf("empty JSON is missing %q", key)
		}
		var values []any
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatalf("%q is not an array: %v", key, err)
		}
		if values == nil {
			t.Fatalf("%q is null, want []", key)
		}
		if len(values) != 0 {
			t.Fatalf("%q = %v, want empty", key, values)
		}
	}

	var stats map[string]json.RawMessage
	if err := json.Unmarshal(doc["stats"], &stats); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"bySeverity", "byCategory"} {
		var m map[string]int
		if err := json.Unmarshal(stats[key], &m); err != nil {
			t.Fatalf("stats.%s is not a map: %v", key, err)
		}
		if m == nil {
			t.Fatalf("stats.%s is null, want {}", key)
		}
	}
}

func TestJSONIncludesSuppressedFindings(t *testing.T) {
	out, err := renderJSON(sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(out), `"suppressed": [`, `"id": "VGL-SUP000005"`, `"suppressed": true`) {
		t.Fatalf("suppressed findings missing from JSON:\n%s", out)
	}
}
