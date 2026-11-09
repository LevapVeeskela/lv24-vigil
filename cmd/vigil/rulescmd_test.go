package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func TestRulesTable(t *testing.T) {
	out, _, err := runCLI(t, "rules", "--category", "secrets")
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	for _, want := range []string{"ID", "SEVERITY", "CATEGORY", "TITLE", "VGL-SEC-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("rules output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "VGL-INJ-001") {
		t.Error("category filter did not exclude injection rules")
	}
}

func TestRulesJSONAndFilters(t *testing.T) {
	out, _, err := runCLI(t, "rules", "--severity", "critical", "--json")
	if err != nil {
		t.Fatalf("rules --json: %v", err)
	}
	var metas []model.RuleMeta
	if err := json.Unmarshal([]byte(out), &metas); err != nil {
		t.Fatalf("rules JSON invalid: %v\n%s", err, out)
	}
	if len(metas) == 0 {
		t.Fatal("no critical rules returned")
	}
	for _, meta := range metas {
		if meta.Severity != model.SeverityCritical {
			t.Errorf("%s has severity %q, want critical", meta.ID, meta.Severity)
		}
	}

	out, _, err = runCLI(t, "rules", "--query", "aws")
	if err != nil {
		t.Fatalf("rules --query: %v", err)
	}
	if !strings.Contains(out, "VGL-SEC-001") {
		t.Errorf("query did not find the AWS rule:\n%s", out)
	}
}

func TestRulesNoMatches(t *testing.T) {
	out, _, err := runCLI(t, "rules", "--query", "definitely-not-a-rule")
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	if !strings.Contains(out, "no rules match") {
		t.Errorf("unexpected output: %s", out)
	}
}
