package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func TestSARIFStructure(t *testing.T) {
	out, err := renderSARIF(sampleResult())
	if err != nil {
		t.Fatal(err)
	}

	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, out)
	}

	if log.Schema != sarifSchema {
		t.Errorf("$schema = %q", log.Schema)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "vigil" {
		t.Errorf("driver.name = %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.InformationURI != vigilInformationURI {
		t.Errorf("driver.informationUri = %q", run.Tool.Driver.InformationURI)
	}
	if run.Tool.Driver.Version != "0.1.0-test" {
		t.Errorf("driver.version = %q", run.Tool.Driver.Version)
	}

	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want 3 (deduplicated by id)", len(run.Tool.Driver.Rules))
	}
	seen := map[string]bool{}
	for _, rule := range run.Tool.Driver.Rules {
		if seen[rule.ID] {
			t.Fatalf("duplicate SARIF rule %q", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Name == "" || rule.ShortDescription.Text == "" || rule.FullDescription.Text == "" {
			t.Errorf("rule %q has empty required text", rule.ID)
		}
	}

	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(run.Results))
	}
	wantLevels := []string{"error", "warning", "note", "note"}
	for i, want := range wantLevels {
		if got := run.Results[i].Level; got != want {
			t.Errorf("results[%d].level = %q, want %q", i, got, want)
		}
	}

	for _, key := range []string{`"$schema"`, `"informationUri"`, `"partialFingerprints"`, `"primaryLocationLineHash"`} {
		if !strings.Contains(string(out), key) {
			t.Errorf("SARIF output missing key %s", key)
		}
	}
}

func TestSARIFResultDetails(t *testing.T) {
	out, err := renderSARIF(sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatal(err)
	}

	result := log.Runs[0].Results[0]
	if result.RuleID != "go/sql-injection" {
		t.Errorf("ruleId = %q", result.RuleID)
	}
	if result.RuleIndex == nil || *result.RuleIndex != 0 {
		t.Errorf("ruleIndex = %v", result.RuleIndex)
	}
	if result.Message.Text != "SQL injection" {
		t.Errorf("message.text = %q", result.Message.Text)
	}
	if len(result.Locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(result.Locations))
	}

	physical := result.Locations[0].PhysicalLocation
	if physical.ArtifactLocation.URI != "internal/db/query%20name.go" {
		t.Errorf("artifactLocation.uri = %q", physical.ArtifactLocation.URI)
	}
	if physical.Region.StartLine != 42 || physical.Region.EndLine != 44 {
		t.Errorf("region lines = %d-%d", physical.Region.StartLine, physical.Region.EndLine)
	}
	if physical.Region.StartColumn != 5 || physical.Region.EndColumn != 20 {
		t.Errorf("region columns = %d-%d", physical.Region.StartColumn, physical.Region.EndColumn)
	}
	if physical.Region.Snippet == nil || !strings.Contains(physical.Region.Snippet.Text, "buildQuery") {
		t.Errorf("region snippet = %+v", physical.Region.Snippet)
	}
	if got := result.PartialFingerprints["primaryLocationLineHash"]; got != "fp_sql_123" {
		t.Errorf("partialFingerprints.primaryLocationLineHash = %q", got)
	}
	if result.Properties.Severity != "critical" ||
		result.Properties.Confidence != "high" ||
		result.Properties.Category != "injection" {
		t.Errorf("result properties = %+v", result.Properties)
	}
}

func TestSARIFRuleMetadata(t *testing.T) {
	out, err := renderSARIF(sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatal(err)
	}

	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.ID != "go/sql-injection" || rule.Name != "go/sql-injection" {
		t.Errorf("rule id/name = %q/%q", rule.ID, rule.Name)
	}
	if rule.ShortDescription.Text != "SQL injection" {
		t.Errorf("shortDescription = %q", rule.ShortDescription.Text)
	}
	if !strings.Contains(rule.FullDescription.Text, "concatenated") {
		t.Errorf("fullDescription = %q", rule.FullDescription.Text)
	}
	if rule.HelpURI != "https://example.com/sql-injection" {
		t.Errorf("helpUri = %q", rule.HelpURI)
	}
	if rule.Properties.Precision != "high" {
		t.Errorf("precision = %q", rule.Properties.Precision)
	}
	for _, tag := range []string{"security", "injection", "critical", "CWE-89", "A03:2021", "sql", "database"} {
		if !contains(rule.Properties.Tags, tag) {
			t.Errorf("tags missing %q: %v", tag, rule.Properties.Tags)
		}
	}

	second := log.Runs[0].Tool.Driver.Rules[1]
	if second.HelpURI != vigilInformationURI {
		t.Errorf("fallback helpUri = %q, want %q", second.HelpURI, vigilInformationURI)
	}
}

func TestSARIFEmptyResult(t *testing.T) {
	out, err := renderSARIF(emptyResult())
	if err != nil {
		t.Fatal(err)
	}

	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Rules == nil {
		t.Error("rules is nil, want []")
	}
	if log.Runs[0].Results == nil {
		t.Error("results is nil, want []")
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 || len(log.Runs[0].Results) != 0 {
		t.Errorf("empty result produced rules/results: %d/%d",
			len(log.Runs[0].Tool.Driver.Rules), len(log.Runs[0].Results))
	}
	if !strings.Contains(string(out), `"rules": []`) {
		t.Error("empty SARIF does not contain an empty rules array")
	}
	if !strings.Contains(string(out), `"results": []`) {
		t.Error("empty SARIF does not contain an empty results array")
	}
}

func TestSARIFExcludesSuppressedFindings(t *testing.T) {
	out, err := renderSARIF(sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs[0].Results) != 4 {
		t.Fatalf("results = %d, want only the 4 active findings", len(log.Runs[0].Results))
	}
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if rule.ID == "secrets/hardcoded" {
			t.Error("suppressed finding contributed a SARIF rule")
		}
	}
	if strings.Contains(string(out), "VGL-SUP000005") {
		t.Error("suppressed finding appears in SARIF output")
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	tests := []struct {
		severity model.Severity
		want     string
	}{
		{model.SeverityCritical, "error"},
		{model.SeverityHigh, "error"},
		{model.SeverityMedium, "warning"},
		{model.SeverityLow, "note"},
		{model.SeverityInfo, "note"},
		{model.Severity("unknown"), "note"},
	}
	for _, tt := range tests {
		if got := sarifLevel(tt.severity); got != tt.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}
