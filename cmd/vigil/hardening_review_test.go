package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Regression: user --rules was appended to the anti-RE list, so
// `vigil hardening --rules VGL-SEC-001` ran non-hardening rules.
func TestHardeningRejectsNonAntiRERules(t *testing.T) {
	dir := newTestRepo(t)

	_, _, err := runCLI(t, "hardening", dir, "--rules", "VGL-SEC-001", "--quiet", "--format", "json")

	if err == nil || !strings.Contains(err.Error(), "VGL-ARE") {
		t.Fatalf("want an anti-RE-only error, got %v", err)
	}
}

func TestHardeningRulesNarrowTheAntiRESet(t *testing.T) {
	dir := newTestRepo(t)

	out, _, err := runCLI(t, "hardening", dir, "--rules", "vgl-are-001", "--quiet", "--format", "json", "--no-baseline")

	if err != nil {
		t.Fatalf("hardening: %v", err)
	}
	var res struct {
		Stats struct {
			RulesRun int `json:"rulesRun"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if res.Stats.RulesRun != 1 {
		t.Fatalf("rulesRun = %d, want 1", res.Stats.RulesRun)
	}
}

func TestHardeningPlatformForWaveOneRules(t *testing.T) {
	cases := map[string]string{
		"VGL-ARE-060": "Android",
		"VGL-ARE-061": "Android",
		"VGL-ARE-062": "Android",
		"VGL-ARE-063": "Electron",
		"VGL-ARE-064": "iOS",
	}
	for id, want := range cases {
		if got := hardeningPlatformFor(id); got != want {
			t.Errorf("hardeningPlatformFor(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestHardeningSummaryGroupsWaveOnePlatforms(t *testing.T) {
	res := &model.ScanResult{
		Root: "/repo",
		Findings: []model.Finding{
			{RuleID: "VGL-ARE-060", Severity: model.SeverityHigh,
				Location: model.Location{Path: "res/xml/network_security_config.xml", StartLine: 4}},
			{RuleID: "VGL-ARE-061", Severity: model.SeverityHigh,
				Location: model.Location{Path: "app/build.gradle", StartLine: 5}},
			{RuleID: "VGL-ARE-062", Severity: model.SeverityHigh,
				Location: model.Location{Path: "app/proguard-rules.pro", StartLine: 2}},
			{RuleID: "VGL-ARE-063", Severity: model.SeverityHigh,
				Location: model.Location{Path: "src/main.js", StartLine: 3}},
			{RuleID: "VGL-ARE-064", Severity: model.SeverityMedium,
				Location: model.Location{Path: "ios/Config/Release.xcconfig", StartLine: 1}},
		},
	}
	var out strings.Builder
	printHardeningSummary(&out, res, false)
	text := out.String()
	for _, want := range []string{"Android (3)", "Electron (1)", "iOS (1)"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Other (") {
		t.Errorf("wave-one rules must not fall into Other:\n%s", text)
	}
}
