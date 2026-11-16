package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
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
		if got := hardeningPlatformFor(id, ""); got != want {
			t.Errorf("hardeningPlatformFor(%q, \"\") = %q, want %q", id, got, want)
		}
	}
}

// TestHardeningPlatformDeclaredWins: the metadata is authoritative, the
// numeric ranges are only the fallback for rules without it.
func TestHardeningPlatformDeclaredWins(t *testing.T) {
	cases := []struct {
		ruleID   string
		platform string
		want     string
	}{
		{"VGL-ARE-050", "Other", "Other"},     // legacy fallback is also Other
		{"VGL-ARE-051", "Other", "Other"},     // legacy fallback is also Other
		{"VGL-ARE-055", "Other", "Other"},     // legacy fallback is also Other
		{"VGL-ARE-060", "Web", "Web"},         // numeric fallback says Android
		{"VGL-ARE-003", "", "Android"},        // no metadata, numeric fallback
		{"VGL-ARE-020", "flutter", "Flutter"}, // declared value is case-insensitive
		{"VGL-ARE-999", "", "Other"},          // unknown numeric range
	}
	for _, tc := range cases {
		got := hardeningPlatform(model.RuleMeta{ID: tc.ruleID, Platform: tc.platform})
		if got != tc.want {
			t.Errorf("hardeningPlatform(%q, platform %q) = %q, want %q", tc.ruleID, tc.platform, got, tc.want)
		}
	}
	// The legacy per-surface rules must stay inside the display order, or the
	// summary would hide their findings behind "… and N more".
	for _, id := range []string{"VGL-ARE-050", "VGL-ARE-051", "VGL-ARE-055"} {
		if got := hardeningPlatformFor(id, ""); got != "Other" {
			t.Errorf("numeric fallback for %s = %q, want Other", id, got)
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
	if strings.Contains(text, "\nOther (") {
		t.Errorf("wave-one rules must not fall into Other:\n%s", text)
	}
}

// TestHardeningSummaryShowsPlatformSelection: a --platform filter must name
// the selected platform and still show which platforms it filtered.
func TestHardeningSummaryShowsPlatformSelection(t *testing.T) {
	hardeningSelectedPlatform = "Android"
	t.Cleanup(func() { hardeningSelectedPlatform = hardeningPlatformAll })

	res := &model.ScanResult{
		Root: "/repo",
		Findings: []model.Finding{
			{RuleID: "VGL-ARE-003", Severity: model.SeverityHigh,
				Location: model.Location{Path: "AndroidManifest.xml", StartLine: 4}},
			{RuleID: "VGL-ARE-064", Severity: model.SeverityMedium,
				Location: model.Location{Path: "ios/Release.xcconfig", StartLine: 1}},
		},
	}
	var out strings.Builder
	printHardeningSummary(&out, res, false)
	text := out.String()

	for _, want := range []string{
		"platform  android",
		"detected",
		"Android (1 finding, 10 rules)",
		"iOS (5 rules, filtered)",
		"Electron (6 rules, filtered)",
		"only android rules were scanned",
		"\nAndroid (1):",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\niOS (") {
		t.Errorf("filtered platform must not get a finding group:\n%s", text)
	}
}

// TestAntiREIDsForPlatform: each platform selects only its own rules and the
// seven groups add up to the whole anti-RE family.
func TestAntiREIDsForPlatform(t *testing.T) {
	total := 0
	seen := map[string]string{}
	for _, platform := range hardeningPlatformOrder {
		ids := antiREIDsForPlatform(platform)
		if len(ids) == 0 {
			t.Errorf("platform %s selects no anti-RE rule", platform)
		}
		for _, id := range ids {
			if first, ok := seen[id]; ok {
				t.Errorf("rule %s is in both %s and %s", id, first, platform)
			}
			seen[id] = platform
		}
		total += len(ids)
	}
	if total != len(antiREIDs()) {
		t.Errorf("per-platform rules add up to %d, want %d anti-RE rules", total, len(antiREIDs()))
	}
	for _, id := range antiREIDs() {
		if seen[id] == "" {
			t.Errorf("rule %s is in no platform group", id)
		}
	}
}

// TestHardeningPlatformFilterRunsOnlyThatPlatform: the flag narrows the rule
// set before rendering, so JSON, exit codes and the report agree.
func TestHardeningPlatformFilterRunsOnlyThatPlatform(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, "Release.xcconfig", "ENABLE_TESTABILITY = YES\nDEBUG_INFORMATION_FORMAT = dwarf\n")

	want := 0
	wantIOS := 0
	for _, meta := range rules.Default().Metas() {
		if meta.Category != model.CategoryAntiRE {
			continue
		}
		switch hardeningPlatform(meta) {
		case "Electron":
			want++
		case "iOS":
			wantIOS++
		}
	}
	if want == 0 {
		t.Fatal("no Electron anti-RE rules in the registry")
	}
	if wantIOS == 0 {
		t.Fatal("no iOS anti-RE rules in the registry")
	}

	out, _, err := runCLI(t, "hardening", dir, "--quiet", "--format", "json", "--no-baseline", "--platform", "electron")
	if err != nil {
		t.Fatalf("hardening --platform electron: %v", err)
	}
	var res struct {
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
		Stats struct {
			RulesRun int `json:"rulesRun"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if res.Stats.RulesRun != want {
		t.Errorf("rulesRun = %d, want %d Electron rules", res.Stats.RulesRun, want)
	}
	for _, f := range res.Findings {
		if got := hardeningPlatformFor(f.RuleID, ""); got != "Electron" {
			t.Errorf("finding from %q (%s) survived --platform electron", f.RuleID, got)
		}
	}

	// The "--flag=value" spelling selects the same platform.
	out, _, err = runCLI(t, "hardening", dir, "--quiet", "--format", "json", "--no-baseline", "--platform=ios")
	if err != nil {
		t.Fatalf("hardening --platform=ios: %v", err)
	}
	res.Findings = nil
	res.Stats.RulesRun = 0
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if res.Stats.RulesRun != wantIOS {
		t.Errorf("rulesRun = %d, want %d iOS rules", res.Stats.RulesRun, wantIOS)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("the iOS fixture produced no findings; the platform loop would be vacuous")
	}
	for _, f := range res.Findings {
		if got := hardeningPlatformFor(f.RuleID, ""); got != "iOS" {
			t.Errorf("finding from %q (%s) survived --platform ios", f.RuleID, got)
		}
	}
}

// TestHardeningPlatformMaxFindings: --max-findings caps the selected
// platform's findings, never another platform's.
func TestHardeningPlatformMaxFindings(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, "Release.xcconfig", "ENABLE_TESTABILITY = YES\nDEBUG_INFORMATION_FORMAT = dwarf\n")

	out, _, err := runCLI(t, "hardening", dir, "--quiet", "--format", "json", "--no-baseline", "--platform", "ios")
	if err != nil {
		t.Fatalf("hardening --platform ios: %v", err)
	}
	var uncapped struct {
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &uncapped); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if len(uncapped.Findings) < 2 {
		t.Fatalf("iOS fixture produced %d findings, want at least 2", len(uncapped.Findings))
	}

	out, _, err = runCLI(t, "hardening", dir, "--quiet", "--format", "json", "--no-baseline", "--platform", "ios", "--max-findings", "1")
	if err != nil {
		t.Fatalf("hardening --platform ios --max-findings 1: %v", err)
	}
	var capped struct {
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
		Stats struct {
			RulesRun int `json:"rulesRun"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &capped); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if len(capped.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 after --max-findings 1", len(capped.Findings))
	}
	if got := hardeningPlatformFor(capped.Findings[0].RuleID, ""); got != "iOS" {
		t.Errorf("capped finding %q belongs to %q, want iOS", capped.Findings[0].RuleID, got)
	}
	wantRules := 0
	for _, meta := range rules.Default().Metas() {
		if meta.Category == model.CategoryAntiRE && hardeningPlatform(meta) == "iOS" {
			wantRules++
		}
	}
	if capped.Stats.RulesRun != wantRules {
		t.Errorf("rulesRun = %d, want %d iOS rules", capped.Stats.RulesRun, wantRules)
	}
}

func TestHardeningRejectsUnknownPlatform(t *testing.T) {
	dir := newTestRepo(t)

	_, _, err := runCLI(t, "hardening", dir, "--platform", "windows", "--quiet")
	if err == nil {
		t.Fatal("want an error for an unknown platform")
	}
	for _, want := range []string{"unknown platform", "windows", "android", "all"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}

	if _, _, err := runCLI(t, "hardening", dir, "--platform"); err == nil || !strings.Contains(err.Error(), "--platform needs a value") {
		t.Errorf("missing value error = %v", err)
	}
}

// TestHardeningPlatformNarrowsRules: --rules may not escape the selected
// platform, and the error says which scope rejected the rule.
func TestHardeningPlatformNarrowsRules(t *testing.T) {
	dir := newTestRepo(t)

	_, _, err := runCLI(t, "hardening", dir, "--platform", "ios", "--rules", "VGL-ARE-003", "--quiet")
	if err == nil {
		t.Fatal("want an error for a rule outside the selected platform")
	}
	for _, want := range []string{"VGL-ARE-003", "platform ios", "--rules"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

// TestHardeningHelpMentionsPlatform documents the flag in the command help.
func TestHardeningHelpMentionsPlatform(t *testing.T) {
	out, _, err := runCLI(t, "hardening", "--help")
	if err != nil {
		t.Fatalf("hardening --help: %v", err)
	}
	if !strings.Contains(out, "--platform") {
		t.Errorf("help does not mention --platform:\n%s", out)
	}
	for _, value := range []string{"android", "ios", "electron", "node", "flutter", "web", "other", "all"} {
		if !strings.Contains(out, value) {
			t.Errorf("help does not list %q:\n%s", value, out)
		}
	}
}
