package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/osv"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// TestHardeningPlatform keeps the numeric fallback honest: rules that declare
// no Platform metadata (older rules, separately enabled scanners) still land in
// a display group, and the legacy per-surface rules use the catch-all.
func TestHardeningPlatform(t *testing.T) {
	cases := map[string]string{
		"VGL-ARE-001":    "Android",
		"VGL-ARE-006":    "Android",
		"VGL-ARE-010":    "iOS",
		"VGL-ARE-011":    "iOS",
		"VGL-ARE-020":    "Flutter",
		"VGL-ARE-030":    "Electron",
		"VGL-ARE-031":    "Electron",
		"VGL-ARE-040":    "Node",
		"VGL-ARE-041":    "Node",
		"VGL-ARE-050":    "Other",
		"VGL-ARE-051":    "Other",
		"VGL-ARE-052":    "iOS",
		"VGL-ARE-053":    "iOS",
		"VGL-ARE-054":    "Android",
		"VGL-ARE-055":    "Other",
		"VGL-ARE-056":    "Electron",
		"VGL-ARE-057":    "Electron",
		"VGL-ARE-058":    "Electron",
		"VGL-ARE-059":    "Web",
		"VGL-ARE-060":    "Android",
		"VGL-ARE-061":    "Android",
		"VGL-ARE-062":    "Android",
		"VGL-ARE-063":    "Electron",
		"VGL-ARE-064":    "iOS",
		"vgl-are-003":    "Android",
		"VGL-SEC-001":    "Other",
		"VGL-OSV-GHSA-1": "Other",
		"":               "Other",
	}
	for id, want := range cases {
		if got := hardeningPlatform(id, nil); got != want {
			t.Errorf("hardeningPlatform(%q, nil) = %q, want %q", id, got, want)
		}
	}
}

// TestHardeningPlatformMetadataWins: the declared Platform is the single source
// of truth, and the numeric ranges only apply when it is absent.
func TestHardeningPlatformMetadataWins(t *testing.T) {
	metas := []model.RuleMeta{
		{ID: "VGL-ARE-050", Category: model.CategoryAntiRE, Platform: "Other"},
		{ID: "VGL-ARE-060", Category: model.CategoryAntiRE, Platform: "Web"},
		{ID: "VGL-ARE-001", Category: model.CategoryAntiRE},
	}
	index := hardeningPlatformIndex(metas)

	for id, want := range map[string]string{
		"VGL-ARE-050": "Other",    // declared Other, legacy fallback also Other
		"VGL-ARE-060": "Web",      // declared Web, numeric fallback says Android
		"VGL-ARE-001": "Android",  // no metadata, numeric fallback applies
		"VGL-ARE-030": "Electron", // unknown rule, numeric fallback applies
	} {
		if got := hardeningPlatform(id, index); got != want {
			t.Errorf("hardeningPlatform(%q, index) = %q, want %q", id, got, want)
		}
	}
}

// TestHardeningPlatformSelector covers the accepted platform values and the
// rejection of anything else.
func TestHardeningPlatformSelector(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "all"},
		{"ALL", "all"},
		{"android", "Android"},
		{"iOS", "iOS"},
		{" electron ", "Electron"},
		{"node", "Node"},
		{"flutter", "Flutter"},
		{"web", "Web"},
		{"other", "Other"},
	} {
		got, err := parseHardeningPlatform(tc.in)
		if err != nil {
			t.Errorf("parseHardeningPlatform(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHardeningPlatform(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := parseHardeningPlatform("windows"); err == nil || !strings.Contains(err.Error(), "unknown platform") {
		t.Errorf("parseHardeningPlatform(windows) error = %v, want unknown platform", err)
	}
}

func TestAntiREIDsSelectsOnlyAntiRE(t *testing.T) {
	metas := []model.RuleMeta{
		{ID: "VGL-ARE-003", Category: model.CategoryAntiRE},
		{ID: "VGL-SEC-001", Category: model.CategorySecrets},
		{ID: "VGL-ARE-030", Category: model.CategoryAntiRE},
		{ID: "VGL-DEP-001", Category: model.CategoryDependency},
	}
	got := antiREIDs(metas)
	if len(got) != 2 || got[0] != "VGL-ARE-003" || got[1] != "VGL-ARE-030" {
		t.Fatalf("antiREIDs = %v, want [VGL-ARE-003 VGL-ARE-030]", got)
	}
	if ids := antiREIDs(nil); len(ids) != 0 {
		t.Fatalf("antiREIDs(nil) = %v, want empty", ids)
	}
}

func TestDependenciesMaxPackages(t *testing.T) {
	cases := []struct {
		in      int
		want    int
		wantErr bool
	}{
		{0, osv.DefaultMaxPackages, false},
		{10, 10, false},
		{osv.MaxAllowedPackages, osv.MaxAllowedPackages, false},
		{osv.MaxAllowedPackages + 1, osv.MaxAllowedPackages, false},
		{-1, 0, true},
	}
	for _, tc := range cases {
		got, err := dependenciesMaxPackages(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("dependenciesMaxPackages(%d) returned %d, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("dependenciesMaxPackages(%d): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("dependenciesMaxPackages(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestHardeningSummaryGroupsEachPlatform: every platform in the stable display
// order gets its own group, and the declared metadata decides the group.
func TestHardeningSummaryGroupsEachPlatform(t *testing.T) {
	metas := []model.RuleMeta{
		{ID: "VGL-ARE-001", Category: model.CategoryAntiRE, Platform: "Android"},
		{ID: "VGL-ARE-010", Category: model.CategoryAntiRE, Platform: "iOS"},
		{ID: "VGL-ARE-030", Category: model.CategoryAntiRE, Platform: "Electron"},
		{ID: "VGL-ARE-040", Category: model.CategoryAntiRE, Platform: "Node"},
		{ID: "VGL-ARE-020", Category: model.CategoryAntiRE, Platform: "Flutter"},
		{ID: "VGL-ARE-059", Category: model.CategoryAntiRE, Platform: "Web"},
		{ID: "VGL-ARE-050", Category: model.CategoryAntiRE, Platform: "Other"},
	}
	res := &model.ScanResult{Root: "/repo"}
	for _, m := range metas {
		res.Findings = append(res.Findings, model.Finding{
			RuleID:   m.ID,
			Severity: model.SeverityMedium,
			Location: model.Location{Path: "build.config", StartLine: 1},
		})
	}
	d := Deps{App: &app.App{Registry: registryWith(metas)}}
	text := hardeningSummary(d, res, antiREIDs(metas), "all", hardeningPlatformCounts(res.Findings, hardeningPlatformIndex(metas)))

	for _, want := range []string{
		"Android (1):", "iOS (1):", "Electron (1):", "Node (1):", "Flutter (1):", "Web (1):", "Other (1):",
		"Platform: all — Android (1 finding, 1 rule), iOS (1 finding, 1 rule), Electron (1 finding, 1 rule), Node (1 finding, 1 rule), Flutter (1 finding, 1 rule), Web (1 finding, 1 rule), Other (1 finding, 1 rule)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q:\n%s", want, text)
		}
	}
}

func TestHardeningSummaryGroupsByPlatform(t *testing.T) {
	res := &model.ScanResult{
		Root: "/repo",
		Findings: []model.Finding{
			{RuleID: "VGL-ARE-003", Title: "Debuggable manifest", Severity: model.SeverityHigh,
				Location: model.Location{Path: "AndroidManifest.xml", StartLine: 4}},
			{RuleID: "VGL-ARE-030", Title: "webSecurity disabled", Severity: model.SeverityHigh,
				Location: model.Location{Path: "main.js", StartLine: 2}},
			{RuleID: "VGL-OSV-GHSA-1", Title: "Vulnerable dependency", Severity: model.SeverityMedium,
				Location: model.Location{Path: "package.json", StartLine: 3}},
		},
	}
	text := hardeningSummary(Deps{}, res, []string{"VGL-ARE-003", "VGL-ARE-030"}, "all", nil)
	for _, want := range []string{
		"Android (1):", "Electron (1):", "Other (1):",
		"hardening gaps", "not vulnerabilities",
		"not part of the anti-RE family",
		"Model: not used",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q:\n%s", want, text)
		}
	}
}

func TestHardeningSummaryGroupsWaveOnePlatforms(t *testing.T) {
	res := &model.ScanResult{
		Root: "/repo",
		Findings: []model.Finding{
			{RuleID: "VGL-ARE-060", Title: "user CA", Severity: model.SeverityHigh,
				Location: model.Location{Path: "res/xml/network_security_config.xml", StartLine: 4}},
			{RuleID: "VGL-ARE-061", Title: "debuggable release", Severity: model.SeverityHigh,
				Location: model.Location{Path: "app/build.gradle", StartLine: 5}},
			{RuleID: "VGL-ARE-062", Title: "dontobfuscate", Severity: model.SeverityHigh,
				Location: model.Location{Path: "app/proguard-rules.pro", StartLine: 2}},
			{RuleID: "VGL-ARE-063", Title: "remote debugging port", Severity: model.SeverityHigh,
				Location: model.Location{Path: "src/main.js", StartLine: 3}},
			{RuleID: "VGL-ARE-064", Title: "optimization off", Severity: model.SeverityMedium,
				Location: model.Location{Path: "ios/Config/Release.xcconfig", StartLine: 1}},
		},
	}
	text := hardeningSummary(Deps{}, res, []string{"VGL-ARE-060", "VGL-ARE-061", "VGL-ARE-062", "VGL-ARE-063", "VGL-ARE-064"}, "all", nil)
	for _, want := range []string{"Android (3):", "Electron (1):", "iOS (1):"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\nOther (") {
		t.Errorf("wave-one rules must not fall into Other:\n%s", text)
	}
}

// Regression: with a model configured, the deterministic hardening summary
// named that model as if it had been used.
func TestHardeningSummaryNeverNamesAConfiguredModel(t *testing.T) {
	d := Deps{App: &app.App{LLM: true, Model: &model.ModelInfo{Provider: "command", Model: "some-model"}}}
	res := &model.ScanResult{Root: "/repo", Model: d.App.Model}

	text := hardeningSummary(d, res, []string{"VGL-ARE-001"}, "all", nil)

	if strings.Contains(text, "some-model") || !strings.Contains(text, "Model: not used") {
		t.Fatalf("summary must say the model is not used:\n%s", text)
	}
}

// registryWith builds a registry holding exactly the given metadata.
func registryWith(metas []model.RuleMeta) *rules.Registry {
	reg := rules.NewRegistry()
	for _, m := range metas {
		reg.Add(rules.New(m, func(*rules.File) []model.Finding { return nil }))
	}
	return reg
}

// hardeningTestApp builds a real, hermetic app on a temp repository: the
// production registry with the declared platform metadata, a scanner and a
// local store.
func hardeningTestApp(t *testing.T) (*app.App, string) {
	t.Helper()
	t.Setenv("VIGIL_NO_LLM", "1")
	t.Setenv("VIGIL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
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

func writeHardeningFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestFilterFindingsByPlatform: every platform keeps its own findings and
// reports the rest as filtered.
func TestFilterFindingsByPlatform(t *testing.T) {
	metas := []model.RuleMeta{
		{ID: "VGL-ARE-001", Category: model.CategoryAntiRE, Platform: "Android"},
		{ID: "VGL-ARE-010", Category: model.CategoryAntiRE, Platform: "iOS"},
		{ID: "VGL-ARE-030", Category: model.CategoryAntiRE, Platform: "Electron"},
		{ID: "VGL-ARE-040", Category: model.CategoryAntiRE, Platform: "Node"},
		{ID: "VGL-ARE-020", Category: model.CategoryAntiRE, Platform: "Flutter"},
		{ID: "VGL-ARE-059", Category: model.CategoryAntiRE, Platform: "Web"},
		{ID: "VGL-ARE-050", Category: model.CategoryAntiRE, Platform: "Other"},
		{ID: "VGL-OSV-GHSA-1", Category: model.CategoryDependency},
	}
	index := hardeningPlatformIndex(metas)
	findings := make([]model.Finding, 0, len(metas))
	for _, m := range metas {
		findings = append(findings, model.Finding{RuleID: m.ID, Severity: model.SeverityMedium})
	}

	for _, platform := range hardeningPlatforms {
		got := filterFindingsByPlatform(findings, platform, index)
		if len(got) == 0 {
			t.Errorf("platform %s kept no finding", platform)
		}
		for _, f := range got {
			if resolved := hardeningPlatform(f.RuleID, index); resolved != platform {
				t.Errorf("filter %s kept %q (%s)", platform, f.RuleID, resolved)
			}
		}
		line := hardeningPlatformLine(platform, hardeningPlatformCounts(findings, index), hardeningRuleCounts(metas))
		if !strings.Contains(line, platform+" (") {
			t.Errorf("platform line %q does not show %s", line, platform)
		}
		if strings.Count(line, "filtered") != len(hardeningPlatforms)-1 {
			t.Errorf("platform line %q should mark %d groups filtered", line, len(hardeningPlatforms)-1)
		}
	}

	// Other collects both the declared Other rule and the dependency finding,
	// matching the pre-metadata behaviour for non-ARE findings.
	if got := len(filterFindingsByPlatform(findings, "Other", index)); got != 2 {
		t.Errorf("Other findings = %d, want 2", got)
	}

	counts := hardeningPlatformCounts(findings, index)
	if len(counts) != len(hardeningPlatforms) {
		t.Fatalf("counts = %+v, want %d platforms", counts, len(hardeningPlatforms))
	}
	for i, c := range counts {
		if c.Platform != hardeningPlatforms[i] {
			t.Errorf("counts[%d] = %s, want %s", i, c.Platform, hardeningPlatforms[i])
		}
	}
}

// TestHandleHardeningPlatformFilter: the platform argument narrows the
// findings and the structured result without hiding the filtered platform.
func TestHandleHardeningPlatformFilter(t *testing.T) {
	a, dir := hardeningTestApp(t)
	writeHardeningFile(t, dir, "AndroidManifest.xml", `<manifest><application android:debuggable="true"/></manifest>`)
	writeHardeningFile(t, dir, "electron/main.js", "new BrowserWindow({webSecurity: false});\n")

	ctx := context.Background()
	filtered, err := handleHardening(ctx, Deps{App: a}, json.RawMessage(`{"noBaseline":true,"platform":"android"}`))
	if err != nil {
		t.Fatalf("handleHardening: %v", err)
	}
	if filtered.IsError {
		t.Fatalf("platform=android failed: %s", textOfResult(t, filtered))
	}
	scan, ok := filtered.StructuredContent.(*model.ScanResult)
	if !ok {
		t.Fatalf("structuredContent = %T, want *model.ScanResult", filtered.StructuredContent)
	}
	if len(scan.Findings) == 0 {
		t.Fatalf("no Android findings in the fixture")
	}

	index := hardeningPlatformIndex(a.Registry.Metas())
	for _, f := range scan.Findings {
		if got := hardeningPlatform(f.RuleID, index); got != "Android" {
			t.Errorf("filtered finding %q belongs to %q, want Android", f.RuleID, got)
		}
	}
	assertHardeningAggregates(t, scan, "Android", index)
	text := textOfResult(t, filtered)
	if !strings.Contains(text, "Platform: android") {
		t.Errorf("text does not name the selection:\n%s", text)
	}
	if !strings.Contains(text, "filtered") {
		t.Errorf("text hides the filtered platforms:\n%s", text)
	}

	all, err := handleHardening(ctx, Deps{App: a}, json.RawMessage(`{"noBaseline":true}`))
	if err != nil {
		t.Fatalf("handleHardening: %v", err)
	}
	unfiltered, ok := all.StructuredContent.(*model.ScanResult)
	if !ok {
		t.Fatalf("structuredContent = %T, want *model.ScanResult", all.StructuredContent)
	}
	if len(unfiltered.Findings) <= len(scan.Findings) {
		t.Errorf("unfiltered findings = %d, want more than the %d Android ones",
			len(unfiltered.Findings), len(scan.Findings))
	}
	found := false
	for _, f := range unfiltered.Findings {
		if f.RuleID == "VGL-ARE-030" {
			found = true
		}
	}
	if !found {
		t.Errorf("electron fixture did not produce VGL-ARE-030: %+v", unfiltered.Findings)
	}
}

// TestHandleHardeningRejectsUnknownPlatform: a bad platform is a clear
// argument error, not a silently empty report.
func TestHandleHardeningRejectsUnknownPlatform(t *testing.T) {
	a, _ := hardeningTestApp(t)

	bad, err := handleHardening(context.Background(), Deps{App: a}, json.RawMessage(`{"platform":"windows"}`))
	if err != nil {
		t.Fatalf("handleHardening: %v", err)
	}
	if !bad.IsError {
		t.Fatalf("unknown platform was not rejected: %s", textOfResult(t, bad))
	}
	text := textOfResult(t, bad)
	if !strings.Contains(text, "unknown platform") || !strings.Contains(text, "windows") {
		t.Errorf("error does not name the bad platform: %s", text)
	}
	if !strings.Contains(text, "android") || !strings.Contains(text, "all") {
		t.Errorf("error does not list the accepted values: %s", text)
	}
}

// Regression: the platform filter used to run every anti-RE rule and trim the
// findings afterwards, so another platform could consume MaxFindings and the
// selected platform could lose every gap. The rule set is now narrowed before
// the scan and the cap therefore applies to the selected platform.
func TestHandleHardeningPlatformMaxFindings(t *testing.T) {
	a, dir := hardeningTestApp(t)
	writeHardeningFile(t, dir, "AndroidManifest.xml", `<manifest><application android:debuggable="true"/></manifest>`)
	writeHardeningFile(t, dir, "ios/Release.xcconfig", "ENABLE_TESTABILITY = YES\nDEBUG_INFORMATION_FORMAT = dwarf\n")

	res, err := handleHardening(context.Background(), Deps{App: a}, json.RawMessage(`{"noBaseline":true,"platform":"ios","maxFindings":1}`))
	if err != nil {
		t.Fatalf("handleHardening: %v", err)
	}
	if res.IsError {
		t.Fatalf("platform=ios failed: %s", textOfResult(t, res))
	}
	scan, ok := res.StructuredContent.(*model.ScanResult)
	if !ok {
		t.Fatalf("structuredContent = %T, want *model.ScanResult", res.StructuredContent)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 iOS finding under maxFindings=1: %+v", len(scan.Findings), scan.Findings)
	}

	index := hardeningPlatformIndex(a.Registry.Metas())
	for _, f := range scan.Findings {
		if got := hardeningPlatform(f.RuleID, index); got != "iOS" {
			t.Errorf("finding %q belongs to %q, want iOS", f.RuleID, got)
		}
	}
	if want := len(antiREIDsForPlatform(a.Registry.Metas(), "iOS")); scan.Stats.RulesRun != want {
		t.Errorf("rulesRun = %d, want the %d iOS rules", scan.Stats.RulesRun, want)
	}
	assertHardeningAggregates(t, scan, "iOS", index)
	if text := textOfResult(t, res); strings.Contains(text, "No hardening gaps") {
		t.Errorf("summary claims there are no gaps although the scan kept one:\n%s", text)
	}
}

// TestApplyHardeningPlatformFilterRebuildsAggregates: filtering findings must
// also rebuild the severity/category totals and drop suppressed entries from
// other platforms, while the scan-level counters stay untouched.
func TestApplyHardeningPlatformFilterRebuildsAggregates(t *testing.T) {
	metas := []model.RuleMeta{
		{ID: "VGL-ARE-001", Category: model.CategoryAntiRE, Platform: "Android"},
		{ID: "VGL-ARE-003", Category: model.CategoryAntiRE, Platform: "Android"},
		{ID: "VGL-ARE-010", Category: model.CategoryAntiRE, Platform: "iOS"},
	}
	index := hardeningPlatformIndex(metas)
	res := &model.ScanResult{
		Findings: []model.Finding{
			{RuleID: "VGL-ARE-001", Severity: model.SeverityHigh, Category: model.CategoryAntiRE},
			{RuleID: "VGL-ARE-003", Severity: model.SeverityMedium, Category: model.CategoryAntiRE},
			{RuleID: "VGL-ARE-010", Severity: model.SeverityHigh, Category: model.CategoryAntiRE},
		},
		Suppressed: []model.Finding{
			{RuleID: "VGL-ARE-003", Severity: model.SeverityLow, Category: model.CategoryAntiRE},
			{RuleID: "VGL-ARE-010", Severity: model.SeverityLow, Category: model.CategoryAntiRE},
		},
		Stats: model.Stats{
			FilesScanned: 9,
			FilesSkipped: 2,
			BytesScanned: 42,
			DurationMS:   17,
			RulesRun:     28,
			BySeverity:   map[model.Severity]int{model.SeverityHigh: 2, model.SeverityMedium: 1},
			ByCategory:   map[model.Category]int{model.CategoryAntiRE: 3},
		},
	}

	applyHardeningPlatformFilter(res, "Android", index)

	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 Android findings", len(res.Findings))
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].RuleID != "VGL-ARE-003" {
		t.Fatalf("suppressed = %+v, want only the Android entry", res.Suppressed)
	}
	if res.Stats.BySeverity[model.SeverityHigh] != 1 || res.Stats.BySeverity[model.SeverityMedium] != 1 {
		t.Errorf("bySeverity = %v, want one high and one medium", res.Stats.BySeverity)
	}
	if res.Stats.ByCategory[model.CategoryAntiRE] != 2 {
		t.Errorf("byCategory = %v, want 2 anti-RE findings", res.Stats.ByCategory)
	}
	if res.Stats.RulesRun != 28 || res.Stats.FilesScanned != 9 || res.Stats.FilesSkipped != 2 ||
		res.Stats.BytesScanned != 42 || res.Stats.DurationMS != 17 {
		t.Errorf("scan-level stats changed: %+v", res.Stats)
	}
	assertHardeningAggregates(t, res, "Android", index)
}

// assertHardeningAggregates checks that the severity/category totals describe
// exactly the findings the caller receives.
func assertHardeningAggregates(t *testing.T, res *model.ScanResult, platform string, index map[string]string) {
	t.Helper()
	bySeverity := 0
	for _, n := range res.Stats.BySeverity {
		bySeverity += n
	}
	if bySeverity != len(res.Findings) {
		t.Errorf("bySeverity sums to %d, want %d findings: %v", bySeverity, len(res.Findings), res.Stats.BySeverity)
	}
	byCategory := 0
	for _, n := range res.Stats.ByCategory {
		byCategory += n
	}
	if byCategory != len(res.Findings) {
		t.Errorf("byCategory sums to %d, want %d findings: %v", byCategory, len(res.Findings), res.Stats.ByCategory)
	}
	for _, f := range res.Findings {
		if platform != hardeningPlatformAll && hardeningPlatform(f.RuleID, index) != platform {
			t.Errorf("finding %q is outside platform %s", f.RuleID, platform)
		}
	}
	for _, f := range res.Suppressed {
		if platform != hardeningPlatformAll && hardeningPlatform(f.RuleID, index) != platform {
			t.Errorf("suppressed finding %q is outside platform %s", f.RuleID, platform)
		}
	}
}

// textOfResult returns the text half of a tool result.
func textOfResult(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("tool result has no content")
	}
	return res.Content[0].Text
}
