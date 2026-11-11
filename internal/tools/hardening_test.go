package tools

import (
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/osv"
)

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
		"VGL-ARE-050":    "Native",
		"VGL-ARE-051":    ".NET",
		"VGL-ARE-052":    "iOS",
		"VGL-ARE-053":    "iOS",
		"VGL-ARE-054":    "Android",
		"VGL-ARE-055":    "React Native",
		"VGL-ARE-056":    "Electron",
		"VGL-ARE-057":    "Electron",
		"VGL-ARE-058":    "Electron",
		"VGL-ARE-059":    "Web",
		"vgl-are-003":    "Android",
		"VGL-SEC-001":    "Other",
		"VGL-OSV-GHSA-1": "Other",
		"":               "Other",
	}
	for id, want := range cases {
		if got := hardeningPlatform(id); got != want {
			t.Errorf("hardeningPlatform(%q) = %q, want %q", id, got, want)
		}
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
	text := hardeningSummary(Deps{}, res, []string{"VGL-ARE-003", "VGL-ARE-030"})
	for _, want := range []string{
		"Android (1)", "Electron (1)", "Other (1)",
		"hardening gaps", "not vulnerabilities",
		"not part of the anti-RE family",
		"Model: not used",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q:\n%s", want, text)
		}
	}
}

// Regression: with a model configured, the deterministic hardening summary
// named that model as if it had been used.
func TestHardeningSummaryNeverNamesAConfiguredModel(t *testing.T) {
	d := Deps{App: &app.App{LLM: true, Model: &model.ModelInfo{Provider: "command", Model: "some-model"}}}
	res := &model.ScanResult{Root: "/repo", Model: d.App.Model}

	text := hardeningSummary(d, res, []string{"VGL-ARE-001"})

	if strings.Contains(text, "some-model") || !strings.Contains(text, "Model: not used") {
		t.Fatalf("summary must say the model is not used:\n%s", text)
	}
}
