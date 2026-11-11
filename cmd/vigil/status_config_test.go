package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Regression: `vigil doctor` (an alias of status) died on the very
// configuration problem it should explain, and `--json` emitted no JSON.

func TestDoctorReportsRejectedProjectKeyWithFix(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		key     string
		wantFix string
		secret  string
	}{
		{"osv mirror", "scan:\n  osv_base_url: http://attacker.example\n", "scan.osv_base_url", "VIGIL_OSV_BASE_URL", "attacker.example"},
		{"api key", "api_key: sk-doctor-secret-must-never-print\n", "api_key", "CI secret", "sk-doctor-secret-must-never-print"},
		{"model endpoint", "base_url: https://u:pw@evil.example/v1\n", "base_url", "VIGIL_BASE_URL", "evil.example"},
		{"follow symlinks", "scan:\n  follow_symlinks: true\n", "scan.follow_symlinks", "user config", ""},
		{"baseline path", "scan:\n  baseline: ../../base.json\n", "scan.baseline", "relative path inside the project", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := newTestRepo(t)
			writeTestFile(t, dir, ".vigil.yaml", tc.body)

			out, _, err := runCLI(t, "doctor", "--json")

			if !errors.Is(err, errStatusConfig) {
				t.Fatalf("err = %v, want errStatusConfig (non-zero exit)", err)
			}
			var report statusReport
			if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
				t.Fatalf("doctor --json is not valid JSON: %v\n%s", jerr, out)
			}
			ce := report.ConfigError
			if ce == nil || ce.Key != tc.key || !strings.HasSuffix(ce.File, ".vigil.yaml") {
				t.Fatalf("configError = %+v, want key %q", ce, tc.key)
			}
			if !strings.Contains(ce.Fix, tc.wantFix) {
				t.Errorf("fix %q does not mention %q", ce.Fix, tc.wantFix)
			}
			if report.Rules == 0 || report.Version == "" {
				t.Errorf("degraded report lost build facts: %+v", report)
			}
			if tc.secret != "" && strings.Contains(out, tc.secret) {
				t.Errorf("doctor output contains the configured value %q:\n%s", tc.secret, out)
			}

			human, _, herr := runCLI(t, "doctor")
			if !errors.Is(herr, errStatusConfig) {
				t.Fatalf("human doctor err = %v", herr)
			}
			for _, want := range []string{"ERROR", "fix", tc.key} {
				if !strings.Contains(human, want) {
					t.Errorf("human output missing %q:\n%s", want, human)
				}
			}
			if strings.Contains(human, "not configured") {
				t.Errorf("degraded output must not show defaults as the user's setup:\n%s", human)
			}
		})
	}
}

func TestDoctorReportsUnparseableConfigGenerically(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, ".vigil.yaml", "scan: [unclosed\n")

	out, _, err := runCLI(t, "doctor", "--json")

	if !errors.Is(err, errStatusConfig) {
		t.Fatalf("err = %v", err)
	}
	var report statusReport
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
		t.Fatalf("not JSON: %v\n%s", jerr, out)
	}
	if report.ConfigError == nil || report.ConfigError.Key != "" || report.ConfigError.Fix == "" {
		t.Fatalf("configError = %+v", report.ConfigError)
	}
}

func TestStatusJSONHasNullConfigErrorWhenHealthy(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "status", "--json")

	if err != nil {
		t.Fatalf("status: %v\n%s", err, stderr)
	}
	var raw map[string]json.RawMessage
	if jerr := json.Unmarshal([]byte(out), &raw); jerr != nil {
		t.Fatal(jerr)
	}
	if v, ok := raw["configError"]; !ok || string(v) != "null" {
		t.Fatalf("configError = %s (present=%v), want null", v, ok)
	}
}
