package osv

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		name  string
		score string
		want  model.Severity
		ok    bool
	}{
		{"numeric critical", "9.8", model.SeverityCritical, true},
		{"numeric high", "7.0", model.SeverityHigh, true},
		{"numeric medium", "4.0", model.SeverityMedium, true},
		{"numeric low", "0.1", model.SeverityLow, true},
		{"numeric info", "0", model.SeverityInfo, true},
		{"vector v3 critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", model.SeverityCritical, true},
		{"vector v3 high", "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", model.SeverityHigh, true},
		{"vector v3 medium", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", model.SeverityMedium, true},
		{"vector v3 low", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", model.SeverityLow, true},
		{"vector v3 info", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", model.SeverityInfo, true},
		{"vector v4 critical", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", model.SeverityCritical, true},
		{"vector v4 low", "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", model.SeverityLow, true},
		{"vector v2 high", "AV:N/AC:L/Au:N/C:P/I:P/A:P", model.SeverityHigh, true},
		{"empty", "", "", false},
		{"garbage", "not-a-score", "", false},
		{"out of range", "11.0", "", false},
		{"vector without impact", "CVSS:3.1/AV:N/AC:L/PR:N", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := severityFromScore(tc.score)
			if ok != tc.ok {
				t.Fatalf("severityFromScore(%q) ok = %v, want %v", tc.score, ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("severityFromScore(%q) = %q, want %q", tc.score, got, tc.want)
			}
		})
	}
}

func TestSeverityFor(t *testing.T) {
	tests := []struct {
		name string
		vuln vulnerability
		want model.Severity
	}{
		{
			name: "numeric score wins over database band",
			vuln: vulnerability{
				Severity:         []severityEntry{{Type: "CVSS_V3", Score: "9.8"}},
				DatabaseSpecific: databaseSpecific{Severity: "LOW"},
			},
			want: model.SeverityCritical,
		},
		{
			name: "highest of several entries wins",
			vuln: vulnerability{
				Severity: []severityEntry{{Type: "CVSS_V3", Score: "5.0"}, {Type: "CVSS_V4", Score: "9.9"}},
			},
			want: model.SeverityCritical,
		},
		{
			name: "database moderate",
			vuln: vulnerability{DatabaseSpecific: databaseSpecific{Severity: "MODERATE"}},
			want: model.SeverityMedium,
		},
		{
			name: "database none",
			vuln: vulnerability{DatabaseSpecific: databaseSpecific{Severity: "none"}},
			want: model.SeverityInfo,
		},
		{
			name: "unusable score falls back to database band",
			vuln: vulnerability{
				Severity:         []severityEntry{{Type: "CVSS_V3", Score: "weird"}},
				DatabaseSpecific: databaseSpecific{Severity: "HIGH"},
			},
			want: model.SeverityHigh,
		},
		{
			name: "no signal defaults to medium",
			vuln: vulnerability{},
			want: model.SeverityMedium,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := severityFor(tc.vuln); got != tc.want {
				t.Fatalf("severityFor() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDatabaseSpecificTolerant(t *testing.T) {
	var vuln vulnerability
	if err := json.Unmarshal([]byte(`{
		"id": "GHSA-test",
		"database_specific": {"severity": "high", "cwe_ids": ["CWE-79", 89, "nope"]}
	}`), &vuln); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if vuln.DatabaseSpecific.Severity != "high" {
		t.Fatalf("severity = %q, want high", vuln.DatabaseSpecific.Severity)
	}
	got := strings.Join(cwesFor(vuln), ",")
	if got != "CWE-79,CWE-89" {
		t.Fatalf("cwesFor = %q, want CWE-79,CWE-89", got)
	}

	var malformed vulnerability
	if err := json.Unmarshal([]byte(`{"id":"X","database_specific":"oops"}`), &malformed); err != nil {
		t.Fatalf("malformed database_specific must not fail unmarshal: %v", err)
	}
	if malformed.DatabaseSpecific.Severity != "" {
		t.Fatalf("unexpected severity %q", malformed.DatabaseSpecific.Severity)
	}
}

func TestCWEsFromReferences(t *testing.T) {
	vuln := vulnerability{
		DatabaseSpecific: databaseSpecific{CWEIDs: []string{"CWE-79", "CWE-89", "CWE-79"}},
		References: []reference{
			{URL: "https://cwe.mitre.org/data/definitions/22.html"},
			{URL: "https://cwe.mitre.org/data/definitions/79.html"},
			{URL: "https://example.test/no-cwe-here"},
		},
	}
	got := strings.Join(cwesFor(vuln), ",")
	if got != "CWE-79,CWE-89,CWE-22" {
		t.Fatalf("cwesFor = %q, want CWE-79,CWE-89,CWE-22", got)
	}
}
