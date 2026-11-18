package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaselineVersion3DispositionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	f := sampleFinding()
	expires := BaselineToday().AddDate(0, 0, 30).Format(BaselineDateLayout)

	dispositions := []string{
		BaselineDispositionFalsePositive,
		BaselineDispositionAcceptedRisk,
		BaselineDispositionWontFix,
	}
	b := NewBaseline()
	for i, disposition := range dispositions {
		b.AddEntry(BaselineFinding{
			ID:          fmt.Sprintf("VGL-DISP%02d", i),
			Fingerprint: fmt.Sprintf("fp_disp%02d", i),
			RuleID:      f.RuleID,
			Path:        f.Location.Path,
			Reason:      "accepted with a disposition",
			Ticket:      fmt.Sprintf("SEC-%d", i+1),
			Expires:     expires,
			Disposition: disposition,
		})
	}
	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	var raw struct {
		Version  int `json:"version"`
		Findings []struct {
			Disposition string `json:"disposition"`
		} `json:"findings"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Version != 3 {
		t.Fatalf("on-disk version = %d, want 3", raw.Version)
	}
	if len(raw.Findings) != len(dispositions) {
		t.Fatalf("on-disk findings = %d, want %d", len(raw.Findings), len(dispositions))
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if loaded.Version != BaselineVersion {
		t.Fatalf("loaded version = %d, want %d", loaded.Version, BaselineVersion)
	}
	got := make(map[string]BaselineFinding, len(loaded.Findings))
	for _, entry := range loaded.Findings {
		got[entry.ID] = entry
	}
	for i, disposition := range dispositions {
		entry, ok := got[fmt.Sprintf("VGL-DISP%02d", i)]
		if !ok {
			t.Fatalf("entry %d did not round-trip", i)
		}
		if entry.Disposition != disposition {
			t.Errorf("entry %d disposition = %q, want %q", i, entry.Disposition, disposition)
		}
		if entry.Ticket != fmt.Sprintf("SEC-%d", i+1) || entry.Expires != expires || entry.Path != f.Location.Path {
			t.Errorf("entry %d lost metadata: %+v", i, entry)
		}
	}
}

func TestBaselineVersion3AcceptsCaseAndRejectsInvalid(t *testing.T) {
	valid := map[string]string{
		"":                "",
		"false_positive":  BaselineDispositionFalsePositive,
		" ACCEPTED_RISK ": BaselineDispositionAcceptedRisk,
		"Wont_Fix":        BaselineDispositionWontFix,
	}
	for input, want := range valid {
		got, err := ParseBaselineDisposition(input)
		if err != nil {
			t.Errorf("ParseBaselineDisposition(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ParseBaselineDisposition(%q) = %q, want %q", input, got, want)
		}
	}

	if _, err := ParseBaselineDisposition("bogus"); err == nil || !strings.Contains(err.Error(), "not a baseline disposition") {
		t.Errorf("bogus disposition error = %v", err)
	}
	if _, err := ParseBaselineDisposition("remediated"); err == nil ||
		!strings.Contains(err.Error(), "must be removed from the baseline") {
		t.Errorf("remediated disposition error = %v, want a removal hint", err)
	}

	dir := t.TempDir()
	for name, disposition := range map[string]string{
		"unknown":    "bogus",
		"remediated": BaselineDispositionRemediated,
	} {
		path := filepath.Join(dir, name+".json")
		doc := fmt.Sprintf(`{"version":3,"findings":[{"id":"VGL-X","reason":"x","disposition":%q}]}`, disposition)
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadBaseline(path)
		if err == nil {
			t.Fatalf("%s disposition was accepted", name)
		}
		want := "not a baseline disposition"
		if disposition == BaselineDispositionRemediated {
			want = "must be removed from the baseline"
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s disposition error = %v, want %q", name, err, want)
		}
	}

	// Saving refuses an invalid disposition too, so a bad entry cannot be
	// written by a caller that never round-trips the file.
	b := NewBaseline()
	b.Findings = append(b.Findings, BaselineFinding{ID: "VGL-X", Disposition: BaselineDispositionRemediated})
	if err := SaveBaseline(filepath.Join(dir, "save.json"), b); err == nil ||
		!strings.Contains(err.Error(), "must be removed from the baseline") {
		t.Errorf("SaveBaseline error = %v, want a remediated refusal", err)
	}
}

func TestBaselineLoadsLegacyVersionsAsV3(t *testing.T) {
	dir := t.TempDir()
	future := BaselineToday().AddDate(0, 0, 14).Format(BaselineDateLayout)

	tests := []struct {
		name         string
		doc          string
		wantID       string
		wantFP       string
		wantTicket   string
		wantExpires  string
		wantLegacyFP bool
	}{
		{
			name:         "version 1",
			doc:          `{"version":1,"fingerprints":["fp_legacy"],"findings":[{"id":"VGL-LEGACY","reason":"legacy acceptance"}]}`,
			wantID:       "VGL-LEGACY",
			wantLegacyFP: true,
		},
		{
			name:        "version 2",
			doc:         fmt.Sprintf(`{"version":2,"findings":[{"id":"VGL-V2","reason":"expiring","fingerprint":"fp_v2","ticket":"SEC-2","expires":%q}]}`, future),
			wantID:      "VGL-V2",
			wantFP:      "fp_v2",
			wantTicket:  "SEC-2",
			wantExpires: future,
		},
		{
			name:   "missing version",
			doc:    `{"findings":[{"id":"VGL-NOVER","reason":"old file"}]}`,
			wantID: "VGL-NOVER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(tt.doc), 0o644); err != nil {
				t.Fatal(err)
			}
			b, err := LoadBaseline(path)
			if err != nil {
				t.Fatalf("LoadBaseline: %v", err)
			}
			if b.Version != BaselineVersion {
				t.Fatalf("version = %d, want %d", b.Version, BaselineVersion)
			}
			var entry *BaselineFinding
			for i := range b.Findings {
				if strings.EqualFold(b.Findings[i].ID, tt.wantID) {
					entry = &b.Findings[i]
				}
			}
			if entry == nil {
				t.Fatalf("entry %s was not loaded: %+v", tt.wantID, b.Findings)
			}
			if entry.Disposition != "" {
				t.Errorf("legacy entry gained a disposition: %q", entry.Disposition)
			}
			if tt.wantFP != "" && entry.Fingerprint != tt.wantFP {
				t.Errorf("fingerprint = %q, want %q", entry.Fingerprint, tt.wantFP)
			}
			if tt.wantTicket != "" && entry.Ticket != tt.wantTicket {
				t.Errorf("ticket = %q, want %q", entry.Ticket, tt.wantTicket)
			}
			if tt.wantExpires != "" && entry.Expires != tt.wantExpires {
				t.Errorf("expires = %q, want %q", entry.Expires, tt.wantExpires)
			}
			if tt.wantLegacyFP {
				found := false
				for _, got := range b.Findings {
					if strings.EqualFold(got.Fingerprint, "fp_legacy") {
						found = true
					}
				}
				if !found {
					t.Errorf("legacy fingerprint was not materialized: %+v", b.Findings)
				}
			}

			if err := SaveBaseline(path, b); err != nil {
				t.Fatalf("SaveBaseline: %v", err)
			}
			reloaded, err := LoadBaseline(path)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if reloaded.Version != 3 {
				t.Fatalf("saved version = %d, want 3", reloaded.Version)
			}
		})
	}
}
