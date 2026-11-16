package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

func sampleFinding() model.Finding {
	f := model.Finding{
		RuleID:     "TEST-SECRET",
		Title:      "secret",
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		Category:   model.CategorySecrets,
		Location:   model.Location{Path: "a.go", StartLine: 3},
		Evidence:   `password = "hunter2"`,
		Source:     model.SourceRule,
	}
	f.Normalize()
	return f
}

func TestBaselineRoundTripAndMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	f := sampleFinding()

	b := NewBaseline()
	if b.Version != BaselineVersion {
		t.Fatalf("version = %d", b.Version)
	}
	b.Add(f, "known issue")
	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if loaded.Version != BaselineVersion {
		t.Fatalf("loaded version = %d", loaded.Version)
	}
	if ok, why := loaded.Match(f); !ok || why != "known issue" {
		t.Fatalf("Match = %v, %q; want true, known issue", ok, why)
	}

	// The ID is an exact match even if the fingerprint was recomputed.
	byID := f
	byID.Fingerprint = "fp_different"
	if ok, _ := loaded.Match(byID); !ok {
		t.Fatal("expected match by finding ID")
	}

	other := f
	other.Evidence = `password = "different"`
	other.ID = ""
	other.Fingerprint = ""
	other.Normalize()
	if ok, _ := loaded.Match(other); ok {
		t.Fatal("unrelated finding matched the baseline")
	}
}

func TestLoadBaselineVersion1Upgrades(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	legacy := `{"version":1,"fingerprints":["fp_legacy"],"findings":[{"id":"VGL-LEGACY","reason":"legacy acceptance"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline(v1): %v", err)
	}
	if b.Version != BaselineVersion {
		t.Fatalf("v1 version = %d, want normalized %d", b.Version, BaselineVersion)
	}

	byID := sampleFinding()
	byID.ID = "VGL-LEGACY"
	byID.Fingerprint = "fp_other"
	if ok, why := b.Match(byID); !ok || why != "legacy acceptance" {
		t.Fatalf("v1 ID match = %v, %q", ok, why)
	}

	var materialized *BaselineFinding
	for i := range b.Findings {
		if strings.EqualFold(b.Findings[i].Fingerprint, "fp_legacy") {
			materialized = &b.Findings[i]
		}
	}
	if materialized == nil {
		t.Fatal("v1 fingerprint was not materialized as an entry")
	}
	if materialized.ID != "" || materialized.Expires != "" || materialized.Reason != legacyFingerprintReason {
		t.Fatalf("materialized entry = %+v", *materialized)
	}

	byFP := sampleFinding()
	byFP.ID = "VGL-OTHER"
	byFP.Fingerprint = "fp_legacy"
	if ok, why := b.Match(byFP); !ok || why != legacyFingerprintReason {
		t.Fatalf("v1 fingerprint match = %v, %q", ok, why)
	}

	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	reloaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Version != BaselineVersion {
		t.Fatalf("saved version = %d, want %d", reloaded.Version, BaselineVersion)
	}
	legacyCount := 0
	for _, entry := range reloaded.Findings {
		if strings.EqualFold(entry.Fingerprint, "fp_legacy") {
			legacyCount++
		}
	}
	if legacyCount != 1 {
		t.Fatalf("legacy fingerprint entries after round trip = %d, want 1 (no duplicates)", legacyCount)
	}

	var raw struct {
		Version int `json:"version"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Version != 2 {
		t.Fatalf("on-disk version = %d, want 2", raw.Version)
	}
}

func TestBaselineVersion2RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	f := sampleFinding()
	expires := BaselineToday().AddDate(0, 0, 30).Format(BaselineDateLayout)

	b := NewBaseline()
	b.AddEntry(BaselineFinding{
		ID:          f.ID,
		Fingerprint: f.Fingerprint,
		RuleID:      f.RuleID,
		Path:        f.Location.Path,
		Reason:      "ticket acceptance",
		Ticket:      "SEC-42",
		Expires:     expires,
	})
	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(loaded.Findings))
	}
	entry := loaded.Findings[0]
	if entry.Fingerprint != f.Fingerprint || entry.RuleID != f.RuleID ||
		entry.Path != f.Location.Path || entry.Ticket != "SEC-42" || entry.Expires != expires {
		t.Fatalf("round trip lost fields: %+v", entry)
	}
	if containsString(loaded.Fingerprints, f.Fingerprint) {
		t.Error("expiring entry leaked into the legacy fingerprint list")
	}

	// The entry still matches while the expiry is in the future.
	other := f
	other.Fingerprint = "fp_other"
	if ok, why := loaded.Match(other); !ok || why != "ticket acceptance" {
		t.Fatalf("future entry match = %v, %q", ok, why)
	}
}

func TestBaselinePathAndRuleScope(t *testing.T) {
	f := sampleFinding()

	byPath := NewBaseline()
	byPath.AddEntry(BaselineFinding{ID: f.ID, Fingerprint: f.Fingerprint, Path: "other.go"})
	if ok, _ := byPath.Match(f); ok {
		t.Fatal("entry scoped to another path suppressed the finding")
	}
	byPath.AddEntry(BaselineFinding{ID: f.ID, Fingerprint: f.Fingerprint, Path: f.Location.Path})
	if ok, _ := byPath.Match(f); !ok {
		t.Fatal("entry scoped to the finding path did not suppress")
	}

	byRule := NewBaseline()
	byRule.AddEntry(BaselineFinding{ID: f.ID, Fingerprint: f.Fingerprint, RuleID: "OTHER-RULE"})
	if ok, _ := byRule.Match(f); ok {
		t.Fatal("entry scoped to another rule suppressed the finding")
	}
	byRule.AddEntry(BaselineFinding{ID: f.ID, Fingerprint: f.Fingerprint, RuleID: f.RuleID})
	if ok, _ := byRule.Match(f); !ok {
		t.Fatal("entry scoped to the finding rule did not suppress")
	}
}

func TestBaselineExpiryBoundary(t *testing.T) {
	f := sampleFinding()
	today := BaselineToday()

	b := NewBaseline()
	b.AddEntry(BaselineFinding{
		ID:      f.ID,
		Expires: today.Format(BaselineDateLayout),
	})
	result := b.MatchFinding(f)
	if !result.Matched || result.Expired {
		t.Fatalf("entry expiring today = %+v, want an active match", result)
	}

	b = NewBaseline()
	b.AddEntry(BaselineFinding{
		ID:      f.ID,
		Expires: today.AddDate(0, 0, -1).Format(BaselineDateLayout),
	})
	result = b.MatchFinding(f)
	if result.Matched || !result.Expired {
		t.Fatalf("entry expiring yesterday = %+v, want an expired non-match", result)
	}
}

func TestBaselinePruneExpired(t *testing.T) {
	today := BaselineToday()
	f := sampleFinding()
	g := sampleFinding()
	g.Evidence = `password = "another"`
	g.ID = ""
	g.Fingerprint = ""
	g.Normalize()

	b := NewBaseline()
	b.Add(f, "expired acceptance")
	b.Add(g, "still valid")
	b.Findings[0].Expires = today.AddDate(0, 0, -1).Format(BaselineDateLayout)
	b.Findings[0].Ticket = "SEC-7"
	b.Findings[1].Expires = today.AddDate(0, 0, 30).Format(BaselineDateLayout)

	removed := b.PruneExpired(today)
	if len(removed) != 1 || removed[0].ID != f.ID {
		t.Fatalf("removed = %+v, want only %s", removed, f.ID)
	}
	if len(b.Findings) != 1 || b.Findings[0].ID != g.ID {
		t.Fatalf("remaining findings = %+v", b.Findings)
	}
	if containsString(b.Fingerprints, f.Fingerprint) {
		t.Error("prune left the expired entry's fingerprint behind")
	}
	if !containsString(b.Fingerprints, g.Fingerprint) {
		t.Error("prune removed a fingerprint that is still accepted")
	}
	if again := b.PruneExpired(today); len(again) != 0 {
		t.Fatalf("second prune = %+v, want none", again)
	}
	if ok, _ := b.Match(f); ok {
		t.Error("pruned entry still suppresses its finding")
	}

	// The future entry is pruned once its date has passed.
	later := today.AddDate(0, 0, 60)
	if removed := b.PruneExpired(later); len(removed) != 1 || removed[0].ID != g.ID {
		t.Fatalf("future prune = %+v, want only %s", removed, g.ID)
	}
}

func TestBaselinePruneIDOnlyExpired(t *testing.T) {
	today := BaselineToday()
	f := sampleFinding()

	b := NewBaseline()
	b.AddEntry(BaselineFinding{
		ID:      f.ID,
		Reason:  "expired acceptance",
		Expires: today.AddDate(0, 0, -1).Format(BaselineDateLayout),
	})
	if len(b.Findings) != 1 || b.Findings[0].Fingerprint != "" {
		t.Fatalf("setup = %+v, want one ID-only entry", b.Findings)
	}

	removed := b.PruneExpired(today)
	if len(removed) != 1 || removed[0].ID != f.ID {
		t.Fatalf("removed = %+v, want the ID-only entry", removed)
	}
	if len(b.Findings) != 0 {
		t.Fatalf("remaining findings = %+v, want none", b.Findings)
	}
}

func TestBaselineLegacyFingerprintMaterialized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	past := BaselineToday().AddDate(0, 0, -1).Format(BaselineDateLayout)
	doc := fmt.Sprintf(`{"version":2,"fingerprints":["fp_legacy"],"findings":[{"id":"VGL-OLD","reason":"expired","expires":%q}]}`, past)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(b.Findings) != 2 {
		t.Fatalf("findings = %+v, want the ID entry plus the materialized fingerprint", b.Findings)
	}
	var legacy *BaselineFinding
	for i := range b.Findings {
		if strings.EqualFold(b.Findings[i].Fingerprint, "fp_legacy") {
			legacy = &b.Findings[i]
		}
	}
	if legacy == nil {
		t.Fatal("orphaned legacy fingerprint was not materialized")
	}
	if legacy.ID != "" || legacy.Expires != "" || legacy.Reason != legacyFingerprintReason {
		t.Fatalf("materialized entry = %+v", *legacy)
	}

	// A shifted line changes the ID; the legacy fingerprint still matches, but
	// now through a visible entry rather than a hidden list channel.
	shifted := sampleFinding()
	shifted.ID = "VGL-SHIFTED"
	shifted.Fingerprint = "fp_legacy"
	result := b.MatchFinding(shifted)
	if !result.Matched || result.Reason != legacyFingerprintReason {
		t.Fatalf("shifted finding = %+v, want a legacy fingerprint match", result)
	}

	removed := b.PruneExpired(BaselineToday())
	if len(removed) != 1 || removed[0].ID != "VGL-OLD" {
		t.Fatalf("removed = %+v, want only the expired ID entry", removed)
	}
	// The materialized acceptance has no expiry, so prune keeps it, and it is
	// listed/removable instead of lingering invisibly.
	if len(b.Findings) != 1 || b.Findings[0].Fingerprint != "fp_legacy" {
		t.Fatalf("after prune findings = %+v, want the legacy fingerprint entry", b.Findings)
	}
	if ok, _ := b.Match(shifted); !ok {
		t.Fatal("prune dropped the still-accepted legacy fingerprint")
	}

	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	reloaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Findings) != 1 || reloaded.Findings[0].Reason != legacyFingerprintReason {
		t.Fatalf("round trip duplicated or lost the legacy entry: %+v", reloaded.Findings)
	}
}

func TestBaselinePruneDropsConsumedFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	today := BaselineToday()
	past := today.AddDate(0, 0, -1).Format(BaselineDateLayout)
	doc := fmt.Sprintf(`{"version":2,"fingerprints":["fp_old"],"findings":[{"id":"VGL-OLD","reason":"expired","fingerprint":"fp_old","expires":%q}]}`, past)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(b.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: a referenced fingerprint is not duplicated", len(b.Findings))
	}

	f := sampleFinding()
	f.ID = "VGL-OLD"
	f.Fingerprint = "fp_old"
	result := b.MatchFinding(f)
	if result.Matched || !result.Expired {
		t.Fatalf("expired entry = %+v, want an expired non-match", result)
	}

	removed := b.PruneExpired(today)
	if len(removed) != 1 || removed[0].ID != "VGL-OLD" {
		t.Fatalf("removed = %+v", removed)
	}
	if len(b.Findings) != 0 || len(b.Fingerprints) != 0 {
		t.Fatalf("prune left findings=%+v fingerprints=%v", b.Findings, b.Fingerprints)
	}

	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	reloaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Findings) != 0 || len(reloaded.Fingerprints) != 0 {
		t.Fatalf("reload resurrected suppression: findings=%+v fingerprints=%v", reloaded.Findings, reloaded.Fingerprints)
	}
	if ok, _ := reloaded.Match(f); ok {
		t.Error("pruned fingerprint still suppresses the finding")
	}
}

func TestBaselineFingerprintMatchingCaseInsensitive(t *testing.T) {
	f := sampleFinding()
	f.ID = "VGL-OTHER"
	f.Fingerprint = "fp_legacy"

	b := NewBaseline()
	b.AddEntry(BaselineFinding{Fingerprint: "FP_LEGACY"})
	if ok, _ := b.Match(f); !ok {
		t.Fatal("entry fingerprint matching is case-sensitive")
	}

	b = NewBaseline()
	b.Fingerprints = []string{"FP_ONE", "fp_one"}
	b.normalize()
	count := 0
	for _, entry := range b.Findings {
		if strings.EqualFold(entry.Fingerprint, "fp_one") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("case-insensitive duplicates materialized %d entries, want 1", count)
	}
}

func TestBaselineMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	b, err := LoadBaseline(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatalf("missing baseline should be a no-op: %v", err)
	}
	if !b.empty() {
		t.Fatal("missing baseline should be empty")
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(bad); err == nil {
		t.Fatal("expected parse error")
	}

	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"version":99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(future); err == nil {
		t.Fatal("expected unsupported version error")
	}

	badExpiry := filepath.Join(dir, "bad-expiry.json")
	if err := os.WriteFile(badExpiry, []byte(`{"version":2,"findings":[{"id":"VGL-X","expires":"31.12.2026"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(badExpiry); err == nil {
		t.Fatal("expected an invalid expiry error")
	}
}

func TestScanExpiredBaselineWarnsAndDoesNotSuppress(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", `var secret = "SECRET"`+"\n")

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-SECRET",
		Title:    "secret",
		Severity: model.SeverityHigh,
		Category: model.CategorySecrets,
	}, secretRule))

	s := New(reg, nil)
	full, err := s.Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("initial Scan: %v", err)
	}
	if len(full.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(full.Findings))
	}
	f := full.Findings[0]
	past := BaselineToday().AddDate(0, 0, -1).Format(BaselineDateLayout)

	b := NewBaseline()
	b.AddEntry(BaselineFinding{
		ID:          f.ID,
		Fingerprint: f.Fingerprint,
		RuleID:      f.RuleID,
		Path:        f.Location.Path,
		Reason:      "expired acceptance",
		Ticket:      "SEC-7",
		Expires:     past,
	})
	if err := SaveBaseline(filepath.Join(root, DefaultBaselineFile), b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	res, err := s.Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatalf("expired baseline Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expired entry must not suppress, got %d findings", len(res.Findings))
	}
	if len(res.Suppressed) != 0 {
		t.Fatalf("expired entry produced suppressions: %+v", res.Suppressed)
	}
	want := fmt.Sprintf("baseline entry for %s expired on %s at %s", f.ID, past, f.Location.Path)
	if len(res.Errors) != 1 || res.Errors[0] != want {
		t.Fatalf("warnings = %v, want exactly [%s]", res.Errors, want)
	}
}

func TestBaselineExpiredWarningDeduplicated(t *testing.T) {
	root := t.TempDir()
	f := sampleFinding()
	past := BaselineToday().AddDate(0, 0, -1).Format(BaselineDateLayout)

	b := NewBaseline()
	b.AddEntry(BaselineFinding{
		ID:      f.ID,
		Path:    f.Location.Path,
		Expires: past,
	})
	if err := SaveBaseline(filepath.Join(root, DefaultBaselineFile), b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	kept, suppressed, errs := applyBaseline([]model.Finding{f, f}, Options{Root: root})
	if len(kept) != 2 || len(suppressed) != 0 {
		t.Fatalf("kept/suppressed = %d/%d, want 2/0", len(kept), len(suppressed))
	}
	if len(errs) != 1 {
		t.Fatalf("warnings = %v, want exactly one deduplicated warning", errs)
	}
}

func secretRule(f *rules.File) []model.Finding {
	for i, line := range f.Lines {
		if strings.Contains(line, `"SECRET"`) {
			return []model.Finding{{
				Location: model.Location{Path: f.Path, StartLine: i + 1},
				Evidence: line,
			}}
		}
	}
	return nil
}

func TestScanAppliesBaseline(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", `var secret = "SECRET"`+"\n")

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-SECRET",
		Title:    "secret",
		Severity: model.SeverityHigh,
		Category: model.CategorySecrets,
	}, func(f *rules.File) []model.Finding {
		for i, line := range f.Lines {
			if strings.Contains(line, "SECRET") {
				return []model.Finding{{
					Location: model.Location{Path: f.Path, StartLine: i + 1},
					Evidence: line,
				}}
			}
		}
		return nil
	}))

	s := New(reg, nil)
	full, err := s.Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("initial Scan: %v", err)
	}
	if len(full.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(full.Findings))
	}

	b := NewBaseline()
	b.Add(full.Findings[0], "accepted risk")
	if err := SaveBaseline(filepath.Join(root, DefaultBaselineFile), b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	res, err := s.Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatalf("baseline Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected all findings suppressed, got %#v", res.Findings)
	}
	if len(res.Suppressed) != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", len(res.Suppressed))
	}
	if !res.Suppressed[0].Suppressed || res.Suppressed[0].SuppressWhy != "accepted risk" {
		t.Fatalf("unexpected suppression: %#v", res.Suppressed[0])
	}

	again, err := s.Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("NoBaseline Scan: %v", err)
	}
	if len(again.Findings) != 1 {
		t.Fatalf("NoBaseline should ignore the file, got %d findings", len(again.Findings))
	}
}

func TestScanCorruptBaselineFailsOpen(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", `var secret = "SECRET"`+"\n")
	writeTestFile(t, root, DefaultBaselineFile, "{not json")

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-SECRET",
		Title:    "secret",
		Severity: model.SeverityHigh,
		Category: model.CategorySecrets,
	}, func(f *rules.File) []model.Finding {
		for i, line := range f.Lines {
			if strings.Contains(line, "SECRET") {
				return []model.Finding{{
					Location: model.Location{Path: f.Path, StartLine: i + 1},
					Evidence: line,
				}}
			}
		}
		return nil
	}))

	res, err := New(reg, nil).Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("corrupt baseline must not hide findings, got %d", len(res.Findings))
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "baseline") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a baseline error, got %v", res.Errors)
	}
}
