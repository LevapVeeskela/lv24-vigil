package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Regression: scans were ordered by the startedAt value read from each stored
// file. A cloned repository that ships .vigil/scans files dated in the future
// made Save prune the scan it had just written and repoint last.json at a
// planted, empty scan, so "vigil report" and "vigil status" showed a
// fabricated clean result.
func TestSaveKeepsJustSavedScanAgainstPlantedFutureScans(t *testing.T) {
	s, _ := newProjectStore(t)
	if err := os.MkdirAll(s.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	checkout := time.Now().Add(-time.Hour)
	for i := 0; i < defaultKeep; i++ {
		id := fmt.Sprintf("scan_99991231T2359%02d_aaaa%02d", i, i)
		body := fmt.Sprintf(`{"id":%q,"startedAt":"9999-12-31T23:59:%02dZ","root":"/x","findings":[]}`, id, i)
		planted := filepath.Join(s.Dir(), id+".json")
		if err := os.WriteFile(planted, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		// The files arrive with the checkout, some time before the scan.
		if err := os.Chtimes(planted, checkout, checkout); err != nil {
			t.Fatal(err)
		}
	}

	res := &model.ScanResult{
		Root:     "real",
		Findings: []model.Finding{{RuleID: "TEST-1", Severity: model.SeverityHigh}},
	}
	if err := s.Save(res); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := s.Get(res.ID); err != nil {
		t.Fatalf("the scan that was just saved was pruned: %v", err)
	}
	last, err := s.Last()
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if last.ID != res.ID {
		t.Fatalf("last scan = %s, want the scan just saved (%s)", last.ID, res.ID)
	}
	if len(last.Findings) != 1 {
		t.Fatalf("last scan has %d findings, want the real one", len(last.Findings))
	}
	list, err := s.List(1)
	if err != nil || len(list) != 1 {
		t.Fatalf("List(1) = %v, %v", list, err)
	}
	if list[0].ID != res.ID {
		t.Fatalf("newest scan in history = %s, want %s", list[0].ID, res.ID)
	}
}
