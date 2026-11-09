package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var scanIDRE = regexp.MustCompile(`^scan_\d{8}T\d{6}_[0-9a-f]{6}$`)

func newProjectStore(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".vigil"), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st, root
}

func sampleResult(started time.Time) *model.ScanResult {
	return &model.ScanResult{
		StartedAt:  started,
		FinishedAt: started.Add(time.Second),
		Root:       "/tmp/project",
		Mode:       "standard",
		Engine:     "vigil-rules",
		Version:    "test",
		Findings: []model.Finding{
			{ID: "VGL-1", Severity: model.SeverityCritical, Location: model.Location{Path: "a.go", StartLine: 1}},
			{ID: "VGL-2", Severity: model.SeverityHigh, Location: model.Location{Path: "b.go", StartLine: 2}},
			{ID: "VGL-3", Severity: model.SeverityLow, Location: model.Location{Path: "c.go", StartLine: 3}},
		},
	}
}

func TestStoreSaveLastGetListPrune(t *testing.T) {
	st, root := newProjectStore(t)
	wantDir := filepath.Join(root, ".vigil", "scans")
	if filepath.Clean(st.Dir()) != filepath.Clean(wantDir) {
		t.Fatalf("Dir = %q, want %q", st.Dir(), wantDir)
	}

	base := time.Now().UTC().Add(-time.Hour)
	first := sampleResult(base)
	if err := st.Save(first); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !scanIDRE.MatchString(first.ID) {
		t.Fatalf("scan ID %q does not match the canonical format", first.ID)
	}

	last, err := st.Last()
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if last.ID != first.ID {
		t.Fatalf("Last ID = %q, want %q", last.ID, first.ID)
	}

	got, err := st.Get(first.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Findings) != 3 {
		t.Fatalf("Get returned %d findings", len(got.Findings))
	}

	list, err := st.List(10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d entries", len(list))
	}
	if list[0].Findings != 3 || list[0].Critical != 1 || list[0].High != 1 {
		t.Fatalf("unexpected summary: %#v", list[0])
	}

	second := sampleResult(base.Add(time.Minute))
	third := sampleResult(base.Add(2 * time.Minute))
	if err := st.Save(second); err != nil {
		t.Fatalf("Save second: %v", err)
	}
	if err := st.Save(third); err != nil {
		t.Fatalf("Save third: %v", err)
	}

	list, err = st.List(0)
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("List all returned %d entries", len(list))
	}
	if list[0].ID != third.ID || list[1].ID != second.ID || list[2].ID != first.ID {
		t.Fatalf("List is not newest-first: %#v", list)
	}

	if err := st.Prune(2); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	list, err = st.List(0)
	if err != nil {
		t.Fatalf("List after prune: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("after Prune(2) got %d entries", len(list))
	}
	last, err = st.Last()
	if err != nil {
		t.Fatalf("Last after prune: %v", err)
	}
	if last.ID != third.ID {
		t.Fatalf("Last after prune = %q, want %q", last.ID, third.ID)
	}

	entries, err := os.ReadDir(st.Dir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vigil-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}

	if err := st.Prune(0); err != nil {
		t.Fatalf("Prune(0): %v", err)
	}
	list, err = st.List(0)
	if err != nil {
		t.Fatalf("List after Prune(0): %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("Prune(0) left %d entries", len(list))
	}
	if _, err := st.Last(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Last after Prune(0) = %v, want os.ErrNotExist", err)
	}
}

func TestStoreLastFallsBackWithoutPointer(t *testing.T) {
	st, _ := newProjectStore(t)
	res := sampleResult(time.Now().UTC())
	if err := st.Save(res); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(st.Dir(), lastFile)); err != nil {
		t.Fatal(err)
	}
	last, err := st.Last()
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if last.ID != res.ID {
		t.Fatalf("Last = %q, want %q", last.ID, res.ID)
	}
}

func TestStoreRejectsInvalidIDs(t *testing.T) {
	st, _ := newProjectStore(t)
	if _, err := st.Get("../escape"); err == nil {
		t.Fatal("Get accepted a traversal ID")
	}
	if _, err := st.Get("last"); err == nil {
		t.Fatal("Get accepted a non-scan ID")
	}
	if err := st.Save(&model.ScanResult{ID: "../escape"}); err == nil {
		t.Fatal("Save accepted a traversal ID")
	}
}

func TestStoreOpenUsesGitRepoDir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}
	root := t.TempDir()
	cmd := exec.Command("git", "-C", root, "init", "-q")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git init failed: %v\n%s", err, out)
	}

	st, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := filepath.Join(root, ".vigil", "scans")
	if filepath.Clean(st.Dir()) != filepath.Clean(want) {
		t.Fatalf("Dir = %q, want %q", st.Dir(), want)
	}
}

func TestStoreOpenCacheFallback(t *testing.T) {
	root := t.TempDir()
	cache := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", root)
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LocalAppData", cache)
	case "darwin":
		t.Setenv("HOME", cache)
	default:
		t.Setenv("XDG_CACHE_HOME", cache)
	}

	st, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !strings.HasSuffix(st.Dir(), filepath.Join("vigil", "scans")) {
		t.Fatalf("unexpected cache directory: %s", st.Dir())
	}
	if strings.HasPrefix(st.Dir(), root) {
		t.Fatalf("cache fallback wrote inside the project: %s", st.Dir())
	}
}
