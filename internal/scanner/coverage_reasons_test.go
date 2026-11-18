package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// assertReasonSum checks the invariant that FilesSkipped is exactly the sum of
// SkippedReasons, so the map never under- or over-reports the count.
func assertReasonSum(t *testing.T, wantKeys map[string]int, skipped int, reasons map[string]int) {
	t.Helper()
	for key, want := range wantKeys {
		if got := reasons[key]; got != want {
			t.Errorf("reason %q = %d, want %d (all reasons: %v)", key, got, want, reasons)
		}
	}
	sum := 0
	for _, count := range reasons {
		sum += count
	}
	if sum != skipped {
		t.Errorf("sum(reasons) = %d, filesSkipped = %d (reasons: %v)", sum, skipped, reasons)
	}
	if len(reasons) != len(wantKeys) {
		t.Errorf("reasons = %v, want exactly %d keys", reasons, len(wantKeys))
	}
}

func TestScanSkippedReasonsFromWalk(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", "package main\n")
	writeTestFile(t, root, "app.min.js", "var x = 1\n")
	writeTestFile(t, root, "blob.dat", "abc\x00def")
	writeTestFile(t, root, "big.txt", strings.Repeat("a", 2048))
	// A pruned directory is not a skipped file.
	writeTestFile(t, root, "node_modules/pkg/index.js", "x\n")

	res, err := New(rules.NewRegistry(), nil).Scan(context.Background(), Options{
		Root:         root,
		MaxFileBytes: 1024,
		NoBaseline:   true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Stats.FilesScanned != 1 {
		t.Fatalf("files scanned = %d, want 1", res.Stats.FilesScanned)
	}
	if res.Stats.FilesSkipped != 3 {
		t.Fatalf("files skipped = %d, want 3 (reasons: %v)", res.Stats.FilesSkipped, res.Stats.SkippedReasons)
	}
	assertReasonSum(t, map[string]int{
		skipReasonIgnored:  1,
		skipReasonBinary:   1,
		skipReasonTooLarge: 1,
	}, res.Stats.FilesSkipped, res.Stats.SkippedReasons)
}

func TestScanNoSkipsHasNoReasonMap(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", "package main\n")

	res, err := New(rules.NewRegistry(), nil).Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Stats.FilesSkipped != 0 {
		t.Fatalf("files skipped = %d, want 0", res.Stats.FilesSkipped)
	}
	if res.Stats.SkippedReasons != nil {
		t.Fatalf("skipped reasons = %v, want nil", res.Stats.SkippedReasons)
	}
}

func TestScanPathsSkippedReasons(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "bin.go", "SECRET\x00\n")
	outside := filepath.Join(filepath.Dir(root), "outside-vigil-reasons.go")
	writeTestFile(t, filepath.Dir(root), "outside-vigil-reasons.go", "SECRET\n")
	defer func() { _ = os.Remove(outside) }()

	res, err := New(rules.NewRegistry(), nil).ScanPaths(context.Background(), root,
		[]string{"bin.go", "bin.go", "missing.go", "../outside-vigil-reasons.go"},
		Options{NoBaseline: true})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if res.Stats.FilesSkipped != 4 {
		t.Fatalf("files skipped = %d, want 4 (reasons: %v)", res.Stats.FilesSkipped, res.Stats.SkippedReasons)
	}
	assertReasonSum(t, map[string]int{
		skipReasonBinary:      1,
		skipReasonDuplicate:   1,
		skipReasonMissing:     1,
		skipReasonOutsideRoot: 1,
	}, res.Stats.FilesSkipped, res.Stats.SkippedReasons)
}

func TestScanDiffSkippedReasons(t *testing.T) {
	root := t.TempDir()
	diff := `--- /dev/null
+++ b/node_modules/x.js
@@ -0,0 +1 @@
+var SECRET = 1
`
	res, err := New(rules.NewRegistry(), nil).Scan(context.Background(), Options{
		Root:       root,
		Diff:       diff,
		NoBaseline: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Stats.FilesSkipped != 1 {
		t.Fatalf("files skipped = %d, want 1", res.Stats.FilesSkipped)
	}
	assertReasonSum(t, map[string]int{skipReasonIgnored: 1}, res.Stats.FilesSkipped, res.Stats.SkippedReasons)
}

func TestScanFilesSkippedReasons(t *testing.T) {
	file := &rules.File{Path: "same.go", Content: []byte("package same\n")}
	res, err := New(rules.NewRegistry(), nil).ScanFiles(context.Background(), []*rules.File{nil, file, file}, Options{NoBaseline: true})
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if res.Stats.FilesScanned != 1 || res.Stats.FilesSkipped != 2 {
		t.Fatalf("stats = %d scanned, %d skipped, want 1/2", res.Stats.FilesScanned, res.Stats.FilesSkipped)
	}
	assertReasonSum(t, map[string]int{
		skipReasonMissing:   1,
		skipReasonDuplicate: 1,
	}, res.Stats.FilesSkipped, res.Stats.SkippedReasons)
}

func TestFilterChangedPathsCountsSkippedFiles(t *testing.T) {
	kept, skipped, reasons := filterChangedPaths(
		[]string{"src/a.go", "node_modules/x.js", "generated/y.go"},
		Options{Exclude: []string{"generated/**"}},
	)
	if len(kept) != 1 || kept[0] != "src/a.go" {
		t.Fatalf("kept = %v, want [src/a.go]", kept)
	}
	if skipped != 2 || reasons[skipReasonToolState] != 1 || reasons[skipReasonIgnored] != 1 {
		t.Fatalf("skipped=%d reasons=%v, want tool_state=1 ignored=1", skipped, reasons)
	}

	kept, skipped, reasons = filterChangedPaths(
		[]string{"src/a.go", "docs/z.md"},
		Options{Include: []string{"src/**"}},
	)
	if len(kept) != 1 || kept[0] != "src/a.go" || skipped != 1 || reasons[skipReasonNotIncluded] != 1 {
		t.Fatalf("include filter: kept=%v skipped=%d reasons=%v", kept, skipped, reasons)
	}
}
