package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

func TestParseDiffAddedRanges(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
index 1111111..2222222 100644
--- a/main.go
+++ b/main.go
@@ -1,3 +1,4 @@
 package main
+var secret = "x"
 func main() {
 }
@@ -10,2 +11,3 @@ func other() {
 a
+b
 c
diff --git a/new.go b/new.go
new file mode 100644
--- /dev/null
+++ b/new.go
@@ -0,0 +1,2 @@
+package new
+var y int
diff --git a/old.go b/old.go
deleted file mode 100644
--- a/old.go
+++ /dev/null
@@ -1,2 +0,0 @@
-a
-b
`
	got, err := ParseDiff(diff)
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	want := map[string][]LineRange{
		"main.go": {{Start: 2, End: 2}, {Start: 12, End: 12}},
		"new.go":  {{Start: 1, End: 2}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d: %#v", len(got), len(want), got)
	}
	for path, wantRanges := range want {
		gotRanges := got[path]
		if len(gotRanges) != len(wantRanges) {
			t.Fatalf("%s: got %#v, want %#v", path, gotRanges, wantRanges)
		}
		for i := range wantRanges {
			if gotRanges[i] != wantRanges[i] {
				t.Errorf("%s range %d = %#v, want %#v", path, i, gotRanges[i], wantRanges[i])
			}
		}
	}
	if _, ok := got["old.go"]; ok {
		t.Error("deleted file should not appear in added ranges")
	}
}

func TestParseDiffPlainUnified(t *testing.T) {
	diff := `--- a/main.go
+++ b/main.go
@@ -1 +1,2 @@
 package main
+var x int
`
	got, err := ParseDiff(diff)
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	ranges := got["main.go"]
	if len(ranges) != 1 || ranges[0] != (LineRange{Start: 2, End: 2}) {
		t.Fatalf("unexpected ranges: %#v", ranges)
	}
}

func TestParseDiffKeepsLeadingDirectoryNamedA(t *testing.T) {
	diff := `--- a/a/foo.go
+++ b/a/foo.go
@@ -0,0 +1 @@
+x
`
	got, err := ParseDiff(diff)
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	if _, ok := got["a/foo.go"]; !ok {
		t.Fatalf("expected path a/foo.go, got %#v", got)
	}
	if _, ok := got["foo.go"]; ok {
		t.Fatal("the a/ prefix was stripped twice")
	}
}

func TestParseDiffCoalescesConsecutiveLines(t *testing.T) {
	diff := `diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -0,0 +1,4 @@
+a
+b
+c
+d
`
	got, err := ParseDiff(diff)
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	ranges := got["a.go"]
	if len(ranges) != 1 || ranges[0] != (LineRange{Start: 1, End: 4}) {
		t.Fatalf("unexpected ranges: %#v", ranges)
	}
}

func TestParseDiffMalformedHunk(t *testing.T) {
	if _, err := ParseDiff("@@ this is not a hunk @@\n"); err == nil {
		t.Fatal("expected an error for a malformed hunk header")
	}
}

func TestScanDiffOnlyAddedLines(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", strings.Join([]string{
		"package main",
		"",
		"var safe = 1",
		`var leak = "secret"`,
		`var added = "SECRET"`,
		"",
	}, "\n"))

	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -4,0 +5,1 @@
+var added = "SECRET"
`
	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-SECRET",
		Title:    "secret",
		Severity: model.SeverityHigh,
		Category: model.CategorySecrets,
	}, func(f *rules.File) []model.Finding {
		var out []model.Finding
		for i, line := range f.Lines {
			if strings.Contains(line, "SECRET") {
				out = append(out, model.Finding{
					Location: model.Location{Path: f.Path, StartLine: i + 1},
					Evidence: line,
				})
			}
		}
		return out
	}))

	s := New(reg, nil)
	res, err := s.Scan(context.Background(), Options{Root: root, Diff: diff, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].Location.StartLine; got != 5 {
		t.Fatalf("finding line = %d, want 5", got)
	}
	if res.Stats.FilesScanned != 1 {
		t.Fatalf("files scanned = %d, want 1", res.Stats.FilesScanned)
	}
}

func TestScanDiffMalformedReturnsError(t *testing.T) {
	root := t.TempDir()
	s := New(rules.NewRegistry(), nil)
	if _, err := s.Scan(context.Background(), Options{Root: root, Diff: "@@ bad @@\n"}); err == nil {
		t.Fatal("expected an error for a malformed diff")
	}
}

func TestScanDiffSkipsHardSkippedDirs(t *testing.T) {
	root := t.TempDir()
	diff := `--- a/node_modules/x.js
+++ b/node_modules/x.js
@@ -0,0 +1 @@
+var SECRET = 1
`
	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))
	res, err := New(reg, nil).Scan(context.Background(), Options{Root: root, Diff: diff, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected node_modules to be skipped, got %#v", res.Findings)
	}
	if res.Stats.FilesSkipped != 1 {
		t.Fatalf("files skipped = %d, want 1", res.Stats.FilesSkipped)
	}
}

func TestScanDiffUsesPatchContent(t *testing.T) {
	root := t.TempDir()
	// The added line is intentionally absent from the working tree: the
	// scanner must use the patch text, not re-read the file.
	writeTestFile(t, root, "main.go", "package main\n\nvar safe = 1\n")

	diff := `--- a/main.go
+++ b/main.go
@@ -3,0 +4,1 @@
+var added = "SECRET"
`
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

	res, err := New(reg, nil).Scan(context.Background(), Options{Root: root, Diff: diff, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from patch content, got %d", len(res.Findings))
	}
	if res.Findings[0].Location.StartLine != 4 {
		t.Fatalf("finding line = %d, want 4", res.Findings[0].Location.StartLine)
	}
}
