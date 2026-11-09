package analysis

import (
	"fmt"
	"strings"
	"testing"
)

func diffWithPaths(oldPath, newPath string) string {
	return fmt.Sprintf("--- %s\n+++ %s\n@@ -1 +1 @@\n-old\n+new\n", oldPath, newPath)
}

func TestValidateDiffValid(t *testing.T) {
	root := t.TempDir()
	if err := ValidateDiff(root, validAuthDiff); err != nil {
		t.Fatalf("ValidateDiff: %v", err)
	}
}

func TestValidateDiffGitStyle(t *testing.T) {
	root := t.TempDir()
	diff := "diff --git a/auth.go b/auth.go\nindex 1234567..89abcde 100644\n" + validAuthDiff
	if err := ValidateDiff(root, diff); err != nil {
		t.Fatalf("ValidateDiff: %v", err)
	}
	extracted, err := extractDiff(diff)
	if err != nil {
		t.Fatalf("extractDiff: %v", err)
	}
	if err := ValidateDiff(root, extracted); err != nil {
		t.Fatalf("ValidateDiff extracted: %v", err)
	}
}

func TestValidateDiffRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name string
		diff string
	}{
		{"absolute", diffWithPaths("/etc/passwd", "/etc/passwd")},
		{"traversal", diffWithPaths("a/../secret.go", "b/../secret.go")},
		{"traversal nested", diffWithPaths("a/../../etc/passwd", "b/../../etc/passwd")},
		{"git dir", diffWithPaths("a/.git/config", "b/.git/config")},
		{"nested git dir", diffWithPaths("a/src/.git/config", "b/src/.git/config")},
		{"windows drive", diffWithPaths(`a/C:\Windows\win.ini`, `b/C:\Windows\win.ini`)},
		{"unc", diffWithPaths(`a/\\server\share\x`, `b/\\server\share\x`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateDiff(root, tc.diff); err == nil {
				t.Fatalf("expected %q to be rejected", tc.diff)
			}
		})
	}
}

func TestValidateDiffRejectsBinary(t *testing.T) {
	root := t.TempDir()
	diff := "--- a/x.bin\n+++ b/x.bin\nGIT binary patch\nliteral 3\n"
	if err := ValidateDiff(root, diff); err == nil {
		t.Fatal("expected a binary diff to be rejected")
	}
	if err := ValidateDiff(root, "Binary files a/x.bin and b/x.bin differ\n"); err == nil {
		t.Fatal("expected a binary file notice to be rejected")
	}
}

func TestValidateDiffRejectsBadHunkCounts(t *testing.T) {
	root := t.TempDir()
	diff := "--- a/auth.go\n+++ b/auth.go\n@@ -1,3 +1,3 @@\n-old\n+new\n"
	if err := ValidateDiff(root, diff); err == nil {
		t.Fatal("expected a hunk count mismatch to be rejected")
	}
}

func TestValidateDiffRejectsNoHunks(t *testing.T) {
	root := t.TempDir()
	if err := ValidateDiff(root, "--- a/auth.go\n+++ b/auth.go\n"); err == nil {
		t.Fatal("expected a diff without hunks to be rejected")
	}
}

func TestValidateDiffRejectsMissingHeaders(t *testing.T) {
	root := t.TempDir()
	if err := ValidateDiff(root, "@@ -1 +1 @@\n-old\n+new\n"); err == nil {
		t.Fatal("expected a hunk without file headers to be rejected")
	}
}

func TestValidateDiffRejectsEmpty(t *testing.T) {
	if err := ValidateDiff(t.TempDir(), "   \n"); err == nil {
		t.Fatal("expected an empty diff to be rejected")
	}
}

func TestValidateDiffAllowsDevNull(t *testing.T) {
	root := t.TempDir()
	diff := "--- /dev/null\n+++ b/new.go\n@@ -0,0 +1,2 @@\n+package x\n+var y = 1\n"
	if err := ValidateDiff(root, diff); err != nil {
		t.Fatalf("ValidateDiff new file: %v", err)
	}
	if files := diffFiles(diff); len(files) != 1 || files[0] != "new.go" {
		t.Fatalf("diffFiles = %v", files)
	}
}

func TestValidateDiffMultipleFilesAndQuotedPath(t *testing.T) {
	root := t.TempDir()
	diff := validAuthDiff +
		"--- \"a/space name.go\"\n+++ \"b/space name.go\"\n@@ -1 +1 @@\n-old\n+new\n"
	if err := ValidateDiff(root, diff); err != nil {
		t.Fatalf("ValidateDiff: %v", err)
	}
	files := diffFiles(diff)
	if strings.Join(files, ",") != "auth.go,space name.go" {
		t.Fatalf("diffFiles = %v", files)
	}
}

func TestExtractDiffSkipsHorizontalRule(t *testing.T) {
	text := "Here is a separator:\n--- not a header\nSome prose.\n```diff\n--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-old\n+new\n```\n"
	got, err := extractDiff(text)
	if err != nil {
		t.Fatalf("extractDiff: %v", err)
	}
	if !strings.HasPrefix(got, "--- a/x.go") {
		t.Fatalf("wrong diff extracted:\n%s", got)
	}
	if err := ValidateDiff(t.TempDir(), got); err != nil {
		t.Fatalf("ValidateDiff: %v", err)
	}
}

func TestValidateDiffAllowsNoNewlineMarker(t *testing.T) {
	root := t.TempDir()
	diff := "--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n"
	if err := ValidateDiff(root, diff); err != nil {
		t.Fatalf("ValidateDiff: %v", err)
	}
}

func TestExtractDiffNoNewlineMarker(t *testing.T) {
	text := "```diff\n--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n```\n"
	got, err := extractDiff(text)
	if err != nil {
		t.Fatalf("extractDiff: %v", err)
	}
	if !strings.Contains(got, "\\ No newline at end of file") {
		t.Fatalf("marker was dropped:\n%s", got)
	}
	if err := ValidateDiff(t.TempDir(), got); err != nil {
		t.Fatalf("ValidateDiff: %v", err)
	}
}

func TestParseHunkHeader(t *testing.T) {
	h, ok := parseHunkHeader("@@ -12,3 +14,5 @@ func main() {")
	if !ok {
		t.Fatal("header was not parsed")
	}
	if h.oldStart != 12 || h.oldCount != 3 || h.newStart != 14 || h.newCount != 5 {
		t.Fatalf("unexpected hunk: %+v", h)
	}
	h, ok = parseHunkHeader("@@ -1 +1 @@")
	if !ok || h.oldCount != 1 || h.newCount != 1 {
		t.Fatalf("single-line header: %+v, %v", h, ok)
	}
	if _, ok := parseHunkHeader("@@ nope @@"); ok {
		t.Fatal("malformed header was accepted")
	}
}
