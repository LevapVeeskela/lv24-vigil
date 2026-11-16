//go:build windows

package safepath

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// shortNameForTest returns the 8.3 alias of an existing path, or "" when the
// volume does not generate short names.
func shortNameForTest(t *testing.T, p string) string {
	t.Helper()
	in, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		t.Fatalf("encode path: %v", err)
	}
	buf := make([]uint16, 1024)
	n, err := syscall.GetShortPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return ""
	}
	short := filepath.Base(syscall.UTF16ToString(buf[:n]))
	if strings.EqualFold(short, filepath.Base(p)) {
		return ""
	}
	return short
}

// Regression: the .git check compared path text only. Windows also addresses
// the directory by its 8.3 alias (GIT~1), so "GIT~1/hooks/pre-commit" passed
// Resolve and a report or baseline write landed in .git/hooks.
func TestResolveRejectsGitShortName(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	short := shortNameForTest(t, filepath.Join(root, ".git"))
	if short == "" {
		t.Skip("this volume does not generate 8.3 short names")
	}
	for _, rel := range []string{
		short + "/hooks/pre-commit",
		short + "/config",
		strings.ToLower(short) + "/hooks/new/dir/hook",
	} {
		if _, err := Resolve(root, rel); err == nil {
			t.Errorf("Resolve(%q) succeeded, want a .git refusal", rel)
		}
	}
	// A directory that merely looks like a short name is not .git.
	if err := os.MkdirAll(filepath.Join(root, "reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(root, "reports/out.md"); err != nil {
		t.Errorf("Resolve(reports/out.md) = %v, want success", err)
	}
}

// A colon after the drive prefix addresses an NTFS alternate data stream.
// ".git::$INDEX_ALLOCATION" is the .git directory itself, and "file:stream"
// writes a stream no reviewer sees.
func TestCleanRelRejectsAlternateDataStreams(t *testing.T) {
	for _, rel := range []string{
		".git::$INDEX_ALLOCATION/hooks/pre-commit",
		"src/app.py:hidden",
		"report.md::$DATA",
	} {
		if _, err := CleanRel(rel); err == nil {
			t.Errorf("CleanRel(%q) succeeded, want a refusal", rel)
		}
	}
}
