package safepath

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func makeDirLink(t *testing.T, link, target string) error {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("symlink is not available")
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func TestCleanRelAcceptsRepositoryPaths(t *testing.T) {
	cases := map[string]string{
		"a.go":                  "a.go",
		"reports/vigil.md":      "reports/vigil.md",
		"./a/./b.txt":           "a/b.txt",
		"a//b":                  "a/b",
		"src\\windows\\path.go": "src/windows/path.go",
		"file.name:with-colon":  "file.name:with-colon",
	}
	for input, want := range cases {
		got, err := CleanRel(input)
		if err != nil {
			t.Errorf("CleanRel(%q) error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("CleanRel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCleanRelRejectsUnsafePaths(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"../escape",
		"a/../../escape",
		"a/../b",
		"/etc/passwd",
		"//server/share/file",
		`\\server\share\file`,
		"C:/Windows/win.ini",
		`C:\Windows\win.ini`,
		"C:drive-relative",
		".git/config",
		".GIT/config",
		".Git/hooks/pre-commit",
		".git./hooks/pre-commit",
		".git /hooks/pre-commit",
		"src/.GIT./config",
		"a\x00b",
		"a\nb",
		"a\rb",
	}
	for _, input := range cases {
		if got, err := CleanRel(input); err == nil {
			t.Errorf("CleanRel(%q) = %q, want an error", input, got)
		}
	}
}

func TestHasMultipleLinks(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.txt")
	if err := os.WriteFile(first, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	multi, err := HasMultipleLinks(first)
	if err != nil {
		t.Fatalf("HasMultipleLinks: %v", err)
	}
	if multi {
		t.Fatal("a fresh file reports multiple links")
	}

	second := filepath.Join(dir, "second.txt")
	if err := os.Link(first, second); err != nil {
		t.Skipf("cannot create a hardlink on this host: %v", err)
	}
	multi, err = HasMultipleLinks(first)
	if err != nil {
		t.Fatalf("HasMultipleLinks(hardlink): %v", err)
	}
	if !multi {
		t.Fatal("a hardlinked file was not detected")
	}
}

func TestResolveStaysInsideRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(root, "reports/vigil.md")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.HasPrefix(got, root) {
		t.Fatalf("Resolve = %q, want inside %q", got, root)
	}
	if _, err := Resolve(root, "../outside.md"); err == nil {
		t.Fatal("Resolve accepted a traversal path")
	}
}

func TestResolveRejectsSymlinkedEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	if err := makeDirLink(t, link, outside); err != nil {
		t.Skipf("cannot create a symlink on this host: %v", err)
	}
	if _, err := Resolve(root, "link/evil.txt"); err == nil {
		t.Fatal("Resolve accepted a path through a symlink that leaves the root")
	}
	if _, err := Resolve(root, "link"); err == nil {
		t.Fatal("Resolve accepted the escaping symlink itself")
	}
}

func TestResolveRejectsSymlinkIntoGit(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := makeDirLink(t, link, gitDir); err != nil {
		t.Skipf("cannot create a symlink on this host: %v", err)
	}
	if _, err := Resolve(root, "alias/config"); err == nil {
		t.Fatal("Resolve accepted a path through a link into .git")
	}
}

func TestResolveAllowsSymlinkInsideRoot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "real")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := makeDirLink(t, link, dir); err != nil {
		t.Skipf("cannot create a symlink on this host: %v", err)
	}
	if _, err := Resolve(root, "alias/file.txt"); err != nil {
		t.Fatalf("Resolve rejected a symlink inside the root: %v", err)
	}
}
