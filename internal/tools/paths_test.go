package tools

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

func TestCleanRelPathRejectsAdversarialPaths(t *testing.T) {
	cases := []string{
		"",
		"../escape.md",
		"reports/../../escape.md",
		"/etc/passwd",
		`C:\Windows\win.ini`,
		"C:drive-relative.md",
		`\\server\share\report.md`,
		"//server/share/report.md",
		".git/config",
		".GIT/hooks/pre-commit",
		".Git/hooks/pre-commit",
		".git./hooks/pre-commit",
		".git /hooks/pre-commit",
		"reports/.GIT./config",
		"a\x00b",
		"a\nb",
	}
	for _, input := range cases {
		if got, err := cleanRelPath(input); err == nil {
			t.Errorf("cleanRelPath(%q) = %q, want an error", input, got)
		}
	}
}

func TestCleanRelPathAcceptsSafePaths(t *testing.T) {
	for _, input := range []string{"reports/vigil.md", "./reports/vigil.md", `reports\vigil.md`} {
		got, err := cleanRelPath(input)
		if err != nil {
			t.Errorf("cleanRelPath(%q): %v", input, err)
			continue
		}
		if got != "reports/vigil.md" {
			t.Errorf("cleanRelPath(%q) = %q", input, got)
		}
	}
}

func TestCleanRelPathDoesNotDecodePercentEscapes(t *testing.T) {
	// There is no URL decoding: %2e%2e is a literal file name, not "..".
	got, err := cleanRelPath("report%2e%2e/escape.md")
	if err != nil {
		t.Fatalf("cleanRelPath: %v", err)
	}
	if got != "report%2e%2e/escape.md" {
		t.Fatalf("cleanRelPath = %q, want the literal path", got)
	}
}

func TestResolveInsideRootRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	if err := makeDirLink(t, link, outside); err != nil {
		t.Skipf("cannot create a symlink on this host: %v", err)
	}
	if got, err := resolveInsideRoot(root, "link/report.md"); err == nil {
		t.Fatalf("resolveInsideRoot accepted %q", got)
	}
	if got, err := resolveInsideRoot(root, "link"); err == nil {
		t.Fatalf("resolveInsideRoot accepted the symlink itself: %q", got)
	}
}

func TestWriteFileAtomicDoesNotFollowHardlink(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(t.TempDir(), "report.md")
	if err := os.Link(outside, inside); err != nil {
		t.Skipf("cannot create a hardlink on this host: %v", err)
	}
	if err := writeFileAtomic(inside, []byte("new report"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("outside hardlink target was modified: %q", data)
	}
	data, err = os.ReadFile(inside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new report" {
		t.Fatalf("report was not written: %q", data)
	}
}

func TestResolveInsideRootAcceptsNestedPath(t *testing.T) {
	root := t.TempDir()
	got, err := resolveInsideRoot(root, "reports/vigil.md")
	if err != nil {
		t.Fatalf("resolveInsideRoot: %v", err)
	}
	if !strings.HasPrefix(got, root) {
		t.Fatalf("resolved path %q is outside %q", got, root)
	}
}
