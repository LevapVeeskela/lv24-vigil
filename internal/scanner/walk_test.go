package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

func writeTestFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func filePaths(files []*rules.File) map[string]*rules.File {
	out := make(map[string]*rules.File, len(files))
	for _, f := range files {
		out[f.Path] = f
	}
	return out
}

func TestEffectiveMaxFileBytesCapsHostileConfig(t *testing.T) {
	if got := effectiveMaxFileBytes(1 << 40); got != MaxAllowedFileBytes {
		t.Fatalf("effectiveMaxFileBytes(1 TiB) = %d, want %d", got, MaxAllowedFileBytes)
	}
	if got := effectiveMaxFileBytes(0); got != DefaultMaxFileBytes {
		t.Fatalf("effectiveMaxFileBytes(0) = %d, want %d", got, DefaultMaxFileBytes)
	}
	if got := effectiveMaxFileBytes(1024); got != 1024 {
		t.Fatalf("effectiveMaxFileBytes(1024) = %d", got)
	}
}

func TestLoadFileSkipsHardlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Link(outside, link); err != nil {
		t.Skipf("cannot create a hardlink on this host: %v", err)
	}
	if _, err := loadFile(link, "link.txt", 1<<20, false); !errors.Is(err, errSkipHardlink) {
		t.Fatalf("loadFile(hardlink) = %v, want errSkipHardlink", err)
	}
}

func TestWalkFilesSkipsIgnoredBinaryAndLarge(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", "package main\n")
	writeTestFile(t, root, "src/app.py", "print('x')\n")
	writeTestFile(t, root, "node_modules/pkg/index.js", "x\n")
	writeTestFile(t, root, "vendor/v.go", "package v\n")
	writeTestFile(t, root, ".git/config", "x\n")
	writeTestFile(t, root, "dist/bundle.js", "x\n")
	writeTestFile(t, root, "bin.dat", "abc\x00def")
	writeTestFile(t, root, "big.txt", strings.Repeat("a", 2048))

	res, err := walkFiles(context.Background(), root, Options{MaxFileBytes: 1024})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	paths := filePaths(res.files)

	if _, ok := paths["main.go"]; !ok {
		t.Fatal("main.go was not scanned")
	}
	if _, ok := paths["src/app.py"]; !ok {
		t.Fatal("src/app.py was not scanned")
	}
	for _, skipped := range []string{
		"node_modules/pkg/index.js", "vendor/v.go", ".git/config",
		"dist/bundle.js", "bin.dat", "big.txt",
	} {
		if _, ok := paths[skipped]; ok {
			t.Errorf("%s should have been skipped", skipped)
		}
	}
	if res.skipped == 0 {
		t.Fatal("expected skipped files to be counted")
	}
	if got := paths["main.go"].Language; got != LanguageGo {
		t.Errorf("main.go language = %q, want go", got)
	}
}

func TestWalkFilesIncludeAllowlist(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", "package main\n")
	writeTestFile(t, root, "src/app.py", "print('x')\n")
	writeTestFile(t, root, "src/lib/util.py", "print('y')\n")
	writeTestFile(t, root, "README.md", "# docs\n")

	res, err := walkFiles(context.Background(), root, Options{Include: []string{"**/*.py"}})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	if len(res.files) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(res.files), res.files)
	}
	for _, f := range res.files {
		if f.Language != LanguagePython {
			t.Errorf("unexpected file %s (%s)", f.Path, f.Language)
		}
	}
}

func TestWalkFilesCustomExclude(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", "package main\n")
	writeTestFile(t, root, "src/app.go", "package app\n")

	res, err := walkFiles(context.Background(), root, Options{Exclude: []string{"src/**"}})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	if len(res.files) != 1 || res.files[0].Path != "main.go" {
		t.Fatalf("expected only main.go, got %v", filePaths(res.files))
	}
}

func TestWalkFilesCRLFAndLines(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "crlf.go", "first\r\nsecond\r\n")

	res, err := walkFiles(context.Background(), root, Options{})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	f := filePaths(res.files)["crlf.go"]
	if f == nil {
		t.Fatal("crlf.go not scanned")
	}
	if len(f.Lines) < 2 || f.Lines[0] != "first" || f.Lines[1] != "second" {
		t.Fatalf("unexpected lines: %#v", f.Lines)
	}
}

func TestWalkFilesSymlinkPolicy(t *testing.T) {
	root := t.TempDir()
	target := writeTestFile(t, root, "real.go", "package real\n")
	link := filepath.Join(root, "link.go")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	res, err := walkFiles(context.Background(), root, Options{})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	if _, ok := filePaths(res.files)["link.go"]; ok {
		t.Fatal("symlink should be skipped when FollowLinks is false")
	}

	res, err = walkFiles(context.Background(), root, Options{FollowLinks: true})
	if err != nil {
		t.Fatalf("walkFiles follow: %v", err)
	}
	if _, ok := filePaths(res.files)["link.go"]; !ok {
		t.Fatal("symlink should be scanned when FollowLinks is true")
	}
}

func TestWalkSkipsGitFileEntry(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, ".git", "gitdir: ../worktrees/example\n")
	writeTestFile(t, root, "main.go", "package main\n")

	res, err := walkFiles(context.Background(), root, Options{})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	paths := filePaths(res.files)
	if _, ok := paths[".git"]; ok {
		t.Fatal(".git file entry should be skipped")
	}
	if _, ok := paths["main.go"]; !ok {
		t.Fatal("main.go was not scanned")
	}
}

func TestWalkFilesFollowsSymlinkDir(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "realdir/inside.go", "package inside\n")
	link := filepath.Join(root, "linkdir")
	if err := os.Symlink(filepath.Join(root, "realdir"), link); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	res, err := walkFiles(context.Background(), root, Options{})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	paths := filePaths(res.files)
	if _, ok := paths["linkdir/inside.go"]; ok {
		t.Fatal("symlink directory should be skipped when FollowLinks is false")
	}
	if _, ok := paths["realdir/inside.go"]; !ok {
		t.Fatal("real directory was not scanned")
	}

	res, err = walkFiles(context.Background(), root, Options{FollowLinks: true})
	if err != nil {
		t.Fatalf("walkFiles follow: %v", err)
	}
	paths = filePaths(res.files)
	_, viaLink := paths["linkdir/inside.go"]
	_, viaReal := paths["realdir/inside.go"]
	if !viaLink && !viaReal {
		t.Fatal("followed directory symlink did not expose its contents")
	}
	if viaLink && viaReal {
		t.Fatal("directory symlink caused a duplicate scan")
	}
}

func TestWalkFilesSymlinkCycle(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a/file.go", "package a\n")
	loop := filepath.Join(root, "a", "loop")
	if err := os.Symlink(root, loop); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	res, err := walkFiles(context.Background(), root, Options{FollowLinks: true})
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	if _, ok := filePaths(res.files)["a/file.go"]; !ok {
		t.Fatal("file was not scanned")
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("plain text")) {
		t.Fatal("text detected as binary")
	}
	if !isBinary([]byte("abc\x00def")) {
		t.Fatal("NUL byte not detected as binary")
	}
	// A NUL after the sniff window is not enough to classify the file.
	data := append([]byte(strings.Repeat("a", binarySniffBytes)), 0)
	if isBinary(data) {
		t.Fatal("NUL outside the sniff window should be ignored")
	}
}
