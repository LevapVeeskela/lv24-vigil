package gitutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Vigil Test",
		"GIT_AUTHOR_EMAIL=vigil@example.test",
		"GIT_COMMITTER_NAME=Vigil Test",
		"GIT_COMMITTER_EMAIL=vigil@example.test",
		"GIT_CONFIG_NOSYSTEM=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	gitRun(t, dir, "config", "core.autocrlf", "false")
	gitRun(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func samePath(t *testing.T, a, b string) bool {
	t.Helper()
	aa, err := filepath.EvalSymlinks(a)
	if err != nil {
		aa = a
	}
	bb, err := filepath.EvalSymlinks(b)
	if err != nil {
		bb = b
	}
	aa = filepath.Clean(aa)
	bb = filepath.Clean(bb)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(aa, bb)
	}
	return aa == bb
}

func TestRepoRootAndChangedFiles(t *testing.T) {
	requireGit(t)
	dir := initRepo(t)
	writeFile(t, dir, "a.go", "package a\n")
	writeFile(t, dir, "sub/b.go", "package b\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "initial")

	root, err := RepoRoot(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatalf("RepoRoot(sub): %v", err)
	}
	if !samePath(t, root, dir) {
		t.Fatalf("RepoRoot = %q, want %q", root, dir)
	}
	rootFromFile, err := RepoRoot(filepath.Join(dir, "a.go"))
	if err != nil {
		t.Fatalf("RepoRoot(file): %v", err)
	}
	if !samePath(t, rootFromFile, dir) {
		t.Fatalf("RepoRoot(file) = %q, want %q", rootFromFile, dir)
	}

	writeFile(t, dir, "a.go", "package a\n// changed\n")
	writeFile(t, dir, "sub/b.go", "package b\n// staged\n")
	gitRun(t, dir, "add", "sub/b.go")
	writeFile(t, dir, "c.go", "package c\n")
	writeFile(t, dir, "sub/d.go", "package d\n")

	changed, err := ChangedFiles(context.Background(), dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles(root): %v", err)
	}
	want := []string{"a.go", "c.go", "sub/b.go", "sub/d.go"}
	if strings.Join(changed, ",") != strings.Join(want, ",") {
		t.Fatalf("ChangedFiles(root) = %v, want %v", changed, want)
	}

	changedSub, err := ChangedFiles(context.Background(), filepath.Join(dir, "sub"), "HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles(sub): %v", err)
	}
	wantSub := []string{"b.go", "d.go"}
	if strings.Join(changedSub, ",") != strings.Join(wantSub, ",") {
		t.Fatalf("ChangedFiles(sub) = %v, want %v", changedSub, wantSub)
	}
}

func TestDiffAndApplyCheck(t *testing.T) {
	requireGit(t)
	dir := initRepo(t)
	writeFile(t, dir, "a.go", "package a\n")
	writeFile(t, dir, "sub/b.go", "package b\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "initial")

	writeFile(t, dir, "a.go", "package a\n// changed\n")
	diff, err := Diff(context.Background(), dir, "HEAD")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !strings.Contains(diff, "+// changed") {
		t.Fatalf("diff does not contain the change:\n%s", diff)
	}

	writeFile(t, dir, "sub/b.go", "package b\n// sub changed\n")
	subDiff, err := Diff(context.Background(), filepath.Join(dir, "sub"), "HEAD")
	if err != nil {
		t.Fatalf("Diff(sub): %v", err)
	}
	if !strings.Contains(subDiff, "b.go") {
		t.Fatalf("sub diff does not mention b.go:\n%s", subDiff)
	}
	if strings.Contains(subDiff, "a.go") {
		t.Fatalf("sub diff leaked a path outside the scan root:\n%s", subDiff)
	}

	// Restore the tree, then verify the patch applies cleanly without being
	// applied.
	gitRun(t, dir, "reset", "--hard", "-q", "HEAD")
	before, err := os.ReadFile(filepath.Join(dir, "a.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyCheck(context.Background(), dir, diff); err != nil {
		t.Fatalf("ApplyCheck(valid): %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "a.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("ApplyCheck modified the working tree")
	}

	if err := ApplyCheck(context.Background(), dir, "this is not a patch\n"); err == nil {
		t.Fatal("expected ApplyCheck to reject an invalid patch")
	}
	if err := ApplyCheck(context.Background(), dir, "  \n"); err != nil {
		t.Fatalf("empty diff should be a no-op: %v", err)
	}
}

func TestChangedFilesWithoutCommits(t *testing.T) {
	requireGit(t)
	dir := initRepo(t)
	writeFile(t, dir, "staged.go", "package staged\n")
	writeFile(t, dir, "untracked.go", "package untracked\n")
	gitRun(t, dir, "add", "staged.go")

	changed, err := ChangedFiles(context.Background(), dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	want := []string{"staged.go", "untracked.go"}
	if strings.Join(changed, ",") != strings.Join(want, ",") {
		t.Fatalf("ChangedFiles = %v, want %v", changed, want)
	}
}

func TestChangedFilesIncludesDeletion(t *testing.T) {
	requireGit(t)
	dir := initRepo(t)
	writeFile(t, dir, "gone.go", "package gone\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "initial")
	if err := os.Remove(filepath.Join(dir, "gone.go")); err != nil {
		t.Fatal(err)
	}

	changed, err := ChangedFiles(context.Background(), dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(changed) != 1 || changed[0] != "gone.go" {
		t.Fatalf("ChangedFiles = %v, want [gone.go]", changed)
	}
}

func TestRepoRootOutsideRepo(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", dir)
	if _, err := RepoRoot(dir); err == nil {
		t.Fatal("expected an error outside a git repository")
	}
}
