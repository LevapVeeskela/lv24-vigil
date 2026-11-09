// Package gitutil provides the small, read-only git operations Vigil needs:
// finding the repository root, listing changed files, producing a unified diff
// and checking whether a proposed fix applies.
package gitutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// RepoRoot returns the absolute root of the git repository containing path.
// If path is a file, its directory is used.
func RepoRoot(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("gitutil: resolve %s: %w", path, err)
	}
	abs = filepath.Clean(abs)
	if info, err := os.Stat(abs); err == nil && !info.IsDir() {
		abs = filepath.Dir(abs)
	}

	out, err := runGit(context.Background(), abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(out)
	if root == "" {
		return "", fmt.Errorf("gitutil: %s is not inside a git repository", abs)
	}
	root = filepath.Clean(filepath.FromSlash(root))
	if !filepath.IsAbs(root) {
		root = filepath.Join(abs, root)
	}
	return root, nil
}

// ChangedFiles lists tracked files that differ from baseRef (staged and
// unstaged) plus untracked files that are not ignored. Paths are relative to
// root, slash-separated and sorted.
func ChangedFiles(ctx context.Context, root, baseRef string) ([]string, error) {
	rootAbs, err := absDir(root)
	if err != nil {
		return nil, err
	}
	repo, err := RepoRoot(rootAbs)
	if err != nil {
		return nil, err
	}
	baseRef = strings.TrimSpace(baseRef)
	if baseRef == "" {
		baseRef = "HEAD"
	}
	if err := validateRef(baseRef); err != nil {
		return nil, err
	}

	tracked, err := runGit(ctx, repo, "diff", "--name-only", "-z", "--no-ext-diff", baseRef, "--")
	if err != nil && baseRef == "HEAD" {
		// A repository with staged files but no commits has no HEAD to diff
		// against; every tracked file is new in that case.
		if _, headErr := runGit(ctx, repo, "rev-parse", "--verify", "--quiet", "HEAD"); headErr != nil {
			tracked, err = runGit(ctx, repo, "ls-files", "-z")
		}
	}
	if err != nil {
		return nil, err
	}
	untracked, err := runGit(ctx, repo, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var rels []string
	for _, raw := range append(splitNul(tracked), splitNul(untracked)...) {
		if raw == "" {
			continue
		}
		abs := filepath.Join(repo, filepath.FromSlash(raw))
		rel, err := filepath.Rel(rootAbs, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		rel = filepath.ToSlash(rel)
		if _, ok := seen[rel]; ok {
			continue
		}
		seen[rel] = struct{}{}
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	return rels, nil
}

// Diff returns a unified diff of the working tree against baseRef with no
// context lines. Paths are relative to root.
func Diff(ctx context.Context, root, baseRef string) (string, error) {
	rootAbs, err := absDir(root)
	if err != nil {
		return "", err
	}
	if _, err := RepoRoot(rootAbs); err != nil {
		return "", err
	}
	baseRef = strings.TrimSpace(baseRef)
	if baseRef == "" {
		baseRef = "HEAD"
	}
	if err := validateRef(baseRef); err != nil {
		return "", err
	}
	return runGit(ctx, rootAbs, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--unified=0", "--relative", baseRef, "--")
}

// validateRef rejects a base ref that git could parse as an option or that
// contains whitespace/control characters. Without this a caller (or an agent
// reading a repository file) could pass --output=..., --ext-diff or a similar
// flag and make git write a file or run a repository-controlled diff driver.
func validateRef(ref string) error {
	if ref == "" {
		return nil
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("gitutil: refusing base ref %q: refs must not start with '-'", ref)
	}
	for _, r := range ref {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("gitutil: refusing base ref %q: refs must not contain whitespace or control characters", ref)
		}
	}
	return nil
}

// ApplyCheck verifies that diff applies cleanly to root without touching the
// working tree. It writes the patch to a temporary file and runs
// `git apply --check`.
func ApplyCheck(ctx context.Context, root, diff string) error {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	rootAbs, err := absDir(root)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "vigil-apply-*.patch")
	if err != nil {
		return fmt.Errorf("gitutil: create temporary patch: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.WriteString(diff); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gitutil: write temporary patch: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("gitutil: close temporary patch: %w", err)
	}

	_, err = runGit(ctx, rootAbs, "apply", "--check", "--unidiff-zero", "--whitespace=nowarn", tmpName)
	return err
}

func absDir(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("gitutil: resolve root %s: %w", root, err)
	}
	abs = filepath.Clean(abs)
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("gitutil: root %s: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("gitutil: root %s is not a directory", abs)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return abs, nil
}

// gitArgs builds the argv for every git invocation. core.fsmonitor is disabled
// because a hostile repository can set it to a hook path, and git executes that
// hook during ordinary diff/status work.
func gitArgs(dir string, args ...string) []string {
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	out := make([]string, 0, len(args)+6)
	out = append(out,
		"-c", "core.fsmonitor=false",
		"-c", "core.untrackedCache=false",
		"-C", dir,
	)
	return append(out, args...)
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmdArgs := gitArgs(dir, args...)
	cmd := exec.CommandContext(ctx, "git", cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			return stdout.String(), fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return stdout.String(), nil
}

func splitNul(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
