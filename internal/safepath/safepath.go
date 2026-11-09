// Package safepath validates repository-relative paths and resolves them
// inside a project root. It is the single place that decides whether a path is
// safe to read or write when the repository itself is untrusted.
//
// The rules are deliberately strict:
//   - no absolute paths, Windows drive letters, drive-relative paths or UNC
//     paths;
//   - no ".." segments and no empty result;
//   - no control characters or NUL bytes;
//   - no ".git" segment, compared case-insensitively and after trimming the
//     trailing dots/spaces that Windows ignores (".GIT", ".git.", ".git ").
//
// Resolve additionally rejects paths that leave the root through a symlink,
// junction or any other reparse point, including through an existing ancestor
// of a file that does not exist yet.
package safepath

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
)

// CleanRel validates a slash- or backslash-separated repository-relative path
// and returns its cleaned, slash-separated form.
func CleanRel(rel string) (string, error) {
	p := strings.TrimSpace(strings.ReplaceAll(rel, "\\", "/"))
	if p == "" {
		return "", errors.New("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains a NUL byte")
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return "", errors.New("path contains control characters")
		}
	}
	if strings.HasPrefix(p, "/") {
		return "", errors.New("absolute paths are not allowed")
	}
	if hasDrivePrefix(p) {
		return "", errors.New("absolute paths are not allowed")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", errors.New("path must not contain '..'")
		}
		if isGitSegment(seg) {
			return "", errors.New("refusing to write inside .git")
		}
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("path is not a file inside the app root")
	}
	for _, seg := range strings.Split(clean, "/") {
		if isGitSegment(seg) {
			return "", errors.New("refusing to write inside .git")
		}
	}
	return clean, nil
}

// hasDrivePrefix reports whether p starts with a Windows volume name such as
// "C:" or a drive-relative "C:foo" form.
func hasDrivePrefix(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isGitSegment reports whether one path segment names the .git directory.
// Windows strips trailing dots and spaces, so ".git.", ".GIT " and ".git"
// all address the same directory there; reject all of them everywhere so a
// repository behaves the same on every platform.
func isGitSegment(seg string) bool {
	return strings.EqualFold(strings.TrimRight(seg, ". "), ".git")
}

// Resolve joins rel onto root and verifies that the result stays inside root.
// Existing symlinks are resolved; for a path that does not exist yet, the
// deepest existing ancestor is checked. The returned path is the lexical
// target, not the symlink-resolved one, so callers keep the requested name.
func Resolve(root, rel string) (string, error) {
	clean, err := CleanRel(rel)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve app root: %w", err)
	}
	rootAbs = filepath.Clean(rootAbs)
	target := filepath.Join(rootAbs, filepath.FromSlash(clean))
	if !Within(rootAbs, target) {
		return "", errors.New("path escapes the app root")
	}

	realRoot := rootAbs
	if resolved, err := filepath.EvalSymlinks(rootAbs); err == nil {
		realRoot = resolved
	}
	resolved, err := resolveComponents(realRoot, clean)
	if err != nil {
		return "", err
	}
	relToRoot, err := filepath.Rel(realRoot, resolved)
	if err != nil {
		return "", errors.New("path escapes the app root")
	}
	for _, seg := range strings.Split(filepath.ToSlash(relToRoot), "/") {
		if isGitSegment(seg) {
			return "", errors.New("refusing to write inside .git")
		}
	}
	return target, nil
}

// resolveComponents walks rel one segment at a time and follows symlinks and
// Windows junctions. filepath.EvalSymlinks does not resolve NTFS junctions, so
// a hostile repository could otherwise place one inside the tree and write
// through it. It returns the fully resolved path.
func resolveComponents(realRoot, rel string) (string, error) {
	cur := realRoot
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." {
			continue
		}
		next := filepath.Join(cur, filepath.FromSlash(seg))
		resolved, err := resolveLink(next, 0)
		if err != nil {
			return "", err
		}
		if !Within(realRoot, resolved) {
			return "", errors.New("path escapes the app root through a symlink")
		}
		cur = resolved
	}
	if !Within(realRoot, cur) {
		return "", errors.New("path escapes the app root through a symlink")
	}
	return cur, nil
}

// resolveLink follows one path through symlinks/junctions, bounded to catch
// loops. A path that does not exist is returned as-is; its parent was already
// checked by resolveComponents.
func resolveLink(p string, depth int) (string, error) {
	if depth > 40 {
		return "", errors.New("path contains a symlink loop")
	}
	target, err := os.Readlink(p)
	if err != nil {
		return p, nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(p), target)
	}
	target = filepath.Clean(target)
	return resolveLink(target, depth+1)
}

// Within reports whether target is inside root. Both paths must be absolute or
// both relative; callers pass absolute paths.
func Within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
