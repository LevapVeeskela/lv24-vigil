package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
)

// DefaultMaxFileBytes is the size limit applied when Options.MaxFileBytes is
// unset. Larger files are skipped: a security scanner should not read a
// multi-gigabyte blob into memory by accident.
const DefaultMaxFileBytes int64 = 2 << 20

// MaxAllowedFileBytes caps a configured per-file limit. A hostile project
// config must not be able to raise the limit to a multi-gigabyte value and
// exhaust memory during a scan.
const MaxAllowedFileBytes int64 = 64 << 20

const binarySniffBytes = 8 << 10

var hardSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".next":        true,
	".nuxt":        true,
	"coverage":     true,
	".idea":        true,
	".vscode":      true,
	".vigil":       true,
}

var (
	errSkipBinary   = errors.New("binary file")
	errSkipTooLarge = errors.New("file exceeds size limit")
	errSkipSpecial  = errors.New("not a regular file")
	errSkipSymlink  = errors.New("symlink")
	errSkipHardlink = errors.New("hardlinked file")
)

type walkResult struct {
	files   []*rules.File
	skipped int
	errs    []string
}

// walkFiles walks root and returns the text files that pass the ignore rules,
// size limit and binary sniff. Symbolic links are skipped unless FollowLinks
// is set; followed directory links are cycle-checked by resolved path.
func walkFiles(ctx context.Context, root string, opts Options) (*walkResult, error) {
	maxBytes := effectiveMaxFileBytes(opts.MaxFileBytes)
	excludes := append(defaultExcludePatterns(), opts.Exclude...)
	matcher := newIgnoreMatcher(excludes, opts.Include)

	res := &walkResult{}
	visited := make(map[string]bool)

	var walkTree func(absDir, relDir string) error
	walkTree = func(absDir, relDir string) error {
		if opts.FollowLinks {
			realDir := absDir
			if resolved, err := filepath.EvalSymlinks(absDir); err == nil {
				realDir = resolved
			}
			if visited[realDir] {
				return nil
			}
			visited[realDir] = true
		}

		return filepath.WalkDir(absDir, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if p == absDir {
					return walkErr
				}
				res.skipped++
				res.errs = append(res.errs, fmt.Sprintf("walk %s: %v", p, walkErr))
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}

			relPart, err := filepath.Rel(absDir, p)
			if err != nil {
				res.skipped++
				res.errs = append(res.errs, fmt.Sprintf("relative path for %s: %v", p, err))
				return nil
			}
			rel := relDir
			if relPart != "." {
				if rel == "" {
					rel = filepath.ToSlash(relPart)
				} else {
					rel = filepath.ToSlash(filepath.Join(relDir, relPart))
				}
			}

			// The root of a walkTree is either the scan root or a followed
			// directory link that was already checked by its parent.
			if d.IsDir() && relPart == "." {
				return nil
			}

			lowerName := strings.ToLower(d.Name())
			if hardSkipDirs[lowerName] {
				if d.IsDir() {
					return filepath.SkipDir
				}
				// .git is a file in worktrees; .vigil is tool state. Other
				// names are directory conventions, so a same-named file is
				// still worth scanning.
				if lowerName == ".git" || lowerName == ".vigil" {
					res.skipped++
					return nil
				}
			}

			if d.IsDir() {
				if opts.FollowLinks {
					realPath := p
					if resolved, err := filepath.EvalSymlinks(p); err == nil {
						realPath = resolved
					}
					if visited[realPath] {
						return filepath.SkipDir
					}
					visited[realPath] = true
				}
				if matcher.ignored(rel, true) {
					return filepath.SkipDir
				}
				return nil
			}

			if d.Type()&os.ModeSymlink != 0 {
				if !opts.FollowLinks {
					res.skipped++
					return nil
				}
				info, err := os.Stat(p)
				if err != nil {
					res.skipped++
					res.errs = append(res.errs, fmt.Sprintf("stat %s: %v", rel, err))
					return nil
				}
				if info.IsDir() {
					if hardSkipDirs[lowerName] {
						res.skipped++
						return nil
					}
					if matcher.ignored(rel, true) {
						return nil
					}
					target, err := filepath.EvalSymlinks(p)
					if err != nil {
						res.skipped++
						res.errs = append(res.errs, fmt.Sprintf("resolve symlink %s: %v", rel, err))
						return nil
					}
					if err := walkTree(target, rel); err != nil {
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							return err
						}
						res.errs = append(res.errs, fmt.Sprintf("walk %s: %v", rel, err))
					}
					return nil
				}
				// A symlink to a regular file falls through; loadFile follows
				// it when FollowLinks is set.
			}

			if matcher.ignored(rel, false) {
				res.skipped++
				return nil
			}
			if !matcher.included(rel) {
				res.skipped++
				return nil
			}

			f, err := loadFile(p, rel, maxBytes, opts.FollowLinks)
			if err != nil {
				res.skipped++
				if !isSkipError(err) {
					res.errs = append(res.errs, fmt.Sprintf("read %s: %v", rel, err))
				}
				return nil
			}
			res.files = append(res.files, f)
			return nil
		})
	}

	if err := walkTree(root, ""); err != nil {
		return nil, err
	}
	return res, nil
}

// loadFile reads one file and converts it into a rules.File. Skip conditions
// are reported as sentinel errors so callers can count them separately from
// real I/O failures.
func loadFile(absPath, relPath string, maxBytes int64, followLinks bool) (*rules.File, error) {
	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if !followLinks {
			return nil, errSkipSymlink
		}
		info, err = os.Stat(absPath)
		if err != nil {
			return nil, err
		}
	}
	if !info.Mode().IsRegular() {
		return nil, errSkipSpecial
	}
	// A hardlink can point at a file outside the repository; reading it would
	// leak that file into findings or a model prompt, and writing it would
	// modify it. Git does not track hardlinks, so this is safe to reject.
	multi, linkErr := safepath.HasMultipleLinks(absPath)
	if linkErr != nil {
		return nil, fmt.Errorf("check links for %s: %w", relPath, linkErr)
	}
	if multi {
		return nil, errSkipHardlink
	}
	if info.Size() > maxBytes {
		return nil, errSkipTooLarge
	}

	fh, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	data, err := io.ReadAll(io.LimitReader(fh, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errSkipTooLarge
	}
	if isBinary(data) {
		return nil, errSkipBinary
	}

	return &rules.File{
		Path:     relPath,
		AbsPath:  absPath,
		Content:  data,
		Lines:    splitLines(data),
		Language: DetectLanguage(relPath),
		Size:     len(data),
	}, nil
}

func effectiveMaxFileBytes(n int64) int64 {
	if n <= 0 {
		return DefaultMaxFileBytes
	}
	if n > MaxAllowedFileBytes {
		return MaxAllowedFileBytes
	}
	return n
}

func isSkipError(err error) bool {
	return errors.Is(err, errSkipBinary) ||
		errors.Is(err, errSkipTooLarge) ||
		errors.Is(err, errSkipSpecial) ||
		errors.Is(err, errSkipSymlink) ||
		errors.Is(err, errSkipHardlink)
}

// hasHardSkipSegment reports whether any path segment is a directory that the
// walker always prunes. Diff mode has no directory walk, so it applies the
// same policy to changed paths explicitly.
func hasHardSkipSegment(rel string) bool {
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		lower := strings.ToLower(part)
		if i == len(parts)-1 {
			// A file named .git (worktree pointer) or .vigil is still tool
			// state; other hard-skip names are directory conventions.
			return lower == ".git" || lower == ".vigil"
		}
		if hardSkipDirs[lower] {
			return true
		}
	}
	return false
}

// isBinary reports whether data contains a NUL byte in the first 8 KiB, the
// conventional heuristic for "this is not text".
func isBinary(data []byte) bool {
	if len(data) > binarySniffBytes {
		data = data[:binarySniffBytes]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// splitLines splits content on '\n' and strips a trailing '\r' from every
// line, so files with CRLF endings behave like files with LF endings.
func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

func defaultExcludePatterns() []string {
	return config.Defaults().Scan.Exclude
}

// resolveRoot turns root into an absolute, existing directory.
func resolveRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve scan root: %w", err)
	}
	abs = filepath.Clean(abs)
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("scan root %s: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("scan root %s is not a directory", abs)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return abs, nil
}

// resolveWithin joins a relative slash path to root and rejects paths that
// escape the root (including absolute paths and Windows volume names).
func resolveWithin(root, rel string) (absPath, cleanRel string, ok bool) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", "", false
	}
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" ||
		strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return "", "", false
	}
	absPath = filepath.Join(root, filepath.FromSlash(rel))
	cleanRoot := filepath.Clean(root)
	r, err := filepath.Rel(cleanRoot, absPath)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", "", false
	}
	return absPath, filepath.ToSlash(r), true
}

// resolveInput is like resolveWithin but also accepts an absolute path as long
// as it stays inside root. ScanPaths uses it so callers can pass either form.
func resolveInput(root, p string) (absPath, cleanRel string, ok bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", "", false
	}
	if filepath.IsAbs(p) {
		absPath = filepath.Clean(p)
		r, err := filepath.Rel(filepath.Clean(root), absPath)
		if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", "", false
		}
		return absPath, filepath.ToSlash(r), true
	}
	return resolveWithin(root, p)
}
