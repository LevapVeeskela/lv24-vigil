package analysis

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// diffHunk tracks the declared and observed line counts of one unified-diff
// hunk. Both counts must match exactly before the hunk is accepted.
type diffHunk struct {
	oldStart int
	oldCount int
	newStart int
	newCount int
	oldSeen  int
	newSeen  int
}

func (h *diffHunk) complete() bool {
	return h.oldSeen >= h.oldCount && h.newSeen >= h.newCount
}

var hunkHeaderRE = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@`)

func parseHunkHeader(line string) (diffHunk, bool) {
	m := hunkHeaderRE.FindStringSubmatch(line)
	if m == nil {
		return diffHunk{}, false
	}
	oldStart, err := strconv.Atoi(m[1])
	if err != nil {
		return diffHunk{}, false
	}
	oldCount := 1
	if m[2] != "" {
		if oldCount, err = strconv.Atoi(m[2]); err != nil {
			return diffHunk{}, false
		}
	}
	newStart, err := strconv.Atoi(m[3])
	if err != nil {
		return diffHunk{}, false
	}
	newCount := 1
	if m[4] != "" {
		if newCount, err = strconv.Atoi(m[4]); err != nil {
			return diffHunk{}, false
		}
	}
	return diffHunk{
		oldStart: oldStart,
		oldCount: oldCount,
		newStart: newStart,
		newCount: newCount,
	}, true
}

// ValidateDiff checks that diff is a plausible, safe unified diff against root.
// It does not touch the working tree and does not run git.
//
// The checks are:
//   - non-empty, at least one hunk and at least one file header;
//   - every path is relative, clean, inside root, has no ".." and is not .git;
//   - hunk header line counts match the body;
//   - no binary patches.
func ValidateDiff(root, diff string) error {
	if strings.TrimSpace(diff) == "" {
		return errors.New("diff is empty")
	}
	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "GIT binary patch") || strings.HasPrefix(line, "Binary files ") {
			return errors.New("binary diffs are not accepted")
		}
	}

	var (
		oldPath, newPath string
		haveOld, haveNew bool
		hunk             *diffHunk
		hunks            int
		files            int
	)

	finalizeHunk := func() error {
		if hunk == nil {
			return nil
		}
		if hunk.oldSeen != hunk.oldCount || hunk.newSeen != hunk.newCount {
			return fmt.Errorf(
				"hunk @@ -%d,%d +%d,%d @@ declares %d old / %d new lines but the body has %d old / %d new",
				hunk.oldStart, hunk.oldCount, hunk.newStart, hunk.newCount,
				hunk.oldCount, hunk.newCount, hunk.oldSeen, hunk.newSeen)
		}
		hunk = nil
		return nil
	}

	finalizeFile := func() error {
		if !haveOld && !haveNew {
			return nil
		}
		if !haveOld || !haveNew {
			return fmt.Errorf("incomplete file header for %q", firstNonEmpty(oldPath, newPath))
		}
		if oldPath == "" && newPath == "" {
			return errors.New("diff file header has no path")
		}
		if oldPath == "/dev/null" && newPath == "/dev/null" {
			return errors.New("diff file header has no real path")
		}
		if err := validateDiffPath(root, oldPath); err != nil {
			return err
		}
		if err := validateDiffPath(root, newPath); err != nil {
			return err
		}
		files++
		oldPath, newPath = "", ""
		haveOld, haveNew = false, false
		return nil
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "\\") {
			// "\ No newline at end of file" belongs to the hunk that just
			// ended; it carries no line count.
			continue
		}
		if hunk != nil && hunk.complete() {
			hunk = nil
		}

		switch {
		case strings.HasPrefix(line, "diff --git "):
			if err := finalizeHunk(); err != nil {
				return err
			}
			if err := finalizeFile(); err != nil {
				return err
			}

		case strings.HasPrefix(line, "--- "):
			if hunk != nil {
				// A removed line whose content starts with "-- " renders as
				// "--- ..."; it belongs to the current hunk, not a new file.
				hunk.oldSeen++
				continue
			}
			if err := finalizeFile(); err != nil {
				return err
			}
			p, ok := diffHeaderPath(line)
			if !ok {
				return fmt.Errorf("line %d: malformed --- header", i+1)
			}
			oldPath, haveOld = p, true

		case strings.HasPrefix(line, "+++ "):
			if hunk != nil {
				hunk.newSeen++
				continue
			}
			p, ok := diffHeaderPath(line)
			if !ok {
				return fmt.Errorf("line %d: malformed +++ header", i+1)
			}
			newPath, haveNew = p, true

		case strings.HasPrefix(line, "@@"):
			if !haveOld || !haveNew {
				return fmt.Errorf("line %d: hunk without complete file headers", i+1)
			}
			if err := finalizeHunk(); err != nil {
				return err
			}
			h, ok := parseHunkHeader(line)
			if !ok {
				return fmt.Errorf("line %d: malformed hunk header %q", i+1, truncateBytes(line, 200))
			}
			hunk = &h
			hunks++

		case isDiffMetadataLine(line):
			// Git metadata lines carry no patch content.

		case hunk != nil:
			if line == "" {
				hunk.oldSeen++
				hunk.newSeen++
				continue
			}
			switch line[0] {
			case ' ':
				hunk.oldSeen++
				hunk.newSeen++
			case '-':
				hunk.oldSeen++
			case '+':
				hunk.newSeen++
			case '\\':
				// "\ No newline at end of file" marker.
			default:
				return fmt.Errorf("line %d: unexpected line inside a hunk", i+1)
			}

		case strings.TrimSpace(line) == "":
			// Separator between files or hunks.

		default:
			return fmt.Errorf("line %d: unexpected content outside a hunk", i+1)
		}
	}

	if err := finalizeHunk(); err != nil {
		return err
	}
	if err := finalizeFile(); err != nil {
		return err
	}
	if hunks == 0 {
		return errors.New("diff has no hunks")
	}
	if files == 0 {
		return errors.New("diff has no file headers")
	}
	return nil
}

// validateDiffPath checks one ---/+++ path. /dev/null is allowed for new and
// deleted files; every real path must stay inside root.
func validateDiffPath(root, raw string) error {
	if raw == "/dev/null" {
		return nil
	}
	p := stripDiffPrefix(raw)
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("empty diff path %q", raw)
	}
	if _, ok := cleanRelativePath(p); !ok {
		return fmt.Errorf("unsafe diff path %q: paths must be relative, clean and outside .git", raw)
	}
	if _, ok := insideRoot(root, p); !ok {
		return fmt.Errorf("diff path %q escapes the scan root", raw)
	}
	return nil
}

// diffHeaderPath extracts the path from a --- or +++ line, including git's
// quoted form and an optional tab-separated timestamp.
func diffHeaderPath(line string) (string, bool) {
	if len(line) < 4 {
		return "", false
	}
	rest := strings.TrimRight(line[4:], " \t")
	if rest == "" {
		return "", false
	}
	if strings.HasPrefix(rest, `"`) {
		if end := strings.Index(rest[1:], `"`); end >= 0 {
			if unquoted, err := strconv.Unquote(rest[:end+2]); err == nil {
				return unquoted, true
			}
		}
	}
	if i := strings.IndexByte(rest, '\t'); i >= 0 {
		rest = strings.TrimSpace(rest[:i])
	}
	return rest, rest != ""
}

// stripDiffPrefix removes the conventional a/ or b/ prefix.
func stripDiffPrefix(p string) string {
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		return p[2:]
	}
	return p
}

// diffFiles lists the repository-relative paths touched by a diff.
func diffFiles(diff string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(line, "--- ") && !strings.HasPrefix(line, "+++ ") {
			continue
		}
		raw, ok := diffHeaderPath(line)
		if !ok || raw == "/dev/null" {
			continue
		}
		clean, ok := cleanRelativePath(stripDiffPrefix(raw))
		if !ok || seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

// isDiffMetadataLine reports whether line is a standard git diff header that
// carries no hunk content.
func isDiffMetadataLine(line string) bool {
	for _, prefix := range []string{
		"index ",
		"new file mode ",
		"deleted file mode ",
		"old mode ",
		"new mode ",
		"similarity index ",
		"rename from ",
		"rename to ",
	} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
