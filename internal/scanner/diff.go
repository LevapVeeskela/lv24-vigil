package scanner

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// LineRange is an inclusive range of 1-based line numbers.
type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

const maxDiffPaddedLines = 2_000_000

var hunkHeaderRE = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// diffParse holds both the added ranges (the public ParseDiff result) and the
// added line text, which the scanner uses to build synthetic files.
type diffParse struct {
	ranges map[string][]LineRange
	text   map[string]map[int]string
}

// ParseDiff extracts the added line ranges from a unified diff. Only lines
// beginning with '+' inside a hunk count; file headers, removed lines and
// context lines do not. Paths are returned without the a/ or b/ prefix.
func ParseDiff(diff string) (map[string][]LineRange, error) {
	parsed, err := parseDiff(diff)
	if err != nil {
		return parsed.ranges, err
	}
	return parsed.ranges, nil
}

func parseDiff(diff string) (*diffParse, error) {
	parsed := &diffParse{
		ranges: map[string][]LineRange{},
		text:   map[string]map[int]string{},
	}
	if strings.TrimSpace(diff) == "" {
		return parsed, nil
	}

	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	var (
		current string
		added   []int
		newLine int
		oldRem  int
		newRem  int
		inHunk  bool
	)

	flush := func() {
		if current != "" && len(added) > 0 {
			parsed.ranges[current] = append(parsed.ranges[current], coalesceLines(added)...)
		}
		added = nil
	}

	for i, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")

		if strings.HasPrefix(line, "diff --git ") {
			flush()
			current = ""
			inHunk = false
			continue
		}

		if !inHunk && strings.HasPrefix(line, "+++ ") {
			flush()
			current = parseDiffTarget(line[4:])
			continue
		}

		if strings.HasPrefix(line, "@@") {
			m := hunkHeaderRE.FindStringSubmatch(line)
			if m == nil {
				return parsed, fmt.Errorf("scanner: malformed hunk header on line %d: %q", i+1, line)
			}
			flush()
			newStart, _ := strconv.Atoi(m[3])
			newLine = newStart
			oldRem = diffCount(m[2])
			newRem = diffCount(m[4])
			inHunk = oldRem > 0 || newRem > 0
			continue
		}

		if !inHunk {
			continue
		}

		switch {
		case line == "":
			// Some tools emit an empty context line without the leading space.
			newLine++
			oldRem--
			newRem--
		case strings.HasPrefix(line, "+"):
			if newRem > 0 {
				added = append(added, newLine)
				if current != "" {
					if parsed.text[current] == nil {
						parsed.text[current] = map[int]string{}
					}
					parsed.text[current][newLine] = strings.TrimPrefix(line, "+")
				}
			}
			newLine++
			newRem--
		case strings.HasPrefix(line, "-"):
			oldRem--
		case strings.HasPrefix(line, "\\"):
			// "\ No newline at end of file" does not advance either side.
		default:
			// Context line (normally starts with a space).
			newLine++
			oldRem--
			newRem--
		}

		if oldRem <= 0 && newRem <= 0 {
			inHunk = false
		}
	}

	flush()
	return parsed, nil
}

func diffCount(s string) int {
	if s == "" {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 1
	}
	return n
}

func parseDiffTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		if unquoted, err := strconv.Unquote(s); err == nil {
			s = unquoted
		}
	} else if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = s[:i]
	}
	if s == "/dev/null" {
		return ""
	}
	switch {
	case strings.HasPrefix(s, "b/"):
		s = s[len("b/"):]
	case strings.HasPrefix(s, "a/"):
		s = s[len("a/"):]
	}
	s = strings.TrimPrefix(s, "./")
	return s
}

// coalesceLines converts sorted added line numbers into inclusive ranges.
func coalesceLines(nums []int) []LineRange {
	if len(nums) == 0 {
		return nil
	}
	sort.Ints(nums)
	out := make([]LineRange, 0, len(nums))
	start, end := nums[0], nums[0]
	for _, n := range nums[1:] {
		if n == end {
			continue
		}
		if n == end+1 {
			end = n
			continue
		}
		out = append(out, LineRange{Start: start, End: end})
		start, end = n, n
	}
	out = append(out, LineRange{Start: start, End: end})
	return out
}

// buildDiffFiles turns a unified diff into rules.File values that contain only
// the added lines, padded with empty strings so line numbers still refer to the
// real file. The added text comes from the diff itself, so a patch does not
// have to be applied to the working tree to be scanned.
func buildDiffFiles(ctx context.Context, root string, opts Options) ([]*rules.File, int, []string, error) {
	parsed, err := parseDiff(opts.Diff)
	if err != nil {
		return nil, 0, nil, err
	}
	if len(parsed.ranges) == 0 {
		return nil, 0, nil, nil
	}

	maxBytes := effectiveMaxFileBytes(opts.MaxFileBytes)
	excludes := append(defaultExcludePatterns(), opts.Exclude...)
	matcher := newIgnoreMatcher(excludes, opts.Include)

	paths := make([]string, 0, len(parsed.ranges))
	for p := range parsed.ranges {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var (
		files       []*rules.File
		skipped     int
		errs        []string
		totalPadded int
	)
	for _, rel := range paths {
		if err := ctx.Err(); err != nil {
			return files, skipped, errs, err
		}
		if hasHardSkipSegment(rel) || matcher.ignored(rel, false) || !matcher.included(rel) {
			skipped++
			continue
		}
		absPath, cleanRel, ok := resolveWithin(root, rel)
		if !ok {
			skipped++
			errs = append(errs, fmt.Sprintf("diff path outside scan root: %s", rel))
			continue
		}

		ranges := parsed.ranges[rel]
		maxLine := 0
		for _, r := range ranges {
			if r.End > maxLine {
				maxLine = r.End
			}
		}
		if maxLine <= 0 {
			skipped++
			continue
		}
		if maxLine > maxDiffPaddedLines || totalPadded+maxLine > maxDiffPaddedLines {
			skipped++
			errs = append(errs, fmt.Sprintf("diff %s: padded line budget exceeded (line range ends at %d)", rel, maxLine))
			continue
		}
		totalPadded += maxLine

		lines := make([]string, maxLine)
		for n, text := range parsed.text[rel] {
			if n >= 1 && n <= maxLine {
				lines[n-1] = text
			}
		}
		joined := strings.Join(lines, "\n")
		if int64(len(joined)) > maxBytes {
			skipped++
			continue
		}
		if isBinary([]byte(joined)) {
			skipped++
			continue
		}

		files = append(files, &rules.File{
			Path:     cleanRel,
			AbsPath:  absPath,
			Content:  []byte(joined),
			Lines:    lines,
			Language: DetectLanguage(cleanRel),
			Size:     len(joined),
		})
	}
	return files, skipped, errs, nil
}
