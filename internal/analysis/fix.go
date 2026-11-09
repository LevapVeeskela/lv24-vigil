package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/llm"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ProposeFix asks the model for a unified diff that fixes one finding.
//
// The diff is validated against root before it is returned. If validation
// fails, the model gets exactly one retry with the validation error appended.
// Nothing is ever applied: callers decide whether to write the patch.
func (a *Analyzer) ProposeFix(ctx context.Context, f model.Finding, root string) (*model.Fix, error) {
	if !a.enabled() {
		return nil, ErrLLMNotConfigured
	}

	rel, ok := cleanRelativePath(f.Location.Path)
	if !ok {
		return nil, fmt.Errorf("fix: unsafe finding path %q", f.Location.Path)
	}
	content, rel, _, err := readFileBounded(root, rel, maxFixFileBytes)
	if err != nil {
		return nil, fmt.Errorf("fix: read %s: %w", rel, err)
	}
	lines := splitLines(string(content))
	if len(lines) == 0 {
		return nil, fmt.Errorf("fix: %s is empty", rel)
	}

	start := f.Location.StartLine
	if start < 1 {
		start = 1
	}
	if start > len(lines) {
		return nil, fmt.Errorf("fix: line %d is outside %s (%d lines)", start, rel, len(lines))
	}
	end := f.Location.EndLine
	if end < start {
		end = start
	}
	if end > len(lines) {
		end = len(lines)
	}

	from := start - maxFixContextLines
	if from < 1 {
		from = 1
	}
	to := end + maxFixContextLines
	if to > len(lines) {
		to = len(lines)
	}
	contextText := numberedLines(lines, from, to)
	prompt := buildFixPrompt(f, rel, contextText, start, end)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		user := prompt
		if lastErr != nil {
			user += "\n\nYour previous diff was rejected: " + lastErr.Error() +
				"\nReturn a corrected JSON object with a valid unified diff. Do not explain."
		}

		resp, err := a.complete(ctx, llm.Request{
			System:   systemFix,
			Messages: []llm.Message{{Role: llm.RoleUser, Content: user}},
			JSON:     true,
		})
		if err != nil {
			return nil, fmt.Errorf("fix: %w", err)
		}

		diff, description, err := parseFixResponse(resp.Text)
		if err != nil {
			lastErr = err
			continue
		}
		if err := ValidateDiff(root, diff); err != nil {
			lastErr = err
			continue
		}

		files := diffFiles(diff)
		if !containsPath(files, rel) {
			lastErr = fmt.Errorf("diff does not modify the finding file %q", rel)
			continue
		}
		if strings.TrimSpace(description) == "" {
			description = fmt.Sprintf("Fix for %s: %s", f.RuleID, f.Title)
		}
		return &model.Fix{
			Description: truncateBytes(stripControls(description), 1000),
			Diff:        diff,
			Files:       files,
		}, nil
	}

	return nil, fmt.Errorf("fix: model did not produce a valid diff: %w", lastErr)
}

// parseFixResponse extracts a diff and an optional description from either a
// JSON object or a fenced/prose-wrapped unified diff.
func parseFixResponse(text string) (string, string, error) {
	if obj, err := llm.ExtractJSONObject(text); err == nil {
		var payload map[string]json.RawMessage
		if json.Unmarshal(obj, &payload) == nil {
			diff := firstJSONString(payload, "diff", "patch", "unified_diff", "unifiedDiff")
			if strings.TrimSpace(diff) != "" {
				description := firstJSONString(payload, "description", "summary", "explanation")
				return normalizeDiff(diff), description, nil
			}
		}
	}

	diff, err := extractDiff(text)
	if err != nil {
		return "", "", err
	}
	return normalizeDiff(diff), "", nil
}

func firstJSONString(m map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// normalizeDiff canonicalises newlines and guarantees a trailing newline. It
// never trims spaces inside a line, because patch context depends on them.
func normalizeDiff(diff string) string {
	diff = strings.ReplaceAll(diff, "\r\n", "\n")
	diff = strings.ReplaceAll(diff, "\r", "\n")
	diff = strings.TrimPrefix(diff, "\ufeff")
	diff = strings.Trim(diff, "\n")
	if diff == "" {
		return ""
	}
	return diff + "\n"
}

// extractDiff finds a unified diff in prose or a fenced block. Hunk headers are
// parsed so trailing prose is not mistaken for patch content.
func extractDiff(text string) (string, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	lines := strings.Split(text, "\n")

	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			start = i
			break
		}
		// Require the +++ header next so a markdown horizontal rule or prose
		// line that happens to start with "--- " is not mistaken for a diff.
		if strings.HasPrefix(line, "--- ") && i+1 < len(lines) && strings.HasPrefix(lines[i+1], "+++ ") {
			start = i
			break
		}
	}
	if start < 0 {
		return "", errors.New("no unified diff found in response")
	}

	var out []string
	var hunk *diffHunk
	sawHunk := false

	for i := start; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			break
		}
		if strings.HasPrefix(line, "\\") {
			out = append(out, line)
			continue
		}

		if hunk != nil && hunk.oldSeen >= hunk.oldCount && hunk.newSeen >= hunk.newCount {
			hunk = nil
		}

		if hunk != nil {
			if line == "" {
				hunk.oldSeen++
				hunk.newSeen++
				out = append(out, line)
				continue
			}
			switch line[0] {
			case ' ':
				hunk.oldSeen++
				hunk.newSeen++
				out = append(out, line)
				continue
			case '-':
				hunk.oldSeen++
				out = append(out, line)
				continue
			case '+':
				hunk.newSeen++
				out = append(out, line)
				continue
			case '\\':
				out = append(out, line)
				continue
			}
			// Not a body line: fall through to header handling.
		}

		switch {
		case strings.HasPrefix(line, "@@"):
			h, ok := parseHunkHeader(line)
			if !ok {
				return "", fmt.Errorf("malformed hunk header %q", truncateBytes(line, 200))
			}
			hunk = &h
			sawHunk = true
			out = append(out, line)
		case isDiffHeaderLine(line):
			out = append(out, line)
		case strings.TrimSpace(line) == "":
			// Blank separator outside a hunk.
		default:
			if len(out) > 0 {
				// Prose after the patch: stop here.
				return strings.Trim(strings.Join(out, "\n"), "\n") + "\n", nil
			}
		}
	}

	if !sawHunk {
		return "", errors.New("no unified diff hunks found in response")
	}
	return strings.Trim(strings.Join(out, "\n"), "\n") + "\n", nil
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func isDiffHeaderLine(line string) bool {
	for _, prefix := range []string{
		"diff --git ",
		"--- ",
		"+++ ",
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
