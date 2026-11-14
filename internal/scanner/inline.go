package scanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// InlineMarker introduces a suppression directive in a comment, for example
//
//	// vigil:ignore VGL-SEC-001 reason="test fixture" until=2027-01-01
const InlineMarker = "vigil:ignore"

const inlineDateLayout = "2006-01-02"

// inlineDirective is one parsed vigil:ignore comment.
type inlineDirective struct {
	all bool
	// rules holds the explicitly listed rule IDs. Empty means every rule,
	// unless unknownOption records a token that was meant to be an option.
	rules map[string]bool
	// unknownOption is the first key of an unrecognized key=value token. It
	// cannot be a rule ID, and it prevents an empty rule list from widening
	// the directive to every rule.
	unknownOption string
	reason        string
	until         time.Time
	untilSet      bool
	untilBad      string
	untilBadSet   bool
}

// matches reports whether the directive covers ruleID. A directive without a
// rule list, or with "*", covers every rule. A directive that only contains an
// unrecognized option covers nothing, so a typo cannot widen its scope.
func (d *inlineDirective) matches(ruleID string) bool {
	if d == nil {
		return false
	}
	if d.all {
		return true
	}
	if len(d.rules) == 0 {
		return d.unknownOption == ""
	}
	return d.rules[strings.ToUpper(strings.TrimSpace(ruleID))]
}

// expired reports whether the directive's until date is before today (UTC).
// A directive without until never expires.
func (d *inlineDirective) expired(today time.Time) bool {
	return d.untilSet && d.until.Before(today)
}

// invalidUntil reports an until value that is not a YYYY-MM-DD date. The
// directive fails closed: an unreadable expiry must not suppress forever.
func (d *inlineDirective) invalidUntil() bool {
	return d.untilBadSet
}

// why is the value stored in Finding.SuppressWhy.
func (d *inlineDirective) why() string {
	if d == nil || strings.TrimSpace(d.reason) == "" {
		return "inline"
	}
	return "inline: " + strings.TrimSpace(d.reason)
}

// applyInlineSuppressions moves findings covered by a vigil:ignore comment from
// kept to suppressed. It runs after dedupe and before the baseline, so an
// inline directive takes precedence over a baseline entry and never changes
// how the remaining findings are matched against the baseline.
func applyInlineSuppressions(findings []model.Finding, files []*rules.File) (kept, suppressed []model.Finding, errs []string) {
	if len(findings) == 0 {
		return findings, nil, nil
	}
	byPath := make(map[string]*rules.File, len(files))
	for _, f := range files {
		if f == nil {
			continue
		}
		byPath[filepath.ToSlash(filepath.Clean(f.Path))] = f
	}
	reader := &inlineLineReader{}

	today := todayUTC()
	seenErr := map[string]bool{}
	for _, f := range findings {
		path := filepath.ToSlash(filepath.Clean(f.Location.Path))
		directive, errsForFinding := inlineDirectiveFor(f, path, byPath[path], reader, today)
		for _, msg := range errsForFinding {
			if seenErr[msg] {
				continue
			}
			seenErr[msg] = true
			errs = append(errs, msg)
		}
		if directive == nil {
			kept = append(kept, f)
			continue
		}
		f.Suppressed = true
		f.SuppressWhy = directive.why()
		suppressed = append(suppressed, f)
	}
	return kept, suppressed, errs
}

// inlineDirectiveFor looks for a matching directive on the finding's line and
// on the immediately preceding line. Errors describe directives that would
// have matched but are no longer valid.
//
// Diff and review scans build padded files that contain added lines only, so
// the unchanged context line above an added line is blank there. When that
// line is empty and the file has an absolute path, the line is read from disk
// so a directive on the context line still applies. Line numbers are unchanged
// by the fallback.
func inlineDirectiveFor(f model.Finding, path string, file *rules.File, reader *inlineLineReader, today time.Time) (*inlineDirective, []string) {
	line := f.Location.StartLine
	if file == nil || line < 1 || line > len(file.Lines) {
		return nil, nil
	}
	type candidate struct {
		text string
		num  int
	}
	candidates := []candidate{{file.Lines[line-1], line}}
	// A trailing comment belongs to its own line. Only a comment that starts
	// the previous line carries the directive over to the next line.
	if line > 1 {
		prev := file.Lines[line-2]
		if prev == "" && file.AbsPath != "" {
			prev = reader.line(file.AbsPath, line-1)
		}
		if ownLineComment(prev) {
			candidates = append(candidates, candidate{prev, line - 1})
		}
	}

	var errs []string
	for _, c := range candidates {
		d := parseInlineDirective(c.text)
		if !d.matches(f.RuleID) {
			continue
		}
		if d.invalidUntil() {
			errs = append(errs, fmt.Sprintf("inline suppression at %s:%d has an invalid until date %q", path, c.num, d.untilBad))
			continue
		}
		if d.expired(today) {
			errs = append(errs, fmt.Sprintf("inline suppression at %s:%d expired on %s", path, c.num, d.until.Format(inlineDateLayout)))
			continue
		}
		return d, errs
	}
	return nil, errs
}

// inlineContextMaxBytes bounds the context-line lookup in a padded diff. A
// larger or unreadable file yields no directive, so a finding is reported
// instead of silently disappearing.
const inlineContextMaxBytes = 4 << 20

// inlineLineReader resolves a line from disk on demand. Diff and review scans
// build padded files from added lines only, so the unchanged context line
// above a finding is absent there even though it can carry a directive. The
// file is read once and cached, because several findings can share a file.
type inlineLineReader struct {
	files map[string][]string
}

func (r *inlineLineReader) line(absPath string, n int) string {
	if r == nil || n < 1 || absPath == "" || !filepath.IsAbs(absPath) {
		return ""
	}
	if r.files == nil {
		r.files = map[string][]string{}
	}
	lines, ok := r.files[absPath]
	if !ok {
		lines = readLinesAt(absPath)
		r.files[absPath] = lines
	}
	if n > len(lines) {
		return ""
	}
	return lines[n-1]
}

// readLinesAt returns the lines of a file on disk, or nil when it cannot be
// read within the context budget.
func readLinesAt(absPath string) []string {
	f, err := os.Open(absPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, inlineContextMaxBytes+1))
	if err != nil || len(data) > inlineContextMaxBytes {
		return nil
	}
	return splitLines(data)
}

// ownLineComment reports whether the first non-space text on line is a comment
// marker, so a directive there is a standalone comment and not a trailing one.
func ownLineComment(line string) bool {
	s := trimIndent(line)
	for _, prefix := range []string{"//", "<!--", "#", "--", ";"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// parseInlineDirective parses one source line. It returns nil when the line has
// no comment that begins with vigil:ignore.
func parseInlineDirective(line string) *inlineDirective {
	comment, ok := commentText(line)
	if !ok {
		return nil
	}
	comment = strings.TrimSpace(comment)
	if !hasInlineMarkerPrefix(comment) {
		return nil
	}
	rest := strings.TrimSpace(comment[len(InlineMarker):])

	d := &inlineDirective{rules: map[string]bool{}}
	// Rules and options can be interleaved, so "reason=fixture TEST-ALPHA"
	// still scopes the directive to TEST-ALPHA instead of leaving an empty
	// rule list that would suppress every rule.
	for rest != "" {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		if key, ok := inlineOptionKey(rest); ok {
			var value string
			value, rest = inlineOptionValue(rest[strings.IndexByte(rest, '=')+1:])
			switch key {
			case "reason":
				d.reason = strings.TrimSpace(value)
			case "until":
				if t, err := time.Parse(inlineDateLayout, strings.TrimSpace(value)); err == nil {
					d.until = t
					d.untilSet = true
				} else {
					d.untilBad = strings.TrimSpace(value)
					d.untilBadSet = true
				}
			}
			continue
		}
		var token string
		token, rest = splitInlineToken(rest)
		for _, id := range strings.Split(token, ",") {
			id = strings.TrimSpace(id)
			switch {
			case id == "":
			case id == "*":
				d.all = true
			case strings.Contains(id, "="):
				// Not a rule ID: an unknown option. Remember it so a
				// directive with no readable rule list stays inert instead
				// of applying to every rule.
				if d.unknownOption == "" {
					d.unknownOption = strings.ToLower(strings.TrimSpace(id[:strings.IndexByte(id, '=')]))
				}
			default:
				d.rules[strings.ToUpper(id)] = true
			}
		}
	}
	return d
}

// inlineOptionKey reports the option name at the start of s, if s begins with
// reason= or until=.
func inlineOptionKey(s string) (string, bool) {
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", false
	}
	key := strings.ToLower(strings.TrimSpace(s[:i]))
	if key != "reason" && key != "until" {
		return "", false
	}
	return key, true
}

// inlineOptionValue extracts one option value. A double- or single-quoted
// value may contain spaces; a bare value ends at the next whitespace.
func inlineOptionValue(s string) (value, rest string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if s[0] == '"' || s[0] == '\'' {
		quote := s[0]
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if s[i] == quote {
				return s[1:i], strings.TrimSpace(s[i+1:])
			}
		}
		return s[1:], ""
	}
	return splitInlineToken(s)
}

func splitInlineToken(s string) (token, rest string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// commentText returns the text that follows the first comment marker outside a
// string literal. It only recognises a marker, not a whole lexer, so the
// directive still has to begin the comment for it to count.
func commentText(line string) (string, bool) {
	s := trimIndent(line)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "<!--") {
		return htmlCommentBody(s), true
	}
	if s[0] == '#' || s[0] == ';' {
		return s[1:], true
	}

	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' && quote != '`' && i+1 < len(s) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '#':
			return s[i+1:], true
		case ';':
			// ";" starts a trailing comment in INI-style, Tcl and Lisp
			// files. Treat it as a comment only when a directive follows;
			// otherwise keep scanning so "x := 1; y := 2 // vigil:ignore"
			// still finds the // comment on the same line.
			if hasInlineMarkerPrefix(strings.TrimLeft(s[i+1:], " \t")) {
				return s[i+1:], true
			}
			continue
		case '/':
			if i+1 < len(s) && s[i+1] == '/' {
				return s[i+2:], true
			}
		case '-':
			// "--" starts an SQL/Lua comment only at a word boundary. A C
			// decrement such as i-- is not a comment.
			if i+1 < len(s) && s[i+1] == '-' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return s[i+2:], true
			}
		case '<':
			if strings.HasPrefix(s[i:], "<!--") {
				return htmlCommentBody(s[i:]), true
			}
		}
	}
	return "", false
}

// hasInlineMarkerPrefix reports whether s begins with the vigil:ignore marker,
// compared case-insensitively.
func hasInlineMarkerPrefix(s string) bool {
	return len(s) >= len(InlineMarker) && strings.EqualFold(s[:len(InlineMarker)], InlineMarker)
}

// trimIndent removes leading spaces and tabs plus a UTF-8 byte-order mark.
// Editors on Windows still write a BOM, and it must not hide a directive on
// the first line of a file.
func trimIndent(line string) string {
	s := strings.TrimLeft(line, " \t")
	s = strings.TrimPrefix(s, "\ufeff")
	return strings.TrimLeft(s, " \t")
}

func htmlCommentBody(s string) string {
	s = strings.TrimPrefix(s, "<!--")
	if end := strings.Index(s, "-->"); end >= 0 {
		s = s[:end]
	}
	return s
}

func todayUTC() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}
