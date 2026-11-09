// Package report renders scan results as Markdown, JSON, SARIF or HTML.
//
// Renderers are pure: they never mutate the result, never read the clock and
// never touch the network. The same input always produces the same bytes.
package report

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Options controls optional presentation details.
type Options struct {
	// Color is reserved for terminal renderers. The formats implemented here
	// are portable (Markdown, JSON, SARIF and HTML) and never contain ANSI
	// escape sequences, so this flag is currently a no-op.
	Color bool
	// ShowFix includes proposed fix diffs in Markdown and HTML.
	ShowFix bool
}

// Canonical format names accepted by Render and Write.
const (
	FormatMarkdown = "md"
	FormatJSON     = "json"
	FormatSARIF    = "sarif"
	FormatHTML     = "html"
)

// severityOrder is the display order used by every human-readable renderer.
var severityOrder = []model.Severity{
	model.SeverityCritical,
	model.SeverityHigh,
	model.SeverityMedium,
	model.SeverityLow,
	model.SeverityInfo,
}

// Render formats res. An empty format means Markdown. It returns an error for
// an unknown format or a nil result.
func Render(format string, res *model.ScanResult, opts Options) ([]byte, error) {
	if res == nil {
		return nil, errors.New("report: nil scan result")
	}

	switch normalizeFormat(format) {
	case FormatMarkdown:
		return renderMarkdown(res, opts)
	case FormatJSON:
		return renderJSON(res)
	case FormatSARIF:
		return renderSARIF(res)
	case FormatHTML:
		return renderHTML(res, opts)
	default:
		return nil, fmt.Errorf("report: unsupported format %q (want md, json, sarif or html)", format)
	}
}

// Write renders res and writes it to w.
func Write(w io.Writer, format string, res *model.ScanResult, opts Options) error {
	if w == nil {
		return errors.New("report: nil writer")
	}
	b, err := Render(format, res, opts)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func normalizeFormat(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	f = strings.TrimPrefix(f, ".")
	switch f {
	case "", "md", "markdown":
		return FormatMarkdown
	case "json":
		return FormatJSON
	case "sarif":
		return FormatSARIF
	case "html", "htm":
		return FormatHTML
	default:
		return f
	}
}

// sortedFindings returns a sorted copy so renderers never mutate the result.
func sortedFindings(fs []model.Finding) []model.Finding {
	out := append([]model.Finding(nil), fs...)
	model.SortFindings(out)
	return out
}

func activeFindings(res *model.ScanResult) []model.Finding {
	return sortedFindings(res.Findings)
}

func suppressedFindings(res *model.ScanResult) []model.Finding {
	return sortedFindings(res.Suppressed)
}

func findingID(f model.Finding) string {
	if f.ID != "" {
		return f.ID
	}
	return f.ComputeID()
}

func findingFingerprint(f model.Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return f.ComputeFingerprint()
}

func displaySeverity(s model.Severity) string {
	v := strings.ToUpper(oneLine(string(s)))
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

func severityLabel(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "Critical"
	case model.SeverityHigh:
		return "High"
	case model.SeverityMedium:
		return "Medium"
	case model.SeverityLow:
		return "Low"
	case model.SeverityInfo:
		return "Info"
	default:
		return "Other"
	}
}

func severityClass(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium,
		model.SeverityLow, model.SeverityInfo:
		return string(s)
	default:
		return "unknown"
	}
}

func isKnownSeverity(s model.Severity) bool {
	switch s {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium,
		model.SeverityLow, model.SeverityInfo:
		return true
	default:
		return false
	}
}

func severityCounts(fs []model.Finding) map[model.Severity]int {
	out := make(map[model.Severity]int, len(severityOrder))
	for _, f := range fs {
		out[f.Severity]++
	}
	return out
}

type severityGroup struct {
	Severity model.Severity
	Findings []model.Finding
}

// groupBySeverity groups already-sorted findings. Findings with an unknown
// severity are merged into a single trailing group so no finding is dropped.
func groupBySeverity(fs []model.Finding) []severityGroup {
	bySeverity := make(map[model.Severity][]model.Finding, len(severityOrder))
	var unknown []model.Finding

	for _, f := range fs {
		if isKnownSeverity(f.Severity) {
			bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
		} else {
			unknown = append(unknown, f)
		}
	}

	groups := make([]severityGroup, 0, len(severityOrder)+1)
	for _, s := range severityOrder {
		if len(bySeverity[s]) > 0 {
			groups = append(groups, severityGroup{Severity: s, Findings: bySeverity[s]})
		}
	}
	if len(unknown) > 0 {
		groups = append(groups, severityGroup{Findings: unknown})
	}
	return groups
}

func unknownSeverityCount(counts map[model.Severity]int) int {
	n := 0
	for severity, count := range counts {
		if !isKnownSeverity(severity) {
			n += count
		}
	}
	return n
}

func pathLine(loc model.Location) string {
	p := oneLine(loc.Path)
	if p == "" {
		p = "(unknown)"
	}
	switch {
	case loc.StartLine > 0 && loc.EndLine > loc.StartLine:
		return fmt.Sprintf("%s:%d-%d", p, loc.StartLine, loc.EndLine)
	case loc.StartLine > 0:
		return fmt.Sprintf("%s:%d", p, loc.StartLine)
	default:
		return p
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

func formatModel(m *model.ModelInfo) string {
	if m == nil {
		return "not used (deterministic rules only)"
	}
	name := strings.Join(nonEmpty(m.Provider, m.Model), "/")
	if name == "" {
		name = "configured"
	}
	if m.BaseURL != "" {
		name += " (" + oneLine(m.BaseURL) + ")"
	}
	return name
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func longestBacktickRun(s string) int {
	longest, current := 0, 0
	for _, r := range s {
		if r == '`' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	return longest
}

// fenceFor returns a backtick fence at least one character longer than the
// longest run inside s, so arbitrary evidence cannot terminate the block.
func fenceFor(s string) string {
	n := longestBacktickRun(s) + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}

// inlineCode renders s as a Markdown code span, widening the delimiters when
// the value itself contains backticks.
func inlineCode(s string) string {
	s = oneLine(s)
	if s == "" {
		return "`-`"
	}
	fence := strings.Repeat("`", longestBacktickRun(s)+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") ||
		strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}

func sortedCategories(m map[model.Category]int) []model.Category {
	out := make([]model.Category, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
