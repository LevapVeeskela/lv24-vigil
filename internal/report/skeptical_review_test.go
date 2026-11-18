package report

import (
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Regression: the Markdown report is the default output on stdout, and the
// evidence block copied scanned bytes verbatim. A file with ESC or BEL
// sequences could clear the terminal, redraw a clean-looking report, or set
// the window title and clipboard (OSC 0 / OSC 52).
func TestMarkdownStripsTerminalControlCharacters(t *testing.T) {
	res := &model.ScanResult{
		ID:   "scan_20260101T000000_abcdef",
		Root: "/repo",
		Findings: []model.Finding{{
			ID:       "VGL-0000000001",
			RuleID:   "TEST-1",
			Title:    "Title with \x1b[31mred\x1b[0m text",
			Severity: model.SeverityHigh,
			Category: model.CategoryInjection,
			Location: model.Location{Path: "src/\x1b]0;pwned\x07app.py", StartLine: 2},
			Evidence: "os.system(x)\t# \x1b[2J\x1b[H\x1b]52;c;ZXZpbA==\x07 \u009b31m done\r\nsecond line",
		}},
		Errors: []string{"read \x1b[2Jevil: denied"},
	}
	out, err := Render("md", res, Options{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(out)
	for _, r := range text {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("the report contains the control character %U", r)
		}
	}
	for _, want := range []string{"os.system(x)\t# ", "second line", "TEST-1", "app.py"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report lost %q", want)
		}
	}
}

func TestSanitizeTerminalKeepsOrdinaryText(t *testing.T) {
	const in = "naïve — 日本語\tтекст\nnext"
	if got := SanitizeTerminal(in); got != in {
		t.Fatalf("SanitizeTerminal changed ordinary text: %q", got)
	}
}
