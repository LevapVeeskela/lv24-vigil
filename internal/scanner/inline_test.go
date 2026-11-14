package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

func inlineRegistry() *rules.Registry {
	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-ALPHA", model.SeverityHigh, "VULN"))
	reg.Add(matchRule("TEST-BETA", model.SeverityMedium, "VULN"))
	return reg
}

func scanInline(t *testing.T, content string, opts Options) *model.ScanResult {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "app.go", content)
	opts.Root = root
	opts.NoBaseline = true
	res, err := New(inlineRegistry(), nil).Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return res
}

func suppressedRules(res *model.ScanResult) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range res.Suppressed {
		out[f.RuleID] = f
	}
	return out
}

func TestInlineSuppressesSameLineAndMatchesOnlyListedRule(t *testing.T) {
	res := scanInline(t, "VULN = 1 // vigil:ignore TEST-ALPHA\n", Options{})

	if len(res.Suppressed) != 1 {
		t.Fatalf("suppressed = %d, want 1: %+v", len(res.Suppressed), res.Suppressed)
	}
	got := res.Suppressed[0]
	if got.RuleID != "TEST-ALPHA" || !got.Suppressed || got.SuppressWhy != "inline" {
		t.Errorf("suppressed finding = %+v, want TEST-ALPHA inline", got)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "TEST-BETA" {
		t.Fatalf("kept findings = %+v, want only TEST-BETA (wrong rule must not be suppressed)", res.Findings)
	}
}

func TestInlineSuppressesPreviousLineRuleList(t *testing.T) {
	res := scanInline(t, "// vigil:ignore TEST-ALPHA,TEST-BETA\nVULN = 1\n", Options{})

	if len(res.Findings) != 0 {
		t.Fatalf("kept = %+v, want none", res.Findings)
	}
	if len(res.Suppressed) != 2 {
		t.Fatalf("suppressed = %d, want 2", len(res.Suppressed))
	}
}

func TestInlineWildcardAndReason(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		why     string
	}{
		{"wildcard", "VULN = 1 // vigil:ignore *\n", "inline"},
		{"quoted reason", `VULN = 1 // vigil:ignore * reason="test fixture"` + "\n", "inline: test fixture"},
		{"bare reason", "VULN = 1 // vigil:ignore * reason=fixture\n", "inline: fixture"},
		{"empty rule list", "VULN = 1 # vigil:ignore\n", "inline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := scanInline(t, tc.content, Options{})
			if len(res.Findings) != 0 {
				t.Fatalf("kept = %+v, want none", res.Findings)
			}
			if len(res.Suppressed) != 2 {
				t.Fatalf("suppressed = %d, want 2", len(res.Suppressed))
			}
			for _, f := range res.Suppressed {
				if f.SuppressWhy != tc.why {
					t.Errorf("%s SuppressWhy = %q, want %q", f.RuleID, f.SuppressWhy, tc.why)
				}
			}
		})
	}
}

func TestInlineReasonBeforeRuleListKeepsScope(t *testing.T) {
	// A regression: the rule list used to be read only before the first
	// option, so "reason=fixture TEST-ALPHA" left an empty list and
	// suppressed every rule on the line.
	res := scanInline(t, "VULN = 1 // vigil:ignore reason=fixture TEST-ALPHA\n", Options{})

	if len(res.Suppressed) != 1 {
		t.Fatalf("suppressed = %d, want 1: %+v", len(res.Suppressed), res.Suppressed)
	}
	if got := res.Suppressed[0]; got.RuleID != "TEST-ALPHA" || got.SuppressWhy != "inline: fixture" {
		t.Errorf("suppressed finding = %+v, want TEST-ALPHA with the fixture reason", got)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "TEST-BETA" {
		t.Fatalf("kept findings = %+v, want only TEST-BETA", res.Findings)
	}
}

func TestInlineTrailingSemicolonDirective(t *testing.T) {
	res := scanInline(t, "VULN = 1 ; vigil:ignore TEST-ALPHA\n", Options{})

	if len(res.Suppressed) != 1 || res.Suppressed[0].RuleID != "TEST-ALPHA" {
		t.Fatalf("suppressed = %+v, want only TEST-ALPHA", res.Suppressed)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "TEST-BETA" {
		t.Fatalf("kept findings = %+v, want only TEST-BETA", res.Findings)
	}
}

func TestInlineSemicolonStatementKeepsFollowingComment(t *testing.T) {
	// A semicolon inside a statement must not hide a // directive later on
	// the same line.
	res := scanInline(t, "VULN = 1; y := 2 // vigil:ignore TEST-ALPHA\n", Options{})
	if len(res.Suppressed) != 1 || res.Suppressed[0].RuleID != "TEST-ALPHA" {
		t.Fatalf("suppressed = %+v, want only TEST-ALPHA", res.Suppressed)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "TEST-BETA" {
		t.Fatalf("kept findings = %+v, want only TEST-BETA", res.Findings)
	}
}

func TestInlineExpiredDirectiveDoesNotSuppress(t *testing.T) {
	res := scanInline(t, "// vigil:ignore TEST-ALPHA,TEST-BETA until=2020-01-01\nVULN = 1\n", Options{})

	if len(res.Findings) != 2 {
		t.Fatalf("kept = %+v, want the expired directive to suppress nothing", res.Findings)
	}
	if len(res.Suppressed) != 0 {
		t.Fatalf("suppressed = %+v, want none", res.Suppressed)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("errors = %v, want exactly one expired warning", res.Errors)
	}
	want := "inline suppression at app.go:1 expired on 2020-01-01"
	if res.Errors[0] != want {
		t.Errorf("error = %q, want %q", res.Errors[0], want)
	}
}

func TestInlineUntilTodayAndFutureSuppress(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")
	future := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	for _, until := range []string{today, future} {
		res := scanInline(t, "VULN = 1 // vigil:ignore * until="+until+"\n", Options{})
		if len(res.Findings) != 0 || len(res.Suppressed) != 2 {
			t.Errorf("until=%s: kept=%d suppressed=%d, want 0/2", until, len(res.Findings), len(res.Suppressed))
		}
		if len(res.Errors) != 0 {
			t.Errorf("until=%s: unexpected errors %v", until, res.Errors)
		}
	}
}

func TestInlineInvalidUntilFailsClosed(t *testing.T) {
	res := scanInline(t, "VULN = 1 // vigil:ignore * until=soon\n", Options{})
	if len(res.Findings) != 2 || len(res.Suppressed) != 0 {
		t.Fatalf("kept=%d suppressed=%d, want 2/0", len(res.Findings), len(res.Suppressed))
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "invalid until date") {
		t.Fatalf("errors = %v, want one invalid-until warning", res.Errors)
	}
}

func TestInlineDoesNotReachBeyondPreviousLine(t *testing.T) {
	res := scanInline(t, "// vigil:ignore *\nx := 1\nVULN = 1\n", Options{})
	if len(res.Suppressed) != 0 || len(res.Findings) != 2 {
		t.Fatalf("kept=%d suppressed=%d, want 2/0", len(res.Findings), len(res.Suppressed))
	}
}

func TestInlineTrailingDirectiveDoesNotLeakToNextLine(t *testing.T) {
	res := scanInline(t, "VULN = 1 // vigil:ignore *\nVULN = 2\n", Options{})
	if len(res.Suppressed) != 2 {
		t.Fatalf("suppressed = %d, want the two line-1 findings", len(res.Suppressed))
	}
	if len(res.Findings) != 2 {
		t.Fatalf("kept = %d, want the two line-2 findings", len(res.Findings))
	}
	for _, f := range res.Findings {
		if f.Location.StartLine != 2 {
			t.Errorf("kept finding on line %d leaked from the line-1 trailing comment", f.Location.StartLine)
		}
	}
}

func TestInlineDirectiveAfterBOM(t *testing.T) {
	// PowerShell and some Windows editors write a UTF-8 BOM; it must not hide
	// a directive on the first line.
	res := scanInline(t, "\ufeff# vigil:ignore *\nVULN = 1\n", Options{})
	if len(res.Findings) != 0 || len(res.Suppressed) != 2 {
		t.Fatalf("kept=%d suppressed=%d, want 0/2", len(res.Findings), len(res.Suppressed))
	}
}

func TestInlineSuppressionsDisabled(t *testing.T) {
	content := "// vigil:ignore *\nVULN = 1\n"
	res := scanInline(t, content, Options{NoInlineSuppressions: true})
	if len(res.Suppressed) != 0 {
		t.Fatalf("suppressed = %+v, want none with NoInlineSuppressions", res.Suppressed)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("kept = %d, want 2", len(res.Findings))
	}
	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none", res.Errors)
	}
}

func TestInlineDirectiveInsideStringDoesNotSuppress(t *testing.T) {
	for _, content := range []string{
		"msg := \"VULN vigil:ignore *\"\n",
		"msg := `VULN # vigil:ignore *`\n",
		"msg := 'VULN ; vigil:ignore *'\n",
		"url := \"https://example.test/VULN // vigil:ignore *\"\n",
	} {
		res := scanInline(t, content, Options{})
		if len(res.Suppressed) != 0 || len(res.Findings) != 2 {
			t.Errorf("%q: kept=%d suppressed=%d, want 2/0", content, len(res.Findings), len(res.Suppressed))
		}
	}
}

func TestInlineStaysBeforeBaseline(t *testing.T) {
	root := t.TempDir()
	// Line 1 is ignored inline, line 2 is accepted by the baseline.
	writeTestFile(t, root, "app.go", "VULN = 1 // vigil:ignore TEST-ALPHA\nVULN = 2\n")
	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-ALPHA", model.SeverityHigh, "VULN"))
	s := New(reg, nil)

	first, err := s.Scan(context.Background(), Options{Root: root, NoBaseline: true, NoInlineSuppressions: true})
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	var baselineFinding model.Finding
	for _, f := range first.Findings {
		if f.Location.StartLine == 2 {
			baselineFinding = f
		}
	}
	if baselineFinding.ID == "" {
		t.Fatalf("no line-2 finding in %+v", first.Findings)
	}
	baseline := NewBaseline()
	baseline.Add(baselineFinding, "accepted earlier")
	if err := SaveBaseline(filepath.Join(root, DefaultBaselineFile), baseline); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	second, err := s.Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if len(second.Findings) != 0 {
		t.Fatalf("kept = %+v, want none", second.Findings)
	}
	byWhy := map[string]int{}
	for _, f := range second.Suppressed {
		byWhy[f.SuppressWhy]++
	}
	if byWhy["inline"] != 1 || byWhy["accepted earlier"] != 1 {
		t.Fatalf("suppressed by reason = %v, want one inline and one baseline", byWhy)
	}
	if len(second.Errors) != 0 {
		t.Fatalf("errors = %v, want none", second.Errors)
	}
}

func TestInlineHandlesNilAndEmptyInput(t *testing.T) {
	kept, suppressed, errs := applyInlineSuppressions(nil, nil)
	if len(kept) != 0 || len(suppressed) != 0 || len(errs) != 0 {
		t.Fatalf("nil input = %v/%v/%v", kept, suppressed, errs)
	}

	file := &rules.File{Path: "empty.go"}
	findings := []model.Finding{{RuleID: "TEST-ALPHA", Location: model.Location{Path: "empty.go", StartLine: 1}}}
	kept, suppressed, errs = applyInlineSuppressions(findings, []*rules.File{nil, file})
	if len(kept) != 1 || len(suppressed) != 0 || len(errs) != 0 {
		t.Fatalf("empty file = %v/%v/%v, want the finding kept", kept, suppressed, errs)
	}

	root := t.TempDir()
	res, err := New(inlineRegistry(), nil).Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("empty scan: %v", err)
	}
	if len(res.Findings) != 0 || len(res.Suppressed) != 0 {
		t.Fatalf("empty root findings/suppressed = %d/%d", len(res.Findings), len(res.Suppressed))
	}
}

func TestParseInlineDirectivePrefixes(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
	}{
		{"# vigil:ignore VGL-SEC-001", true},
		{"   // vigil:ignore *", true},
		{"-- vigil:ignore VGL-SEC-001 until=2030-01-01", true},
		{"; vigil:ignore *", true},
		{"value = 1 ; vigil:ignore TEST-ALPHA", true},
		{"VULN = 1; y := 2 // vigil:ignore TEST-ALPHA", true},
		{"<!-- vigil:ignore VGL-SEC-001 -->", true},
		{`password = "x"  # vigil:ignore VGL-SEC-001`, true},
		{`value := 1 // vigil:ignore reason="fixture value"`, true},
		{"x = 1", false},
		{`s = "# vigil:ignore"`, false},
		{"# not a directive", false},
		{"// lowercase:ignore", false},
		{"i--; j = \"// vigil:ignore\"", false},
	}
	for _, tc := range cases {
		d := parseInlineDirective(tc.line)
		if (d != nil) != tc.ok {
			t.Errorf("parseInlineDirective(%q) = %v, ok = %v", tc.line, d, tc.ok)
		}
	}
}

func TestParseInlineDirectiveRuleList(t *testing.T) {
	d := parseInlineDirective(`// vigil:ignore VGL-SEC-001, vgl-web-002 reason="test fixture" until=2030-05-06`)
	if d == nil {
		t.Fatal("directive was not parsed")
	}
	if !d.matches("VGL-SEC-001") || !d.matches("vgl-web-002") {
		t.Errorf("rule list not matched case-insensitively: %+v", d.rules)
	}
	if d.matches("VGL-SEC-003") {
		t.Error("unlisted rule matched")
	}
	if d.why() != "inline: test fixture" {
		t.Errorf("why = %q", d.why())
	}
	if !d.untilSet || d.until.Format(inlineDateLayout) != "2030-05-06" {
		t.Errorf("directive = %+v", d)
	}
}

func TestParseInlineDirectiveRulesAfterOptions(t *testing.T) {
	d := parseInlineDirective(`// vigil:ignore reason=fixture TEST-ALPHA until=2030-05-06`)
	if d == nil {
		t.Fatal("directive was not parsed")
	}
	if !d.matches("TEST-ALPHA") {
		t.Error("rule ID after an option was dropped")
	}
	if d.matches("TEST-BETA") {
		t.Error("directive widened to a rule that was not listed")
	}
	if d.reason != "fixture" {
		t.Errorf("reason = %q, want fixture", d.reason)
	}
	if !d.untilSet || d.until.Format(inlineDateLayout) != "2030-05-06" {
		t.Errorf("until = %+v", d.until)
	}
}

func TestParseInlineDirectiveUnknownOptionDoesNotWiden(t *testing.T) {
	d := parseInlineDirective("// vigil:ignore untill=2030-01-01")
	if d == nil {
		t.Fatal("directive was not parsed")
	}
	if d.matches("TEST-ALPHA") {
		t.Error("an unrecognized option widened the directive to every rule")
	}
}
