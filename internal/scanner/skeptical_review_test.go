package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// Regression: a secret rule masks the value it reports, but an unrelated rule
// that fires on the same or a neighbouring line quoted the source verbatim in
// its evidence and three-line snippet. The raw credential then reached JSON,
// SARIF, the MCP result and the stored scan.
func TestScanRedactsDetectedSecretsInOtherFindings(t *testing.T) {
	const (
		password = "Xk9#mN2vB7qR4tLw"
		ghToken  = "ghp_SYNTHETIC0000000000000000000000000000"
	)
	root := t.TempDir()
	writeTestFile(t, root, "app.py", strings.Join([]string{
		"import os",
		"from flask import request",
		"DB_PASSWORD = \"" + password + "\"",
		"os.system(\"ls \" + request.args[\"d\"])  # token " + ghToken,
		"print(\"done\")",
		"",
	}, "\n"))

	s := New(rules.Default(), nil)
	res, err := s.Scan(context.Background(), Options{Root: root, NoBaseline: true, MinSeverity: model.SeverityInfo})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var injection, secret *model.Finding
	for i := range res.Findings {
		f := &res.Findings[i]
		switch {
		case f.Location.StartLine == 4 && f.Category == model.CategoryInjection:
			injection = f
		case f.Location.StartLine == 3 && f.Category == model.CategorySecrets:
			secret = f
		}
	}
	if injection == nil || secret == nil {
		t.Fatalf("fixture needs an injection finding on line 4 and a secret finding on line 3, got %+v", res.Findings)
	}

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, value := range []string{password, ghToken} {
		if strings.Contains(string(raw), value) {
			t.Errorf("the scan result contains the raw credential %q", value)
		}
	}
	if !strings.Contains(injection.Location.Snippet, "os.system") {
		t.Errorf("the snippet lost its code: %q", injection.Location.Snippet)
	}
	for i := range res.Findings {
		if len(res.Findings[i].SecretValues) != 0 {
			t.Errorf("finding %s still carries raw secret values", res.Findings[i].RuleID)
		}
	}

	// Masking happens after IDs and fingerprints are fixed, so an existing
	// baseline entry for the injection finding stays valid.
	unmasked := model.Finding{
		RuleID:   injection.RuleID,
		Location: model.Location{Path: injection.Location.Path, StartLine: injection.Location.StartLine},
		Evidence: "os.system(\"ls \" + request.args[\"d\"])  # token " + ghToken,
	}
	if got, want := injection.Fingerprint, unmasked.ComputeFingerprint(); got != want {
		t.Errorf("fingerprint changed: got %s, want %s (existing baselines would stop matching)", got, want)
	}
}

func TestRedactSecretsIgnoresShortValues(t *testing.T) {
	got := rules.RedactSecrets("retry = 3 and mode = abc", []string{"abc", "3"})
	if got != "retry = 3 and mode = abc" {
		t.Fatalf("short values must not be replaced, got %q", got)
	}
}

// Regression: with a rule list present, an unrecognized key=value token was
// dropped silently. A mistyped expiry ("untill=", or the baseline's
// "expires=") therefore suppressed the finding forever and emitted nothing.
// Like an invalid until date, such a directive must fail closed and say why.
func TestInlineUnknownOptionWithRuleListFailsClosed(t *testing.T) {
	for _, directive := range []string{
		"// vigil:ignore TEST-ALPHA untill=2020-01-01",
		"// vigil:ignore TEST-ALPHA expires=2020-01-01",
		"// vigil:ignore TEST-ALPHA,TEST-BETA expiry=2020-01-01 reason=legacy",
	} {
		res := scanInline(t, directive+"\nVULN = 1\n", Options{})
		if len(res.Suppressed) != 0 {
			t.Errorf("%q suppressed %d finding(s), want none", directive, len(res.Suppressed))
		}
		if joined := strings.Join(res.Errors, "\n"); !strings.Contains(joined, "unrecognized option") {
			t.Errorf("%q emitted no warning: %v", directive, res.Errors)
		}
	}

	// The documented options still work next to a rule list.
	res := scanInline(t, "// vigil:ignore TEST-ALPHA reason=fixture until=2999-01-01\nVULN = 1\n", Options{})
	if len(res.Suppressed) != 1 || res.Suppressed[0].RuleID != "TEST-ALPHA" {
		t.Fatalf("a valid directive stopped working: %+v", res.Suppressed)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("a valid directive emitted warnings: %v", res.Errors)
	}
}

// Regression: an unterminated quote swallowed the rest of the comment, rule
// list included, which widened the directive to every rule.
func TestInlineUnterminatedQuoteFailsClosed(t *testing.T) {
	res := scanInline(t, "// vigil:ignore reason=\"unterminated TEST-NOPE\nVULN = 1\n", Options{})
	if len(res.Suppressed) != 0 {
		t.Fatalf("an unterminated quote suppressed %d finding(s): %+v", len(res.Suppressed), res.Suppressed)
	}
	if joined := strings.Join(res.Errors, "\n"); !strings.Contains(joined, "unterminated quote") {
		t.Fatalf("no warning for the unterminated quote: %v", res.Errors)
	}
}

// Regression: an entry key the loader does not know was ignored. An expiry
// written as "expiry" (or "until") therefore produced a permanent suppression
// that "baseline list" showed without a date. An unknown key must be rejected
// so the mistake is visible and nothing is suppressed on its strength.
func TestLoadBaselineRejectsUnknownEntryField(t *testing.T) {
	for name, body := range map[string]string{
		"expiry": `{"version":2,"findings":[{"id":"VGL-0000000001","fingerprint":"fp_0000000000000001","expiry":"2020-01-01"}]}`,
		"until":  `{"version":2,"findings":[{"id":"VGL-0000000001","until":"2020-01-01"}]}`,
	} {
		path := filepath.Join(t.TempDir(), "baseline.json")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBaseline(path); err == nil {
			t.Errorf("a baseline entry with the unknown key %q was accepted", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not name the unknown key %q: %v", name, err)
		}
	}

	// Every key this build writes is still accepted, in both file versions.
	for name, body := range map[string]string{
		"v2": `{"version":2,"fingerprints":[],"findings":[{"id":"VGL-0000000001","reason":"r","fingerprint":"fp_0000000000000001","ruleId":"TEST-1","path":"a.go","ticket":"T-1","expires":"2999-01-01"}]}`,
		"v1": `{"version":1,"fingerprints":["fp_0000000000000001"],"findings":[{"id":"VGL-0000000001","reason":"r"}]}`,
	} {
		path := filepath.Join(t.TempDir(), "baseline.json")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBaseline(path); err != nil {
			t.Errorf("%s baseline rejected: %v", name, err)
		}
	}
}
