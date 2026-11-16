package report

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type junitXMLOutcome struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitXMLCase struct {
	Classname string           `xml:"classname,attr"`
	Name      string           `xml:"name,attr"`
	Time      string           `xml:"time,attr"`
	Failure   *junitXMLOutcome `xml:"failure"`
	Skipped   *junitXMLOutcome `xml:"skipped"`
}

type junitXMLSuite struct {
	Name      string         `xml:"name,attr"`
	Tests     int            `xml:"tests,attr"`
	Failures  int            `xml:"failures,attr"`
	Errors    int            `xml:"errors,attr"`
	Skipped   int            `xml:"skipped,attr"`
	Time      string         `xml:"time,attr"`
	Timestamp string         `xml:"timestamp,attr"`
	Cases     []junitXMLCase `xml:"testcase"`
}

type junitXMLSuites struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Skipped  int             `xml:"skipped,attr"`
	Time     string          `xml:"time,attr"`
	Suites   []junitXMLSuite `xml:"testsuite"`
}

func decodeJUnit(t *testing.T, out []byte) junitXMLSuites {
	t.Helper()
	if !bytes.HasPrefix(out, []byte(xml.Header)) {
		t.Fatalf("JUnit output does not start with the XML header:\n%s", out)
	}
	var suites junitXMLSuites
	if err := xml.Unmarshal(out, &suites); err != nil {
		t.Fatalf("JUnit output is not valid XML: %v\n%s", err, out)
	}
	if len(suites.Suites) != 1 {
		t.Fatalf("testsuites has %d suite(s), want 1", len(suites.Suites))
	}
	return suites
}

func junitCaseByClass(t *testing.T, suite junitXMLSuite, classname string) junitXMLCase {
	t.Helper()
	for _, c := range suite.Cases {
		if c.Classname == classname {
			return c
		}
	}
	t.Fatalf("no testcase with classname %q", classname)
	return junitXMLCase{}
}

func TestRenderJUnitCountsAndShape(t *testing.T) {
	out, err := Render(FormatJUnit, sampleResult(), Options{})
	if err != nil {
		t.Fatalf("Render(junit): %v", err)
	}
	suites := decodeJUnit(t, out)
	suite := suites.Suites[0]

	if suites.Tests != 5 || suites.Failures != 4 || suites.Errors != 0 || suites.Skipped != 1 {
		t.Errorf("testsuites counts = tests %d, failures %d, errors %d, skipped %d; want 5/4/0/1",
			suites.Tests, suites.Failures, suites.Errors, suites.Skipped)
	}
	if suite.Tests != 5 || suite.Failures != 4 || suite.Errors != 0 || suite.Skipped != 1 {
		t.Errorf("testsuite counts = %d/%d/%d/%d, want 5/4/0/1",
			suite.Tests, suite.Failures, suite.Errors, suite.Skipped)
	}
	if len(suite.Cases) != 5 {
		t.Fatalf("testcase count = %d, want 5", len(suite.Cases))
	}
	if suites.Name != "vigil" || suite.Name != "vigil" {
		t.Errorf("names = %q/%q, want vigil", suites.Name, suite.Name)
	}
	if suites.Time != "0.123" || suite.Time != "0.123" {
		t.Errorf("time = %q/%q, want 0.123", suites.Time, suite.Time)
	}
	if got := strings.Count(string(out), `name="vigil"`); got != 2 {
		t.Errorf("name attribute appears %d times, want 2 (testsuites and testsuite)", got)
	}
	if suite.Timestamp != "2026-02-03T04:05:00Z" {
		t.Errorf("timestamp = %q", suite.Timestamp)
	}

	critical := junitCaseByClass(t, suite, "go/sql-injection")
	if critical.Failure == nil {
		t.Fatalf("active finding has no failure element: %+v", critical)
	}
	if critical.Name != "SQL injection" {
		t.Errorf("name = %q, want the finding title", critical.Name)
	}
	if critical.Failure.Message != "SQL injection" || critical.Failure.Type != "critical" {
		t.Errorf("failure = %+v, want the title and severity", critical.Failure)
	}
	for _, want := range []string{"internal/db/query name.go:42-44", "SELECT * FROM users"} {
		if !strings.Contains(critical.Failure.Body, want) {
			t.Errorf("failure body missing %q:\n%s", want, critical.Failure.Body)
		}
	}

	suppressed := junitCaseByClass(t, suite, "secrets/hardcoded")
	if suppressed.Failure != nil {
		t.Errorf("suppressed finding has a failure element: %+v", suppressed.Failure)
	}
	if suppressed.Skipped == nil {
		t.Fatalf("suppressed finding has no skipped element: %+v", suppressed)
	}
	if !strings.Contains(suppressed.Skipped.Message, "baseline") {
		t.Errorf("skipped message = %q, want the suppression reason", suppressed.Skipped.Message)
	}
}

func TestJUnitEscaping(t *testing.T) {
	res := emptyResult()
	res.Findings = []model.Finding{{
		ID:         "VGL-ESC000001",
		RuleID:     "web/xss",
		Title:      `<script>alert("x") & 'quoted'</script>`,
		Severity:   model.SeverityHigh,
		Evidence:   `if (a < b && c > d) { return "x" & 'y'; }`,
		Location:   model.Location{Path: "web/<view>.html", StartLine: 4},
		Suppressed: false,
		Source:     model.SourceRule,
	}}

	out, err := Render("junit", res, Options{})
	if err != nil {
		t.Fatalf("Render(junit): %v", err)
	}
	if strings.Contains(string(out), "<script>") {
		t.Fatalf("unescaped markup in JUnit output:\n%s", out)
	}
	if !strings.Contains(string(out), "&lt;script&gt;") {
		t.Fatalf("JUnit output does not contain escaped markup:\n%s", out)
	}

	suite := decodeJUnit(t, out).Suites[0]
	c := junitCaseByClass(t, suite, "web/xss")
	if c.Name != res.Findings[0].Title {
		t.Errorf("name = %q, want the raw title back after parsing", c.Name)
	}
	if c.Failure == nil {
		t.Fatal("missing failure element")
	}
	if c.Failure.Message != res.Findings[0].Title {
		t.Errorf("message = %q, want the raw title", c.Failure.Message)
	}
	if !strings.Contains(c.Failure.Body, res.Findings[0].Evidence) {
		t.Errorf("body lost the evidence:\n%s", c.Failure.Body)
	}
	if !strings.Contains(c.Failure.Body, "web/<view>.html:4") {
		t.Errorf("body lost the location:\n%s", c.Failure.Body)
	}
}

func TestJUnitBoundsLongFields(t *testing.T) {
	long := strings.Repeat("A", 5000)
	res := emptyResult()
	res.Findings = []model.Finding{{
		ID:       "VGL-LONG000001",
		RuleID:   "rule/long",
		Title:    long,
		Severity: model.SeverityMedium,
		Evidence: long,
		Location: model.Location{Path: "a.go", StartLine: 1},
		Source:   model.SourceRule,
	}}

	out, err := Render("junit", res, Options{})
	if err != nil {
		t.Fatalf("Render(junit): %v", err)
	}
	c := junitCaseByClass(t, decodeJUnit(t, out).Suites[0], "rule/long")
	if c.Failure == nil {
		t.Fatal("missing failure element")
	}
	if len(c.Failure.Message) > junitMaxMessage+len(junitTruncated) {
		t.Errorf("message is %d bytes, want at most %d", len(c.Failure.Message), junitMaxMessage+len(junitTruncated))
	}
	if !strings.HasSuffix(c.Failure.Message, junitTruncated) {
		t.Errorf("message was not marked as truncated: %q", c.Failure.Message)
	}
	if len(c.Failure.Body) > junitMaxEvidence+len(junitTruncated)+len("a.go:1\n\n") {
		t.Errorf("body is %d bytes, want at most %d", len(c.Failure.Body), junitMaxEvidence+len(junitTruncated)+len("a.go:1\n\n"))
	}
	if !utf8.ValidString(c.Failure.Body) || !utf8.ValidString(c.Failure.Message) {
		t.Error("truncation split a UTF-8 sequence")
	}

	// Multi-byte runes must be cut on a boundary too.
	multibyte := emptyResult()
	multibyte.Findings = []model.Finding{{
		RuleID:   "rule/utf8",
		Title:    strings.Repeat("é", 5000),
		Evidence: strings.Repeat("é", 5000),
		Severity: model.SeverityLow,
		Location: model.Location{Path: "a.go", StartLine: 1},
		Source:   model.SourceRule,
	}}
	utf8Out, uerr := Render("junit", multibyte, Options{})
	if uerr != nil {
		t.Fatalf("Render(junit) utf8: %v", uerr)
	}
	utf8Case := junitCaseByClass(t, decodeJUnit(t, utf8Out).Suites[0], "rule/utf8")
	if utf8Case.Failure == nil || !utf8.ValidString(utf8Case.Failure.Body) {
		t.Error("multi-byte truncation produced invalid UTF-8")
	}
}

func TestJUnitAttributesAreUnique(t *testing.T) {
	out, err := Render("junit", sampleResult(), Options{})
	if err != nil {
		t.Fatalf("Render(junit): %v", err)
	}
	dec := xml.NewDecoder(bytes.NewReader(out))
	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			return
		}
		if terr != nil {
			t.Fatalf("JUnit is not valid XML: %v", terr)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		seen := make(map[string]bool, len(start.Attr))
		for _, attr := range start.Attr {
			if seen[attr.Name.Local] {
				t.Fatalf("<%s> has a duplicate %q attribute", start.Name.Local, attr.Name.Local)
			}
			seen[attr.Name.Local] = true
		}
	}
}

func TestJUnitEmptyResult(t *testing.T) {
	out, err := Render("junit", emptyResult(), Options{})
	if err != nil {
		t.Fatalf("Render(junit) empty: %v", err)
	}
	suites := decodeJUnit(t, out)
	if suites.Tests != 0 || suites.Failures != 0 || suites.Skipped != 0 || suites.Errors != 0 {
		t.Errorf("empty counts = %+v", suites)
	}
	if len(suites.Suites[0].Cases) != 0 {
		t.Errorf("empty result produced %d testcases", len(suites.Suites[0].Cases))
	}
}

func TestJUnitFormatAliasesAndDeterminism(t *testing.T) {
	res := sampleResult()
	first, err := Render("junit", res, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"JUNIT", ".junit"} {
		out, err := Render(format, res, Options{})
		if err != nil {
			t.Fatalf("Render(%q): %v", format, err)
		}
		if !bytes.Equal(out, first) {
			t.Errorf("Render(%q) differs from Render(junit)", format)
		}
	}
	second, err := Render("junit", res, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("JUnit output is not deterministic")
	}
}

func TestWriteJUnitMatchesRender(t *testing.T) {
	res := sampleResult()
	want, err := Render("junit", res, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, "junit", res, Options{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Error("Write output differs from Render output")
	}
}

func TestJUnitReplacesControlCharacters(t *testing.T) {
	res := emptyResult()
	res.Findings = []model.Finding{{
		ID:       "VGL-CTRL000001",
		RuleID:   "rule/nul\x00byte",
		Title:    "nul \x00 and start-of-heading \x01",
		Severity: model.SeverityHigh,
		Evidence: "before\x00middle\x01after",
		Location: model.Location{Path: "a\x00b.go", StartLine: 1},
		Source:   model.SourceRule,
	}}

	out, err := Render("junit", res, Options{})
	if err != nil {
		t.Fatalf("Render(junit): %v", err)
	}
	for _, control := range []byte{0x00, 0x01} {
		if bytes.IndexByte(out, control) >= 0 {
			t.Fatalf("JUnit output contains raw control byte %#x:\n%q", control, out)
		}
	}
	if !utf8.Valid(out) {
		t.Fatal("JUnit output is not valid UTF-8")
	}

	// A successful decode proves the control characters were substituted with
	// a legal XML character instead of producing a document parsers reject.
	suites := decodeJUnit(t, out)
	c := junitCaseByClass(t, suites.Suites[0], "rule/nul\uFFFDbyte")
	if c.Name != "nul \uFFFD and start-of-heading \uFFFD" {
		t.Errorf("name = %q, want the control characters replaced with U+FFFD", c.Name)
	}
	if c.Failure == nil {
		t.Fatal("missing failure element")
	}
	if !strings.Contains(c.Failure.Body, "before\uFFFDmiddle\uFFFDafter") {
		t.Errorf("body = %q, want the control characters replaced with U+FFFD", c.Failure.Body)
	}

	again, err := Render("junit", res, Options{})
	if err != nil {
		t.Fatalf("Render(junit) second pass: %v", err)
	}
	if !bytes.Equal(out, again) {
		t.Error("control-character substitution is not deterministic")
	}
}

func TestBoundedKeepsShortStrings(t *testing.T) {
	if got := bounded("short", 512); got != "short" {
		t.Errorf("bounded(short) = %q", got)
	}
	if got := bounded("", 10); got != "" {
		t.Errorf("bounded(empty) = %q", got)
	}
	if got := bounded("abcdef", 3); got != "abc"+junitTruncated {
		t.Errorf("bounded(abcdef, 3) = %q", got)
	}
}
