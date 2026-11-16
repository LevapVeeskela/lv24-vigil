package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// JUnit renders every active finding as a failing test case and every
// suppressed finding as a skipped one. Bounds keep one hostile finding from
// producing an arbitrarily large file.
const (
	junitMaxMessage  = 512
	junitMaxEvidence = 2048
	junitTruncated   = "... (truncated)"
	// junitEpoch keeps the timestamp attribute valid and deterministic when a
	// stored result has no start time.
	junitEpoch = "1970-01-01T00:00:00Z"
)

func renderJUnit(res *model.ScanResult) ([]byte, error) {
	active := activeFindings(res)
	suppressed := suppressedFindings(res)
	total := len(active) + len(suppressed)
	duration := junitTime(res)

	timestamp := junitEpoch
	if !res.StartedAt.IsZero() {
		timestamp = res.StartedAt.UTC().Format(time.RFC3339)
	}

	counts := []xml.Attr{
		xmlAttr("tests", strconv.Itoa(total)),
		xmlAttr("failures", strconv.Itoa(len(active))),
		xmlAttr("errors", "0"),
		xmlAttr("skipped", strconv.Itoa(len(suppressed))),
		xmlAttr("time", duration),
	}

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")

	suites := xml.StartElement{
		Name: xml.Name{Local: "testsuites"},
		Attr: append([]xml.Attr{xmlAttr("name", "vigil")}, counts...),
	}
	if err := enc.EncodeToken(suites); err != nil {
		return nil, fmt.Errorf("report: encode junit: %w", err)
	}

	suite := xml.StartElement{
		Name: xml.Name{Local: "testsuite"},
		Attr: append(append([]xml.Attr{xmlAttr("name", "vigil")}, counts...), xmlAttr("timestamp", timestamp)),
	}
	if err := enc.EncodeToken(suite); err != nil {
		return nil, fmt.Errorf("report: encode junit: %w", err)
	}

	for _, f := range active {
		if err := writeJUnitCase(enc, f, false); err != nil {
			return nil, fmt.Errorf("report: encode junit: %w", err)
		}
	}
	for _, f := range suppressed {
		if err := writeJUnitCase(enc, f, true); err != nil {
			return nil, fmt.Errorf("report: encode junit: %w", err)
		}
	}

	if err := enc.EncodeToken(suite.End()); err != nil {
		return nil, fmt.Errorf("report: encode junit: %w", err)
	}
	if err := enc.EncodeToken(suites.End()); err != nil {
		return nil, fmt.Errorf("report: encode junit: %w", err)
	}
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("report: encode junit: %w", err)
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// writeJUnitCase emits one testcase. The rule ID is the classname and the
// finding title is the name, so a dashboard groups repeats of one rule.
func writeJUnitCase(enc *xml.Encoder, f model.Finding, suppressed bool) error {
	ruleID := strings.TrimSpace(f.RuleID)
	if ruleID == "" {
		ruleID = "unknown"
	}
	name := bounded(oneLine(f.Title), junitMaxMessage)
	if name == "" {
		name = bounded(oneLine(f.Description), junitMaxMessage)
	}
	if name == "" {
		name = ruleID
	}

	start := xml.StartElement{Name: xml.Name{Local: "testcase"}, Attr: []xml.Attr{
		xmlAttr("classname", ruleID),
		xmlAttr("name", name),
		xmlAttr("time", "0"),
	}}
	if err := enc.EncodeToken(start); err != nil {
		return err
	}

	if suppressed {
		reason := bounded(oneLine(f.SuppressWhy), junitMaxMessage)
		if reason == "" {
			reason = "suppressed"
		}
		if err := encodeEmptyElement(enc, "skipped", []xml.Attr{xmlAttr("message", reason)}); err != nil {
			return err
		}
	} else {
		severity := strings.TrimSpace(string(f.Severity))
		if severity == "" {
			severity = "unknown"
		}
		attrs := []xml.Attr{
			xmlAttr("message", name),
			xmlAttr("type", severity),
		}
		if err := encodeTextElement(enc, "failure", attrs, junitFailureBody(f)); err != nil {
			return err
		}
	}

	return enc.EncodeToken(start.End())
}

// junitFailureBody carries the location and the bounded rule evidence.
func junitFailureBody(f model.Finding) string {
	parts := make([]string, 0, 2)
	if location := strings.TrimSpace(oneLine(pathLine(f.Location))); location != "" {
		parts = append(parts, location)
	}
	if evidence := strings.TrimSpace(bounded(f.Evidence, junitMaxEvidence)); evidence != "" {
		parts = append(parts, evidence)
	}
	return strings.Join(parts, "\n\n")
}

// junitTime reports the scan duration in seconds with millisecond precision.
func junitTime(res *model.ScanResult) string {
	ms := res.Stats.DurationMS
	if ms <= 0 && !res.StartedAt.IsZero() && !res.FinishedAt.IsZero() {
		ms = res.FinishedAt.Sub(res.StartedAt).Milliseconds()
	}
	if ms < 0 {
		ms = 0
	}
	return strconv.FormatFloat(float64(ms)/1000, 'f', 3, 64)
}

// bounded truncates s to at most max bytes on a rune boundary and marks the
// cut, so long evidence cannot bloat the report or split a UTF-8 sequence.
func bounded(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimRight(s[:cut], " \t\r\n") + junitTruncated
}

func xmlAttr(name, value string) xml.Attr {
	return xml.Attr{Name: xml.Name{Local: name}, Value: value}
}

func encodeEmptyElement(enc *xml.Encoder, name string, attrs []xml.Attr) error {
	start := xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs}
	if err := enc.EncodeToken(start); err != nil {
		return err
	}
	return enc.EncodeToken(start.End())
}

func encodeTextElement(enc *xml.Encoder, name string, attrs []xml.Attr, text string) error {
	start := xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs}
	if err := enc.EncodeToken(start); err != nil {
		return err
	}
	if text != "" {
		if err := enc.EncodeToken(xml.CharData(text)); err != nil {
			return err
		}
	}
	return enc.EncodeToken(start.End())
}
