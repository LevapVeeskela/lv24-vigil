package osv

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// databaseSpecific is the tolerant view of the free-form OSV
// database_specific object. Records in the wild use different shapes (GitHub
// uses LOW/MODERATE/HIGH/CRITICAL, others use cwe_ids as numbers), so a shape we
// do not understand is ignored instead of failing the whole batch.
type databaseSpecific struct {
	Severity string   `json:"severity,omitempty"`
	CWEIDs   []string `json:"cwe_ids,omitempty"`
}

func (d *databaseSpecific) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var sev string
	if err := json.Unmarshal(raw["severity"], &sev); err == nil {
		d.Severity = sev
	}
	var ids []json.RawMessage
	if err := json.Unmarshal(raw["cwe_ids"], &ids); err == nil {
		for _, item := range ids {
			var s string
			if err := json.Unmarshal(item, &s); err == nil {
				d.CWEIDs = append(d.CWEIDs, s)
				continue
			}
			var n int
			if err := json.Unmarshal(item, &n); err == nil {
				d.CWEIDs = append(d.CWEIDs, "CWE-"+strconv.Itoa(n))
			}
		}
	}
	return nil
}

var (
	cweRe      = regexp.MustCompile(`(?i)\bCWE[-_ ]?(\d{1,5})\b`)
	mitreCweRe = regexp.MustCompile(`(?i)cwe\.mitre\.org/data/definitions/(\d{1,5})`)
)

// severityFor picks the highest severity band any signal supports:
//
//  1. a numeric CVSS score or a CVSS vector from severity[];
//  2. database_specific.severity (GHSA uses CRITICAL/HIGH/MODERATE/LOW);
//  3. medium, the conservative default for an advisory without a rating.
//
// The signals are combined with max instead of first-match: a CVSS v4 vector is
// only approximated (see severityFromVector), and an advisory is never less
// severe than the band its own database assigned, so a gate such as
// --fail-on high must not pass because one representation rounded down.
func severityFor(vuln vulnerability) model.Severity {
	best := model.Severity("")
	raise := func(sev model.Severity) {
		if best == "" || sev.Rank() > best.Rank() {
			best = sev
		}
	}
	for _, entry := range vuln.Severity {
		if sev, ok := severityFromScore(entry.Score); ok {
			raise(sev)
		}
	}
	if sev, ok := severityFromBand(vuln.DatabaseSpecific.Severity); ok {
		raise(sev)
	}
	if best != "" {
		return best
	}
	return model.SeverityMedium
}

// severityFromScore accepts either a numeric CVSS base score ("9.8") or a
// vector ("CVSS:3.1/AV:N/...").
func severityFromScore(score string) (model.Severity, bool) {
	s := strings.TrimSpace(score)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(strings.ToUpper(s), "CVSS:") || strings.Contains(s, "AV:") {
		return severityFromVector(s)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f > 10 {
		return "", false
	}
	return severityFromCVSSScore(f), true
}

// severityFromCVSSScore maps a CVSS base score to the standard bands.
func severityFromCVSSScore(score float64) model.Severity {
	switch {
	case score >= 9.0:
		return model.SeverityCritical
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// severityFromVector derives a severity band from a CVSS vector.
//
//   - CVSS v3.0/v3.1: the official base-score formula.
//   - CVSS v2: the official base-score formula.
//   - CVSS v4.0: the official score needs the macro-vector lookup table, which
//     this scanner does not ship. The vulnerable-system metrics are mapped onto
//     the v3.1 formula instead (VC/VI/VA as C/I/A, any subsequent-system impact
//     as a changed scope, AT:P as high attack complexity, UI:P/A as required
//     interaction). severityFor combines the result with the database band so
//     the approximation cannot lower a rated advisory.
//
// A vector that is missing base metrics falls back to an additive estimate; a
// vector without any impact metric yields no signal.
func severityFromVector(vector string) (model.Severity, bool) {
	metrics := parseCVSSMetrics(vector)
	switch cvssVersion(metrics) {
	case 3:
		if score, ok := cvss3BaseScore(metrics); ok {
			return severityFromCVSSScore(score), true
		}
	case 4:
		if score, ok := cvss3BaseScore(cvss4AsV3Metrics(metrics)); ok {
			return severityFromCVSSScore(score), true
		}
	case 2:
		if score, ok := cvss2BaseScore(metrics); ok {
			return severityFromCVSSScore(score), true
		}
	}
	return severityFromVectorEstimate(metrics)
}

func parseCVSSMetrics(vector string) map[string]string {
	metrics := make(map[string]string, 16)
	for _, part := range strings.Split(vector, "/") {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		value = strings.ToUpper(strings.TrimSpace(value))
		if key == "" || value == "" {
			continue
		}
		metrics[key] = value
	}
	return metrics
}

// cvssVersion returns the major CVSS version of a vector, or 0 when it cannot
// be told. CVSS v2 vectors usually carry no "CVSS:" prefix and are recognised
// by their Au metric.
func cvssVersion(metrics map[string]string) int {
	switch v := metrics["CVSS"]; {
	case strings.HasPrefix(v, "3."):
		return 3
	case strings.HasPrefix(v, "4."):
		return 4
	case strings.HasPrefix(v, "2."):
		return 2
	}
	if _, ok := metrics["AU"]; ok {
		return 2
	}
	if _, ok := metrics["VC"]; ok {
		return 4
	}
	if _, ok := metrics["S"]; ok {
		return 3
	}
	return 0
}

// cvss3BaseScore implements the CVSS v3.1 base-score equations. It reports
// false when a base metric is missing or has an unknown value.
func cvss3BaseScore(m map[string]string) (float64, bool) {
	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	c, ok4 := cvss3Impact(m["C"])
	i, ok5 := cvss3Impact(m["I"])
	a, ok6 := cvss3Impact(m["A"])
	scope := m["S"]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || (scope != "U" && scope != "C") {
		return 0, false
	}
	changed := scope == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	total := impact + exploitability
	if changed {
		total *= 1.08
	}
	return cvssRoundUp(math.Min(total, 10)), true
}

func cvss3Impact(value string) (float64, bool) {
	switch value {
	case "H":
		return 0.56, true
	case "L":
		return 0.22, true
	case "N":
		return 0, true
	default:
		return 0, false
	}
}

// cvssRoundUp is the CVSS v3.1 Roundup function: the smallest number with one
// decimal place that is not below x, computed on integers so floating-point
// noise cannot push a score across a band boundary.
func cvssRoundUp(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// cvss4AsV3Metrics maps the CVSS v4.0 vulnerable-system metrics onto v3.1
// names. See severityFromVector for why this is an approximation.
func cvss4AsV3Metrics(m map[string]string) map[string]string {
	out := map[string]string{
		"AV": m["AV"],
		"AC": m["AC"],
		"PR": m["PR"],
		"C":  m["VC"],
		"I":  m["VI"],
		"A":  m["VA"],
		"S":  "U",
		"UI": "R",
	}
	if m["AT"] == "P" {
		out["AC"] = "H"
	}
	if m["UI"] == "N" {
		out["UI"] = "N"
	}
	for _, key := range []string{"SC", "SI", "SA"} {
		if v := m[key]; v == "H" || v == "L" {
			out["S"] = "C"
		}
	}
	return out
}

// cvss2BaseScore implements the CVSS v2 base-score equations.
func cvss2BaseScore(m map[string]string) (float64, bool) {
	av, ok1 := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
	ac, ok2 := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
	au, ok3 := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}[m["AU"]]
	impactValue := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	c, ok4 := impactValue[m["C"]]
	i, ok5 := impactValue[m["I"]]
	a, ok6 := impactValue[m["A"]]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0, false
	}
	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	if impact == 0 {
		return 0, true
	}
	exploitability := 20 * av * ac * au
	score := (0.6*impact + 0.4*exploitability - 1.5) * 1.176
	return math.Round(score*10) / 10, true
}

// severityFromVectorEstimate is the fallback for a vector that is missing base
// metrics. It adds the impact weights (H or complete = 2, L or partial = 1) to
// coarse exploitability terms; a vector without any impact metric yields no
// signal, one whose impacts are all "none" is informational, and any real
// impact is at least low.
func severityFromVectorEstimate(metrics map[string]string) (model.Severity, bool) {
	// v4 uses VC/VI/VA for the vulnerable system; v3 and v2 use C/I/A.
	impact := 0
	seenImpact := false
	for _, key := range []string{"VC", "VI", "VA", "C", "I", "A"} {
		value, ok := metrics[key]
		if !ok {
			continue
		}
		seenImpact = true
		impact += impactWeight(value)
	}
	if !seenImpact {
		return "", false
	}
	if impact == 0 {
		return model.SeverityInfo, true
	}

	score := float64(impact)
	switch metrics["AV"] {
	case "N":
		score += 2
	case "A":
		score++
	case "P":
		score--
	}
	if metrics["AC"] == "L" {
		score++
	}
	switch metrics["PR"] {
	case "N":
		score++
	case "H":
		score--
	}
	// CVSS v2 calls the privilege metric Au instead of PR.
	if metrics["AU"] == "N" {
		score++
	}
	if metrics["AT"] == "P" {
		score--
	}

	// Any real impact is at least low.
	if score < 1 {
		score = 1
	}
	if score > 10 {
		score = 10
	}
	return severityFromCVSSScore(score), true
}

// impactWeight maps CVSS impact values. P and C are the CVSS v2 "partial" and
// "complete" values.
func impactWeight(value string) int {
	switch value {
	case "H", "C":
		return 2
	case "L", "P":
		return 1
	default:
		return 0
	}
}

// severityFromBand understands the textual ratings used by OSV records.
func severityFromBand(band string) (model.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(band)) {
	case "critical":
		return model.SeverityCritical, true
	case "high":
		return model.SeverityHigh, true
	case "moderate", "medium":
		return model.SeverityMedium, true
	case "low":
		return model.SeverityLow, true
	case "info", "informational", "none", "negligible":
		return model.SeverityInfo, true
	default:
		return "", false
	}
}

// cwesFor collects CWE identifiers from database_specific.cwe_ids and from
// reference URLs (cwe.mitre.org links carry the number in the path).
func cwesFor(vuln vulnerability) []string {
	var out []string
	seen := make(map[string]bool, len(vuln.DatabaseSpecific.CWEIDs)+2)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		m := cweRe.FindStringSubmatch(raw)
		if m == nil {
			m = mitreCweRe.FindStringSubmatch(raw)
		}
		if m == nil {
			return
		}
		id := "CWE-" + m[1]
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, id := range vuln.DatabaseSpecific.CWEIDs {
		add(id)
	}
	for _, ref := range vuln.References {
		add(ref.URL)
	}
	return out
}
