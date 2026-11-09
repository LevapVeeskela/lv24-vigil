package osv

import (
	"encoding/json"
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

// severityFor picks the most reliable severity signal available:
//
//  1. a numeric CVSS score or a CVSS v3/v4 vector from severity[];
//  2. database_specific.severity (GHSA uses CRITICAL/HIGH/MODERATE/LOW);
//  3. medium, the conservative default for an advisory without a rating.
//
// When severity[] carries several entries the highest band wins, because an
// advisory with both v3 and v4 ratings is not less severe than its worst
// representation.
func severityFor(vuln vulnerability) model.Severity {
	best := model.Severity("")
	for _, entry := range vuln.Severity {
		sev, ok := severityFromScore(entry.Score)
		if !ok {
			continue
		}
		if best == "" || sev.Rank() > best.Rank() {
			best = sev
		}
	}
	if best != "" {
		return best
	}
	if sev, ok := severityFromBand(vuln.DatabaseSpecific.Severity); ok {
		return sev
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

// severityFromVector derives a severity band from a CVSS vector without
// implementing the full specification. The official base score is a piecewise
// formula; this scanner only needs a defensible band, so it uses a documented
// heuristic:
//
//	impact = sum of C/I/A (v3) or VC/VI/VA (v4) with H=2, L=1, N=0
//	score  = impact
//	         +2 network / +1 adjacent / -1 physical (AV)
//	         +1 low attack complexity (AC:L)
//	         +1 no privileges required / -1 high privileges (PR or v2 Au)
//	         -1 when attack requirements are present (AT:P, v4)
//
// A vector with any impact is never rated below low; a vector with no impact at
// all (C:N/I:N/A:N) is informational. The heuristic intentionally rounds up at
// band boundaries rather than hiding a real vulnerability behind a lower band.
func severityFromVector(vector string) (model.Severity, bool) {
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

// impactWeight maps CVSS impact values. P is the CVSS v2 "partial" value.
func impactWeight(value string) int {
	switch value {
	case "H":
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
