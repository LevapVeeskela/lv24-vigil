package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	buildinfo "github.com/levapveeskela/lv24-vigil/internal/version"
)

const (
	sarifSchema         = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion        = "2.1.0"
	vigilInformationURI = "https://github.com/levapveeskela/lv24-vigil"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	Tags      []string `json:"tags"`
	Precision string   `json:"precision"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           *int                  `json:"ruleIndex,omitempty"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations"`
	PartialFingerprints map[string]string     `json:"partialFingerprints"`
	Properties          sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Category   string `json:"category"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int                   `json:"startLine"`
	EndLine     int                   `json:"endLine"`
	StartColumn int                   `json:"startColumn,omitempty"`
	EndColumn   int                   `json:"endColumn,omitempty"`
	Snippet     *sarifArtifactContent `json:"snippet,omitempty"`
}

type sarifArtifactContent struct {
	Text string `json:"text"`
}

func renderSARIF(res *model.ScanResult) ([]byte, error) {
	findings := activeFindings(res)

	rules := make([]sarifRule, 0, len(findings))
	ruleIndex := make(map[string]int, len(findings))
	for _, f := range findings {
		id := sarifRuleID(f)
		if _, ok := ruleIndex[id]; ok {
			continue
		}
		ruleIndex[id] = len(rules)
		rules = append(rules, buildSARIFRule(f))
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, buildSARIFResult(f, ruleIndex[sarifRuleID(f)], res.Root))
	}

	version := strings.TrimSpace(res.Version)
	if version == "" {
		version = strings.TrimSpace(buildinfo.Version)
	}
	if version == "" {
		version = "unknown"
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "vigil",
				InformationURI: vigilInformationURI,
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: marshal sarif: %w", err)
	}
	return append(b, '\n'), nil
}

func sarifRuleID(f model.Finding) string {
	if id := strings.TrimSpace(f.RuleID); id != "" {
		return id
	}
	return "unknown"
}

func buildSARIFRule(f model.Finding) sarifRule {
	id := sarifRuleID(f)

	title := oneLine(f.Title)
	if title == "" {
		title = id
	}
	description := strings.TrimSpace(f.Description)
	if description == "" {
		description = title
	}

	return sarifRule{
		ID:               id,
		Name:             id,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: description},
		HelpURI:          ruleHelpURI(f.References),
		Properties: sarifRuleProperties{
			Tags:      sarifRuleTags(f),
			Precision: sarifPrecision(f.Confidence),
		},
	}
}

func buildSARIFResult(f model.Finding, ruleIndex int, root string) sarifResult {
	idx := ruleIndex
	return sarifResult{
		RuleID:    sarifRuleID(f),
		RuleIndex: &idx,
		Level:     sarifLevel(f.Severity),
		Message:   sarifMessage{Text: sarifMessageText(f)},
		Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: artifactURI(f.Location.Path, root)},
			Region:           sarifRegionFor(f),
		}}},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": findingFingerprint(f),
		},
		Properties: sarifResultProperties{
			Severity:   string(f.Severity),
			Confidence: string(f.Confidence),
			Category:   string(f.Category),
		},
	}
}

func sarifRegionFor(f model.Finding) sarifRegion {
	loc := f.Location
	startLine := loc.StartLine
	if startLine < 1 {
		startLine = 1
	}
	endLine := loc.EndLine
	if endLine < startLine {
		endLine = startLine
	}

	region := sarifRegion{StartLine: startLine, EndLine: endLine}
	if loc.StartColumn > 0 {
		region.StartColumn = loc.StartColumn
		if loc.EndColumn > loc.StartColumn {
			region.EndColumn = loc.EndColumn
		}
	}

	snippet := loc.Snippet
	if strings.TrimSpace(snippet) == "" {
		snippet = f.Evidence
	}
	if strings.TrimSpace(snippet) != "" {
		region.Snippet = &sarifArtifactContent{Text: snippet}
	}
	return region
}

func sarifMessageText(f model.Finding) string {
	if title := oneLine(f.Title); title != "" {
		return title
	}
	if description := oneLine(f.Description); description != "" {
		return description
	}
	return sarifRuleID(f)
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifPrecision(c model.Confidence) string {
	switch c {
	case model.ConfidenceHigh:
		return "high"
	case model.ConfidenceMedium:
		return "medium"
	case model.ConfidenceLow:
		return "low"
	default:
		return "medium"
	}
}

func sarifRuleTags(f model.Finding) []string {
	tags := []string{"security"}
	if f.Category != "" {
		tags = append(tags, string(f.Category))
	}
	if f.Severity != "" {
		tags = append(tags, string(f.Severity))
	}
	tags = append(tags, f.Tags...)
	tags = append(tags, f.CWE...)
	tags = append(tags, f.OWASP...)
	return uniqueSorted(tags)
}

func firstHTTPReference(refs []string) string {
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
			return ref
		}
	}
	return ""
}

// ruleHelpURI always returns a usable URI. Rule-specific references win; the
// project page is a stable fallback so every SARIF rule has helpUri set.
func ruleHelpURI(refs []string) string {
	if ref := firstHTTPReference(refs); ref != "" {
		return ref
	}
	return vigilInformationURI
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// artifactURI converts a filesystem path to a relative, slash-separated SARIF
// URI. Segments are percent-encoded so spaces and non-ASCII names stay valid.
func artifactURI(p, root string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	root = strings.TrimSuffix(strings.ReplaceAll(strings.TrimSpace(root), "\\", "/"), "/")
	p = strings.TrimPrefix(p, "./")

	if root != "" && len(p) > len(root) && p[len(root)] == '/' &&
		strings.EqualFold(p[:len(root)], root) {
		p = p[len(root)+1:]
	}
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}
	p = strings.TrimLeft(p, "/")
	if p == "" {
		return "unknown"
	}
	p = path.Clean(p)
	if p == "." || p == "" {
		return "unknown"
	}

	segments := strings.Split(p, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}
