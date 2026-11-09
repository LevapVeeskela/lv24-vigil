// Package osv enriches a dependency scan with known vulnerabilities from the
// OSV.dev database.
//
// The package is deliberately narrow: it reads dependency manifests from a
// repository, asks the public OSV API about the exact package versions it found
// and turns every advisory into a model.Finding. It never writes to the scanned
// tree, never executes package-manager code and never sends telemetry. The only
// network traffic is the documented OSV querybatch endpoint.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

const (
	// DefaultMaxPackages bounds how many distinct packages one scan queries.
	DefaultMaxPackages = 200
	// MaxAllowedPackages is the hard ceiling for Options.MaxPackages. A hostile
	// project configuration must not be able to turn one scan into thousands of
	// API calls.
	MaxAllowedPackages = 1000
	// DefaultBaseURL is the public OSV API.
	DefaultBaseURL = "https://api.osv.dev"
	// DefaultTimeout is the per-request timeout.
	DefaultTimeout = 20 * time.Second

	// queryBatchSize is the number of packages per querybatch call. OSV allows
	// larger batches, but 100 keeps request and response bodies small and lets a
	// failure lose at most one batch of work.
	queryBatchSize = 100
	// maxResponseBytes bounds how much of an OSV response is read.
	maxResponseBytes = 16 << 20
	// maxReferences is the number of advisory references copied to a finding.
	// The OSV permalink is appended on top of these.
	maxReferences = 5
	// maxDetailChars truncates the free-form advisory body.
	maxDetailChars = 1200
	// ruleIDMaxLen keeps RuleID within the size the reporters expect.
	ruleIDMaxLen = 80
	// osvVulnURL is the human-readable permalink prefix.
	osvVulnURL = "https://osv.dev/vulnerability/"
)

// Options controls one OSV scan. The zero value is usable, but note the
// IncludeDev caveat: Go cannot distinguish an unset bool from false, so callers
// that want the documented "include dev dependencies" default should start from
// DefaultOptions.
type Options struct {
	// MaxPackages caps the number of distinct packages queried. Default 200,
	// hard cap 1000.
	MaxPackages int
	// Timeout is the per-request HTTP timeout. Default 20s.
	Timeout time.Duration
	// HTTPClient overrides the HTTP client. When nil a client with Timeout is
	// created. A supplied client is used as-is; the per-request context still
	// carries Timeout.
	HTTPClient *http.Client
	// IncludeDev also queries devDependencies, composer packages-dev and
	// Maven test-scoped dependencies. DefaultOptions sets it to true; a zero
	// Options value leaves it false.
	IncludeDev bool
	// BaseURL is the OSV API root. Default https://api.osv.dev.
	BaseURL string
}

// DefaultOptions returns the documented defaults.
func DefaultOptions() Options {
	return Options{
		MaxPackages: DefaultMaxPackages,
		Timeout:     DefaultTimeout,
		IncludeDev:  true,
		BaseURL:     DefaultBaseURL,
	}
}

// withDefaults fills unset numeric, duration and URL fields. IncludeDev is
// intentionally left alone; see Options.
func (o Options) withDefaults() Options {
	if o.MaxPackages <= 0 {
		o.MaxPackages = DefaultMaxPackages
	}
	if o.MaxPackages > MaxAllowedPackages {
		o.MaxPackages = MaxAllowedPackages
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	o.BaseURL = strings.TrimRight(strings.TrimSpace(o.BaseURL), "/")
	if o.BaseURL == "" {
		o.BaseURL = DefaultBaseURL
	}
	return o
}

// Scan reads dependency manifests under root, asks the OSV.dev API about every
// package it found and returns one finding per advisory.
//
// Scan is fail-open: when a request fails, the findings collected so far are
// returned together with the error, so a flaky network never hides the
// deterministic results that were already available.
//
// Scan performs no writes and sends no telemetry. The only network traffic is
// the OSV querybatch endpoint at Options.BaseURL.
func Scan(ctx context.Context, root string, opts Options) ([]model.Finding, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = opts.withDefaults()

	baseURL, err := normalizeBaseURL(opts.BaseURL)
	if err != nil {
		return nil, err
	}

	packages, err := collectPackages(ctx, root, opts.IncludeDev, opts.MaxPackages)
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, nil
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}

	var findings []model.Finding
	var firstErr error
	for start := 0; start < len(packages); start += queryBatchSize {
		end := start + queryBatchSize
		if end > len(packages) {
			end = len(packages)
		}
		batch := packages[start:end]

		results, queryErr := queryBatch(ctx, client, baseURL, opts.Timeout, batch)
		// Convert whatever the API returned before recording the error: a
		// truncated response still carries useful advisories.
		for i, res := range results {
			if i >= len(batch) {
				break
			}
			for _, vuln := range res.Vulns {
				if finding, ok := findingFor(batch[i], vuln); ok {
					findings = append(findings, finding)
				}
			}
		}
		if queryErr != nil {
			firstErr = queryErr
			break
		}
	}

	findings = dedupeFindings(findings)
	model.SortFindings(findings)
	return findings, firstErr
}

// normalizeBaseURL validates the API root so a bad configuration fails fast
// instead of turning into a confusing request error later.
func normalizeBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		s = DefaultBaseURL
	}
	s = strings.TrimRight(s, "/")
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("osv: invalid base URL %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("osv: base URL %q must be an absolute http(s) URL", raw)
	}
	return s, nil
}

// queryBatch sends one querybatch request and returns the results in the same
// order as pkgs. A result-count mismatch is reported as an error together with
// the results that were present.
func queryBatch(ctx context.Context, client *http.Client, baseURL string, timeout time.Duration, pkgs []Package) ([]queryResult, error) {
	body := queryBatchRequest{Queries: make([]query, 0, len(pkgs))}
	for _, p := range pkgs {
		body.Queries = append(body.Queries, query{
			Package: packageRef{Name: p.Name, Ecosystem: p.Ecosystem},
			Version: p.Version,
		})
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("osv: encode query: %w", err)
	}

	reqCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/v1/querybatch", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: querybatch: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("osv: read response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("osv: response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("osv: querybatch: unexpected status %d: %s", resp.StatusCode, summarizeBody(data))
	}

	var out queryBatchResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("osv: decode response: %w", err)
	}
	if len(out.Results) != len(pkgs) {
		return out.Results, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(out.Results), len(pkgs))
	}
	return out.Results, nil
}

func userAgent() string {
	v := strings.TrimSpace(version.Version)
	if v == "" {
		v = "dev"
	}
	return "lv24-vigil/" + strings.ReplaceAll(v, " ", "-")
}

func summarizeBody(data []byte) string {
	s := strings.Join(strings.Fields(string(data)), " ")
	if r := []rune(s); len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

// findingFor converts one advisory into a finding for pkg.
func findingFor(pkg Package, vuln vulnerability) (model.Finding, bool) {
	id := strings.TrimSpace(vuln.ID)
	if id == "" && len(vuln.Aliases) > 0 {
		id = strings.TrimSpace(vuln.Aliases[0])
	}
	ruleID := ruleIDFor(id)
	if ruleID == "" {
		return model.Finding{}, false
	}

	line := pkg.Line
	if line <= 0 {
		line = 1
	}
	f := model.Finding{
		RuleID:      ruleID,
		Title:       fmt.Sprintf("Vulnerable dependency %s@%s (%s)", pkg.Name, pkg.Version, id),
		Description: descriptionFor(vuln),
		Severity:    severityFor(vuln),
		Confidence:  model.ConfidenceHigh,
		Category:    model.CategoryDependency,
		CWE:         cwesFor(vuln),
		Location:    model.Location{Path: pkg.Manifest, StartLine: line},
		Evidence:    fmt.Sprintf("%s@%s (%s)", pkg.Name, pkg.Version, pkg.Ecosystem),
		Remediation: remediationFor(pkg, vuln),
		References:  referencesFor(vuln),
		Source:      model.SourceRule,
	}
	f.Normalize()
	return f, true
}

// ruleIDFor derives a stable rule id from an advisory id. Characters that are
// not safe in a rule id are replaced, and the result is capped at 80 bytes.
func ruleIDFor(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(id) + len("VGL-OSV-"))
	b.WriteString("VGL-OSV-")
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if len(out) > ruleIDMaxLen {
		out = strings.TrimRight(out[:ruleIDMaxLen], "-")
	}
	return out
}

var htmlTagRe = regexp.MustCompile(`(?s)<[^>]*>`)

// descriptionFor joins the advisory summary with a bounded, plain-text body.
func descriptionFor(vuln vulnerability) string {
	summary := stripHTML(vuln.Summary)
	details := stripHTML(vuln.Details)
	if r := []rune(details); len(r) > maxDetailChars {
		details = string(r[:maxDetailChars]) + "…"
	}
	switch {
	case summary == "":
		return details
	case details == "":
		return summary
	case strings.HasPrefix(details, summary):
		return details
	default:
		return summary + "\n\n" + details
	}
}

// stripHTML removes markup and collapses whitespace so reports stay readable
// and terminal-safe.
func stripHTML(s string) string {
	if s == "" {
		return ""
	}
	s = htmlTagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

// referencesFor copies at most five advisory references and appends the OSV
// permalink.
func referencesFor(vuln vulnerability) []string {
	out := make([]string, 0, maxReferences+1)
	seen := make(map[string]bool, maxReferences+1)
	add := func(raw string) bool {
		u := strings.TrimSpace(raw)
		if u == "" || seen[u] {
			return false
		}
		seen[u] = true
		out = append(out, u)
		return true
	}
	count := 0
	for _, ref := range vuln.References {
		if count >= maxReferences {
			break
		}
		if add(ref.URL) {
			count++
		}
	}
	if id := strings.TrimSpace(vuln.ID); id != "" {
		add(osvVulnURL + id)
	} else if len(vuln.Aliases) > 0 {
		if alias := strings.TrimSpace(vuln.Aliases[0]); alias != "" {
			add(osvVulnURL + alias)
		}
	}
	return out
}

// remediationFor names the next fixed version when the advisory provides one.
func remediationFor(pkg Package, vuln vulnerability) string {
	fixed := fixedVersion(pkg, vuln)
	ref := ""
	for _, r := range vuln.References {
		if u := strings.TrimSpace(r.URL); u != "" {
			ref = u
			break
		}
	}

	var b strings.Builder
	if fixed != "" {
		fmt.Fprintf(&b, "Upgrade %s to %s or later.", pkg.Name, fixed)
	} else {
		fmt.Fprintf(&b, "Upgrade %s to a fixed version.", pkg.Name)
	}
	if ref != "" {
		fmt.Fprintf(&b, " See %s.", ref)
	}
	return b.String()
}

// fixedVersion returns the smallest fixed event that is newer than the installed
// version, falling back to the first fixed event when none compares newer (for
// example when the advisory lists a later vulnerable interval).
func fixedVersion(pkg Package, vuln vulnerability) string {
	var candidates []string
	for _, a := range vuln.Affected {
		if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, pkg.Name) {
			continue
		}
		if a.Package.Ecosystem != "" && !strings.EqualFold(a.Package.Ecosystem, pkg.Ecosystem) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if strings.TrimSpace(e.Fixed) != "" {
					candidates = append(candidates, strings.TrimSpace(e.Fixed))
				}
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}

	best := ""
	for _, c := range candidates {
		if compareVersions(c, pkg.Version) <= 0 {
			continue
		}
		if best == "" || compareVersions(c, best) < 0 {
			best = c
		}
	}
	if best != "" {
		return best
	}
	return candidates[0]
}

// compareVersions is a loose ordering for version strings. It is only used to
// pick a sensible fixed version from an advisory; it is not a package-manager
// implementation. Segments are split on '.', '-', '+' and '_'; numeric segments
// compare numerically and sort after a non-numeric pre-release label, so
// "1.0.0" > "1.0.0-rc1".
func compareVersions(a, b string) int {
	as := versionSegments(a)
	bs := versionSegments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xi, xErr := strconv.Atoi(x)
		yi, yErr := strconv.Atoi(y)
		switch {
		case xErr == nil && yErr == nil:
			if xi != yi {
				if xi < yi {
					return -1
				}
				return 1
			}
		case xErr == nil:
			return 1
		case yErr == nil:
			return -1
		default:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

func versionSegments(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '+' || r == '_'
	})
	return fields
}

// dedupeFindings removes duplicates by rule, path and line.
func dedupeFindings(in []model.Finding) []model.Finding {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.Finding, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, f := range in {
		key := f.RuleID + "\x00" + f.Location.Path + "\x00" + strconv.Itoa(f.Location.StartLine)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// queryBatchRequest is the wire shape of POST /v1/querybatch.
type queryBatchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package packageRef `json:"package"`
	Version string     `json:"version,omitempty"`
}

type packageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryBatchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns []vulnerability `json:"vulns"`
}

// vulnerability mirrors the OSV schema fields the engine consumes.
type vulnerability struct {
	ID               string           `json:"id"`
	Aliases          []string         `json:"aliases"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Severity         []severityEntry  `json:"severity"`
	Affected         []affected       `json:"affected"`
	DatabaseSpecific databaseSpecific `json:"database_specific"`
	References       []reference      `json:"references"`
	Published        string           `json:"published"`
	Modified         string           `json:"modified"`
}

type severityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type affected struct {
	Package  packageRef      `json:"package"`
	Ranges   []affectedRange `json:"ranges"`
	Versions []string        `json:"versions"`
}

type affectedRange struct {
	Type   string       `json:"type"`
	Events []rangeEvent `json:"events"`
}

type rangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
