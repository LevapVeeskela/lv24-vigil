package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type capturedRequest struct {
	path        string
	method      string
	contentType string
	userAgent   string
	payload     queryBatchRequest
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestScanQueriesAndMapsVulnerabilities(t *testing.T) {
	ghsa := vulnerability{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Aliases: []string{"CVE-2021-33203"},
		Summary: "Django path traversal",
		Details: "<p>Some <b>details</b> &amp; more.</p>",
		Severity: []severityEntry{
			{Type: "CVSS_V3", Score: "9.8"},
		},
		Affected: []affected{{
			Package: packageRef{Name: "django", Ecosystem: ecosystemPyPI},
			Ranges: []affectedRange{{
				Type:   "ECOSYSTEM",
				Events: []rangeEvent{{Introduced: "0"}, {Fixed: "3.2.4"}},
			}},
		}},
		DatabaseSpecific: databaseSpecific{Severity: "HIGH", CWEIDs: []string{"CWE-22"}},
		References:       []reference{{Type: "WEB", URL: "https://example.test/advisory"}},
		Published:        "2021-05-06T00:00:00Z",
		Modified:         "2021-06-01T00:00:00Z",
	}
	cve := vulnerability{
		ID:               "CVE-2023-32681",
		Aliases:          []string{"GHSA-j8r2-6x86-q33q"},
		Summary:          "Requests proxy leak",
		Severity:         []severityEntry{{Type: "CVSS_V3", Score: "6.1"}},
		DatabaseSpecific: databaseSpecific{Severity: "MODERATE", CWEIDs: []string{"CWE-918"}},
		References:       []reference{{Type: "WEB", URL: "https://example.test/requests"}},
	}

	requests := make(chan capturedRequest, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload queryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requests <- capturedRequest{
			path:        r.URL.Path,
			method:      r.Method,
			contentType: r.Header.Get("Content-Type"),
			userAgent:   r.Header.Get("User-Agent"),
			payload:     payload,
		}
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{
			{Vulns: []vulnerability{ghsa}},
			{Vulns: []vulnerability{cve}},
		}})
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "django==3.2.0\nrequests==2.19.0\n")

	findings, err := Scan(context.Background(), dir, Options{BaseURL: srv.URL, IncludeDev: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	got := <-requests
	if got.path != "/v1/querybatch" {
		t.Errorf("path = %q, want /v1/querybatch", got.path)
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.method)
	}
	if got.contentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", got.contentType)
	}
	if !strings.HasPrefix(got.userAgent, "lv24-vigil/") {
		t.Errorf("user-agent = %q, want lv24-vigil/<version>", got.userAgent)
	}
	if len(got.payload.Queries) != 2 {
		t.Fatalf("got %d queries, want 2", len(got.payload.Queries))
	}
	first := got.payload.Queries[0]
	if first.Package.Name != "django" || first.Package.Ecosystem != "PyPI" || first.Version != "3.2.0" {
		t.Errorf("unexpected first query: %+v", first)
	}

	critical := findings[0]
	if critical.RuleID != "VGL-OSV-GHSA-XXXX-YYYY-ZZZZ" {
		t.Errorf("rule id = %q", critical.RuleID)
	}
	if critical.Title != "Vulnerable dependency django@3.2.0 (GHSA-xxxx-yyyy-zzzz)" {
		t.Errorf("title = %q", critical.Title)
	}
	if critical.Severity != model.SeverityCritical {
		t.Errorf("severity = %q, want critical", critical.Severity)
	}
	if critical.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q, want high", critical.Confidence)
	}
	if critical.Category != model.CategoryDependency {
		t.Errorf("category = %q, want dependency", critical.Category)
	}
	if critical.Source != model.SourceRule {
		t.Errorf("source = %q, want rule", critical.Source)
	}
	if critical.Location.Path != "requirements.txt" || critical.Location.StartLine != 1 {
		t.Errorf("location = %+v", critical.Location)
	}
	if critical.Evidence != "django@3.2.0 (PyPI)" {
		t.Errorf("evidence = %q", critical.Evidence)
	}
	if !strings.Contains(critical.Description, "Django path traversal") {
		t.Errorf("description lost the summary: %q", critical.Description)
	}
	if !strings.Contains(critical.Description, "Some details & more.") {
		t.Errorf("description lost the details: %q", critical.Description)
	}
	if strings.Contains(critical.Description, "<p>") {
		t.Errorf("description kept HTML markup: %q", critical.Description)
	}
	if !strings.Contains(critical.Remediation, "3.2.4") {
		t.Errorf("remediation does not name the fixed version: %q", critical.Remediation)
	}
	if !strings.Contains(critical.Remediation, "https://example.test/advisory") {
		t.Errorf("remediation does not reference the advisory: %q", critical.Remediation)
	}
	if !containsString(critical.References, "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz") {
		t.Errorf("references missing the OSV permalink: %v", critical.References)
	}
	if len(critical.CWE) != 1 || critical.CWE[0] != "CWE-22" {
		t.Errorf("cwe = %v, want [CWE-22]", critical.CWE)
	}
	if critical.ID == "" || critical.Fingerprint == "" {
		t.Error("finding was not normalised")
	}

	medium := findings[1]
	if medium.RuleID != "VGL-OSV-CVE-2023-32681" {
		t.Errorf("rule id = %q", medium.RuleID)
	}
	if medium.Severity != model.SeverityMedium {
		t.Errorf("severity = %q, want medium", medium.Severity)
	}
	if medium.Remediation != "Upgrade requests to a fixed version. See https://example.test/requests." {
		t.Errorf("remediation = %q", medium.Remediation)
	}
}

func TestScanBatchesQueries(t *testing.T) {
	payloads := make(chan queryBatchRequest, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload queryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payloads <- payload
		results := make([]queryResult, len(payload.Queries))
		for i := range results {
			results[i].Vulns = []vulnerability{{ID: fmt.Sprintf("CVE-2024-%04d", i), Summary: "batch"}}
		}
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: results})
	}))
	defer srv.Close()

	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&b, "pkg%03d==1.0.0\n", i)
	}
	writeFixture(t, dir, "requirements.txt", b.String())

	findings, err := Scan(context.Background(), dir, Options{
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
		IncludeDev: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 150 {
		t.Fatalf("got %d findings, want 150", len(findings))
	}
	if len(payloads) != 2 {
		t.Fatalf("got %d batches, want 2", len(payloads))
	}
	first := <-payloads
	second := <-payloads
	if len(first.Queries) != 100 {
		t.Errorf("first batch has %d queries, want 100", len(first.Queries))
	}
	if len(second.Queries) != 50 {
		t.Errorf("second batch has %d queries, want 50", len(second.Queries))
	}
}

func TestScanFailOpenOnHTTPError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var payload queryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		results := make([]queryResult, len(payload.Queries))
		for i := range results {
			results[i].Vulns = []vulnerability{{ID: fmt.Sprintf("CVE-2024-%04d", i), Summary: "first batch"}}
		}
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: results})
	}))
	defer srv.Close()

	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 101; i++ {
		fmt.Fprintf(&b, "pkg%03d==1.0.0\n", i)
	}
	writeFixture(t, dir, "requirements.txt", b.String())

	findings, err := Scan(context.Background(), dir, Options{BaseURL: srv.URL, IncludeDev: true})
	if err == nil {
		t.Fatal("expected an error for the failed batch")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention the status: %v", err)
	}
	if len(findings) != 100 {
		t.Fatalf("got %d findings, want the 100 collected before the failure", len(findings))
	}
}

func TestScanContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.31.0\n")

	findings, err := Scan(context.Background(), dir, Options{
		BaseURL:    srv.URL,
		Timeout:    50 * time.Millisecond,
		IncludeDev: true,
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if findings != nil {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestScanMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results": [`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.31.0\n")

	findings, err := Scan(context.Background(), dir, Options{BaseURL: srv.URL, IncludeDev: true})
	if err == nil {
		t.Fatal("expected a decode error")
	}
	if findings != nil {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestScanResultCountMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results": []}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.31.0\n")

	findings, err := Scan(context.Background(), dir, Options{BaseURL: srv.URL, IncludeDev: true})
	if err == nil {
		t.Fatal("expected a result-count error")
	}
	if !strings.Contains(err.Error(), "results") {
		t.Errorf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestScanEmptyRepoMakesNoRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"results": []}`))
	}))
	defer srv.Close()

	findings, err := Scan(context.Background(), t.TempDir(), Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if findings != nil {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if calls.Load() != 0 {
		t.Fatalf("expected no HTTP calls, got %d", calls.Load())
	}
}

func TestScanMissingRoot(t *testing.T) {
	_, err := Scan(context.Background(), filepath.Join(t.TempDir(), "missing"), Options{})
	if err == nil {
		t.Fatal("expected an error for a missing root")
	}
}

func TestScanInvalidBaseURL(t *testing.T) {
	_, err := Scan(context.Background(), t.TempDir(), Options{BaseURL: "ftp://example.test"})
	if err == nil {
		t.Fatal("expected an error for a non-http base URL")
	}
}

func TestScanDeduplicatesAdvisories(t *testing.T) {
	vuln := vulnerability{ID: "CVE-2024-1234", Summary: "duplicate"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{
			{Vulns: []vulnerability{vuln, vuln}},
		}})
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.31.0\n")

	findings, err := Scan(context.Background(), dir, Options{BaseURL: srv.URL, IncludeDev: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 after dedupe", len(findings))
	}
}

func TestOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.MaxPackages != DefaultMaxPackages {
		t.Errorf("MaxPackages = %d, want %d", o.MaxPackages, DefaultMaxPackages)
	}
	if o.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", o.Timeout, DefaultTimeout)
	}
	if o.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", o.BaseURL, DefaultBaseURL)
	}
	if o.IncludeDev {
		t.Error("a zero Options value cannot enable IncludeDev; DefaultOptions must be used")
	}

	d := DefaultOptions()
	if !d.IncludeDev {
		t.Error("DefaultOptions must include dev dependencies")
	}
	if d.MaxPackages != DefaultMaxPackages || d.Timeout != DefaultTimeout || d.BaseURL != DefaultBaseURL {
		t.Errorf("unexpected DefaultOptions: %+v", d)
	}

	o = Options{MaxPackages: 5000, Timeout: time.Second, BaseURL: "https://example.test/"}.withDefaults()
	if o.MaxPackages != MaxAllowedPackages {
		t.Errorf("MaxPackages = %d, want the hard cap %d", o.MaxPackages, MaxAllowedPackages)
	}
	if o.BaseURL != "https://example.test" {
		t.Errorf("BaseURL = %q, want the trailing slash removed", o.BaseURL)
	}
}

func TestRuleIDFor(t *testing.T) {
	tests := map[string]string{
		"GHSA-xxxx-yyyy-zzzz": "VGL-OSV-GHSA-XXXX-YYYY-ZZZZ",
		"CVE-2024-1234":       "VGL-OSV-CVE-2024-1234",
		"GHSA/xx y":           "VGL-OSV-GHSA-XX-Y",
		"":                    "",
	}
	for in, want := range tests {
		if got := ruleIDFor(in); got != want {
			t.Errorf("ruleIDFor(%q) = %q, want %q", in, got, want)
		}
	}
	long := ruleIDFor(strings.Repeat("A", 200))
	if len(long) > ruleIDMaxLen {
		t.Errorf("rule id is %d bytes, want <= %d", len(long), ruleIDMaxLen)
	}
	if !strings.HasPrefix(long, "VGL-OSV-") {
		t.Errorf("rule id lost its prefix: %q", long)
	}
}

func TestFindingForReferencesAndLocation(t *testing.T) {
	pkg := Package{Name: "pkg", Version: "1.0.2", Ecosystem: ecosystemNPM, Manifest: "package-lock.json", Line: 3}
	refs := make([]reference, 7)
	for i := range refs {
		refs[i] = reference{URL: fmt.Sprintf("https://ref.test/%d", i)}
	}
	f, ok := findingFor(pkg, vulnerability{ID: "CVE-2024-9999", References: refs})
	if !ok {
		t.Fatal("findingFor returned false")
	}
	if len(f.References) != 6 {
		t.Fatalf("got %d references, want 5 advisory links plus the OSV permalink", len(f.References))
	}
	if !containsString(f.References, "https://osv.dev/vulnerability/CVE-2024-9999") {
		t.Errorf("references missing the OSV permalink: %v", f.References)
	}
	if f.Location.Path != "package-lock.json" || f.Location.StartLine != 3 {
		t.Errorf("location = %+v", f.Location)
	}
	if f.Evidence != "pkg@1.0.2 (npm)" {
		t.Errorf("evidence = %q", f.Evidence)
	}
}

func TestFixedVersion(t *testing.T) {
	pkg := Package{Name: "pkg", Version: "1.0.2", Ecosystem: ecosystemNPM}
	vuln := vulnerability{Affected: []affected{
		{
			Package: packageRef{Name: "pkg", Ecosystem: ecosystemNPM},
			Ranges: []affectedRange{{Events: []rangeEvent{
				{Fixed: "1.0.1"}, {Fixed: "1.0.5"}, {Fixed: "1.0.3"},
			}}},
		},
		{
			Package: packageRef{Name: "other", Ecosystem: ecosystemNPM},
			Ranges:  []affectedRange{{Events: []rangeEvent{{Fixed: "9.9.9"}}}},
		},
	}}
	if got := fixedVersion(pkg, vuln); got != "1.0.3" {
		t.Fatalf("fixedVersion = %q, want the smallest fixed version above 1.0.2", got)
	}

	older := vulnerability{Affected: []affected{{
		Ranges: []affectedRange{{Events: []rangeEvent{{Fixed: "0.9.0"}}}},
	}}}
	if got := fixedVersion(pkg, older); got != "0.9.0" {
		t.Fatalf("fixedVersion = %q, want the first fixed event as fallback", got)
	}

	none := vulnerability{Affected: []affected{{
		Ranges: []affectedRange{{Events: []rangeEvent{{Introduced: "0"}}}},
	}}}
	if got := fixedVersion(pkg, none); got != "" {
		t.Fatalf("fixedVersion = %q, want empty", got)
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0-rc1", 1},
		{"v1.2.3", "1.2.3", 0},
		{"1.10.0", "1.9.0", 1},
		{"1.9.0", "1.10.0", -1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
	}
	for _, tc := range tests {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDescriptionFor(t *testing.T) {
	got := descriptionFor(vulnerability{
		Summary: "Summary",
		Details: "<p>Hello <b>world</b> &amp; friends.</p>",
	})
	if got != "Summary\n\nHello world & friends." {
		t.Fatalf("descriptionFor = %q", got)
	}

	long := descriptionFor(vulnerability{Details: strings.Repeat("a", 5000)})
	if r := []rune(long); len(r) != maxDetailChars+1 {
		t.Fatalf("description has %d runes, want %d", len(r), maxDetailChars+1)
	}
	if !strings.HasSuffix(long, "…") {
		t.Fatalf("truncated description should end with an ellipsis: %q", long[len(long)-10:])
	}

	duplicate := descriptionFor(vulnerability{Summary: "Same", Details: "Same text"})
	if duplicate != "Same text" {
		t.Fatalf("description should not repeat the summary: %q", duplicate)
	}
}
