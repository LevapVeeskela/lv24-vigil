package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Skeptical-review regressions (post 0.7.1). Each test failed before its fix.

// idOnlyServer mimics the real OSV API: querybatch returns only advisory IDs,
// and the full record lives at /v1/vulns/{id}.
func idOnlyServer(t *testing.T, details map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var detailCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var payload queryBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			results := make([]map[string]any, len(payload.Queries))
			for i := range results {
				results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-01-01T00:00:00Z"}}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			detailCalls.Add(1)
			body, ok := details[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(body))
		default:
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &detailCalls
}

func TestAuditHydratesIDOnlyQueryBatchResults(t *testing.T) {
	// Arrange
	srv, calls := idOnlyServer(t, map[string]string{
		"GHSA-aaaa-bbbb-cccc": `{"id":"GHSA-aaaa-bbbb-cccc","summary":"Prototype pollution",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`,
	})
	dir := t.TempDir()
	writeFixture(t, dir, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"t"},"node_modules/lodash":{"version":"4.17.15"}}}`)

	// Act
	res, err := Audit(context.Background(), dir, Options{BaseURL: srv.URL, HTTPClient: srv.Client(), IncludeDev: true})

	// Assert
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %q, want critical from the hydrated CVSS vector", f.Severity)
	}
	if !strings.Contains(f.Remediation, "4.17.21") {
		t.Errorf("remediation should name the fixed version: %q", f.Remediation)
	}
	if !strings.Contains(f.Description, "Prototype pollution") {
		t.Errorf("description should come from the full record: %q", f.Description)
	}
	if calls.Load() != 1 {
		t.Errorf("detail requests = %d, want 1", calls.Load())
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
}

func TestAuditReportsUnhydratedAdvisories(t *testing.T) {
	// Arrange: the detail endpoint knows no record.
	srv, _ := idOnlyServer(t, map[string]string{})
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.0.0\n")

	// Act
	res, err := Audit(context.Background(), dir, Options{BaseURL: srv.URL, HTTPClient: srv.Client(), IncludeDev: true})

	// Assert: the finding stays, but the understated severity is disclosed.
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != model.SeverityMedium {
		t.Fatalf("want one medium fallback finding, got %+v", res.Findings)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "could not be fetched") {
		t.Fatalf("errors = %v, want a hydration warning", res.Errors)
	}
}

func TestAuditRejectsHydratedRecordForDifferentID(t *testing.T) {
	// Arrange: a hostile mirror answers with another advisory.
	srv, _ := idOnlyServer(t, map[string]string{
		"GHSA-aaaa-bbbb-cccc": `{"id":"GHSA-zzzz-zzzz-zzzz","summary":"other","database_specific":{"severity":"LOW"}}`,
	})
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.0.0\n")

	// Act
	res, err := Audit(context.Background(), dir, Options{BaseURL: srv.URL, HTTPClient: srv.Client(), IncludeDev: true})

	// Assert
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Description == "other" {
		t.Fatalf("the mismatched record must not be used: %+v", res.Findings)
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "different advisory") {
		t.Fatalf("errors = %v, want a different-advisory warning", res.Errors)
	}
}

func TestAuditDiscardsMisalignedBatch(t *testing.T) {
	// Arrange: two results for three queries; position-based alignment is lost.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2024-0001","summary":"x"}]},{"vulns":[]}]}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "aaa==1.0.0\nbbb==1.0.0\nccc==1.0.0\n")

	// Act
	res, err := Audit(context.Background(), dir, Options{BaseURL: srv.URL, HTTPClient: srv.Client(), IncludeDev: true})

	// Assert
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("misaligned advisories were attributed: %+v", res.Findings)
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "2 results for 3 queries") {
		t.Fatalf("errors = %v, want the count mismatch", res.Errors)
	}
}

func TestCollectPackagesReportsCoverageGaps(t *testing.T) {
	// Arrange
	dir := t.TempDir()
	writeFixture(t, dir, "broken/package-lock.json", `{not json`)
	writeFixture(t, dir, "big/composer.lock", strings.Repeat(" ", maxManifestBytes+1))
	writeFixture(t, dir, "requirements.txt", "aaa==1.0.0\nbbb==1.0.0\nccc==1.0.0\n")

	// Act
	pkgs, warnings, err := collectPackages(context.Background(), dir, true, 2)

	// Assert
	if err != nil {
		t.Fatalf("collectPackages: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"broken/package-lock.json", "big/composer.lock", "found 3 packages but only the first 2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}
}

// pagedServer returns advisory "GHSA-page-<n>" on page n and a next token
// until lastPage (0 = never stops).
func pagedServer(t *testing.T, lastPage int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload struct {
			Queries []struct {
				PageToken string `json:"page_token"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload.Queries) != 1 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		page := 1
		if tok := payload.Queries[0].PageToken; tok != "" {
			page = int(tok[len(tok)-1]-'0') + 0
		}
		result := map[string]any{"vulns": []map[string]any{{
			"id": "GHSA-page-" + string(rune('0'+page%10)), "summary": "s", "database_specific": map[string]string{"severity": "LOW"},
		}}}
		if lastPage == 0 || page < lastPage {
			result["next_page_token"] = "tok" + string(rune('0'+(page+1)%10))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{result}})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestAuditFollowsQueryBatchPages(t *testing.T) {
	srv, calls := pagedServer(t, 3)
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.0.0\n")

	res, err := Audit(context.Background(), dir, Options{BaseURL: srv.URL, HTTPClient: srv.Client(), IncludeDev: true})

	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("got %d findings, want 3 (one per page): %+v", len(res.Findings), res.Findings)
	}
	if calls.Load() != 3 {
		t.Errorf("requests = %d, want 3", calls.Load())
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
}

func TestAuditStopsEndlessPaginationWithWarning(t *testing.T) {
	srv, calls := pagedServer(t, 0)
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.0.0\n")

	res, err := Audit(context.Background(), dir, Options{BaseURL: srv.URL, HTTPClient: srv.Client(), IncludeDev: true})

	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if got := calls.Load(); got != 1+maxPagesPerPackage {
		t.Errorf("requests = %d, want %d", got, 1+maxPagesPerPackage)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "page limit") {
		t.Fatalf("errors = %v, want a page-limit warning", res.Errors)
	}
}
