package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	precheckTestToken = "test-staff-jwt-ops-security-scans"

	precheckTestSARIF = `{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "vigil", "version": "0.3.0"}},
      "results": [
        {
          "ruleId": "go/sql-injection",
          "level": "error",
          "message": {"text": "raw SQL built from a request value"},
          "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "db.go"}, "region": {"startLine": 12}}}
          ]
        }
      ]
    }
  ]
}`

	precheckTestCreated = `{"id":"0f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b","createdAt":"2026-11-10T09:15:00Z",` +
		`"actor":"44444444-4444-4444-4444-444444444444","target":"lv24/lv24","commit":"6b7ae2e",` +
		`"tool":"vigil","toolVersion":"0.3.0",` +
		`"summary":{"total":6,"error":1,"warning":2,"note":3,"byRule":{"go/sql-injection":1}}}`
)

func writePrecheckTestSARIF(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vigil.sarif")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	return path
}

// precheckTestServer counts every request so a local validation failure can be
// proven to stop before any network call.
func precheckTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestPrecheckUploadsSARIF(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	var got precheckRequest
	var method, gotPath, auth, contentType string
	server, calls := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		gotPath = r.URL.Path
		auth = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("request body is not JSON: %v\n%s", err, body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, precheckTestCreated)
	})

	out, stderr, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL+"/",
		"--token", precheckTestToken,
		"--target", "lv24/lv24",
		"--commit", "6b7ae2e",
		"--tool-version", "0.3.0",
	)
	if err != nil {
		t.Fatalf("precheck: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls.Load())
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if gotPath != precheckEndpoint {
		t.Errorf("path = %q, want %q (the trailing slash on --api must be trimmed)", gotPath, precheckEndpoint)
	}
	if auth != "Bearer "+precheckTestToken {
		t.Errorf("Authorization = %q, want a bearer token", auth)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if got.Target != "lv24/lv24" || got.Commit != "6b7ae2e" {
		t.Errorf("target/commit = %q/%q", got.Target, got.Commit)
	}
	if got.Tool != "vigil" {
		t.Errorf("tool = %q, want vigil", got.Tool)
	}
	if got.ToolVersion != "0.3.0" {
		t.Errorf("toolVersion = %q, want 0.3.0", got.ToolVersion)
	}
	var sent struct {
		Version string `json:"version"`
		Runs    []any  `json:"runs"`
	}
	if err := json.Unmarshal(got.SARIF, &sent); err != nil {
		t.Fatalf("sarif in the request body is not JSON: %v", err)
	}
	if sent.Version != "2.1.0" || len(sent.Runs) != 1 {
		t.Errorf("sarif = version %q, %d runs; want 2.1.0 and 1 run", sent.Version, len(sent.Runs))
	}

	want := "precheck 0f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b created: 1 error / 2 warning / 3 note\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if strings.Contains(out, precheckTestToken) || strings.Contains(stderr, precheckTestToken) {
		t.Error("the staff JWT leaked to the terminal")
	}
}

func TestPrecheckTokenFromEnv(t *testing.T) {
	t.Setenv(precheckTokenEnv, "env-staff-jwt")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	var auth string
	server, _ := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, precheckTestCreated)
	})

	if _, _, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL,
		"--target", "lv24/lv24",
	); err != nil {
		t.Fatalf("precheck: %v", err)
	}
	if auth != "Bearer env-staff-jwt" {
		t.Errorf("Authorization = %q, want the env token", auth)
	}
}

func TestPrecheckJSONOutput(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	server, _ := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, precheckTestCreated)
	})

	out, _, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL,
		"--token", precheckTestToken,
		"--target", "lv24/lv24",
		"--json",
	)
	if err != nil {
		t.Fatalf("precheck --json: %v", err)
	}
	var res struct {
		ID      string `json:"id"`
		Summary struct {
			Error   int `json:"error"`
			Warning int `json:"warning"`
			Note    int `json:"note"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if res.ID != "0f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b" {
		t.Errorf("id = %q", res.ID)
	}
	if res.Summary.Error != 1 || res.Summary.Warning != 2 || res.Summary.Note != 3 {
		t.Errorf("summary = %+v", res.Summary)
	}
	if strings.Contains(out, "created:") {
		t.Errorf("--json must not mix the human line into stdout:\n%s", out)
	}
}

func TestPrecheckInvalidSARIFResponse(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	server, _ := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"INVALID_SARIF","message":"sarif.runs[0].results[0].message.text is required"}`)
	})

	_, _, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL,
		"--token", precheckTestToken,
		"--target", "lv24/lv24",
	)
	if err == nil {
		t.Fatal("expected an error for a 400 response")
	}
	for _, want := range []string{"HTTP 400", "INVALID_SARIF", "message.text is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestPrecheckServerError(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	server, _ := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"code":"INTERNAL","message":"pre-check store unavailable"}`)
	})

	_, _, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL,
		"--token", precheckTestToken,
		"--target", "lv24/lv24",
	)
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	for _, want := range []string{"HTTP 500", "pre-check store unavailable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestPrecheckMissingToken(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	server, calls := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request must be sent without a token")
	})

	_, _, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL,
		"--target", "lv24/lv24",
	)
	if err == nil {
		t.Fatal("expected an error without a token")
	}
	for _, want := range []string{"--token", precheckTokenEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestPrecheckMissingFile(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	missing := filepath.Join(t.TempDir(), "vigil.sarif")

	server, calls := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request must be sent for a missing file")
	})

	_, _, err := runCLI(t, "precheck",
		"--sarif", missing,
		"--api", server.URL,
		"--token", precheckTestToken,
		"--target", "lv24/lv24",
	)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if !strings.Contains(err.Error(), "vigil.sarif") {
		t.Errorf("error %q does not name the missing file", err)
	}
	if calls.Load() != 0 {
		t.Errorf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestPrecheckMissingTarget(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	_, _, err := runCLI(t, "precheck", "--sarif", sarifPath, "--token", precheckTestToken)
	if err == nil || !strings.Contains(err.Error(), "--target") {
		t.Fatalf("err = %v, want a --target hint", err)
	}
}

func TestPrecheckInvalidSARIFVersion(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, `{"version":"2.0.0","runs":[{"results":[]}]}`)

	server, calls := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("an invalid SARIF must not reach the control plane")
	})

	_, _, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL,
		"--token", precheckTestToken,
		"--target", "lv24/lv24",
	)
	if err == nil {
		t.Fatal("expected an error for a 2.0.0 SARIF")
	}
	if !strings.Contains(err.Error(), "2.1.") || !strings.Contains(err.Error(), "2.0.0") {
		t.Errorf("error %q does not explain the version requirement", err)
	}
	if calls.Load() != 0 {
		t.Errorf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestPrecheckTokenNotPrintedOnUnauthorized(t *testing.T) {
	t.Setenv(precheckTokenEnv, "")
	sarifPath := writePrecheckTestSARIF(t, precheckTestSARIF)

	server, _ := precheckTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":"UNAUTHORIZED","message":"staff JWT required"}`)
	})

	out, stderr, err := runCLI(t, "precheck",
		"--sarif", sarifPath,
		"--api", server.URL,
		"--token", precheckTestToken,
		"--target", "lv24/lv24",
	)
	if err == nil {
		t.Fatal("expected an error for a 401 response")
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("error %q does not mention HTTP 401", err)
	}
	if strings.Contains(err.Error(), precheckTestToken) ||
		strings.Contains(out, precheckTestToken) ||
		strings.Contains(stderr, precheckTestToken) {
		t.Error("the staff JWT leaked into the output")
	}
}

func TestPrecheckHelp(t *testing.T) {
	out, _, err := runCLI(t, "precheck", "--help")
	if err != nil {
		t.Fatalf("precheck --help: %v", err)
	}
	for _, want := range []string{"Usage: vigil precheck", "--sarif", "--target", precheckTokenEnv} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output missing %q\n%s", want, out)
		}
	}

	help, _, err := runCLI(t, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(help, "vigil precheck") {
		t.Errorf("main help does not list precheck:\n%s", help)
	}
}

func TestReadPrecheckSARIFCap(t *testing.T) {
	path := writePrecheckTestSARIF(t, strings.Repeat("a", 64))
	if _, err := readPrecheckSARIF(path, 16); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("err = %v, want a cap error", err)
	}
	if _, err := readPrecheckSARIF(path, 64); err != nil {
		t.Fatalf("a file at the limit must be accepted: %v", err)
	}
}

func TestReadPrecheckSARIFStripsBOM(t *testing.T) {
	path := writePrecheckTestSARIF(t, "\ufeff"+precheckTestSARIF)
	data, err := readPrecheckSARIF(path, precheckMaxSARIFBytes)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := validatePrecheckSARIF(data); err != nil {
		t.Fatalf("a PowerShell-written BOM must not fail validation: %v", err)
	}
}

func TestValidatePrecheckSARIF(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{name: "valid", doc: precheckTestSARIF},
		{name: "valid clean run", doc: `{"version":"2.1.0","runs":[{"results":[]}]}`},
		{name: "not json", doc: `not json`, wantErr: "not a JSON object"},
		{name: "array", doc: `[]`, wantErr: "not a JSON object"},
		{name: "missing version", doc: `{"runs":[{}]}`, wantErr: "sarif.version is missing"},
		{name: "wrong version", doc: `{"version":"2.0.0","runs":[{}]}`, wantErr: "2.1.x"},
		{name: "missing runs", doc: `{"version":"2.1.0"}`, wantErr: "sarif.runs must be a non-empty array"},
		{name: "empty runs", doc: `{"version":"2.1.0","runs":[]}`, wantErr: "sarif.runs must be a non-empty array"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePrecheckSARIF([]byte(tc.doc))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestPrecheckURL(t *testing.T) {
	tests := []struct {
		api     string
		want    string
		wantErr bool
	}{
		{api: "http://localhost:3791", want: "http://localhost:3791" + precheckEndpoint},
		{api: "http://localhost:3791/", want: "http://localhost:3791" + precheckEndpoint},
		{api: "https://lv24.by/api/", want: "https://lv24.by/api" + precheckEndpoint},
		{api: "", wantErr: true},
		{api: "localhost:3791", wantErr: true},
		{api: "ftp://localhost:3791", wantErr: true},
		{api: "http://localhost:3791/?x=1", wantErr: true},
	}
	for _, tc := range tests {
		got, err := precheckURL(tc.api)
		if tc.wantErr {
			if err == nil {
				t.Errorf("precheckURL(%q) = %q, want an error", tc.api, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("precheckURL(%q): %v", tc.api, err)
			continue
		}
		if got != tc.want {
			t.Errorf("precheckURL(%q) = %q, want %q", tc.api, got, tc.want)
		}
	}
}
