package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// newOSVRepo builds a repository with one dependency manifest and an optional
// OSV config. The endpoint is always a local httptest server.
func newOSVRepo(t *testing.T, osvEnabled bool) string {
	t.Helper()
	repo := newTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if osvEnabled {
		if err := os.WriteFile(filepath.Join(repo, ".vigil.yaml"), []byte("scan:\n  osv: true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

// TestScanSetsOSVQueriedOnAttempt covers the successful and failing lookup:
// the field records that the channel was used, not that advisories were found.
func TestScanSetsOSVQueriedOnAttempt(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"results":[{}]}`))
			},
		},
		{
			name: "failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "osv unavailable", http.StatusInternalServerError)
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hermeticEnv(t)
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			t.Setenv("VIGIL_OSV_BASE_URL", server.URL)

			repo := newOSVRepo(t, true)
			a, err := New(repo, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = a.Close() })

			disabled := false
			res, err := a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if !res.Stats.OSVQueried {
				t.Errorf("stats.osvQueried = false, want true after an attempted lookup")
			}
			hadOSVErr := false
			for _, e := range res.Errors {
				hadOSVErr = hadOSVErr || strings.HasPrefix(e, "osv:")
			}
			if hadOSVErr != tc.wantErr {
				t.Errorf("osv error present = %v, want %v (errors: %v)", hadOSVErr, tc.wantErr, res.Errors)
			}
		})
	}
}

// TestScanWithoutOSVLeavesOSVQueriedFalse: the deterministic default must not
// claim egress.
func TestScanWithoutOSVLeavesOSVQueriedFalse(t *testing.T) {
	hermeticEnv(t)
	repo := newOSVRepo(t, false)
	a, err := New(repo, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	disabled := false
	res, err := a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Stats.OSVQueried {
		t.Error("stats.osvQueried = true without an enabled OSV lookup")
	}
}
