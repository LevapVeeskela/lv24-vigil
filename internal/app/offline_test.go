package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// TestOfflineMakesNoNetworkRequests proves the offline promise end to end: a
// fully configured model and OSV endpoint receive zero requests, and the
// resolved configuration no longer carries anything that could make one.
func TestOfflineMakesNoNetworkRequests(t *testing.T) {
	hermeticEnv(t)

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// A valid empty querybatch body; a model call would reach the counter
		// too, because every request is counted before the path is inspected.
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()

	t.Setenv("VIGIL_PROVIDER", "openai")
	t.Setenv("VIGIL_MODEL", "gpt-test")
	t.Setenv("VIGIL_API_KEY", "test")
	t.Setenv("VIGIL_BASE_URL", server.URL)
	t.Setenv("VIGIL_OSV", "1")
	t.Setenv("VIGIL_OSV_BASE_URL", server.URL)

	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"),
		[]byte(`{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "config.py"),
		[]byte("aws_access_key_id = \""+testAWSKey+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := New(repo, nil, WithOffline())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	cfg := a.Config
	if a.LLM {
		t.Error("offline app reports a configured model")
	}
	if a.Model != nil {
		t.Errorf("offline app has model info: %+v", a.Model)
	}
	if cfg.Provider != "" || cfg.Model != "" || cfg.BaseURL != "" || cfg.APIKey != "" {
		t.Errorf("offline config kept model settings: provider=%q model=%q base_url=%q key set=%v",
			cfg.Provider, cfg.Model, cfg.BaseURL, cfg.APIKey != "")
	}
	if len(cfg.Command) != 0 {
		t.Errorf("offline config kept a command provider: %v", cfg.Command)
	}
	if cfg.Scan.OSV {
		t.Error("offline config still enables OSV")
	}
	if cfg.Scan.OSVBaseURL != "" {
		t.Errorf("offline config kept OSV base URL %q", cfg.Scan.OSVBaseURL)
	}
	if cfg.Scan.UseLLM == nil || *cfg.Scan.UseLLM {
		t.Errorf("offline config did not force scan.use_llm=false: %v", cfg.Scan.UseLLM)
	}
	if cfg.LLMEnabled() {
		t.Error("offline config still reports the LLM as enabled")
	}
	if !warningsContain(a.Warnings, "offline mode") {
		t.Errorf("offline warning missing from %v", a.Warnings)
	}

	res, err := a.Scan(context.Background(), model.ScanRequest{Mode: "quick"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("offline scan made %d network request(s), want 0", got)
	}
	if res.Model != nil {
		t.Errorf("offline scan recorded model info: %+v", res.Model)
	}
	if res.Stats.LLMCalls != 0 {
		t.Errorf("offline scan reports %d LLM calls", res.Stats.LLMCalls)
	}
	found := false
	for _, f := range res.Findings {
		found = found || f.RuleID == "VGL-SEC-001"
	}
	if !found {
		t.Fatalf("deterministic scan did not report the AWS key: %+v", res.Findings)
	}

	// Control, not part of the guarantee: the same environment without
	// WithOffline must reach the server, so a zero counter above is meaningful
	// rather than an inert fixture.
	t.Run("control: the same endpoint counts a request without offline", func(t *testing.T) {
		b, err := New(repo, nil)
		if err != nil {
			t.Fatalf("New without offline: %v", err)
		}
		t.Cleanup(func() { _ = b.Close() })

		if b.Config.Provider != "openai" || b.Config.Model != "gpt-test" {
			t.Fatalf("control config did not read the model env: provider=%q model=%q",
				b.Config.Provider, b.Config.Model)
		}
		if b.Config.APIKey != "test" || b.Config.BaseURL != server.URL {
			t.Fatalf("control config did not read the endpoint env: key set=%v base_url=%q",
				b.Config.APIKey != "", b.Config.BaseURL)
		}
		if !b.Config.Scan.OSV || b.Config.Scan.OSVBaseURL != server.URL {
			t.Fatalf("control config did not read the OSV env: osv=%v base_url=%q",
				b.Config.Scan.OSV, b.Config.Scan.OSVBaseURL)
		}
		// hermeticEnv sets VIGIL_NO_LLM=1, so the control exercises the OSV
		// channel; the model channel was proven live by the config above.
		if b.LLM {
			t.Fatal("control app built a model despite VIGIL_NO_LLM=1")
		}
		if _, err := b.Scan(context.Background(), model.ScanRequest{Mode: "quick"}); err != nil {
			t.Fatalf("control scan: %v", err)
		}
		if requests.Load() == 0 {
			t.Fatal("control scan made no request: the counter cannot detect egress")
		}
	})
}

func warningsContain(warnings []string, substring string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substring) {
			return true
		}
	}
	return false
}
