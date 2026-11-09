package llm

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func baseConfig(provider, baseURL, key string) config.Config {
	return config.Config{
		Provider:    provider,
		Model:       "test-model",
		BaseURL:     baseURL,
		APIKey:      key,
		MaxTokens:   256,
		Temperature: 0.1,
		Timeout:     5 * time.Second,
	}
}

func newTestClient(t *testing.T, cfg config.Config) Client {
	t.Helper()
	client, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatalf("New(%s): %v", cfg.Provider, err)
	}
	fastRetries(client)
	return client
}

// fastRetries keeps retry tests quick without changing production defaults.
func fastRetries(client Client) {
	var tr *transport
	switch c := client.(type) {
	case *openAIClient:
		tr = c.http
	case *anthropicClient:
		tr = c.http
	case *geminiClient:
		tr = c.http
	}
	if tr != nil {
		tr.baseDelay = time.Millisecond
		tr.maxDelay = 2 * time.Millisecond
	}
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("decode request body: %v", err)
	}
	return body
}

func writeBody(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
