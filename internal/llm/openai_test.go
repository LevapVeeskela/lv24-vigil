package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

const openAISuccessBody = `{
	"model": "test-model",
	"choices": [{"message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
	"usage": {"prompt_tokens": 11, "completion_tokens": 7}
}`

func TestOpenAICompleteSuccess(t *testing.T) {
	const key = "sk-test-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %s, want /chat/completions", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+key {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "lv24-vigil/") {
			t.Errorf("User-Agent = %q", got)
		}

		body := decodeBody(t, r)
		if body["model"] != "test-model" {
			t.Errorf("model = %v", body["model"])
		}
		if body["stream"] != false {
			t.Errorf("stream = %v, want false", body["stream"])
		}
		if body["max_tokens"] != float64(64) {
			t.Errorf("max_tokens = %v, want 64", body["max_tokens"])
		}
		if body["temperature"] != 0.3 {
			t.Errorf("temperature = %v, want 0.3", body["temperature"])
		}
		messages, ok := body["messages"].([]any)
		if !ok || len(messages) != 2 {
			t.Fatalf("messages = %#v", body["messages"])
		}
		first, _ := messages[0].(map[string]any)
		if first["role"] != "system" || first["content"] != "be careful" {
			t.Errorf("system message = %#v", first)
		}
		second, _ := messages[1].(map[string]any)
		if second["role"] != "user" || second["content"] != "hi" {
			t.Errorf("user message = %#v", second)
		}

		writeBody(w, http.StatusOK, openAISuccessBody)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, key))
	resp, err := client.Complete(context.Background(), Request{
		System:      "be careful",
		Messages:    []Message{{Role: RoleUser, Content: "hi"}},
		MaxTokens:   64,
		Temperature: 0.3,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "hello" {
		t.Errorf("Text = %q", resp.Text)
	}
	if resp.Model != "test-model" {
		t.Errorf("Model = %q", resp.Model)
	}
	if resp.InputTokens != 11 || resp.OutputTokens != 7 {
		t.Errorf("usage = %d/%d", resp.InputTokens, resp.OutputTokens)
	}
	if resp.FinishReason != "stop" {
		t.Errorf("FinishReason = %q", resp.FinishReason)
	}
	if client.Name() != config.ProviderOpenAI || client.Model() != "test-model" {
		t.Errorf("Name/Model = %q/%q", client.Name(), client.Model())
	}
}

func TestOpenAIJSONModeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		format, ok := body["response_format"].(map[string]any)
		if !ok {
			t.Fatalf("response_format missing: %#v", body["response_format"])
		}
		if format["type"] != "json_object" {
			t.Errorf("response_format.type = %v", format["type"])
		}
		messages, _ := body["messages"].([]any)
		if len(messages) == 0 {
			t.Fatalf("messages missing")
		}
		system, _ := messages[0].(map[string]any)
		if !strings.Contains(system["content"].(string), "JSON object") {
			t.Errorf("system prompt does not mention JSON: %q", system["content"])
		}
		writeBody(w, http.StatusOK, `{"choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "give me JSON"}},
		JSON:     true,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestOpenAIJSONSchemaBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		format, ok := body["response_format"].(map[string]any)
		if !ok {
			t.Fatalf("response_format missing")
		}
		if format["type"] != "json_schema" {
			t.Errorf("response_format.type = %v", format["type"])
		}
		schema, ok := format["json_schema"].(map[string]any)
		if !ok {
			t.Fatalf("json_schema missing")
		}
		if schema["name"] != "vigil_response" {
			t.Errorf("json_schema.name = %v", schema["name"])
		}
		if _, ok := schema["schema"].(map[string]any); !ok {
			t.Errorf("json_schema.schema = %#v", schema["schema"])
		}
		writeBody(w, http.StatusOK, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages:   []Message{{Role: RoleUser, Content: "give me JSON"}},
		JSON:       true,
		JSONSchema: []byte(`{"type":"object","properties":{"ok":{"type":"boolean"}}}`),
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestOpenAILocalProviderSkipsJSONMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty", got)
		}
		body := decodeBody(t, r)
		if _, ok := body["response_format"]; ok {
			t.Errorf("response_format must not be sent to ollama: %#v", body["response_format"])
		}
		writeBody(w, http.StatusOK, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOllama, srv.URL, ""))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "give me JSON"}},
		JSON:     true,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestOpenAIJSONModeFallsBackOn400(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		if calls.Add(1) == 1 {
			if _, ok := body["response_format"]; !ok {
				t.Errorf("first request should ask for JSON")
			}
			writeBody(w, http.StatusBadRequest, `{"error":{"message":"response_format is not supported","type":"invalid_request_error"}}`)
			return
		}
		if _, ok := body["response_format"]; ok {
			t.Errorf("fallback request must omit response_format")
		}
		writeBody(w, http.StatusOK, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "give me JSON"}},
		JSON:     true,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

func TestOpenAIRetries429ThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			writeBody(w, http.StatusTooManyRequests, `{"error":{"message":"rate limited","type":"rate_limit_error"}}`)
			return
		}
		writeBody(w, http.StatusOK, openAISuccessBody)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

func TestOpenAIRetryExhaustionOn500(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeBody(w, http.StatusInternalServerError, `{"error":{"message":"upstream exploded","type":"server_error"}}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if providerErr.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d", providerErr.Status)
	}
	if !providerErr.Retryable {
		t.Error("Retryable = false, want true")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3 (initial + 2 retries)", got)
	}
}

func TestOpenAIDoesNotRetry401(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeBody(w, http.StatusUnauthorized, `{"error":{"message":"invalid api key","type":"invalid_request_error"}}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if providerErr.Status != http.StatusUnauthorized || providerErr.Retryable {
		t.Errorf("status/retryable = %d/%v", providerErr.Status, providerErr.Retryable)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestOpenAIMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, http.StatusOK, `{"choices":[`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "decode") {
		t.Errorf("error = %v, want a decode error", err)
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "decode_response" {
		t.Errorf("error = %#v", providerErr)
	}
}

func TestOpenAIContextTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	_, err := client.Complete(ctx, Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	close(release)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if providerErr.Code != "timeout" {
		t.Errorf("Code = %q, want timeout", providerErr.Code)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Errorf("ctx error = %v", ctx.Err())
	}
}

func TestOpenAIErrorRedactsKey(t *testing.T) {
	const key = "sk-live-supersecret-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, http.StatusUnauthorized,
			`{"error":{"message":"Incorrect API key provided: `+key+`","type":"invalid_request_error"}}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, key))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("error leaks the API key: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("error = %v, want [REDACTED]", err)
	}
}

func TestOpenRouterHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("HTTP-Referer"); got != openRouterReferer {
			t.Errorf("HTTP-Referer = %q", got)
		}
		if got := r.Header.Get("X-Title"); got != openRouterTitle {
			t.Errorf("X-Title = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer or-key" {
			t.Errorf("Authorization = %q", got)
		}
		writeBody(w, http.StatusOK, openAISuccessBody)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenRouter, srv.URL, "or-key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestOpenAIUsesConfigDefaults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		if body["max_tokens"] != float64(256) {
			t.Errorf("max_tokens = %v, want configured 256", body["max_tokens"])
		}
		if body["temperature"] != 0.1 {
			t.Errorf("temperature = %v, want configured 0.1", body["temperature"])
		}
		writeBody(w, http.StatusOK, openAISuccessBody)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderOpenAI, srv.URL, "sk-key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}
