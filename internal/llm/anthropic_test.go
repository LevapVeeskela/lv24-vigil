package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

func TestAnthropicCompleteSuccess(t *testing.T) {
	const key = "anthropic-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %s, want /v1/messages", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != key {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Errorf("anthropic-version = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty", got)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "lv24-vigil/") {
			t.Errorf("User-Agent = %q", got)
		}

		body := decodeBody(t, r)
		if body["model"] != "test-model" {
			t.Errorf("model = %v", body["model"])
		}
		if body["system"] != "be careful\n\nextra rule" {
			t.Errorf("system = %q", body["system"])
		}
		if body["max_tokens"] != float64(64) {
			t.Errorf("max_tokens = %v", body["max_tokens"])
		}
		if body["temperature"] != 0.3 {
			t.Errorf("temperature = %v", body["temperature"])
		}
		messages, ok := body["messages"].([]any)
		if !ok || len(messages) != 2 {
			t.Fatalf("messages = %#v", body["messages"])
		}
		first, _ := messages[0].(map[string]any)
		second, _ := messages[1].(map[string]any)
		if first["role"] != "user" || first["content"] != "hi" {
			t.Errorf("first message = %#v", first)
		}
		if second["role"] != "assistant" || second["content"] != "hello" {
			t.Errorf("second message = %#v", second)
		}

		writeBody(w, http.StatusOK, `{
			"model": "test-model",
			"content": [{"type": "text", "text": "part1"}, {"type": "text", "text": " part2"}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 5, "output_tokens": 6}
		}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderAnthropic, srv.URL, key))
	resp, err := client.Complete(context.Background(), Request{
		System: "be careful",
		Messages: []Message{
			{Role: RoleUser, Content: "hi"},
			{Role: RoleSystem, Content: "extra rule"},
			{Role: RoleAssistant, Content: "hello"},
		},
		MaxTokens:   64,
		Temperature: 0.3,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "part1 part2" {
		t.Errorf("Text = %q", resp.Text)
	}
	if resp.InputTokens != 5 || resp.OutputTokens != 6 {
		t.Errorf("usage = %d/%d", resp.InputTokens, resp.OutputTokens)
	}
	if resp.FinishReason != "end_turn" {
		t.Errorf("FinishReason = %q", resp.FinishReason)
	}
	if client.Name() != config.ProviderAnthropic {
		t.Errorf("Name = %q", client.Name())
	}
}

func TestAnthropicJSONModeUsesSystemInstruction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		system, _ := body["system"].(string)
		if !strings.Contains(system, "JSON object") {
			t.Errorf("system = %q, want JSON instruction", system)
		}
		if _, ok := body["response_format"]; ok {
			t.Errorf("anthropic must not receive response_format")
		}
		writeBody(w, http.StatusOK, `{"content":[{"type":"text","text":"{}"}],"stop_reason":"end_turn"}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderAnthropic, srv.URL, "key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "give me JSON"}},
		JSON:     true,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestAnthropicBaseURLWithV1Suffix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %s, want /v1/messages", r.URL.Path)
		}
		writeBody(w, http.StatusOK, `{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderAnthropic, srv.URL+"/v1", "key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestAnthropicErrorPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, http.StatusBadRequest, `{
			"type": "error",
			"error": {"type": "invalid_request_error", "message": "bad request"}
		}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderAnthropic, srv.URL, "key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) {
		t.Fatalf("error type = %T", err)
	}
	if providerErr.Status != http.StatusBadRequest {
		t.Errorf("Status = %d", providerErr.Status)
	}
	if providerErr.Code != "invalid_request_error" {
		t.Errorf("Code = %q", providerErr.Code)
	}
	if providerErr.Message != "bad request" {
		t.Errorf("Message = %q", providerErr.Message)
	}
	if providerErr.Retryable {
		t.Error("Retryable = true, want false")
	}
}

func TestAnthropicRejectsAssistantFirst(t *testing.T) {
	client := newTestClient(t, baseConfig(config.ProviderAnthropic, "http://127.0.0.1:1", "key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleAssistant, Content: "prefill"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "invalid_request" {
		t.Errorf("error = %#v", providerErr)
	}
}

func TestAnthropicMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, http.StatusOK, `{"content":`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderAnthropic, srv.URL, "key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "decode") {
		t.Fatalf("error = %v, want decode error", err)
	}
}
