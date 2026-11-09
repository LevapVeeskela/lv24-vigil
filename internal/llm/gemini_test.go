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

func TestGeminiCompleteSuccess(t *testing.T) {
	const key = "gem-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/models/test-model:generateContent" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("key"); got != key {
			t.Errorf("key = %q", got)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "lv24-vigil/") {
			t.Errorf("User-Agent = %q", got)
		}

		body := decodeBody(t, r)
		system, ok := body["systemInstruction"].(map[string]any)
		if !ok {
			t.Fatalf("systemInstruction missing: %#v", body["systemInstruction"])
		}
		parts, _ := system["parts"].([]any)
		if len(parts) != 1 {
			t.Fatalf("system parts = %#v", system["parts"])
		}
		part, _ := parts[0].(map[string]any)
		if part["text"] != "be careful" {
			t.Errorf("system text = %v", part["text"])
		}

		contents, ok := body["contents"].([]any)
		if !ok || len(contents) != 3 {
			t.Fatalf("contents = %#v", body["contents"])
		}
		first, _ := contents[0].(map[string]any)
		second, _ := contents[1].(map[string]any)
		third, _ := contents[2].(map[string]any)
		if first["role"] != "user" {
			t.Errorf("first role = %v", first["role"])
		}
		if second["role"] != "model" {
			t.Errorf("second role = %v", second["role"])
		}
		if third["role"] != "user" {
			t.Errorf("third role = %v", third["role"])
		}

		configBody, _ := body["generationConfig"].(map[string]any)
		if configBody["maxOutputTokens"] != float64(64) {
			t.Errorf("maxOutputTokens = %v", configBody["maxOutputTokens"])
		}
		if configBody["temperature"] != 0.3 {
			t.Errorf("temperature = %v", configBody["temperature"])
		}

		writeBody(w, http.StatusOK, `{
			"candidates": [{
				"content": {"role": "model", "parts": [
					{"text": "a"},
					{"text": "b"},
					{"text": "thinking", "thought": true}
				]},
				"finishReason": "STOP"
			}],
			"usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7},
			"modelVersion": "test-model"
		}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderGemini, srv.URL, key))
	resp, err := client.Complete(context.Background(), Request{
		System: "be careful",
		Messages: []Message{
			{Role: RoleUser, Content: "hi"},
			{Role: RoleAssistant, Content: "hello"},
			{Role: RoleUser, Content: "again"},
		},
		MaxTokens:   64,
		Temperature: 0.3,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "ab" {
		t.Errorf("Text = %q, want thought parts skipped", resp.Text)
	}
	if resp.InputTokens != 3 || resp.OutputTokens != 4 {
		t.Errorf("usage = %d/%d", resp.InputTokens, resp.OutputTokens)
	}
	if resp.FinishReason != "STOP" {
		t.Errorf("FinishReason = %q", resp.FinishReason)
	}
	if client.Name() != config.ProviderGemini {
		t.Errorf("Name = %q", client.Name())
	}
}

func TestGeminiJSONMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		configBody, _ := body["generationConfig"].(map[string]any)
		if configBody["responseMimeType"] != "application/json" {
			t.Errorf("responseMimeType = %v", configBody["responseMimeType"])
		}
		system, _ := body["systemInstruction"].(map[string]any)
		parts, _ := system["parts"].([]any)
		if len(parts) == 0 {
			t.Fatalf("systemInstruction missing")
		}
		part, _ := parts[0].(map[string]any)
		if !strings.Contains(part["text"].(string), "JSON object") {
			t.Errorf("system text = %q", part["text"])
		}
		writeBody(w, http.StatusOK, `{"candidates":[{"content":{"parts":[{"text":"{}"}]},"finishReason":"STOP"}]}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderGemini, srv.URL, "gem-key"))
	if _, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "give me JSON"}},
		JSON:     true,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestGeminiErrorPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, http.StatusBadRequest, `{
			"error": {"code": 400, "message": "API key not valid", "status": "INVALID_ARGUMENT"}
		}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderGemini, srv.URL, "gem-key"))
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
	if providerErr.Code != "INVALID_ARGUMENT" {
		t.Errorf("Code = %q", providerErr.Code)
	}
	if providerErr.Message != "API key not valid" {
		t.Errorf("Message = %q", providerErr.Message)
	}
	if providerErr.Retryable {
		t.Error("Retryable = true, want false")
	}
}

func TestGeminiBlockedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, http.StatusOK, `{"promptFeedback":{"blockReason":"SAFETY"}}`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderGemini, srv.URL, "gem-key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "blocked" {
		t.Errorf("error = %#v", providerErr)
	}
	if !strings.Contains(providerErr.Message, "SAFETY") {
		t.Errorf("Message = %q", providerErr.Message)
	}
}

func TestGeminiTransportErrorRedactsKey(t *testing.T) {
	const key = "gemini-super-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderGemini, url, key))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("error leaks the API key: %v", err)
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "network" {
		t.Errorf("error = %#v", providerErr)
	}
}

func TestGeminiMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, http.StatusOK, `{"candidates":`)
	}))
	defer srv.Close()

	client := newTestClient(t, baseConfig(config.ProviderGemini, srv.URL, "gem-key"))
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "decode") {
		t.Fatalf("error = %v, want decode error", err)
	}
}
