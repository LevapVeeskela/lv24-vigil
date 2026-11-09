package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

func TestNewAllProviders(t *testing.T) {
	cases := []struct {
		provider string
		key      string
	}{
		{config.ProviderOpenAI, "key"},
		{config.ProviderAnthropic, "key"},
		{config.ProviderGemini, "key"},
		{config.ProviderOpenRouter, "key"},
		{config.ProviderGroq, "key"},
		{config.ProviderDeepSeek, "key"},
		{config.ProviderMistral, "key"},
		{config.ProviderXAI, "key"},
		{config.ProviderOpenCodeGo, "key"},
		{config.ProviderOllama, ""},
		{config.ProviderLMStudio, ""},
		{config.ProviderCustom, ""},
	}

	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			client, err := New(baseConfig(tc.provider, "http://127.0.0.1:1", tc.key), nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if client.Name() != tc.provider {
				t.Errorf("Name = %q, want %q", client.Name(), tc.provider)
			}
			if client.Model() != "test-model" {
				t.Errorf("Model = %q", client.Model())
			}

			switch tc.provider {
			case config.ProviderAnthropic:
				if _, ok := client.(*anthropicClient); !ok {
					t.Errorf("type = %T, want *anthropicClient", client)
				}
			case config.ProviderGemini:
				if _, ok := client.(*geminiClient); !ok {
					t.Errorf("type = %T, want *geminiClient", client)
				}
			default:
				openAI, ok := client.(*openAIClient)
				if !ok {
					t.Fatalf("type = %T, want *openAIClient", client)
				}
				wantJSONMode := tc.provider != config.ProviderOllama && tc.provider != config.ProviderLMStudio
				if openAI.jsonMode != wantJSONMode {
					t.Errorf("jsonMode = %v, want %v", openAI.jsonMode, wantJSONMode)
				}
			}
		})
	}
}

func TestNewRequiresKeyForHostedProviders(t *testing.T) {
	hosted := []string{
		config.ProviderOpenAI,
		config.ProviderAnthropic,
		config.ProviderGemini,
		config.ProviderOpenRouter,
		config.ProviderGroq,
		config.ProviderDeepSeek,
		config.ProviderMistral,
		config.ProviderXAI,
		config.ProviderOpenCodeGo,
	}
	for _, provider := range hosted {
		t.Run(provider, func(t *testing.T) {
			_, err := New(config.Config{
				Provider: provider,
				Model:    "test-model",
				BaseURL:  "http://127.0.0.1:1",
			}, nil)
			if err == nil {
				t.Fatal("expected missing-key error")
			}
			message := err.Error()
			if !strings.Contains(message, "VIGIL_API_KEY") {
				t.Errorf("error does not mention VIGIL_API_KEY: %v", err)
			}
			if !strings.Contains(message, providerKeyEnv(provider)) {
				t.Errorf("error does not mention %s: %v", providerKeyEnv(provider), err)
			}
		})
	}
}

func TestNewErrors(t *testing.T) {
	t.Run("no provider", func(t *testing.T) {
		_, err := New(config.Config{Model: "test-model"}, nil)
		if err == nil || !strings.Contains(err.Error(), "no LLM provider configured") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := New(config.Config{Provider: "nope", Model: "test-model"}, nil)
		if err == nil || !strings.Contains(err.Error(), "unknown LLM provider") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("missing model", func(t *testing.T) {
		_, err := New(config.Config{
			Provider: config.ProviderOpenAI,
			APIKey:   "key",
			BaseURL:  "http://127.0.0.1:1",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "requires a model") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("custom without base url", func(t *testing.T) {
		_, err := New(config.Config{
			Provider: config.ProviderCustom,
			Model:    "test-model",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "base URL") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestNewUsesDefaultBaseURLAndTimeout(t *testing.T) {
	client, err := New(config.Config{
		Provider: config.ProviderOpenAI,
		Model:    "test-model",
		APIKey:   "key",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	openAI, ok := client.(*openAIClient)
	if !ok {
		t.Fatalf("type = %T", client)
	}
	if openAI.baseURL != config.ProviderBaseURL(config.ProviderOpenAI) {
		t.Errorf("baseURL = %q", openAI.baseURL)
	}
	if openAI.http.client.Timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", openAI.http.client.Timeout, defaultTimeout)
	}
}

func TestDetect(t *testing.T) {
	clearProviderEnv(t)

	if got := Detect(); len(got) != 0 {
		t.Fatalf("Detect() = %v, want none", got)
	}

	t.Setenv("OPENAI_API_KEY", "openai-key")
	if got, want := Detect(), []string{config.ProviderOpenAI}; !reflect.DeepEqual(got, want) {
		t.Errorf("Detect() = %v, want %v", got, want)
	}

	t.Setenv("ANTHROPIC_API_KEY", "anthropic-key")
	if got, want := Detect(), []string{config.ProviderAnthropic, config.ProviderOpenAI}; !reflect.DeepEqual(got, want) {
		t.Errorf("Detect() = %v, want %v", got, want)
	}

	t.Setenv("VIGIL_PROVIDER", config.ProviderGroq)
	t.Setenv("VIGIL_API_KEY", "groq-key")
	if got, want := Detect(), []string{config.ProviderGroq}; !reflect.DeepEqual(got, want) {
		t.Errorf("Detect() = %v, want %v", got, want)
	}

	t.Setenv("VIGIL_PROVIDER", config.ProviderOllama)
	t.Setenv("VIGIL_API_KEY", "")
	if got, want := Detect(), []string{config.ProviderOllama}; !reflect.DeepEqual(got, want) {
		t.Errorf("Detect() = %v, want %v", got, want)
	}

	t.Setenv("VIGIL_PROVIDER", config.ProviderCustom)
	t.Setenv("VIGIL_BASE_URL", "http://localhost:8080/v1")
	if got, want := Detect(), []string{config.ProviderCustom}; !reflect.DeepEqual(got, want) {
		t.Errorf("Detect() = %v, want %v", got, want)
	}

	t.Setenv("VIGIL_PROVIDER", config.ProviderCustom)
	t.Setenv("VIGIL_BASE_URL", "")
	if got := Detect(); len(got) != 0 {
		t.Errorf("Detect() = %v, want none for unconfigured custom", got)
	}

	t.Setenv("VIGIL_PROVIDER", "")
	t.Setenv("VIGIL_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "google-key")
	if got, want := Detect(), []string{config.ProviderGemini}; !reflect.DeepEqual(got, want) {
		t.Errorf("Detect() = %v, want %v", got, want)
	}
}

func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"VIGIL_PROVIDER", "VIGIL_API_KEY", "VIGIL_BASE_URL",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
		"OPENROUTER_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY", "MISTRAL_API_KEY",
		"XAI_API_KEY", "OPENCODE_API_KEY", "OPENCODE_GO_API_KEY", "OLLAMA_HOST",
	} {
		t.Setenv(key, "")
	}
}

func TestOpenCodeGoSendsSessionHeader(t *testing.T) {
	t.Setenv("VIGIL_OPENCODE_SESSION", "")
	t.Setenv("OPENCODE_SESSION_ID", "")
	var gotSession, gotUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = r.Header.Get("x-opencode-session")
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"deepseek-v4.1-flash","choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer server.Close()

	client, err := New(config.Config{
		Provider: config.ProviderOpenCodeGo,
		Model:    "deepseek-v4.1-flash",
		BaseURL:  server.URL,
		APIKey:   "test-key",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.HasPrefix(gotSession, "vigil-") {
		t.Fatalf("x-opencode-session = %q, want a vigil- id", gotSession)
	}
	if !strings.HasPrefix(gotUA, "lv24-vigil/") {
		t.Fatalf("User-Agent = %q, want lv24-vigil/<version>", gotUA)
	}
}

func TestOpenCodeGoSessionOverride(t *testing.T) {
	t.Setenv("VIGIL_OPENCODE_SESSION", "my-stable-session")
	client, err := New(config.Config{
		Provider: config.ProviderOpenCodeGo,
		Model:    "deepseek-v4.1-flash",
		BaseURL:  "http://127.0.0.1:1",
		APIKey:   "test-key",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	openAI, ok := client.(*openAIClient)
	if !ok {
		t.Fatalf("type = %T", client)
	}
	if openAI.sessionID != "my-stable-session" {
		t.Fatalf("sessionID = %q", openAI.sessionID)
	}
}
