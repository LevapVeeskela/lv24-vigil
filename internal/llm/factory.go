package llm

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

// baseClient holds the settings shared by all provider implementations.
type baseClient struct {
	provider string
	model    string
	baseURL  string
	apiKey   string

	defaultMaxTokens   int
	defaultTemperature float64

	http *transport
}

// Name implements Client.
func (b baseClient) Name() string { return b.provider }

// Model implements Client.
func (b baseClient) Model() string { return b.model }

// maxTokens falls back to the configured default because a zero token budget
// is never a valid request.
func (b baseClient) maxTokens(requested int) int {
	if requested > 0 {
		return requested
	}
	if b.defaultMaxTokens > 0 {
		return b.defaultMaxTokens
	}
	return 4096
}

// temperature treats zero as "use the configured default". Request has no way
// to distinguish an unset value from an explicit 0.0, and falling back to the
// configured value is safer than letting each provider pick its own default.
func (b baseClient) temperature(requested float64) float64 {
	if requested > 0 {
		return requested
	}
	if b.defaultTemperature > 0 {
		return b.defaultTemperature
	}
	return 0
}

func (b baseClient) headers() http.Header {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("User-Agent", userAgent())
	return h
}

var providerNames = []string{
	config.ProviderOpenAI,
	config.ProviderAnthropic,
	config.ProviderGemini,
	config.ProviderOpenRouter,
	config.ProviderGroq,
	config.ProviderDeepSeek,
	config.ProviderMistral,
	config.ProviderXAI,
	config.ProviderOllama,
	config.ProviderLMStudio,
	config.ProviderCustom,
	config.ProviderOpenCodeGo,
}

// New builds the provider client described by cfg. A missing provider, model
// or API key produces an actionable error instead of a failed network call.
func New(cfg config.Config, logger *slog.Logger) (Client, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	provider := config.CanonicalProvider(cfg.Provider)
	if provider == "" {
		if detected := Detect(); len(detected) > 0 {
			return nil, fmt.Errorf(
				"no LLM provider configured (found credentials for %s); set VIGIL_PROVIDER",
				strings.Join(detected, ", "))
		}
		return nil, fmt.Errorf(
			"no LLM provider configured: set VIGIL_PROVIDER and VIGIL_API_KEY, or one of ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, GROQ_API_KEY, DEEPSEEK_API_KEY, MISTRAL_API_KEY, XAI_API_KEY, OLLAMA_HOST")
	}
	if !isKnownProvider(provider) {
		return nil, fmt.Errorf("unknown LLM provider %q (use one of: %s)", cfg.Provider, strings.Join(providerNames, ", "))
	}

	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		return nil, fmt.Errorf("provider %q requires a model (set VIGIL_MODEL)", provider)
	}

	apiKey := strings.TrimSpace(cfg.APIKey)
	if requiresAPIKey(provider) && apiKey == "" {
		return nil, fmt.Errorf(
			"provider %q requires an API key: set VIGIL_API_KEY or %s",
			provider, providerKeyEnv(provider))
	}

	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = config.ProviderBaseURL(provider)
	}
	if baseURL == "" {
		return nil, fmt.Errorf("provider %q requires a base URL (set VIGIL_BASE_URL)", provider)
	}

	base := baseClient{
		provider:           provider,
		model:              model,
		baseURL:            strings.TrimRight(baseURL, "/"),
		apiKey:             apiKey,
		defaultMaxTokens:   cfg.MaxTokens,
		defaultTemperature: cfg.Temperature,
		http:               newTransport(provider, cfg.Timeout, apiKey, logger),
	}

	switch provider {
	case config.ProviderOpenAI,
		config.ProviderOpenRouter,
		config.ProviderGroq,
		config.ProviderDeepSeek,
		config.ProviderMistral,
		config.ProviderXAI,
		config.ProviderCustom,
		config.ProviderOpenCodeGo:
		return newOpenAIClient(base, true), nil
	case config.ProviderOllama, config.ProviderLMStudio:
		// Local servers often reject response_format even though they speak the
		// OpenAI chat API, so JSON mode is prompt-only for them.
		return newOpenAIClient(base, false), nil
	case config.ProviderAnthropic:
		return &anthropicClient{baseClient: base}, nil
	case config.ProviderGemini:
		return &geminiClient{baseClient: base}, nil
	default:
		return nil, fmt.Errorf("unknown LLM provider %q", provider)
	}
}

// Detect returns the providers that appear configured from the environment.
// The order follows config.Load's inference priority so `vigil status` shows
// the provider that would actually be selected first.
func Detect() []string {
	explicit := strings.ToLower(strings.TrimSpace(os.Getenv("VIGIL_PROVIDER")))
	if explicit != "" {
		if providerAppearsConfigured(explicit) {
			return []string{explicit}
		}
		return nil
	}

	candidates := []struct {
		provider string
		env      []string
	}{
		{config.ProviderAnthropic, []string{"ANTHROPIC_API_KEY"}},
		{config.ProviderOpenAI, []string{"OPENAI_API_KEY"}},
		{config.ProviderGemini, []string{"GEMINI_API_KEY", "GOOGLE_API_KEY"}},
		{config.ProviderOpenRouter, []string{"OPENROUTER_API_KEY"}},
		{config.ProviderDeepSeek, []string{"DEEPSEEK_API_KEY"}},
		{config.ProviderGroq, []string{"GROQ_API_KEY"}},
		{config.ProviderMistral, []string{"MISTRAL_API_KEY"}},
		{config.ProviderXAI, []string{"XAI_API_KEY"}},
		{config.ProviderOpenCodeGo, []string{"OPENCODE_API_KEY", "OPENCODE_GO_API_KEY"}},
		{config.ProviderOllama, []string{"OLLAMA_HOST"}},
	}

	var detected []string
	for _, candidate := range candidates {
		for _, env := range candidate.env {
			if strings.TrimSpace(os.Getenv(env)) != "" {
				detected = append(detected, candidate.provider)
				break
			}
		}
	}
	return detected
}

func providerAppearsConfigured(provider string) bool {
	switch provider {
	case config.ProviderOllama, config.ProviderLMStudio:
		return true
	case config.ProviderCustom:
		return strings.TrimSpace(os.Getenv("VIGIL_BASE_URL")) != "" ||
			strings.TrimSpace(os.Getenv("VIGIL_API_KEY")) != ""
	}

	if !isKnownProvider(provider) {
		return false
	}
	if strings.TrimSpace(os.Getenv("VIGIL_API_KEY")) != "" {
		return true
	}
	for _, env := range providerKeyEnvs(provider) {
		if strings.TrimSpace(os.Getenv(env)) != "" {
			return true
		}
	}
	return false
}

func isKnownProvider(provider string) bool {
	for _, name := range providerNames {
		if name == provider {
			return true
		}
	}
	return false
}

// requiresAPIKey reports whether the provider is a hosted service. Local
// OpenAI-compatible servers (ollama, lmstudio, custom) may run without a key.
func requiresAPIKey(provider string) bool {
	switch provider {
	case config.ProviderOllama, config.ProviderLMStudio, config.ProviderCustom:
		return false
	default:
		return true
	}
}

func providerKeyEnvs(provider string) []string {
	switch provider {
	case config.ProviderOpenAI:
		return []string{"OPENAI_API_KEY"}
	case config.ProviderAnthropic:
		return []string{"ANTHROPIC_API_KEY"}
	case config.ProviderGemini:
		return []string{"GEMINI_API_KEY", "GOOGLE_API_KEY"}
	case config.ProviderOpenRouter:
		return []string{"OPENROUTER_API_KEY"}
	case config.ProviderGroq:
		return []string{"GROQ_API_KEY"}
	case config.ProviderDeepSeek:
		return []string{"DEEPSEEK_API_KEY"}
	case config.ProviderMistral:
		return []string{"MISTRAL_API_KEY"}
	case config.ProviderXAI:
		return []string{"XAI_API_KEY"}
	case config.ProviderOpenCodeGo:
		return []string{"OPENCODE_API_KEY", "OPENCODE_GO_API_KEY"}
	default:
		return nil
	}
}

func providerKeyEnv(provider string) string {
	envs := providerKeyEnvs(provider)
	if len(envs) == 0 {
		return "VIGIL_API_KEY"
	}
	return strings.Join(envs, " or ")
}
