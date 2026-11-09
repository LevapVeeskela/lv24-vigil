// Package llm defines the provider-neutral model client used for triage, deep
// review and fix generation. Providers are plain HTTP clients: no SDK, no
// telemetry, and the API key never leaves the process except to the endpoint the
// user configured.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
)

// Role is a chat role.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is one chat message.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// Request is a provider-neutral completion request.
type Request struct {
	System      string
	Messages    []Message
	MaxTokens   int
	Temperature float64
	// JSON asks the provider for a JSON object response. Providers that do not
	// support a JSON mode still receive the instruction in the system prompt.
	JSON bool
	// JSONSchema, when set, is passed to providers that support structured
	// output. It must be a JSON Schema object.
	JSONSchema json.RawMessage
}

// Response is a provider-neutral completion.
type Response struct {
	Text         string
	Model        string
	InputTokens  int
	OutputTokens int
	FinishReason string
}

// Client is implemented by every provider.
type Client interface {
	// Name is the provider identifier, e.g. "openai", "anthropic", "ollama".
	Name() string
	// Model is the configured model id.
	Model() string
	// Complete performs one request. Implementations must honour ctx and must
	// never log the API key or the full prompt.
	Complete(ctx context.Context, req Request) (Response, error)
}

// Error is a typed provider error. Status 0 means a transport error.
type Error struct {
	Provider  string
	Status    int
	Code      string
	Message   string
	Retryable bool
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("%s: %s", e.Provider, e.Message)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.Provider, e.Status, e.Message)
}

// TruncateText bounds a string for error messages and logs.
func TruncateText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
