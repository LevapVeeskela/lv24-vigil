package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

const anthropicVersion = "2023-06-01"

// anthropicClient speaks the Anthropic Messages API.
type anthropicClient struct {
	baseClient
}

type anthropicRequest struct {
	Model       string    `json:"model"`
	System      string    `json:"system,omitempty"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
}

type anthropicResponse struct {
	Model   string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error json.RawMessage `json:"error"`
}

// Complete implements Client.
func (c *anthropicClient) Complete(ctx context.Context, req Request) (Response, error) {
	system, messages := anthropicMessages(req.System, req.Messages)
	if len(messages) == 0 {
		return Response{}, c.http.newError(0, "invalid_request", "request has no messages", false)
	}
	if messages[0].Role != RoleUser {
		return Response{}, c.http.newError(0, "invalid_request", "anthropic conversations must start with a user message", false)
	}

	if req.JSON || len(req.JSONSchema) > 0 {
		// Anthropic has no response_format; state the contract in the system
		// prompt instead.
		system = withJSONSchemaInstruction(system, req.JSONSchema)
	}

	payload := anthropicRequest{
		Model:       c.model,
		System:      system,
		Messages:    messages,
		MaxTokens:   c.maxTokens(req.MaxTokens),
		Temperature: clampFloat(c.temperature(req.Temperature), 0, 1),
	}
	body, encodeErr := encodeRequest(c.provider, payload)
	if encodeErr != nil {
		return Response{}, encodeErr
	}

	data, err := c.http.do(ctx, http.MethodPost, c.endpoint(), c.headers(), body)
	if err != nil {
		return Response{}, err
	}
	return c.parse(data)
}

func (c *anthropicClient) endpoint() string {
	base := strings.TrimRight(c.baseURL, "/")
	if strings.HasSuffix(base, "/v1") {
		return base + "/messages"
	}
	return base + "/v1/messages"
}

func (c *anthropicClient) headers() http.Header {
	h := c.baseClient.headers()
	if c.apiKey != "" {
		h.Set("x-api-key", c.apiKey)
	}
	h.Set("anthropic-version", anthropicVersion)
	return h
}

func (c *anthropicClient) parse(data []byte) (Response, error) {
	var payload anthropicResponse
	if err := DecodeInto(data, &payload); err != nil {
		return Response{}, c.http.newError(0, "decode_response", err.Error(), false)
	}
	if len(payload.Error) > 0 && !isJSONNull(payload.Error) {
		code, message := parseProviderError(payload.Error)
		return Response{}, c.http.newError(0, code, message, false)
	}
	if len(payload.Content) == 0 {
		return Response{}, c.http.newError(0, "empty_response", "provider returned no content", false)
	}

	var text strings.Builder
	for _, block := range payload.Content {
		text.WriteString(block.Text)
	}
	if strings.TrimSpace(text.String()) == "" {
		return Response{}, c.http.newError(0, "empty_content", "provider returned an empty message", false)
	}

	model := strings.TrimSpace(payload.Model)
	if model == "" {
		model = c.model
	}
	return Response{
		Text:         text.String(),
		Model:        model,
		InputTokens:  payload.Usage.InputTokens,
		OutputTokens: payload.Usage.OutputTokens,
		FinishReason: payload.StopReason,
	}, nil
}

// anthropicMessages merges system-role messages into the top-level system
// prompt and normalises the remaining roles. Anthropic accepts only user and
// assistant roles inside the messages array.
func anthropicMessages(system string, messages []Message) (string, []Message) {
	var systemParts []string
	if strings.TrimSpace(system) != "" {
		systemParts = append(systemParts, system)
	}

	out := make([]Message, 0, len(messages))
	for _, message := range messages {
		if strings.TrimSpace(message.Content) == "" {
			continue
		}
		switch message.Role {
		case RoleSystem:
			systemParts = append(systemParts, message.Content)
		case RoleAssistant:
			out = append(out, Message{Role: RoleAssistant, Content: message.Content})
		default:
			out = append(out, Message{Role: RoleUser, Content: message.Content})
		}
	}
	return strings.Join(systemParts, "\n\n"), out
}
