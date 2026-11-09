package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

const (
	openRouterReferer = "https://github.com/LevapVeeskela/lv24-vigil"
	openRouterTitle   = "lv24-vigil"
)

// openAIClient speaks the OpenAI chat-completions API. It also covers every
// hosted provider in this package that exposes an OpenAI-compatible endpoint.
type openAIClient struct {
	baseClient
	// jsonMode reports whether the endpoint understands response_format. It is
	// false for local servers (ollama, lmstudio) that commonly reject it.
	jsonMode bool
}

func newOpenAIClient(base baseClient, jsonMode bool) *openAIClient {
	return &openAIClient{baseClient: base, jsonMode: jsonMode}
}

type openAIRequest struct {
	Model          string                `json:"model"`
	Messages       []Message             `json:"messages"`
	MaxTokens      int                   `json:"max_tokens"`
	Temperature    float64               `json:"temperature"`
	Stream         bool                  `json:"stream"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIResponseFormat struct {
	Type       string            `json:"type"`
	JSONSchema *openAIJSONSchema `json:"json_schema,omitempty"`
}

type openAIJSONSchema struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict,omitempty"`
}

type openAIResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content openAIContent `json:"content"`
			Refusal string        `json:"refusal"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error json.RawMessage `json:"error"`
}

// openAIContent accepts both a plain string and the newer array-of-parts
// content shape used by some OpenAI-compatible gateways.
type openAIContent struct {
	Text string
}

func (c *openAIContent) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		c.Text = ""
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		c.Text = text
		return nil
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(data, &parts); err == nil {
		var b strings.Builder
		for _, part := range parts {
			b.WriteString(part.Text)
		}
		c.Text = b.String()
		return nil
	}
	var object struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(data, &object); err == nil && object.Text != "" {
		c.Text = object.Text
		return nil
	}
	return errors.New("unsupported message content")
}

// Complete implements Client.
func (c *openAIClient) Complete(ctx context.Context, req Request) (Response, error) {
	payload, buildErr := c.buildRequest(req)
	if buildErr != nil {
		return Response{}, buildErr
	}
	data, err := c.send(ctx, payload)
	if err != nil {
		return Response{}, err
	}
	return c.parse(data)
}

func (c *openAIClient) buildRequest(req Request) (openAIRequest, *Error) {
	system := req.System
	wantJSON := req.JSON || len(req.JSONSchema) > 0
	if wantJSON {
		system = withJSONInstruction(system)
	}

	messages := normalizeMessages(system, req.Messages)
	if len(messages) == 0 {
		return openAIRequest{}, c.http.newError(0, "invalid_request", "request has no messages", false)
	}

	payload := openAIRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   c.maxTokens(req.MaxTokens),
		Temperature: clampFloat(c.temperature(req.Temperature), 0, 2),
		Stream:      false,
	}
	if wantJSON && c.jsonMode {
		payload.ResponseFormat = openAIResponseFormatFor(req.JSONSchema)
	}
	return payload, nil
}

func openAIResponseFormatFor(schema json.RawMessage) *openAIResponseFormat {
	if len(schema) > 0 && json.Valid(schema) {
		return &openAIResponseFormat{
			Type: "json_schema",
			JSONSchema: &openAIJSONSchema{
				Name:   "vigil_response",
				Schema: schema,
			},
		}
	}
	return &openAIResponseFormat{Type: "json_object"}
}

func (c *openAIClient) send(ctx context.Context, payload openAIRequest) ([]byte, error) {
	body, encodeErr := encodeRequest(c.provider, payload)
	if encodeErr != nil {
		return nil, encodeErr
	}
	data, err := c.http.do(ctx, http.MethodPost, c.endpoint(), c.headers(), body)
	if err == nil || payload.ResponseFormat == nil || !isHTTPStatus(err, http.StatusBadRequest) {
		return data, err
	}

	// Best effort: several OpenAI-compatible servers reject response_format.
	// Retry once without it; the system prompt still asks for JSON.
	payload.ResponseFormat = nil
	body, encodeErr = encodeRequest(c.provider, payload)
	if encodeErr != nil {
		return nil, encodeErr
	}
	return c.http.do(ctx, http.MethodPost, c.endpoint(), c.headers(), body)
}

func (c *openAIClient) parse(data []byte) (Response, error) {
	var payload openAIResponse
	if err := DecodeInto(data, &payload); err != nil {
		return Response{}, c.http.newError(0, "decode_response", err.Error(), false)
	}
	if len(payload.Error) > 0 && !isJSONNull(payload.Error) {
		code, message := parseProviderError(payload.Error)
		return Response{}, c.http.newError(0, code, message, false)
	}
	if len(payload.Choices) == 0 {
		return Response{}, c.http.newError(0, "empty_response", "provider returned no choices", false)
	}

	choice := payload.Choices[0]
	text := choice.Message.Content.Text
	if strings.TrimSpace(text) == "" {
		if strings.TrimSpace(choice.Message.Refusal) != "" {
			return Response{}, c.http.newError(0, "refusal", choice.Message.Refusal, false)
		}
		return Response{}, c.http.newError(0, "empty_content", "provider returned an empty message", false)
	}

	model := strings.TrimSpace(payload.Model)
	if model == "" {
		model = c.model
	}
	return Response{
		Text:         text,
		Model:        model,
		InputTokens:  payload.Usage.PromptTokens,
		OutputTokens: payload.Usage.CompletionTokens,
		FinishReason: choice.FinishReason,
	}, nil
}

func (c *openAIClient) endpoint() string {
	return joinURL(c.baseURL, "chat/completions")
}

func (c *openAIClient) headers() http.Header {
	h := c.baseClient.headers()
	if c.apiKey != "" {
		h.Set("Authorization", "Bearer "+c.apiKey)
	}
	if c.provider == config.ProviderOpenRouter {
		h.Set("HTTP-Referer", openRouterReferer)
		h.Set("X-Title", openRouterTitle)
	}
	return h
}
