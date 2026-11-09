package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// geminiClient speaks the Google Gemini generateContent API.
type geminiClient struct {
	baseClient
}

type geminiRequest struct {
	SystemInstruction *geminiContent         `json:"systemInstruction,omitempty"`
	Contents          []geminiContent        `json:"contents"`
	GenerationConfig  geminiGenerationConfig `json:"generationConfig"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens  int     `json:"maxOutputTokens"`
	Temperature      float64 `json:"temperature"`
	ResponseMimeType string  `json:"responseMimeType,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Role  string `json:"role"`
			Parts []struct {
				Text    string `json:"text"`
				Thought bool   `json:"thought"`
			} `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
	ModelVersion   string `json:"modelVersion"`
	PromptFeedback struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
	Error json.RawMessage `json:"error"`
}

// Complete implements Client.
func (c *geminiClient) Complete(ctx context.Context, req Request) (Response, error) {
	system, contents := geminiContents(req.System, req.Messages)
	if len(contents) == 0 {
		return Response{}, c.http.newError(0, "invalid_request", "request has no messages", false)
	}

	wantJSON := req.JSON || len(req.JSONSchema) > 0
	if wantJSON {
		system = withJSONSchemaInstruction(system, req.JSONSchema)
	}

	payload := geminiRequest{
		Contents: contents,
		GenerationConfig: geminiGenerationConfig{
			MaxOutputTokens: c.maxTokens(req.MaxTokens),
			Temperature:     clampFloat(c.temperature(req.Temperature), 0, 2),
		},
	}
	if strings.TrimSpace(system) != "" {
		payload.SystemInstruction = &geminiContent{Parts: []geminiPart{{Text: system}}}
	}
	if wantJSON {
		payload.GenerationConfig.ResponseMimeType = "application/json"
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

func (c *geminiClient) endpoint() string {
	model := strings.TrimPrefix(strings.TrimSpace(c.model), "models/")
	base := strings.TrimRight(c.baseURL, "/")
	return base + "/models/" + model + ":generateContent?key=" + url.QueryEscape(c.apiKey)
}

func (c *geminiClient) parse(data []byte) (Response, error) {
	var payload geminiResponse
	if err := DecodeInto(data, &payload); err != nil {
		return Response{}, c.http.newError(0, "decode_response", err.Error(), false)
	}
	if len(payload.Error) > 0 && !isJSONNull(payload.Error) {
		code, message := parseProviderError(payload.Error)
		return Response{}, c.http.newError(0, code, message, false)
	}
	if len(payload.Candidates) == 0 {
		if reason := strings.TrimSpace(payload.PromptFeedback.BlockReason); reason != "" {
			return Response{}, c.http.newError(0, "blocked", "response blocked by provider: "+reason, false)
		}
		return Response{}, c.http.newError(0, "empty_response", "provider returned no candidates", false)
	}

	candidate := payload.Candidates[0]
	var text strings.Builder
	for _, part := range candidate.Content.Parts {
		if part.Thought {
			continue
		}
		text.WriteString(part.Text)
	}
	if strings.TrimSpace(text.String()) == "" {
		message := "provider returned an empty message"
		if reason := strings.TrimSpace(candidate.FinishReason); reason != "" {
			message += " (finish reason: " + reason + ")"
		}
		return Response{}, c.http.newError(0, "empty_content", message, false)
	}

	model := strings.TrimSpace(payload.ModelVersion)
	if model == "" {
		model = c.model
	}
	return Response{
		Text:         text.String(),
		Model:        model,
		InputTokens:  payload.UsageMetadata.PromptTokenCount,
		OutputTokens: payload.UsageMetadata.CandidatesTokenCount,
		FinishReason: candidate.FinishReason,
	}, nil
}

// geminiContents merges system-role messages into systemInstruction and maps
// assistant to Gemini's "model" role.
func geminiContents(system string, messages []Message) (string, []geminiContent) {
	var systemParts []string
	if strings.TrimSpace(system) != "" {
		systemParts = append(systemParts, system)
	}

	contents := make([]geminiContent, 0, len(messages))
	for _, message := range messages {
		if strings.TrimSpace(message.Content) == "" {
			continue
		}
		switch message.Role {
		case RoleSystem:
			systemParts = append(systemParts, message.Content)
			continue
		case RoleAssistant:
			contents = append(contents, geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: message.Content}},
			})
		default:
			contents = append(contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: message.Content}},
			})
		}
	}
	return strings.Join(systemParts, "\n\n"), contents
}
