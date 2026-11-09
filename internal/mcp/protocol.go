// Package mcp implements the Model Context Protocol server transport and the
// JSON-RPC types Vigil exposes. It is deliberately small and dependency-free:
// one line of JSON per message over stdio, plus an optional HTTP transport.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the newest version Vigil speaks. Clients that ask for an
// older supported version get that version echoed back, as the spec requires.
const ProtocolVersion = "2025-06-18"

// SupportedProtocolVersions lists the versions accepted during initialize.
var SupportedProtocolVersions = []string{
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// JSONRPC is the JSON-RPC version string.
const JSONRPC = "2.0"

// Standard JSON-RPC error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Request is a JSON-RPC request or notification. A notification has no ID.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the request omits the id.
func (r Request) IsNotification() bool { return len(r.ID) == 0 }

// Response is a JSON-RPC response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("%s (%d)", e.Message, e.Code) }

// NewError builds an RPCError.
func NewError(code int, format string, args ...any) *RPCError {
	return &RPCError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// InitializeParams is the client's handshake.
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      Implementation `json:"clientInfo"`
}

// Implementation identifies a client or server.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title,omitempty"`
}

// InitializeResult is the server handshake.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// ServerCapabilities advertises what the server supports.
type ServerCapabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
	Logging   *struct{}            `json:"logging,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// Tool is one callable tool.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations map[string]any  `json:"annotations,omitempty"`
	// Handler is not serialised.
	Handler ToolHandler `json:"-"`
}

// ToolHandler executes a tool. Args is the raw JSON object from the client.
type ToolHandler func(ctx context.Context, args json.RawMessage) (*CallToolResult, error)

// Content is one piece of tool output.
type Content struct {
	Type     string `json:"type"` // text | image | resource
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Data     string `json:"data,omitempty"`
}

// CallToolResult is the result of tools/call.
type CallToolResult struct {
	Content           []Content `json:"content"`
	StructuredContent any       `json:"structuredContent,omitempty"`
	IsError           bool      `json:"isError,omitempty"`
}

// TextResult builds a text-only result.
func TextResult(text string) *CallToolResult {
	return &CallToolResult{Content: []Content{{Type: "text", Text: text}}}
}

// TextError builds an isError result with a human-readable message.
func TextError(format string, args ...any) *CallToolResult {
	return &CallToolResult{
		Content: []Content{{Type: "text", Text: fmt.Sprintf(format, args...)}},
		IsError: true,
	}
}

// ToolsListResult is the tools/list response.
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// Resource describes an MCP resource.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourceContents is the resources/read payload.
type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

type ResourcesListResult struct {
	Resources []Resource `json:"resources"`
}

type ResourcesReadResult struct {
	Contents []ResourceContents `json:"contents"`
}

// PromptArgument describes a prompt parameter.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt is an MCP prompt template.
type Prompt struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
	// Handler is not serialised.
	Handler PromptHandler `json:"-"`
}

// PromptHandler renders a prompt.
type PromptHandler func(ctx context.Context, args map[string]string) (*GetPromptResult, error)

type PromptsListResult struct {
	Prompts []Prompt `json:"prompts"`
}

type PromptMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// ProgressNotification is sent by the server while a long tool runs.
type ProgressNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		ProgressToken any     `json:"progressToken"`
		Progress      float64 `json:"progress"`
		Total         float64 `json:"total,omitempty"`
		Message       string  `json:"message,omitempty"`
	} `json:"params"`
}

// JSONSchema helpers keep tool schemas readable in code.

// ObjectSchema builds a JSON Schema object with properties and required names.
func ObjectSchema(properties map[string]any, required ...string) json.RawMessage {
	obj := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		obj["required"] = required
	}
	data, _ := json.Marshal(obj)
	return data
}

// Prop builds a schema property.
func Prop(typ, description string) map[string]any {
	return map[string]any{"type": typ, "description": description}
}

// PropEnum builds a string property with an enum.
func PropEnum(description string, values ...string) map[string]any {
	return map[string]any{"type": "string", "description": description, "enum": values}
}

// PropArray builds an array-of-strings property.
func PropArray(description string) map[string]any {
	return map[string]any{
		"type":        "array",
		"description": description,
		"items":       map[string]any{"type": "string"},
	}
}

// PropBool builds a boolean property.
func PropBool(description string) map[string]any {
	return map[string]any{"type": "boolean", "description": description}
}

// PropInt builds an integer property.
func PropInt(description string) map[string]any {
	return map[string]any{"type": "integer", "description": description}
}
