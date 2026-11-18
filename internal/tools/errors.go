package tools

import (
	"errors"
	"fmt"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
)

// Stable tool error codes. Clients may branch on
// structuredContent.error.code, so existing codes must not be renamed.
const (
	CodeArgs       = "VGL-ARGS"
	CodeBadPath    = "VGL-BAD-PATH"
	CodeNoScan     = "VGL-NO-SCAN"
	CodeNoFindings = "VGL-NO-FINDINGS"
	CodeNotFound   = "VGL-NOT-FOUND"
	CodeAmbiguous  = "VGL-AMBIGUOUS"
	CodeReadOnly   = "VGL-READONLY"
	CodeOffline    = "VGL-OFFLINE"
)

// Candidate is one alternative in a missing or ambiguous lookup. It carries no
// snippet or evidence text: error paths must not leak code.
type Candidate struct {
	FindingID string `json:"findingId"`
	RuleID    string `json:"ruleId,omitempty"`
	Location  string `json:"location"`
	Severity  string `json:"severity,omitempty"`
}

// ToolError is a typed tool failure. Its text form starts with the code, and
// errorResult turns it into structuredContent.error while keeping isError set.
type ToolError struct {
	Code       string
	Message    string
	Candidates []Candidate
}

// Error implements error.
func (e *ToolError) Error() string {
	if e == nil {
		return ""
	}
	return "[" + e.Code + "] " + e.Message
}

// toolErrorf builds a typed error without candidates.
func toolErrorf(code, format string, args ...any) *ToolError {
	return &ToolError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// asToolError unwraps a typed error, including one wrapped with %w.
func asToolError(err error) *ToolError {
	var te *ToolError
	if errors.As(err, &te) {
		return te
	}
	return nil
}

// errorBody is the stable shape of structuredContent.error.
type errorBody struct {
	Code       string      `json:"code"`
	Message    string      `json:"message"`
	Candidates []Candidate `json:"candidates,omitempty"`
}

type errorPayload struct {
	Error errorBody `json:"error"`
}

// typedResult renders a ToolError as a redacted isError result. The structured
// payload lets a client retry deterministically (for example with a candidate
// finding ID) without parsing the message.
func typedResult(d Deps, te *ToolError) *mcp.CallToolResult {
	res := mcp.TextError("%s", redactKey(d, te.Error()))
	res.StructuredContent = errorPayload{Error: errorBody{
		Code:       te.Code,
		Message:    redactKey(d, te.Message),
		Candidates: te.Candidates,
	}}
	return res
}

// toolErrorResult renders err, preserving a ToolError code when present.
func toolErrorResult(d Deps, err error) *mcp.CallToolResult {
	if te := asToolError(err); te != nil {
		return typedResult(d, te)
	}
	return errorResult(d, "%v", err)
}

// readOnlyResult rejects a write made against a read-only server.
func readOnlyResult(d Deps, what string) *mcp.CallToolResult {
	return typedResult(d, toolErrorf(CodeReadOnly,
		"%s is disabled: the MCP server runs in read-only mode. Restart it without --read-only to allow writes.", what))
}

// offlineResult rejects an operation that needs network access in offline mode.
func offlineResult(d Deps, what string) *mcp.CallToolResult {
	return typedResult(d, toolErrorf(CodeOffline,
		"%s needs network access, and the MCP server runs in offline mode. "+
			"Restart it without --offline (or unset VIGIL_MCP_OFFLINE) to allow this request.", what))
}
