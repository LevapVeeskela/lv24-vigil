package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
)

type threatModelArgs struct {
	Path string `json:"path"`
}

func registerThreatModel(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_threat_model",
		Title: "Generate a threat model with Vigil",
		Description: "Ask the configured model for a repository threat model: assets, trust boundaries, " +
			"entry points and the most likely attack paths. Requires a model.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"path": mcp.Prop("string", "Directory to model. Must match the server's project root; defaults to it."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleThreatModel(ctx, d, raw)
		},
	})
}

func handleThreatModel(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args threatModelArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	root, err := resolvePath(d, args.Path)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}
	if !samePath(root, d.App.Root) {
		return mcp.TextError("invalid arguments: this server is rooted at %s; start a Vigil MCP server in %s to model that repository", d.App.Root, root), nil
	}
	if !d.App.LLM {
		return mcp.TextError("vigil_threat_model needs a model: set VIGIL_PROVIDER, VIGIL_MODEL and VIGIL_API_KEY (or a local OLLAMA_HOST)."), nil
	}

	md, err := d.App.ThreatModel(ctx)
	if err != nil {
		return errorResult(d, "threat model failed: %v", err), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Threat model — %s\n\n", d.App.Root)
	fmt.Fprintf(&b, "Model: %s\n\n", modelLine(d, d.App.Model))
	b.WriteString(strings.TrimSpace(md))
	b.WriteString("\n")

	payload := map[string]any{
		"root":        d.App.Root,
		"model":       modelLine(d, d.App.Model),
		"threatModel": strings.TrimSpace(md),
	}
	return result(d, b.String(), payload), nil
}
