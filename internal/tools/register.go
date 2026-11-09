// Package tools implements Vigil's MCP surface: the vigil_* tools, the
// vigil:// resources and the review prompts.
//
// Every tool is read-only by default. Only vigil_fix with apply=true modifies
// source files; vigil_report writes a report only when a path is supplied, and
// vigil_baseline writes the baseline file. Tool text is bounded to roughly
// 40 KiB; structured content is left intact so clients can consume the full
// model.ScanResult.
package tools

import (
	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

// Deps is the runtime the MCP surface operates on.
type Deps struct {
	App     *app.App
	Version string
}

// ToolNames lists the tools Register installs, in registration order.
func ToolNames() []string {
	return []string{
		"vigil_scan",
		"vigil_review",
		"vigil_explain",
		"vigil_fix",
		"vigil_threat_model",
		"vigil_status",
		"vigil_rules",
		"vigil_baseline",
		"vigil_report",
		"vigil_verify",
		"vigil_history",
	}
}

// Register installs every tool, resource and prompt on srv. Registration order
// is stable so tools/list output is predictable across builds.
func Register(srv *mcp.Server, d Deps) {
	if srv == nil {
		return
	}
	if d.Version == "" {
		d.Version = version.Version
	}

	registerScan(srv, d)
	registerReview(srv, d)
	registerExplain(srv, d)
	registerFix(srv, d)
	registerThreatModel(srv, d)
	registerStatus(srv, d)
	registerRules(srv, d)
	registerBaseline(srv, d)
	registerReport(srv, d)
	registerVerify(srv, d)
	registerHistory(srv, d)

	registerResources(srv, d)
	registerPrompts(srv, d)
}
