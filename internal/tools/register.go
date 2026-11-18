// Package tools implements Vigil's MCP surface: the vigil_* tools, the
// vigil:// resources and the review prompts.
//
// No tool modifies source files except vigil_fix with apply=true. Scans write
// local history so later tools can address their findings; vigil_report writes
// a report only when a path is supplied, and vigil_baseline writes the baseline
// file. A Deps with ReadOnly set hides vigil_fix and rejects those writes.
// Tool text is bounded to roughly 40 KiB; structured content is left intact so
// clients can consume the full model.ScanResult. Typed failures carry a stable
// VGL-* code in the text and in structuredContent.error.
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
	// ReadOnly hides vigil_fix from tools/list and rejects every write to
	// source files, the baseline and report paths. Scan history is still
	// recorded locally so later tools can address the findings.
	ReadOnly bool
	// Offline disables every network call: the model client is not built and
	// OSV lookups are forced off, including a configured OSV base URL.
	Offline bool
	// UnsafeUnboundFix restores the 0.10 behaviour where vigil_fix apply=true
	// proposes and applies in one call without a reviewed fixId/diffSha256.
	// It is a deliberate compatibility escape hatch and defaults to false.
	UnsafeUnboundFix bool
}

// ToolNames lists the tools Register installs, in registration order.
func ToolNames() []string {
	return []string{
		"vigil_scan",
		"vigil_review",
		"vigil_dependencies",
		"vigil_hardening",
		"vigil_mcp_audit",
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
	registerDependencies(srv, d)
	registerHardening(srv, d)
	registerMCPAudit(srv, d)
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
