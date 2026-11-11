package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/osv"
)

// dependenciesTopFindings bounds the advisory list in the text summary. The
// full list is always available in structuredContent.
const dependenciesTopFindings = 20

type dependenciesArgs struct {
	Path        string `json:"path"`
	IncludeDev  *bool  `json:"includeDev"`
	MaxPackages int    `json:"maxPackages"`
	OSVBaseURL  string `json:"osvBaseUrl"`
}

// dependenciesPayload is the structuredContent of vigil_dependencies. It is
// deliberately flat: clients can read the inventory, the advisories, the
// coverage errors and the limitation text without parsing prose.
type dependenciesPayload struct {
	Packages    []osv.Package   `json:"packages"`
	Findings    []model.Finding `json:"findings"`
	Errors      []string        `json:"errors"`
	Limitations []string        `json:"limitations"`
}

func registerDependencies(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_dependencies",
		Title: "Audit dependency advisories with Vigil",
		Description: "Read dependency manifests and lockfiles, query the public OSV.dev database for the exact " +
			"versions found and report known public advisories. Returns a text summary and the inventory, " +
			"findings, coverage errors and limitations as structuredContent. Read-only: no package manager " +
			"runs, no writes and no telemetry.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"path":        mcp.Prop("string", "Directory or repository to audit. Defaults to the server's project root."),
			"includeDev":  mcp.PropBool("Also query dev dependencies. Defaults to true."),
			"maxPackages": mcp.PropInt("Maximum distinct packages to query (default 200, capped at 1000)."),
			"osvBaseUrl":  mcp.Prop("string", "Override the OSV API root. Defaults to https://api.osv.dev; must be https, or http on a loopback host (127.0.0.1, ::1, localhost). Credentials in the URL are refused."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": true},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleDependencies(ctx, d, raw)
		},
	})
}

func handleDependencies(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args dependenciesArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	root, err := resolveAuditRoot(d, args.Path)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}
	maxPackages, err := dependenciesMaxPackages(args.MaxPackages)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}

	opts := osv.DefaultOptions()
	opts.MaxPackages = maxPackages
	includeDev := true
	if args.IncludeDev != nil {
		includeDev = *args.IncludeDev
	}
	opts.IncludeDev = includeDev
	if base := strings.TrimSpace(args.OSVBaseURL); base != "" {
		if err := checkAgentOSVBaseURL(base); err != nil {
			return mcp.TextError("invalid arguments: %v", err), nil
		}
		opts.BaseURL = base
	}

	audit, err := osv.Audit(ctx, root, opts)
	if err != nil && audit == nil {
		return errorResult(d, "dependency audit failed: %v", err), nil
	}
	if audit == nil {
		audit = &osv.AuditResult{}
	}
	errors := append([]string(nil), audit.Errors...)
	if err != nil {
		errors = append(errors, err.Error())
	}

	payload := dependenciesPayload{
		Packages:    nonNilPackages(audit.Packages),
		Findings:    nonNilFindings(audit.Findings),
		Errors:      nonNilStrings(errors),
		Limitations: dependencyLimitations(),
	}
	return result(d, dependenciesSummary(root, payload, includeDev, maxPackages), payload), nil
}

// resolveAuditRoot resolves path against the app root and rejects a missing
// path or a regular file before any manifest walk starts.
func resolveAuditRoot(d Deps, p string) (string, error) {
	root, err := resolvePath(d, p)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("path %q does not exist or is not readable", root)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %q is not a directory", root)
	}
	return root, nil
}

// checkAgentOSVBaseURL limits where an MCP caller may send the package
// inventory. The argument can come from an agent steered by untrusted content,
// so plain http is accepted only on a loopback host (a local mirror or test
// server), and credentials in the URL are refused without echoing them.
// Other schemes fall through to the osv package's own validation.
func checkAgentOSVBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("osvBaseUrl is not a valid URL")
	}
	if u.User != nil {
		return errors.New("osvBaseUrl must not contain credentials")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("osvBaseUrl must use https; plain http is accepted only for a loopback host (127.0.0.1, ::1, localhost)")
	default:
		return nil
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// dependenciesMaxPackages applies the documented default and cap. A negative
// value is a caller bug, not something to guess at.
func dependenciesMaxPackages(n int) (int, error) {
	if n < 0 {
		return 0, fmt.Errorf("maxPackages must be a positive integer (default %d, cap %d)", osv.DefaultMaxPackages, osv.MaxAllowedPackages)
	}
	return clampInt(n, osv.DefaultMaxPackages, osv.MaxAllowedPackages), nil
}

// dependenciesSummary renders the human-readable half of vigil_dependencies.
// Every claim about coverage is stated here, not only in the payload.
func dependenciesSummary(root string, payload dependenciesPayload, includeDev bool, maxPackages int) string {
	var b strings.Builder
	b.WriteString("Vigil dependency audit — known public advisories only\n")
	fmt.Fprintf(&b, "Root: %s\n", root)
	dev := "dev dependencies included"
	if !includeDev {
		dev = "dev dependencies excluded"
	}
	fmt.Fprintf(&b, "Packages: %d queried (%s, maxPackages %d)\n", len(payload.Packages), dev, maxPackages)
	fmt.Fprintf(&b, "Findings: %d (%s)\n", len(payload.Findings), severityLine(payload.Findings))
	fmt.Fprintf(&b, "Warnings: %s\n", warningLine(payload.Errors))
	b.WriteString("\nKnown public advisories only; no match does not mean safe. ")
	b.WriteString("OSV.dev is queried for exact versions from supported manifests: unpublished, private and ")
	b.WriteString("zero-day advisories are not covered, and no exploitability or reachability analysis is performed.\n")

	if len(payload.Findings) == 0 {
		if len(payload.Packages) == 0 {
			b.WriteString("\nNo supported dependency manifests were found in this scope. Nothing was queried.\n")
			return b.String()
		}
		if len(payload.Errors) > 0 {
			b.WriteString("\nThe query reported warnings, so coverage is incomplete: do not treat this as a clean result.\n")
			return b.String()
		}
		b.WriteString("\nNo known public advisory matched the queried packages. That is not proof that they are safe.\n")
		return b.String()
	}

	b.WriteString("\nAdvisories:\n")
	for i, f := range payload.Findings {
		if i == dependenciesTopFindings {
			fmt.Fprintf(&b, "  … and %d more (structuredContent carries every finding)\n", len(payload.Findings)-dependenciesTopFindings)
			break
		}
		fmt.Fprintf(&b, "  %d. %s\n", i+1, findingSummary(f))
		if rem := oneLine(f.Remediation); rem != "" {
			fmt.Fprintf(&b, "     fix: %s\n", truncateRunes(rem, 240))
		}
	}
	b.WriteString("\nThese are known public advisories, not a vulnerability verdict for the application.\n")
	return b.String()
}

// dependencyLimitations is the machine-readable form of the coverage caveats.
// It is returned in structuredContent and repeated in the text summary.
func dependencyLimitations() []string {
	return []string{
		"Known public advisories only (OSV.dev): a package with no match is not proof of safety.",
		"Only exact versions from supported manifests and lockfiles are queried; ranges, vendored code, container images and OS-level packages are not covered.",
		"No zero-day, private or unpublished advisory detection; no exploitability or reachability analysis.",
		"Results reflect the OSV database at query time; re-run after dependency changes.",
	}
}

func nonNilPackages(in []osv.Package) []osv.Package {
	if in == nil {
		return []osv.Package{}
	}
	return in
}

func nonNilFindings(in []model.Finding) []model.Finding {
	if in == nil {
		return []model.Finding{}
	}
	return in
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
