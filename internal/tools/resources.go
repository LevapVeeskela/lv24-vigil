package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
)

// registerResources exposes the read-only JSON resources. Scan resources are
// registered for the scans that exist at start-up: the MCP server dispatches
// resources by exact URI, so a new scan becomes readable after the server is
// restarted (or by calling vigil_report / the tools in the same session).
func registerResources(srv *mcp.Server, d Deps) {
	srv.AddResource(mcp.Resource{
		URI:         "vigil://status",
		Name:        "status",
		Title:       "Vigil status",
		Description: "Version, root, model configuration (key redacted), rule count and the last scan summary.",
		MimeType:    "application/json",
	}, func(_ context.Context, uri string) ([]mcp.ResourceContents, error) {
		return jsonResource(uri, statusPayloadFor(d))
	})

	srv.AddResource(mcp.Resource{
		URI:         "vigil://rules",
		Name:        "rules",
		Title:       "Vigil rules",
		Description: "Every deterministic rule with its severity, category, languages and metadata.",
		MimeType:    "application/json",
	}, func(_ context.Context, uri string) ([]mcp.ResourceContents, error) {
		if d.App == nil {
			return nil, fmt.Errorf("vigil is not initialised")
		}
		metas := d.App.Registry.Metas()
		return jsonResource(uri, map[string]any{"count": len(metas), "rules": metas})
	})

	readScan := func(_ context.Context, uri string) ([]mcp.ResourceContents, error) {
		if d.App == nil {
			return nil, fmt.Errorf("vigil is not initialised")
		}
		id := strings.TrimPrefix(uri, "vigil://scan/")
		if id == "" {
			return nil, fmt.Errorf("invalid scan resource %q", uri)
		}
		if id == "last" {
			res, err := d.App.LastScan()
			if err != nil {
				return nil, fmt.Errorf("no stored scans: %v (run vigil_scan first)", err)
			}
			return jsonResource(uri, res)
		}
		res, err := d.App.GetScan(id)
		if err != nil {
			return nil, fmt.Errorf("unknown scan %q: %v", id, err)
		}
		return jsonResource(uri, res)
	}

	srv.AddResource(mcp.Resource{
		URI:         "vigil://scan/last",
		Name:        "scan-last",
		Title:       "Last Vigil scan",
		Description: "The full result of the most recent scan.",
		MimeType:    "application/json",
	}, readScan)

	if d.App == nil {
		return
	}
	summaries, err := d.App.Store.List(20)
	if err != nil {
		return
	}
	for _, s := range summaries {
		srv.AddResource(mcp.Resource{
			URI:         "vigil://scan/" + s.ID,
			Name:        "scan-" + s.ID,
			Title:       "Vigil scan " + s.ID,
			Description: fmt.Sprintf("Stored scan %s (%d findings, %d critical, %d high).", s.ID, s.Findings, s.Critical, s.High),
			MimeType:    "application/json",
		}, readScan)
	}
}

func jsonResource(uri string, v any) ([]mcp.ResourceContents, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", uri, err)
	}
	return []mcp.ResourceContents{{
		URI:      uri,
		MimeType: "application/json",
		Text:     string(data) + "\n",
	}}, nil
}
