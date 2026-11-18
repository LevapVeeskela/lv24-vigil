package tools_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

// writeBaseline seeds the default baseline file with n accepted findings.
func writeBaseline(t *testing.T, repo string, ids ...string) string {
	t.Helper()
	path := filepath.Join(repo, scanner.DefaultBaselineFile)
	b := scanner.NewBaseline()
	for _, id := range ids {
		b.Findings = append(b.Findings, scanner.BaselineFinding{ID: id, Reason: "test"})
	}
	if err := scanner.SaveBaseline(path, b); err != nil {
		t.Fatalf("save baseline: %v", err)
	}
	return path
}

type baselinePagePayload struct {
	Findings []scanner.BaselineFinding `json:"findings"`
	Total    int                       `json:"findingsTotal"`
	Page     struct {
		Offset     int  `json:"offset"`
		Limit      int  `json:"limit"`
		Total      int  `json:"total"`
		HasMore    bool `json:"hasMore"`
		NextOffset *int `json:"nextOffset"`
	} `json:"page"`
}

func decodeBaselinePage(t *testing.T, res mcp.CallToolResult) baselinePagePayload {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var payload baselinePagePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}

func TestBaselineListPaginates(t *testing.T) {
	h := newHarness(t)
	writeBaseline(t, h.repo, "VGL-A", "VGL-B", "VGL-C")

	res := callTool(t, h.client, "vigil_baseline", map[string]any{"action": "list", "limit": 1})
	if res.IsError {
		t.Fatalf("baseline list: %+v", res.Content)
	}
	payload := decodeBaselinePage(t, res)
	if len(payload.Findings) != 1 || payload.Total != 3 || payload.Page.Total != 3 {
		t.Fatalf("first page = %+v, want 1 of 3 findings", payload)
	}
	if !payload.Page.HasMore || payload.Page.NextOffset == nil || *payload.Page.NextOffset != 1 {
		t.Fatalf("first page cursor = %+v, want nextOffset=1", payload.Page)
	}

	res = callTool(t, h.client, "vigil_baseline", map[string]any{"action": "list", "offset": 2, "limit": 1})
	payload = decodeBaselinePage(t, res)
	if len(payload.Findings) != 1 || payload.Page.HasMore || payload.Page.NextOffset != nil {
		t.Fatalf("last page = %+v, want one finding and no cursor", payload)
	}

	res = callTool(t, h.client, "vigil_baseline", map[string]any{"action": "list", "offset": 99})
	if res.IsError {
		t.Fatalf("offset past the end must not be an error: %+v", res.Content)
	}
	payload = decodeBaselinePage(t, res)
	if len(payload.Findings) != 0 || payload.Page.HasMore {
		t.Fatalf("overshoot page = %+v, want empty and no cursor", payload)
	}

	res = callTool(t, h.client, "vigil_baseline", map[string]any{"action": "list", "offset": -1})
	if got := toolErrorCode(t, res); got != "VGL-ARGS" {
		t.Errorf("negative offset code = %q, want VGL-ARGS", got)
	}
}
