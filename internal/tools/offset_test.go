package tools_test

import (
	"math"
	"testing"
)

// TestScanOffsetsRejectUnreachablePages: a scan can page through at most 500
// findings, and an enormous offset must never overflow into an unlimited scan.
func TestScanOffsetsRejectUnreachablePages(t *testing.T) {
	h := newHarness(t)
	tools := []string{"vigil_scan", "vigil_review", "vigil_hardening", "vigil_mcp_audit"}
	for _, name := range tools {
		for _, offset := range []int{501, math.MaxInt} {
			res := callTool(t, h.client, name, map[string]any{"offset": offset})
			if code := toolErrorCode(t, res); code != "VGL-ARGS" {
				t.Errorf("%s offset=%d code = %q, want VGL-ARGS", name, offset, code)
			}
		}
	}
}
