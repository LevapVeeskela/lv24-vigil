package tools_test

import (
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

func TestBaselineClearRequiresConfirmation(t *testing.T) {
	h := newHarness(t)
	path := writeBaseline(t, h.repo, "VGL-A")

	res := callTool(t, h.client, "vigil_baseline", map[string]any{"action": "clear"})
	if code := toolErrorCode(t, res); code != "VGL-ARGS" {
		t.Fatalf("clear without confirm code = %q, want VGL-ARGS", code)
	}
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if len(b.Findings) != 1 {
		t.Fatalf("clear without confirm changed the baseline: %+v", b.Findings)
	}

	res = callTool(t, h.client, "vigil_baseline", map[string]any{"action": "clear", "confirm": true})
	if res.IsError {
		t.Fatalf("confirmed clear failed: %+v", res.Content)
	}
	b, err = scanner.LoadBaseline(path)
	if err != nil {
		t.Fatalf("load cleared baseline: %v", err)
	}
	if len(b.Findings) != 0 {
		t.Fatalf("confirmed clear kept %d entries", len(b.Findings))
	}
}

func TestBaselineListSanitizesHandEditedFields(t *testing.T) {
	h := newHarness(t)
	path := writeBaseline(t, h.repo, "VGL-A")
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	b.Findings[0].Reason = "accepted\n\n# injected heading"
	b.Findings[0].Ticket = "SEC-1\ninjected"
	b.Findings[0].Path = "a.go\ninjected"
	if err := scanner.SaveBaseline(path, b); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	res := callTool(t, h.client, "vigil_baseline", map[string]any{"action": "list"})
	if res.IsError {
		t.Fatalf("baseline list: %+v", res.Content)
	}
	text := textOf(t, res)
	for _, bad := range []string{"accepted\n\n# injected heading", "# injected heading\n", "SEC-1\ninjected", "a.go\ninjected"} {
		if strings.Contains(text, bad) {
			t.Errorf("baseline list kept raw newlines in a field: %q\n%s", bad, text)
		}
	}
	if !strings.Contains(text, "# injected heading") {
		t.Errorf("baseline list dropped the sanitized reason entirely:\n%s", text)
	}
}
