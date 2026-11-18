package main

import (
	"strings"
	"testing"
)

func TestMCPHelpDocumentsModes(t *testing.T) {
	out, _, err := runCLI(t, "mcp", "--help")
	if err != nil {
		t.Fatalf("mcp --help: %v", err)
	}
	for _, want := range []string{"--read-only", "--offline", "VIGIL_MCP_READ_ONLY", "VIGIL_MCP_OFFLINE"} {
		if !strings.Contains(out, want) {
			t.Errorf("mcp help missing %q\n%s", want, out)
		}
	}
}

func TestEnvBool(t *testing.T) {
	cases := map[string]bool{
		"":         false,
		"0":        false,
		"false":    false,
		"nonsense": false,
		"1":        true,
		"true":     true,
		"TRUE":     true,
		"yes":      false, // strconv.ParseBool does not accept yes: leave the default.
	}
	for value, want := range cases {
		t.Setenv("VIGIL_TEST_ENV_BOOL", value)
		if got := envBool("VIGIL_TEST_ENV_BOOL"); got != want {
			t.Errorf("envBool(%q) = %v, want %v", value, got, want)
		}
	}
}
