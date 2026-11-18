package main

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/tools"
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
	cases := []struct {
		value   string
		want    bool
		wantErr bool
	}{
		{"", false, false},
		{"0", false, false},
		{"false", false, false},
		{"1", true, false},
		{"true", true, false},
		{"TRUE", true, false},
		{"nonsense", false, true},
		{"yes", false, true},
	}
	for _, tc := range cases {
		t.Setenv("VIGIL_TEST_ENV_BOOL", tc.value)
		got, err := envBool("VIGIL_TEST_ENV_BOOL")
		if tc.wantErr {
			if err == nil {
				t.Errorf("envBool(%q) = %v, want an error", tc.value, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("envBool(%q): %v", tc.value, err)
		}
		if got != tc.want {
			t.Errorf("envBool(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestMCPRejectsInvalidModeEnv(t *testing.T) {
	t.Setenv("VIGIL_MCP_READ_ONLY", "yes")
	err := runMCP(nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("runMCP accepted VIGIL_MCP_READ_ONLY=yes")
	}
	if !strings.Contains(err.Error(), "VIGIL_MCP_READ_ONLY") {
		t.Errorf("error does not name the variable: %v", err)
	}
}

func TestRunMCPReadOnlyHidesFix(t *testing.T) {
	repo := t.TempDir()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	previous := stdinReader
	stdinReader = inR
	t.Cleanup(func() {
		stdinReader = previous
		_ = inW.Close()
	})

	done := make(chan error, 1)
	go func() {
		done <- runMCP([]string{"--root", repo, "--read-only"}, outW, io.Discard)
		_ = outW.Close()
	}()

	reader := bufio.NewReader(outR)
	send := func(line string) {
		t.Helper()
		if _, err := io.WriteString(inW, line+"\n"); err != nil {
			t.Fatalf("write request: %v", err)
		}
	}
	read := func() map[string]any {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("decode response %q: %v", line, err)
		}
		return resp
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if got := read()["id"]; got != float64(1) {
		t.Fatalf("initialize response id = %v, want 1", got)
	}

	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	resp := read()
	if got := resp["id"]; got != float64(2) {
		t.Fatalf("tools/list response id = %v, want 2", got)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list result = %#v", resp["result"])
	}
	rawTools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("tools/list tools = %#v", result["tools"])
	}
	for _, raw := range rawTools {
		tool, _ := raw.(map[string]any)
		if tool["name"] == "vigil_fix" {
			t.Error("runMCP --read-only still listed vigil_fix")
		}
	}
	if len(rawTools) != len(tools.ToolNames())-1 {
		t.Errorf("read-only tools/list has %d tools, want %d", len(rawTools), len(tools.ToolNames())-1)
	}

	_ = inW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runMCP: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runMCP did not stop after stdin closed")
	}
}
