package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// e2eTimeout bounds every read in the end-to-end tests so a transport
// regression fails instead of hanging the suite.
const e2eTimeout = 10 * time.Second

// e2eIsolateHostConfig keeps the end-to-end tests independent of the
// developer's real Vigil config and API keys. These tests use fixture tools,
// but the isolation makes that guarantee explicit and future-proof.
func e2eIsolateHostConfig(t *testing.T) {
	t.Helper()
	t.Setenv("VIGIL_NO_LLM", "1")
	t.Setenv("VIGIL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
}

// e2eTool builds a fixture tool with a simple object schema.
func e2eTool(name string, handler ToolHandler) Tool {
	return Tool{
		Name:        name,
		Title:       "Fixture " + name,
		Description: "end-to-end fixture tool " + name,
		InputSchema: ObjectSchema(map[string]any{
			"text": Prop("string", "optional text"),
		}),
		Handler: handler,
	}
}

// trySend writes one JSON-RPC message without calling testing.T, so it is safe
// to use from a sender goroutine.
func (c *testClient) trySend(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	if _, err := c.in.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	return nil
}

// TestE2EInitializeEveryVersionAndFallback walks the handshake for every
// supported protocol version, plus an unknown version and a missing one. A
// client that asks for an unknown version must get the newest supported
// version back rather than an error.
func TestE2EInitializeEveryVersionAndFallback(t *testing.T) {
	e2eIsolateHostConfig(t)
	srv := NewServer("vigil", "e2e-version", "Vigil E2E")
	srv.Instructions = "end-to-end test instructions"
	c := startTestServer(t, srv)

	versions := append([]string{}, SupportedProtocolVersions...)
	versions = append(versions, "1999-01-01", "")

	for i, version := range versions {
		id := i + 1
		resp := c.call(id, "initialize", map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "e2e", "version": "1.0"},
		})
		if resp.Error != nil {
			t.Fatalf("initialize(%q): %v", version, resp.Error)
		}
		var init InitializeResult
		if err := json.Unmarshal(resp.Result, &init); err != nil {
			t.Fatalf("decode initialize(%q): %v", version, err)
		}
		want := version
		if !supportedVersion(version) {
			want = ProtocolVersion
		}
		if init.ProtocolVersion != want {
			t.Errorf("initialize(%q) protocolVersion = %q, want %q", version, init.ProtocolVersion, want)
		}
		if init.ServerInfo.Name != "vigil" || init.ServerInfo.Version != "e2e-version" || init.ServerInfo.Title != "Vigil E2E" {
			t.Errorf("initialize(%q) serverInfo = %+v", version, init.ServerInfo)
		}
		if init.Instructions != "end-to-end test instructions" {
			t.Errorf("initialize(%q) instructions = %q", version, init.Instructions)
		}
		if init.Capabilities.Tools == nil || init.Capabilities.Resources == nil ||
			init.Capabilities.Prompts == nil || init.Capabilities.Logging == nil {
			t.Errorf("initialize(%q) capabilities = %+v", version, init.Capabilities)
		}
	}
}

// TestE2ENotificationsNeverProduceResponses sends every notification the
// server knows about plus an unknown one, then checks that the first response
// on the wire belongs to the following request.
func TestE2ENotificationsNeverProduceResponses(t *testing.T) {
	e2eIsolateHostConfig(t)
	srv := NewServer("vigil", "e2e", "Vigil E2E")
	c := startTestServer(t, srv)

	for _, method := range []string{
		"notifications/initialized",
		"notifications/cancelled",
		"notifications/progress",
		"notifications/unknown",
	} {
		c.send(map[string]any{
			"jsonrpc": JSONRPC,
			"method":  method,
			"params":  map[string]any{"reason": "e2e"},
		})
	}

	// Send the ping directly and inspect the first raw line. c.call would skip
	// id-less responses, which could hide a spurious notification response.
	c.send(map[string]any{"jsonrpc": JSONRPC, "id": 41, "method": "ping"})
	line := c.readLine()
	var ping testResponse
	if err := json.Unmarshal(line, &ping); err != nil {
		t.Fatalf("first line after notifications is not JSON: %v (%q)", err, line)
	}
	var id int
	if err := json.Unmarshal(ping.ID, &id); err != nil || id != 41 {
		t.Fatalf("first response after notifications is %q, want the ping response with id 41", line)
	}
	if ping.Error != nil {
		t.Fatalf("ping after notifications: %v", ping.Error)
	}
}

// TestE2EToolsListSchemas registers exactly eleven fixture tools (the same
// count as the real Vigil surface) and validates the serialised list. The real
// eleven tools and their schemas are covered by internal/tools/e2e_test.go.
func TestE2EToolsListSchemas(t *testing.T) {
	e2eIsolateHostConfig(t)
	srv := NewServer("vigil", "e2e", "Vigil E2E")
	for i := 0; i < 11; i++ {
		name := fmt.Sprintf("e2e_tool_%02d", i)
		srv.AddTool(Tool{
			Name:        name,
			Title:       "Fixture " + name,
			Description: "fixture",
			InputSchema: ObjectSchema(map[string]any{
				"text":  Prop("string", "text"),
				"count": PropInt("count"),
			}, "text"),
			Handler: func(context.Context, json.RawMessage) (*CallToolResult, error) {
				return TextResult("ok"), nil
			},
		})
	}

	c := startTestServer(t, srv)
	resp := c.call(1, "tools/list", nil)
	if resp.Error != nil {
		t.Fatalf("tools/list: %v", resp.Error)
	}
	var list ToolsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(list.Tools) != 11 {
		t.Fatalf("tools/list returned %d tools, want 11", len(list.Tools))
	}
	if strings.Contains(string(resp.Result), "Handler") {
		t.Error("tools/list serialised the handler")
	}
	seen := map[string]bool{}
	for i, tool := range list.Tools {
		if tool.Name != fmt.Sprintf("e2e_tool_%02d", i) {
			t.Errorf("tool %d = %q, want stable registration order", i, tool.Name)
		}
		if seen[tool.Name] {
			t.Errorf("duplicate tool %q", tool.Name)
		}
		seen[tool.Name] = true
		if len(tool.InputSchema) == 0 {
			t.Errorf("tool %q has an empty inputSchema", tool.Name)
			continue
		}
		var schema struct {
			Type                 string                    `json:"type"`
			AdditionalProperties bool                      `json:"additionalProperties"`
			Required             []string                  `json:"required"`
			Properties           map[string]map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Errorf("tool %q schema is not JSON: %v", tool.Name, err)
			continue
		}
		if schema.Type != "object" || schema.AdditionalProperties {
			t.Errorf("tool %q schema = %+v", tool.Name, schema)
		}
		for _, req := range schema.Required {
			if _, ok := schema.Properties[req]; !ok {
				t.Errorf("tool %q requires %q but does not declare it", tool.Name, req)
			}
		}
	}

	// Every listed tool must still be callable after the schema round-trip.
	call := c.call(2, "tools/call", map[string]any{
		"name":      "e2e_tool_00",
		"arguments": map[string]any{"text": "hello"},
	})
	if call.Error != nil {
		t.Fatalf("tools/call: %v", call.Error)
	}
	var result CallToolResult
	if err := json.Unmarshal(call.Result, &result); err != nil {
		t.Fatalf("decode tools/call: %v", err)
	}
	if result.IsError || len(result.Content) != 1 || result.Content[0].Text != "ok" {
		t.Fatalf("tools/call result = %+v", result)
	}
}

// TestE2EMalformedJSONThenPing checks that a broken line is answered with a
// parse error and does not poison the stream.
func TestE2EMalformedJSONThenPing(t *testing.T) {
	e2eIsolateHostConfig(t)
	srv := NewServer("vigil", "e2e", "Vigil E2E")
	c := startTestServer(t, srv)

	badLines := []string{
		`{"jsonrpc":"2.0","id":1,"method":`,
		`not json at all`,
		string([]byte{0xff, 0xfe, 0xfd}),
	}
	for i, bad := range badLines {
		c.sendLine(bad)
		line := c.readLine()
		var resp testResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			t.Fatalf("bad line %d: response is not JSON: %v (%q)", i, err, line)
		}
		if resp.Error == nil || resp.Error.Code != CodeParseError {
			t.Fatalf("bad line %d: response = %+v, want a parse error", i, resp)
		}
	}

	ping := c.call(99, "ping", nil)
	if ping.Error != nil {
		t.Fatalf("ping after parse errors: %v", ping.Error)
	}
}

// TestE2EHandlerPanicKeepsServing checks the panic barrier: a handler panic
// becomes a JSON-RPC internal error and the server keeps serving.
func TestE2EHandlerPanicKeepsServing(t *testing.T) {
	e2eIsolateHostConfig(t)
	srv := NewServer("vigil", "e2e", "Vigil E2E")
	srv.AddTool(e2eTool("panic", func(context.Context, json.RawMessage) (*CallToolResult, error) {
		panic("e2e boom")
	}))
	c := startTestServer(t, srv)

	params := map[string]any{"name": "panic", "arguments": map[string]any{}}
	for i := 1; i <= 2; i++ {
		resp := c.call(i, "tools/call", params)
		if resp.Error == nil || resp.Error.Code != CodeInternalError {
			t.Fatalf("call %d: response = %+v, want internal error %d", i, resp, CodeInternalError)
		}
		if !strings.Contains(resp.Error.Message, "internal error") {
			t.Errorf("call %d: error message = %q, want an internal-error message", i, resp.Error.Message)
		}
		if len(resp.Result) != 0 && string(resp.Result) != "null" {
			t.Errorf("call %d: panic response leaked a result: %s", i, resp.Result)
		}
	}

	ping := c.call(3, "ping", nil)
	if ping.Error != nil {
		t.Fatalf("ping after handler panics: %v", ping.Error)
	}
}

// e2eOversizedLineReader produces size 'x' bytes followed by a newline without
// ever allocating the line. Each Read is bounded by the caller's buffer, so the
// test exercises the scanner limit instead of the test's memory.
type e2eOversizedLineReader struct {
	remaining int64
	newline   bool
}

func (r *e2eOversizedLineReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining > 0 {
		n := int64(len(p))
		if n > r.remaining {
			n = r.remaining
		}
		for i := int64(0); i < n; i++ {
			p[i] = 'x'
		}
		r.remaining -= n
		return int(n), nil
	}
	if !r.newline {
		r.newline = true
		p[0] = '\n'
		return 1, nil
	}
	return 0, io.EOF
}

// TestE2EHugeLineRejectedCleanly sends 16 MiB + 1 bytes on one line. Serve may
// reject it with a parse error or a transport error, but it must not panic,
// allocate the whole line, or hang.
func TestE2EHugeLineRejectedCleanly(t *testing.T) {
	e2eIsolateHostConfig(t)
	const limit = 16*1024*1024 + 1
	srv := NewServer("vigil", "e2e", "Vigil E2E")
	reader := &e2eOversizedLineReader{remaining: limit}

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(context.Background(), reader, io.Discard)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve accepted a line larger than the 16 MiB limit")
		}
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("Serve error = %v, want bufio.ErrTooLong", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Serve hung on an oversized line")
	}
}

// TestE2EConcurrentTwentyCalls sends twenty tools/call requests with distinct
// ids. More than maxConcurrentRequests requests exercise the backpressure
// semaphore; the writer must still see exactly one response per id, one JSON
// document per line, with no interleaving.
func TestE2EConcurrentTwentyCalls(t *testing.T) {
	e2eIsolateHostConfig(t)
	srv := NewServer("vigil", "e2e", "Vigil E2E")
	srv.AddTool(e2eTool("slow", func(context.Context, json.RawMessage) (*CallToolResult, error) {
		time.Sleep(10 * time.Millisecond)
		return TextResult("ok"), nil
	}))
	c := startTestServer(t, srv)

	const n = 20
	sendErr := make(chan error, 1)
	go func() {
		for i := 1; i <= n; i++ {
			if err := c.trySend(map[string]any{
				"jsonrpc": JSONRPC,
				"id":      i,
				"method":  "tools/call",
				"params":  map[string]any{"name": "slow", "arguments": map[string]any{}},
			}); err != nil {
				sendErr <- err
				return
			}
		}
		sendErr <- nil
	}()

	seen := map[int]bool{}
	for i := 0; i < n; i++ {
		line := c.readLine()
		if !json.Valid(line) {
			t.Fatalf("response %d is not a single valid JSON document: %q", i, line)
		}
		var resp testResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			t.Fatalf("decode response %d: %v", i, err)
		}
		var id int
		if err := json.Unmarshal(resp.ID, &id); err != nil {
			t.Fatalf("response %d has no integer id: %q", i, line)
		}
		if seen[id] {
			t.Fatalf("duplicate response id %d", id)
		}
		seen[id] = true
		if resp.Error != nil {
			t.Fatalf("response %d error: %v", id, resp.Error)
		}
		var result CallToolResult
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			t.Fatalf("decode result for %d: %v", id, err)
		}
		if result.IsError || len(result.Content) != 1 || result.Content[0].Text != "ok" {
			t.Fatalf("result for %d = %+v", id, result)
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("sender: %v", err)
	}
	if len(seen) != n {
		t.Fatalf("received %d distinct ids, want %d", len(seen), n)
	}
	for i := 1; i <= n; i++ {
		if !seen[i] {
			t.Errorf("missing response for id %d", i)
		}
	}
}

// TestE2EContextCancellationDuringHandler cancels the server context while a
// handler is blocked. The handler must observe cancellation, its response must
// still reach the client, and Serve must return cleanly when the input closes.
func TestE2EContextCancellationDuringHandler(t *testing.T) {
	e2eIsolateHostConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	srv := NewServer("vigil", "e2e", "Vigil E2E")
	srv.AddTool(e2eTool("block", func(handlerCtx context.Context, _ json.RawMessage) (*CallToolResult, error) {
		close(entered)
		select {
		case <-handlerCtx.Done():
			return TextResult("cancelled: " + handlerCtx.Err().Error()), nil
		case <-release:
			return TextResult("released"), nil
		}
	}))

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, inR, outW)
		_ = outW.Close()
	}()
	c := &testClient{t: t, in: inW, out: bufio.NewReader(outR), done: done}
	t.Cleanup(func() {
		_ = inW.Close()
		_ = outR.Close()
	})

	if err := c.trySend(map[string]any{
		"jsonrpc": JSONRPC,
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": "block", "arguments": map[string]any{}},
	}); err != nil {
		t.Fatalf("send blocked call: %v", err)
	}

	select {
	case <-entered:
	case <-time.After(e2eTimeout):
		t.Fatal("handler did not start")
	}

	cancel()

	line := c.readLine()
	var resp testResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode cancelled response: %v (%q)", err, line)
	}
	var result CallToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode cancelled result: %v", err)
	}
	if result.IsError || len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, "cancelled") {
		t.Fatalf("cancelled result = %+v", result)
	}

	// Cancellation is per-request context only: the transport keeps serving.
	ping := c.call(2, "ping", nil)
	if ping.Error != nil {
		t.Fatalf("ping after cancellation: %v", ping.Error)
	}

	_ = inW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil after EOF", err)
		}
	case <-time.After(e2eTimeout):
		t.Fatal("Serve did not return after the input closed")
	}
}
