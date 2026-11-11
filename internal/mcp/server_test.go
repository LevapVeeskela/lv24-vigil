package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type testClient struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Reader
	done chan error
}

func startTestServer(t *testing.T, srv *Server) *testClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(context.Background(), inR, outW)
		_ = outW.Close()
	}()
	c := &testClient{t: t, in: inW, out: bufio.NewReader(outR), done: done}
	t.Cleanup(func() {
		_ = inW.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("mcp server did not stop")
		}
		_ = outR.Close()
	})
	return c
}

func (c *testClient) sendLine(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.in, line+"\n"); err != nil {
		c.t.Fatalf("write request: %v", err)
	}
}

func (c *testClient) send(v any) {
	c.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		c.t.Fatalf("encode request: %v", err)
	}
	c.sendLine(string(data))
}

func (c *testClient) readLine() []byte {
	c.t.Helper()
	type result struct {
		line []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := c.out.ReadBytes('\n')
		ch <- result{line: line, err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			c.t.Fatalf("read response: %v", r.err)
		}
		return bytes.TrimSpace(r.line)
	case <-time.After(10 * time.Second):
		c.t.Fatal("timed out waiting for an MCP response")
		return nil
	}
}

type testResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

func (c *testClient) call(id int, method string, params any) testResponse {
	c.t.Helper()
	req := map[string]any{"jsonrpc": JSONRPC, "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	c.send(req)
	for {
		line := c.readLine()
		var resp testResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			c.t.Fatalf("decode response %q: %v", line, err)
		}
		if len(resp.ID) == 0 {
			continue // server notification
		}
		var gotID int
		if err := json.Unmarshal(resp.ID, &gotID); err != nil || gotID != id {
			continue
		}
		return resp
	}
}

func TestInitializeSupportedVersionsAndFallback(t *testing.T) {
	for _, version := range SupportedProtocolVersions {
		t.Run(version, func(t *testing.T) {
			srv := NewServer("vigil", "test", "Vigil")
			c := startTestServer(t, srv)
			resp := c.call(1, "initialize", map[string]any{
				"protocolVersion": version,
				"capabilities":    map[string]any{},
				"clientInfo":      map[string]any{"name": "test", "version": "1"},
			})
			if resp.Error != nil {
				t.Fatalf("initialize: %v", resp.Error)
			}
			var init InitializeResult
			if err := json.Unmarshal(resp.Result, &init); err != nil {
				t.Fatalf("decode initialize: %v", err)
			}
			if init.ProtocolVersion != version {
				t.Errorf("protocolVersion = %q, want %q", init.ProtocolVersion, version)
			}
			if init.ServerInfo.Name != "vigil" || init.ServerInfo.Version != "test" {
				t.Errorf("serverInfo = %+v", init.ServerInfo)
			}
			if init.Capabilities.Tools == nil || init.Capabilities.Resources == nil || init.Capabilities.Prompts == nil {
				t.Errorf("capabilities = %+v", init.Capabilities)
			}
		})
	}

	t.Run("unknown falls back", func(t *testing.T) {
		srv := NewServer("vigil", "test", "Vigil")
		c := startTestServer(t, srv)
		resp := c.call(1, "initialize", map[string]any{"protocolVersion": "1999-01-01"})
		if resp.Error != nil {
			t.Fatalf("initialize: %v", resp.Error)
		}
		var init InitializeResult
		if err := json.Unmarshal(resp.Result, &init); err != nil {
			t.Fatalf("decode initialize: %v", err)
		}
		if init.ProtocolVersion != ProtocolVersion {
			t.Errorf("fallback version = %q, want %q", init.ProtocolVersion, ProtocolVersion)
		}
	})
}

func TestPingAndUnknownMethod(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	c := startTestServer(t, srv)

	ping := c.call(1, "ping", nil)
	if ping.Error != nil {
		t.Fatalf("ping: %v", ping.Error)
	}
	var pong map[string]any
	if err := json.Unmarshal(ping.Result, &pong); err != nil {
		t.Fatalf("decode ping: %v", err)
	}
	if len(pong) != 0 {
		t.Errorf("ping result = %v, want an empty object", pong)
	}

	unknown := c.call(2, "does/not/exist", nil)
	if unknown.Error == nil || unknown.Error.Code != CodeMethodNotFound {
		t.Fatalf("unknown method error = %+v, want %d", unknown.Error, CodeMethodNotFound)
	}
}

func TestToolsListAndCall(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	srv.AddTool(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: ObjectSchema(map[string]any{
			"text": Prop("string", "text"),
		}, "text"),
		Handler: func(_ context.Context, raw json.RawMessage) (*CallToolResult, error) {
			var args struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return TextError("bad arguments: %v", err), nil
			}
			return TextResult("echo: " + args.Text), nil
		},
	})
	c := startTestServer(t, srv)

	list := c.call(1, "tools/list", nil)
	if list.Error != nil {
		t.Fatalf("tools/list: %v", list.Error)
	}
	var tools ToolsListResult
	if err := json.Unmarshal(list.Result, &tools); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo" {
		t.Fatalf("tools = %+v", tools.Tools)
	}
	var schema map[string]any
	if err := json.Unmarshal(tools.Tools[0].InputSchema, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Errorf("schema = %v", schema)
	}
	if _, ok := schema["required"]; !ok {
		t.Error("schema has no required list")
	}
	if strings.Contains(string(list.Result), "Handler") {
		t.Error("tools/list serialised the handler")
	}

	call := c.call(2, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"text": "hi"},
	})
	if call.Error != nil {
		t.Fatalf("tools/call: %v", call.Error)
	}
	var result CallToolResult
	if err := json.Unmarshal(call.Result, &result); err != nil {
		t.Fatalf("decode tools/call: %v", err)
	}
	if result.IsError || len(result.Content) != 1 || result.Content[0].Text != "echo: hi" {
		t.Fatalf("result = %+v", result)
	}

	unknown := c.call(3, "tools/call", map[string]any{"name": "nope", "arguments": map[string]any{}})
	if unknown.Error == nil || unknown.Error.Code != CodeInvalidParams {
		t.Fatalf("unknown tool error = %+v", unknown.Error)
	}

	badArgs := c.call(4, "tools/call", map[string]any{"name": "echo", "arguments": 5})
	if badArgs.Error != nil {
		t.Fatalf("bad arguments should be a tool result, got %v", badArgs.Error)
	}
	var badResult CallToolResult
	if err := json.Unmarshal(badArgs.Result, &badResult); err != nil {
		t.Fatalf("decode bad-arguments result: %v", err)
	}
	if !badResult.IsError {
		t.Error("bad arguments did not produce isError")
	}
}

func TestHandlerErrorBecomesIsErrorContent(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	srv.AddTool(Tool{
		Name:        "boom",
		Description: "boom",
		InputSchema: ObjectSchema(map[string]any{}),
		Handler: func(context.Context, json.RawMessage) (*CallToolResult, error) {
			return nil, errors.New("handler exploded")
		},
	})
	c := startTestServer(t, srv)
	resp := c.call(1, "tools/call", map[string]any{"name": "boom", "arguments": map[string]any{}})
	if resp.Error != nil {
		t.Fatalf("handler error leaked as a JSON-RPC error: %v", resp.Error)
	}
	var result CallToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.IsError {
		t.Fatal("handler error did not set isError")
	}
	if len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, "handler exploded") {
		t.Fatalf("result content = %+v", result.Content)
	}
}

func TestHandlerPanicBecomesInternalError(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	srv.AddTool(Tool{
		Name:        "panic",
		Description: "panic",
		InputSchema: ObjectSchema(map[string]any{}),
		Handler: func(context.Context, json.RawMessage) (*CallToolResult, error) {
			panic("boom")
		},
	})
	c := startTestServer(t, srv)

	resp := c.call(1, "tools/call", map[string]any{"name": "panic", "arguments": map[string]any{}})
	if resp.Error == nil || resp.Error.Code != CodeInternalError {
		t.Fatalf("panic response = %+v, want an internal error", resp)
	}
	ping := c.call(2, "ping", nil)
	if ping.Error != nil {
		t.Fatalf("server did not keep serving after a handler panic: %v", ping.Error)
	}
}

func TestBadJSONKeepsServing(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	c := startTestServer(t, srv)

	c.sendLine(`{"jsonrpc":"2.0","id":1,"method":`)
	first := c.readLine()
	var parseErr testResponse
	if err := json.Unmarshal(first, &parseErr); err != nil {
		t.Fatalf("parse-error response is not JSON: %v\n%s", err, first)
	}
	if parseErr.Error == nil || parseErr.Error.Code != CodeParseError {
		t.Fatalf("first response = %+v, want a parse error", parseErr)
	}

	ping := c.call(2, "ping", nil)
	if ping.Error != nil {
		t.Fatalf("server did not keep serving after a parse error: %v", ping.Error)
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	c := startTestServer(t, srv)

	c.send(map[string]any{"jsonrpc": JSONRPC, "method": "notifications/initialized"})
	c.send(map[string]any{"jsonrpc": JSONRPC, "id": 7, "method": "ping"})
	line := c.readLine()
	var resp testResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.ID) == 0 {
		t.Fatalf("notification produced a response: %s", line)
	}
	var id int
	if err := json.Unmarshal(resp.ID, &id); err != nil || id != 7 {
		t.Fatalf("first response id = %s, want 7", resp.ID)
	}
	if resp.Error != nil {
		t.Fatalf("ping after notification: %v", resp.Error)
	}
}

func TestResourcesAndPrompts(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	srv.AddResource(Resource{
		URI: "vigil://test", Name: "test", MimeType: "application/json",
	}, func(_ context.Context, uri string) ([]ResourceContents, error) {
		return []ResourceContents{{URI: uri, MimeType: "application/json", Text: `{"ok":true}`}}, nil
	})
	srv.AddPrompt(Prompt{
		Name:      "test_prompt",
		Arguments: []PromptArgument{{Name: "value", Required: true}},
		Handler: func(_ context.Context, args map[string]string) (*GetPromptResult, error) {
			if args["value"] == "" {
				return nil, errors.New("value is required")
			}
			return &GetPromptResult{Messages: []PromptMessage{{
				Role: "user", Content: Content{Type: "text", Text: "value=" + args["value"]},
			}}}, nil
		},
	})
	c := startTestServer(t, srv)

	list := c.call(1, "resources/list", nil)
	if list.Error != nil {
		t.Fatalf("resources/list: %v", list.Error)
	}
	var resources ResourcesListResult
	if err := json.Unmarshal(list.Result, &resources); err != nil {
		t.Fatalf("decode resources/list: %v", err)
	}
	if len(resources.Resources) != 1 || resources.Resources[0].URI != "vigil://test" {
		t.Fatalf("resources = %+v", resources.Resources)
	}

	read := c.call(2, "resources/read", map[string]any{"uri": "vigil://test"})
	if read.Error != nil {
		t.Fatalf("resources/read: %v", read.Error)
	}
	var contents ResourcesReadResult
	if err := json.Unmarshal(read.Result, &contents); err != nil {
		t.Fatalf("decode resources/read: %v", err)
	}
	if len(contents.Contents) != 1 || contents.Contents[0].Text != `{"ok":true}` {
		t.Fatalf("contents = %+v", contents.Contents)
	}

	missing := c.call(3, "resources/read", map[string]any{"uri": "vigil://nope"})
	if missing.Error == nil || missing.Error.Code != CodeInvalidParams {
		t.Fatalf("missing resource error = %+v", missing.Error)
	}

	prompts := c.call(4, "prompts/list", nil)
	if prompts.Error != nil {
		t.Fatalf("prompts/list: %v", prompts.Error)
	}
	var promptList PromptsListResult
	if err := json.Unmarshal(prompts.Result, &promptList); err != nil {
		t.Fatalf("decode prompts/list: %v", err)
	}
	if len(promptList.Prompts) != 1 || promptList.Prompts[0].Name != "test_prompt" {
		t.Fatalf("prompts = %+v", promptList.Prompts)
	}

	get := c.call(5, "prompts/get", map[string]any{
		"name": "test_prompt", "arguments": map[string]string{"value": "x"},
	})
	if get.Error != nil {
		t.Fatalf("prompts/get: %v", get.Error)
	}
	var prompt GetPromptResult
	if err := json.Unmarshal(get.Result, &prompt); err != nil {
		t.Fatalf("decode prompts/get: %v", err)
	}
	if len(prompt.Messages) != 1 || prompt.Messages[0].Content.Text != "value=x" {
		t.Fatalf("prompt = %+v", prompt)
	}

	promptErr := c.call(6, "prompts/get", map[string]any{
		"name": "test_prompt", "arguments": map[string]string{},
	})
	if promptErr.Error == nil || promptErr.Error.Code != CodeInternalError {
		t.Fatalf("prompt handler error = %+v", promptErr.Error)
	}
}

func TestConcurrentToolCallsHaveDistinctIDs(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	srv.AddTool(Tool{
		Name:        "slow",
		Description: "slow",
		InputSchema: ObjectSchema(map[string]any{}),
		Handler: func(context.Context, json.RawMessage) (*CallToolResult, error) {
			time.Sleep(20 * time.Millisecond)
			return TextResult("ok"), nil
		},
	})
	c := startTestServer(t, srv)

	const n = 12
	go func() {
		for i := 1; i <= n; i++ {
			c.send(map[string]any{"jsonrpc": JSONRPC, "id": i, "method": "tools/call",
				"params": map[string]any{"name": "slow", "arguments": map[string]any{}}})
		}
	}()

	seen := map[int]bool{}
	for i := 0; i < n; i++ {
		line := c.readLine()
		var resp testResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			t.Fatalf("interleaved or invalid response line %q: %v", line, err)
		}
		var id int
		if err := json.Unmarshal(resp.ID, &id); err != nil {
			t.Fatalf("response has no integer id: %q", line)
		}
		if seen[id] {
			t.Fatalf("duplicate response id %d", id)
		}
		seen[id] = true
		if resp.Error != nil {
			t.Fatalf("response %d error: %v", id, resp.Error)
		}
	}
	if len(seen) != n {
		t.Fatalf("received %d distinct ids, want %d", len(seen), n)
	}
}

func TestDeeplyNestedArgumentsDoNotPanic(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	srv.AddTool(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: ObjectSchema(map[string]any{"text": Prop("string", "text")}),
		Handler: func(_ context.Context, raw json.RawMessage) (*CallToolResult, error) {
			var args struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return TextError("invalid arguments: %v", err), nil
			}
			return TextResult("echo: " + args.Text), nil
		},
	})
	c := startTestServer(t, srv)

	nested := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	c.sendLine(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi","nested":` + nested + `}}}`)
	line := c.readLine()
	var resp testResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, line)
	}
	if resp.Error == nil {
		var result CallToolResult
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if !result.IsError && (len(result.Content) == 0 || result.Content[0].Text != "echo: hi") {
			t.Fatalf("unexpected result: %+v", result)
		}
	}
}

func TestHugeLineRejectedWithoutPanic(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	huge := append(bytes.Repeat([]byte("x"), 16*1024*1024+1), '\n')
	err := srv.Serve(context.Background(), bytes.NewReader(huge), io.Discard)
	if err == nil {
		t.Fatal("Serve accepted a line larger than the 16 MiB limit")
	}
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("Serve error = %v, want bufio.ErrTooLong", err)
	}
}

func TestInvalidJSONRPCVersion(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	c := startTestServer(t, srv)
	c.sendLine(`{"jsonrpc":"1.0","id":1,"method":"ping"}`)
	line := c.readLine()
	var resp testResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != CodeInvalidRequest {
		t.Fatalf("response = %+v, want an invalid-request error", resp)
	}
}

func TestObjectSchemaShape(t *testing.T) {
	raw := ObjectSchema(map[string]any{
		"name":  Prop("string", "name"),
		"count": PropInt("count"),
		"on":    PropBool("on"),
		"kind":  PropEnum("kind", "a", "b"),
		"list":  PropArray("list"),
	}, "name")
	var schema struct {
		Type                 string                    `json:"type"`
		AdditionalProperties bool                      `json:"additionalProperties"`
		Required             []string                  `json:"required"`
		Properties           map[string]map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	if schema.Type != "object" || schema.AdditionalProperties {
		t.Errorf("schema = %+v", schema)
	}
	if fmt.Sprint(schema.Required) != "[name]" {
		t.Errorf("required = %v", schema.Required)
	}
	if schema.Properties["kind"]["type"] != "string" || schema.Properties["list"]["type"] != "array" {
		t.Errorf("properties = %+v", schema.Properties)
	}
}

// Regression: prompts/list and resources/list iterated Go maps, so their order
// changed between calls. Lists must be stable for clients and caches.
func TestPromptsAndResourcesListAreSorted(t *testing.T) {
	srv := NewServer("vigil", "test", "Vigil")
	names := []string{"zeta", "alpha", "mike", "delta", "kilo", "bravo", "x-ray", "echo"}
	for _, n := range names {
		srv.AddPrompt(Prompt{Name: n, Handler: func(context.Context, map[string]string) (*GetPromptResult, error) {
			return &GetPromptResult{}, nil
		}})
		srv.AddResource(Resource{URI: "vigil://" + n, Name: n}, func(context.Context, string) ([]ResourceContents, error) {
			return nil, nil
		})
	}
	c := startTestServer(t, srv)

	for i := 0; i < 5; i++ {
		var prompts PromptsListResult
		if err := json.Unmarshal(c.call(10+i, "prompts/list", nil).Result, &prompts); err != nil {
			t.Fatal(err)
		}
		var resources ResourcesListResult
		if err := json.Unmarshal(c.call(20+i, "resources/list", nil).Result, &resources); err != nil {
			t.Fatal(err)
		}
		for j := 1; j < len(names); j++ {
			if prompts.Prompts[j-1].Name > prompts.Prompts[j].Name {
				t.Fatalf("prompts not sorted: %+v", prompts.Prompts)
			}
			if resources.Resources[j-1].URI > resources.Resources[j].URI {
				t.Fatalf("resources not sorted: %+v", resources.Resources)
			}
		}
	}
}
