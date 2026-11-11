package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
)

// Server is an MCP server. Register tools, resources and prompts, then call
// Serve. It is safe to use from tests with in-memory pipes.
type Server struct {
	Name         string
	Version      string
	Title        string
	Instructions string
	Logger       *slog.Logger

	mu        sync.RWMutex
	tools     map[string]Tool
	order     []string
	resources map[string]registeredResource
	prompts   map[string]Prompt
	writerMu  sync.Mutex
	out       io.Writer
	sem       chan struct{}
}

// maxConcurrentRequests bounds in-flight tool calls. A hostile client can send
// many lines quickly; without backpressure each line would start a goroutine
// and an expensive scan, exhausting memory and CPU.
const maxConcurrentRequests = 16

type registeredResource struct {
	resource Resource
	reader   ResourceReader
}

// ResourceReader renders one resource.
type ResourceReader func(ctx context.Context, uri string) ([]ResourceContents, error)

// NewServer returns an empty server.
func NewServer(name, version, title string) *Server {
	return &Server{
		Name:      name,
		Version:   version,
		Title:     title,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		tools:     map[string]Tool{},
		resources: map[string]registeredResource{},
		prompts:   map[string]Prompt{},
		sem:       make(chan struct{}, maxConcurrentRequests),
	}
}

// AddTool registers a tool. Duplicate names replace the previous handler.
func (s *Server) AddTool(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[t.Name]; !exists {
		s.order = append(s.order, t.Name)
	}
	s.tools[t.Name] = t
}

// AddResource registers a resource URI and its reader.
func (s *Server) AddResource(r Resource, reader ResourceReader) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources[r.URI] = registeredResource{resource: r, reader: reader}
}

// AddPrompt registers a prompt.
func (s *Server) AddPrompt(p Prompt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts[p.Name] = p
}

// Tools returns registered tools in registration order.
func (s *Server) Tools() []Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tool, 0, len(s.order))
	for _, name := range s.order {
		out = append(out, s.tools[name])
	}
	return out
}

// Serve reads newline-delimited JSON-RPC from in and writes responses to out.
// It returns nil on EOF.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.writerMu.Lock()
	s.out = out
	s.writerMu.Unlock()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.write(Response{JSONRPC: JSONRPC, Error: NewError(CodeParseError, "invalid JSON: %v", err)})
			continue
		}
		if req.JSONRPC != "" && req.JSONRPC != JSONRPC {
			s.write(Response{JSONRPC: JSONRPC, ID: req.ID, Error: NewError(CodeInvalidRequest, "unsupported jsonrpc version %q", req.JSONRPC)})
			continue
		}
		if req.IsNotification() {
			s.handleNotification(ctx, req)
			continue
		}
		// Backpressure: wait for a free slot before starting another handler.
		// A nil channel (a Server built as a struct literal in a test) means
		// no limit.
		if s.sem != nil {
			s.sem <- struct{}{}
		}
		go func(req Request) {
			if s.sem != nil {
				defer func() { <-s.sem }()
			}
			s.handleRequest(ctx, req)
		}(req)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (s *Server) handleNotification(ctx context.Context, req Request) {
	switch req.Method {
	case "notifications/initialized", "notifications/cancelled":
		// Nothing to do: requests are short-lived and cancellation is best
		// effort through the client closing the stream.
	default:
		if s.Logger != nil {
			s.Logger.Debug("unhandled notification", "method", req.Method)
		}
	}
}

func (s *Server) handleRequest(ctx context.Context, req Request) {
	resp := Response{JSONRPC: JSONRPC, ID: req.ID}
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.Logger != nil {
				s.Logger.Error("handler panicked", "method", req.Method, "panic", recovered)
			}
			resp.Result = nil
			resp.Error = NewError(CodeInternalError, "internal error: %v", recovered)
			s.write(resp)
		}
	}()
	result, rpcErr := s.dispatch(ctx, req)
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	s.write(resp)
}

func (s *Server) dispatch(ctx context.Context, req Request) (any, *RPCError) {
	switch req.Method {
	case "initialize":
		return s.initialize(req.Params)
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return s.listTools(), nil
	case "tools/call":
		return s.callTool(ctx, req.Params)
	case "resources/list":
		return s.listResources(), nil
	case "resources/read":
		return s.readResource(ctx, req.Params)
	case "prompts/list":
		return s.listPrompts(), nil
	case "prompts/get":
		return s.getPrompt(ctx, req.Params)
	default:
		return nil, NewError(CodeMethodNotFound, "method %q not found", req.Method)
	}
}

func (s *Server) initialize(raw json.RawMessage) (any, *RPCError) {
	var params InitializeParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, NewError(CodeInvalidParams, "initialize: %v", err)
		}
	}
	version := params.ProtocolVersion
	if !supportedVersion(version) {
		version = ProtocolVersion
	}
	return InitializeResult{
		ProtocolVersion: version,
		Capabilities: ServerCapabilities{
			Tools:     &ToolsCapability{},
			Resources: &ResourcesCapability{},
			Prompts:   &PromptsCapability{},
			Logging:   &struct{}{},
		},
		ServerInfo:   Implementation{Name: s.Name, Version: s.Version, Title: s.Title},
		Instructions: s.Instructions,
	}, nil
}

func supportedVersion(v string) bool {
	for _, s := range SupportedProtocolVersions {
		if s == v {
			return true
		}
	}
	return false
}

func (s *Server) listTools() any {
	tools := s.Tools()
	out := make([]Tool, 0, len(tools))
	for _, t := range tools {
		t.Handler = nil
		out = append(out, t)
	}
	return ToolsListResult{Tools: out}
}

func (s *Server) callTool(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, NewError(CodeInvalidParams, "tools/call: %v", err)
	}
	s.mu.RLock()
	tool, ok := s.tools[params.Name]
	s.mu.RUnlock()
	if !ok {
		return nil, NewError(CodeInvalidParams, "unknown tool %q", params.Name)
	}
	if len(params.Arguments) == 0 || string(params.Arguments) == "null" {
		params.Arguments = json.RawMessage(`{}`)
	}
	if !json.Valid(params.Arguments) {
		return nil, NewError(CodeInvalidParams, "arguments for %q are not valid JSON", params.Name)
	}
	result, err := tool.Handler(ctx, params.Arguments)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Warn("tool failed", "tool", params.Name, "error", err)
		}
		return TextError("%v", err), nil
	}
	if result == nil {
		return TextResult("ok"), nil
	}
	return result, nil
}

func (s *Server) listResources() any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Resource, 0, len(s.resources))
	for _, r := range s.resources {
		out = append(out, r.resource)
	}
	// Map iteration order is random; clients and caches expect a stable list.
	sort.Slice(out, func(i, j int) bool { return out[i].URI < out[j].URI })
	return ResourcesListResult{Resources: out}
}

func (s *Server) readResource(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, NewError(CodeInvalidParams, "resources/read: %v", err)
	}
	s.mu.RLock()
	entry, ok := s.resources[params.URI]
	s.mu.RUnlock()
	if !ok {
		return nil, NewError(CodeInvalidParams, "unknown resource %q", params.URI)
	}
	contents, err := entry.reader(ctx, params.URI)
	if err != nil {
		return nil, NewError(CodeInternalError, "read %s: %v", params.URI, err)
	}
	return ResourcesReadResult{Contents: contents}, nil
}

func (s *Server) listPrompts() any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Prompt, 0, len(s.prompts))
	for _, p := range s.prompts {
		p.Handler = nil
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return PromptsListResult{Prompts: out}
}

func (s *Server) getPrompt(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, NewError(CodeInvalidParams, "prompts/get: %v", err)
	}
	s.mu.RLock()
	prompt, ok := s.prompts[params.Name]
	s.mu.RUnlock()
	if !ok {
		return nil, NewError(CodeInvalidParams, "unknown prompt %q", params.Name)
	}
	result, err := prompt.Handler(ctx, params.Arguments)
	if err != nil {
		return nil, NewError(CodeInternalError, "prompt %s: %v", params.Name, err)
	}
	return result, nil
}

func (s *Server) write(resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Error("marshal response", "error", err)
		}
		return
	}
	s.writerMu.Lock()
	defer s.writerMu.Unlock()
	if s.out == nil {
		return
	}
	_, _ = s.out.Write(append(data, '\n'))
}

// Notify writes a server-initiated notification. Used for progress updates.
func (s *Server) Notify(method string, params any) {
	msg := map[string]any{"jsonrpc": JSONRPC, "method": method, "params": params}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	s.writerMu.Lock()
	defer s.writerMu.Unlock()
	if s.out == nil {
		return
	}
	_, _ = s.out.Write(append(data, '\n'))
}

// ServeStdio is a convenience wrapper around Serve.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	if err := s.Serve(ctx, in, out); err != nil {
		return fmt.Errorf("mcp serve: %w", err)
	}
	return nil
}
