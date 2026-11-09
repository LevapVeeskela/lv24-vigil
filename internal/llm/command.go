package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

const (
	// commandPromptPlaceholder is replaced by the whole prompt in one argv
	// element. When it is absent the prompt is appended as one argument or
	// written to stdin, depending on command_prompt_mode.
	commandPromptPlaceholder = "{prompt}"

	commandStderrLimit = 64 << 10
	commandStderrTail  = 2 << 10
	// commandWaitDelay bounds how long Wait waits for inherited stdout/stderr
	// pipes after the process exits or the context is canceled. A CLI that
	// spawns a detached child must not hang a scan forever.
	commandWaitDelay = 2 * time.Second
)

// ansiPattern matches CSI and OSC escape sequences emitted by CLIs that still
// colour output when stdout is a pipe.
var ansiPattern = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))`)

// commandClient runs a local CLI that already owns its authentication. It
// stores no API key, performs no HTTP calls and never invokes a shell.
type commandClient struct {
	model      string
	argv       []string
	promptMode string
	outputMode string
	timeout    time.Duration
	maxOutput  int
	env        []string
	secrets    []string
	logger     *slog.Logger
	batchWarn  sync.Once
}

// Name implements Client.
func (c *commandClient) Name() string { return config.ProviderCommand }

// Model implements Client.
func (c *commandClient) Model() string { return c.model }

func newCommandClient(cfg config.Config, model string, logger *slog.Logger) (Client, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	argv := append([]string(nil), cfg.Command...)
	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return nil, fmt.Errorf("provider %q requires command (set command in the user config or VIGIL_COMMAND)", config.ProviderCommand)
	}

	promptMode := strings.ToLower(strings.TrimSpace(cfg.CommandPromptMode))
	if promptMode == "" {
		promptMode = config.CommandPromptArg
	}
	switch promptMode {
	case config.CommandPromptArg, config.CommandPromptStdin:
	default:
		return nil, fmt.Errorf("command_prompt_mode must be arg or stdin (got %q)", cfg.CommandPromptMode)
	}

	outputMode := strings.ToLower(strings.TrimSpace(cfg.CommandOutput))
	if outputMode == "" {
		outputMode = config.CommandOutputAuto
	}
	switch outputMode {
	case config.CommandOutputAuto, config.CommandOutputText, config.CommandOutputOpenCodeJSON:
	default:
		return nil, fmt.Errorf("command_output must be auto, text or opencode-json (got %q)", cfg.CommandOutput)
	}

	timeout := cfg.CommandTimeout
	if timeout <= 0 {
		timeout = cfg.Timeout
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	maxOutput := cfg.CommandMaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = config.DefaultCommandMaxOutputBytes
	}
	if maxOutput > config.MaxCommandMaxOutputBytes {
		maxOutput = config.MaxCommandMaxOutputBytes
	}

	// Sorted keys make the child environment deterministic and the debug
	// output reproducible.
	keys := make([]string, 0, len(cfg.CommandEnv))
	for key := range cfg.CommandEnv {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	secrets := make([]string, 0, len(keys))
	for _, key := range keys {
		if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "=\x00") {
			return nil, fmt.Errorf("command_env keys must be non-empty and must not contain '=' or NUL")
		}
		value := cfg.CommandEnv[key]
		env = append(env, key+"="+value)
		// Short values are too common to redact safely ("1", "true", a path);
		// anything longer may be a token passed to the CLI.
		if len(value) >= 8 {
			secrets = append(secrets, value)
		}
	}

	model = strings.TrimSpace(model)
	if model == "" {
		model = config.DefaultCommandModel
	}

	return &commandClient{
		model:      model,
		argv:       argv,
		promptMode: promptMode,
		outputMode: outputMode,
		timeout:    timeout,
		maxOutput:  maxOutput,
		env:        env,
		secrets:    secrets,
		logger:     logger,
	}, nil
}

// Complete implements Client by running the configured CLI once.
func (c *commandClient) Complete(ctx context.Context, req Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, c.contextError(err)
	}

	prompt := buildCommandPrompt(req)
	if strings.TrimSpace(prompt) == "" {
		return Response{}, c.newError("empty_request", "request has no prompt", false)
	}

	argv := append([]string(nil), c.argv...)
	useStdin := false
	placeholder := false
	for i, arg := range argv {
		if strings.Contains(arg, commandPromptPlaceholder) {
			argv[i] = strings.ReplaceAll(arg, commandPromptPlaceholder, prompt)
			placeholder = true
		}
	}
	if !placeholder {
		if c.promptMode == config.CommandPromptStdin {
			useStdin = true
		} else {
			argv = append(argv, prompt)
		}
	}

	// LookPath first so a missing CLI produces an actionable error instead of
	// a generic CreateProcess failure.
	resolved, lookErr := exec.LookPath(argv[0])
	if lookErr != nil {
		return Response{}, c.newError("command_not_found",
			fmt.Sprintf("cannot run %q: %v", argv[0], lookErr), false)
	}
	if runtime.GOOS == "windows" && !useStdin && isBatchShim(resolved) {
		// cmd.exe re-parses %*, which can mangle a multi-line prompt. stdin
		// mode bypasses the shim's argument handling.
		c.batchWarn.Do(func() {
			c.logger.Warn("llm: command resolves to a batch shim; use the real executable or command_prompt_mode=stdin",
				"provider", config.ProviderCommand,
				"executable", resolved)
		})
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if c.timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	stdout := newBoundedBuffer(c.maxOutput)
	stderr := newBoundedBuffer(commandStderrLimit)

	cmd := exec.CommandContext(runCtx, resolved, argv[1:]...)
	cmd.WaitDelay = commandWaitDelay
	// The child inherits the user's environment; extra variables only add or
	// replace entries. No API key is injected by Vigil.
	cmd.Env = append(os.Environ(), c.env...)
	if useStdin {
		cmd.Stdin = strings.NewReader(prompt)
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	started := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(started)

	if ctxErr := runCtx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			c.logger.Debug("llm: command timed out",
				"provider", config.ProviderCommand,
				"timeout", c.timeout.String(),
				"duration", elapsed.String(),
				"prompt_bytes", len(prompt))
			return Response{}, c.newError("timeout",
				fmt.Sprintf("command timed out after %s (raise command_timeout or VIGIL_COMMAND_TIMEOUT)", c.timeout), false)
		}
		return Response{}, c.contextError(ctxErr)
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return Response{}, c.newError("command_failed",
				fmt.Sprintf("cannot run %q: %v", argv[0], runErr), false)
		}
		code := exitErr.ExitCode()
		c.logger.Debug("llm: command failed",
			"provider", config.ProviderCommand,
			"exit_code", code,
			"stderr_bytes", len(stderr.Bytes()),
			"duration", elapsed.String())
		message := fmt.Sprintf("command exited with status %d", code)
		if tail := commandTail(stderr.Bytes(), commandStderrTail); tail != "" {
			message += ": " + tail
		}
		return Response{}, c.newError("exit_status", message, false)
	}

	if stdout.Truncated() {
		return Response{}, c.newError("output_too_large",
			fmt.Sprintf("command stdout exceeded %d bytes (raise command_max_output_bytes)", c.maxOutput), false)
	}

	text, parsedModel, inputTokens, outputTokens, parseErr := parseCommandOutput(c.outputMode, stdout.Bytes())
	if parseErr != nil {
		message := parseErr.message
		if tail := commandTail(stderr.Bytes(), commandStderrTail); tail != "" {
			message += ": " + tail
		}
		return Response{}, c.newError(parseErr.code, message, false)
	}
	if parsedModel == "" {
		parsedModel = c.model
	}

	// Lengths only: the prompt and the completion are never logged.
	c.logger.Debug("llm: command completed",
		"provider", config.ProviderCommand,
		"executable", resolved,
		"args", len(argv)-1,
		"stdin", useStdin,
		"prompt_bytes", len(prompt),
		"stdout_bytes", len(stdout.Bytes()),
		"stderr_bytes", len(stderr.Bytes()),
		"duration", elapsed.String())

	return Response{
		Text:         text,
		Model:        parsedModel,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		FinishReason: "stop",
	}, nil
}

// buildCommandPrompt flattens the provider-neutral request into one prompt.
// A CLI has no chat roles, so a system prompt is followed by the conversation
// with role labels only when there is more than one exchange. JSON requests
// append the same instruction the prompt-only providers use.
func buildCommandPrompt(req Request) string {
	system := req.System
	if req.JSON || len(req.JSONSchema) > 0 {
		system = withJSONSchemaInstruction(system, req.JSONSchema)
	}
	messages := normalizeMessages(system, req.Messages)
	if len(messages) == 0 {
		return ""
	}
	if len(messages) == 1 {
		return messages[0].Content
	}
	if len(messages) == 2 && messages[0].Role == RoleSystem {
		return messages[0].Content + "\n\n" + messages[1].Content
	}

	var b strings.Builder
	for i, message := range messages {
		if i > 0 {
			b.WriteString("\n\n")
		}
		switch message.Role {
		case RoleSystem:
			b.WriteString(message.Content)
		case RoleAssistant:
			b.WriteString("Assistant:\n")
			b.WriteString(message.Content)
		default:
			b.WriteString("User:\n")
			b.WriteString(message.Content)
		}
	}
	return b.String()
}

type commandParseError struct {
	code    string
	message string
}

// parseCommandOutput converts stdout into text and token counts. In auto mode
// a JSONL line starting with {"type": selects the OpenCode parser.
func parseCommandOutput(mode string, data []byte) (string, string, int, int, *commandParseError) {
	raw := strings.TrimSpace(strings.ToValidUTF8(string(data), ""))
	if raw == "" {
		return "", "", 0, 0, &commandParseError{"empty_response", "command produced no output"}
	}

	switch mode {
	case config.CommandOutputOpenCodeJSON:
		return parseOpenCodeJSON(raw)
	case config.CommandOutputText:
		text := cleanCommandText(raw)
		if text == "" {
			return "", "", 0, 0, &commandParseError{"empty_response", "command produced no text"}
		}
		return text, "", 0, 0, nil
	default:
		if looksLikeOpenCodeJSON(raw) {
			return parseOpenCodeJSON(raw)
		}
		text := cleanCommandText(raw)
		if text == "" {
			return "", "", 0, 0, &commandParseError{"empty_response", "command produced no text"}
		}
		return text, "", 0, 0, nil
	}
}

// openCodeEvent is the subset of `opencode run --format json` events Vigil
// needs: text parts and the final step's token counts.
type openCodeEvent struct {
	Type  string `json:"type"`
	Error string `json:"error"`
	Part  struct {
		Type    string `json:"type"`
		Text    string `json:"text"`
		Model   string `json:"model"`
		Message string `json:"message"`
		Tokens  struct {
			Input     int `json:"input"`
			Output    int `json:"output"`
			Reasoning int `json:"reasoning"`
			Cache     struct {
				Read  int `json:"read"`
				Write int `json:"write"`
			} `json:"cache"`
		} `json:"tokens"`
	} `json:"part"`
}

func looksLikeOpenCodeJSON(s string) bool {
	for i, line := range strings.Split(s, "\n") {
		if i >= 20 {
			break
		}
		if strings.HasPrefix(strings.TrimSpace(line), `{"type":`) {
			return true
		}
	}
	return false
}

func parseOpenCodeJSON(raw string) (string, string, int, int, *commandParseError) {
	var (
		text         strings.Builder
		model        string
		inputTokens  int
		outputTokens int
		sawEvent     bool
	)

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var event openCodeEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// A stray non-JSON line is not fatal: the CLI may print a
			// banner. Real output still has to contain text parts.
			continue
		}
		sawEvent = true
		if event.Part.Model != "" {
			model = event.Part.Model
		}
		switch event.Type {
		case "text":
			if event.Part.Type == "" || event.Part.Type == "text" {
				text.WriteString(event.Part.Text)
			}
		case "step_finish":
			inputTokens += event.Part.Tokens.Input
			outputTokens += event.Part.Tokens.Output
		case "error":
			message := firstNonEmpty(event.Part.Message, event.Error)
			if message == "" {
				message = "command reported an error"
			}
			return "", "", 0, 0, &commandParseError{"command_error", message}
		}
	}

	if !sawEvent {
		return "", "", 0, 0, &commandParseError{"decode_response", "command output is not OpenCode JSONL"}
	}
	result := strings.TrimSpace(text.String())
	if result == "" {
		return "", "", 0, 0, &commandParseError{"empty_response", "command produced no text parts"}
	}
	return result, model, inputTokens, outputTokens, nil
}

// cleanCommandText strips ANSI colour, CRLF and a leading `> agent · model`
// header, which OpenCode prints even with --format text.
func cleanCommandText(s string) string {
	s = stripANSI(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = stripCommandHeader(s)
	return strings.TrimSpace(s)
}

func stripANSI(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}

func stripCommandHeader(s string) string {
	lines := strings.Split(s, "\n")
	for len(lines) > 0 {
		line := strings.TrimSpace(lines[0])
		if line == "" {
			lines = lines[1:]
			continue
		}
		if strings.HasPrefix(line, ">") && strings.Contains(line, "·") {
			lines = lines[1:]
			continue
		}
		break
	}
	return strings.Join(lines, "\n")
}

// isBatchShim reports whether path is a Windows batch wrapper. Such wrappers
// re-parse arguments, so a multi-line prompt can be corrupted before the real
// executable sees it.
func isBatchShim(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cmd", ".bat":
		return true
	default:
		return false
	}
}

// commandTail returns the last limit bytes of stderr with control characters
// removed, safe to put in an error message.
func commandTail(data []byte, limit int) string {
	if len(data) == 0 || limit <= 0 {
		return ""
	}
	s := stripANSI(strings.ToValidUTF8(string(data), ""))
	if len(s) > limit {
		s = s[len(s)-limit:]
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)
	return strings.TrimSpace(s)
}

func (c *commandClient) newError(code, message string, retryable bool) *Error {
	message = strings.TrimSpace(singleLine(message))
	if message == "" {
		message = "command failed"
	}
	return &Error{
		Provider:  config.ProviderCommand,
		Code:      code,
		Message:   TruncateText(redact(message, c.secrets...), 2200),
		Retryable: retryable,
	}
}

func (c *commandClient) contextError(err error) *Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return c.newError("timeout", "command timed out: "+err.Error(), false)
	}
	return c.newError("canceled", "command canceled: "+err.Error(), false)
}

// boundedBuffer keeps at most limit bytes and remembers that it dropped data.
// It never returns a short write, so the child is not blocked by the cap.
type boundedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	if limit < 0 {
		limit = 0
	}
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	remaining := b.limit - b.buf.Len()
	switch {
	case remaining <= 0:
		if len(p) > 0 {
			b.truncated = true
		}
	case len(p) > remaining:
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
	default:
		_, _ = b.buf.Write(p)
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *boundedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
