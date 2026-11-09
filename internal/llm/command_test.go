package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/config"
)

// TestCommandHelperProcess is not a real test. It is the child process used by
// every command-client test, so the suite works on Windows and Unix without
// shell scripts. The parent passes the mode after "--".
func TestCommandHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_COMMAND_HELPER") != "1" {
		return
	}

	args := helperArgs()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "helper: missing mode")
		os.Exit(2)
	}

	switch args[0] {
	case "jsonl":
		fmt.Println("> build · test-model")
		fmt.Println(`{"type":"step_start","part":{"type":"step_start","model":"parsed-model"}}`)
		fmt.Println(`{"type":"text","part":{"type":"text","text":"Hello, "}}`)
		fmt.Println(`{"type":"text","part":{"type":"text","text":"world"}}`)
		fmt.Println(`{"type":"step_finish","part":{"tokens":{"input":11,"output":7,"reasoning":3,"cache":{"read":2,"write":1}}}}`)
	case "jsonl-no-text":
		fmt.Println(`{"type":"step_finish","part":{"tokens":{"input":1,"output":0}}}`)
	case "jsonl-error":
		fmt.Println(`{"type":"error","part":{"message":"model refused"}}`)
	case "text":
		fmt.Println("> build · test-model")
		fmt.Print("\x1b[32mhello\x1b[0m\nworld\n")
	case "stdin":
		data, _ := io.ReadAll(os.Stdin)
		fmt.Printf("stdin:%s", data)
	case "echoarg":
		if len(args) < 2 {
			os.Exit(3)
		}
		fmt.Print(args[1])
	case "argc":
		fmt.Printf("%d", len(args)-1)
	case "fail":
		fmt.Fprintln(os.Stderr, "boom: something broke")
		os.Exit(3)
	case "fail-secret":
		fmt.Fprintln(os.Stderr, "token="+os.Getenv("VIGIL_TEST_SECRET"))
		os.Exit(1)
	case "hang":
		time.Sleep(10 * time.Second)
	case "big":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 1<<20))
	case "env":
		fmt.Print(os.Getenv("VIGIL_COMMAND_TEST"))
	case "env-inherited":
		fmt.Print(os.Getenv("VIGIL_INHERITED_TEST"))
	case "empty":
		// Exit 0 with no output.
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q", args[0])
		os.Exit(2)
	}
	os.Exit(0)
}

func helperArgs() []string {
	for i, arg := range os.Args {
		if arg == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

func helperCommand(t *testing.T, mode string, extra ...string) []string {
	t.Helper()
	argv := []string{os.Args[0], "-test.run=TestCommandHelperProcess", "--", mode}
	return append(argv, extra...)
}

func commandTestConfig(t *testing.T, argv []string) config.Config {
	t.Helper()
	return config.Config{
		Provider:              config.ProviderCommand,
		Model:                 "test-model",
		Command:               argv,
		CommandPromptMode:     config.CommandPromptArg,
		CommandOutput:         config.CommandOutputAuto,
		CommandMaxOutputBytes: config.DefaultCommandMaxOutputBytes,
		CommandEnv:            map[string]string{"GO_WANT_COMMAND_HELPER": "1"},
		Timeout:               5 * time.Second,
	}
}

func newTestCommandClient(t *testing.T, cfg config.Config) Client {
	t.Helper()
	client, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatalf("New(command): %v", err)
	}
	return client
}

func TestCommandJSONLOutput(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "jsonl")))

	resp, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "Hello, world" {
		t.Errorf("Text = %q", resp.Text)
	}
	if resp.Model != "parsed-model" {
		t.Errorf("Model = %q, want the parsed model", resp.Model)
	}
	if resp.InputTokens != 11 || resp.OutputTokens != 7 {
		t.Errorf("tokens = %d/%d, want 11/7", resp.InputTokens, resp.OutputTokens)
	}
	if resp.FinishReason != "stop" {
		t.Errorf("FinishReason = %q", resp.FinishReason)
	}
}

func TestCommandTextOutputStripsHeaderAndANSI(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "text"))
	cfg.CommandOutput = config.CommandOutputText
	client := newTestCommandClient(t, cfg)

	resp, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "hello\nworld" {
		t.Fatalf("Text = %q, want the ANSI/header-free body", resp.Text)
	}
	if strings.Contains(resp.Text, "\x1b") || strings.HasPrefix(resp.Text, ">") {
		t.Errorf("Text still contains terminal decoration: %q", resp.Text)
	}
	if resp.Model != "test-model" {
		t.Errorf("Model = %q, want the configured label", resp.Model)
	}
}

func TestCommandAutoModeTreatsPlainTextAsText(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "text")))

	resp, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "hello\nworld" {
		t.Fatalf("Text = %q", resp.Text)
	}
}

func TestCommandStdinMode(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "stdin"))
	cfg.CommandPromptMode = config.CommandPromptStdin
	client := newTestCommandClient(t, cfg)

	resp, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hello stdin"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "stdin:hello stdin" {
		t.Fatalf("Text = %q, want the prompt on stdin", resp.Text)
	}
}

func TestCommandPlaceholderWinsOverStdinMode(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "echoarg", "prefix-{prompt}-suffix"))
	cfg.CommandPromptMode = config.CommandPromptStdin
	client := newTestCommandClient(t, cfg)

	resp, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "prefix-hello-suffix" {
		t.Fatalf("Text = %q, want placeholder substitution", resp.Text)
	}
}

func TestCommandPromptStaysOneArgvElement(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "echoarg")))
	prompt := `hello"; rm -rf / && echo pwned`

	resp, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: prompt}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != prompt {
		t.Fatalf("Text = %q, want the prompt unchanged", resp.Text)
	}

	argcClient := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "argc")))
	argcResp, err := argcClient.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: prompt}},
	})
	if err != nil {
		t.Fatalf("Complete(argc): %v", err)
	}
	if argcResp.Text != "1" {
		t.Fatalf("helper received %s arguments, want 1 (no shell splitting)", argcResp.Text)
	}
}

func TestCommandNonZeroExit(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "fail")))
	prompt := "very secret prompt"

	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: prompt}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want an exit error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) {
		t.Fatalf("error type = %T, want *llm.Error", err)
	}
	if providerErr.Code != "exit_status" {
		t.Errorf("Code = %q", providerErr.Code)
	}
	if !strings.Contains(providerErr.Message, "boom") || !strings.Contains(providerErr.Message, "3") {
		t.Errorf("Message = %q, want the stderr tail and status", providerErr.Message)
	}
	if strings.Contains(providerErr.Message, prompt) {
		t.Errorf("Message leaks the prompt: %q", providerErr.Message)
	}
}

func TestCommandStderrIsRedacted(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "fail-secret"))
	cfg.CommandEnv["VIGIL_TEST_SECRET"] = "super-secret-token"
	client := newTestCommandClient(t, cfg)

	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want an exit error")
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("error leaks the command_env secret: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("error does not show a redaction marker: %v", err)
	}
}

func TestCommandTimeout(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "hang"))
	cfg.CommandTimeout = 100 * time.Millisecond
	client := newTestCommandClient(t, cfg)

	started := time.Now()
	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("Complete succeeded, want a timeout")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "timeout" {
		t.Fatalf("error = %v, want code timeout", err)
	}
	if !strings.Contains(providerErr.Message, "timed out") {
		t.Errorf("Message = %q", providerErr.Message)
	}
	if elapsed > 5*time.Second {
		t.Errorf("timeout took %v", elapsed)
	}
}

func TestCommandContextCanceled(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "text")))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Complete(ctx, Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want a cancellation")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "canceled" {
		t.Fatalf("error = %v, want code canceled", err)
	}
}

func TestCommandOutputCap(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "big"))
	cfg.CommandMaxOutputBytes = 64
	client := newTestCommandClient(t, cfg)

	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want an output cap error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "output_too_large" {
		t.Fatalf("error = %v, want code output_too_large", err)
	}
}

func TestCommandMissingExecutable(t *testing.T) {
	cfg := commandTestConfig(t, []string{"vigil-command-does-not-exist-xyz", "{prompt}"})
	client := newTestCommandClient(t, cfg)

	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want a lookup error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "command_not_found" {
		t.Fatalf("error = %v, want code command_not_found", err)
	}
}

func TestCommandEmptyArgv(t *testing.T) {
	_, err := New(config.Config{
		Provider: config.ProviderCommand,
		Model:    "test-model",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "requires command") {
		t.Fatalf("New = %v, want a command error", err)
	}
}

func TestCommandEnvIsAddedAndInherited(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "env"))
	cfg.CommandEnv["VIGIL_COMMAND_TEST"] = "from-command-env"
	client := newTestCommandClient(t, cfg)

	resp, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "from-command-env" {
		t.Fatalf("Text = %q, want the extra env value", resp.Text)
	}

	t.Setenv("VIGIL_INHERITED_TEST", "inherited-value")
	inherited := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "env-inherited")))
	resp, err = inherited.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err != nil {
		t.Fatalf("Complete(inherited): %v", err)
	}
	if resp.Text != "inherited-value" {
		t.Fatalf("Text = %q, want the inherited environment", resp.Text)
	}
}

func TestCommandEmptyOutput(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "empty")))

	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want an empty-output error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "empty_response" {
		t.Fatalf("error = %v, want code empty_response", err)
	}
}

func TestCommandJSONLWithoutText(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "jsonl-no-text")))

	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want an empty-output error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "empty_response" {
		t.Fatalf("error = %v, want code empty_response", err)
	}
}

func TestCommandJSONLErrorEvent(t *testing.T) {
	client := newTestCommandClient(t, commandTestConfig(t, helperCommand(t, "jsonl-error")))

	_, err := client.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "prompt"}},
	})
	if err == nil {
		t.Fatal("Complete succeeded, want a command error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "command_error" {
		t.Fatalf("error = %v, want code command_error", err)
	}
	if !strings.Contains(providerErr.Message, "model refused") {
		t.Errorf("Message = %q", providerErr.Message)
	}
}

func TestCommandFactoryRouting(t *testing.T) {
	client, err := New(config.Config{
		Provider: config.ProviderCommand,
		Model:    "my-label",
		Command:  helperCommand(t, "text"),
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.Name() != config.ProviderCommand {
		t.Errorf("Name = %q", client.Name())
	}
	if client.Model() != "my-label" {
		t.Errorf("Model = %q", client.Model())
	}
	if _, ok := client.(*commandClient); !ok {
		t.Fatalf("type = %T, want *commandClient", client)
	}

	// No API key and no base URL are required, and the model label has a
	// default so a direct llm.New call also works.
	defaulted, err := New(config.Config{
		Provider: config.ProviderCommand,
		Command:  helperCommand(t, "text"),
	}, nil)
	if err != nil {
		t.Fatalf("New without model: %v", err)
	}
	if defaulted.Model() != config.DefaultCommandModel {
		t.Errorf("Model = %q, want %q", defaulted.Model(), config.DefaultCommandModel)
	}
}

func TestDetectNeverInfersCommand(t *testing.T) {
	clearProviderEnv(t)

	if got := Detect(); len(got) != 0 {
		t.Fatalf("Detect() = %v, want none without an explicit provider", got)
	}

	t.Setenv("VIGIL_PROVIDER", config.ProviderCommand)
	got := Detect()
	if len(got) != 1 || got[0] != config.ProviderCommand {
		t.Fatalf("Detect() = %v, want the explicit command provider", got)
	}
}

func TestCommandPromptIncludesSystemAndJSONInstruction(t *testing.T) {
	cfg := commandTestConfig(t, helperCommand(t, "echoarg", "{prompt}"))
	client := newTestCommandClient(t, cfg)

	resp, err := client.Complete(context.Background(), Request{
		System:   "You are a reviewer.",
		Messages: []Message{{Role: RoleUser, Content: "Return a verdict."}},
		JSON:     true,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(resp.Text, "You are a reviewer.") {
		t.Errorf("prompt lost the system message: %q", resp.Text)
	}
	if !strings.Contains(resp.Text, "Return a verdict.") {
		t.Errorf("prompt lost the user message: %q", resp.Text)
	}
	if !strings.Contains(resp.Text, "single valid JSON object") {
		t.Errorf("prompt lost the JSON instruction: %q", resp.Text)
	}
}
