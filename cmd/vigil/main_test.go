package main

import (
	"strings"
	"testing"
)

func TestHelpListsCommands(t *testing.T) {
	out, _, err := runCLI(t, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, want := range []string{
		"vigil scan [path]",
		"vigil review",
		"vigil fix FINDING_ID",
		"vigil threat-model",
		"vigil mcp",
		"vigil baseline",
		"vigil report",
		"--fail-on",
		"Exit codes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing %q\n%s", want, out)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	out, _, err := runCLI(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.HasPrefix(out, "vigil ") {
		t.Fatalf("unexpected version output: %q", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	_, _, err := runCLI(t, "frobnicate")
	if err == nil {
		t.Fatal("expected an error for an unknown command")
	}
	if !strings.Contains(err.Error(), "unknown command") || !strings.Contains(err.Error(), "vigil help") {
		t.Fatalf("error is not actionable: %v", err)
	}
}

func TestStringListFlag(t *testing.T) {
	var list stringList
	if err := list.Set("*.go, *.ts"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := list.Set("*.py"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	want := []string{"*.go", "*.ts", "*.py"}
	if len(list) != len(want) {
		t.Fatalf("got %v, want %v", list, want)
	}
	for i := range want {
		if list[i] != want[i] {
			t.Fatalf("got %v, want %v", list, want)
		}
	}
}

func TestUseColor(t *testing.T) {
	var buf strings.Builder
	t.Setenv("NO_COLOR", "")
	if !useColor("always", &buf) {
		t.Error("--color always must win over a non-terminal writer")
	}
	if useColor("never", &buf) {
		t.Error("--color never must disable color")
	}
	if useColor("auto", &buf) {
		t.Error("auto must not colorize a non-terminal writer")
	}
	t.Setenv("NO_COLOR", "1")
	if useColor("auto", &buf) {
		t.Error("auto must respect NO_COLOR")
	}
	if !useColor("always", &buf) {
		t.Error("--color always must ignore NO_COLOR")
	}
}
