package analysis

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/llm"
)

func threatModelFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeRepoFile(t, root, "README.md", "# Demo\n\nAssets: user accounts and payments.\n")
	writeRepoFile(t, root, "go.mod", "module demo\n\ngo 1.22\n")
	writeRepoFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeRepoFile(t, root, "internal/auth/login.go", "package auth\n\nfunc Login() {}\n")
	writeRepoFile(t, root, "node_modules/pkg/index.js", "module.exports = 1\n")
	writeRepoFile(t, root, ".env", "SUPER_SECRET=do-not-send\n")
	return root
}

func TestThreatModelHappyPath(t *testing.T) {
	root := threatModelFixture(t)
	var prompt string
	a, _ := newTestAnalyzer(func(_ context.Context, req llm.Request) (llm.Response, error) {
		prompt = req.Messages[0].Content
		return llm.Response{Text: `# Threat model

## Assets
- User accounts

## Trust boundaries
- HTTP edge to auth service

## Threats
| Threat | STRIDE | Severity | Mitigation |
| --- | --- | --- | --- |
| Credential stuffing | Spoofing | high | rate limiting |

## Recommended checks
- Add login throttling tests.`}, nil
	})

	got, err := a.ThreatModel(context.Background(), root)
	if err != nil {
		t.Fatalf("ThreatModel: %v", err)
	}
	for _, want := range []string{"Assets", "Trust boundaries", "Threats", "Recommended checks"} {
		if !strings.Contains(got, want) {
			t.Errorf("result missing %q", want)
		}
	}
	for _, want := range []string{"README", "Demo", "go.mod", "internal/auth/login.go", "node_modules", "SUPER_SECRET"} {
		if want == "node_modules" || want == "SUPER_SECRET" {
			if strings.Contains(prompt, want) {
				t.Errorf("prompt leaked %q", want)
			}
			continue
		}
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestThreatModelCapsResponse(t *testing.T) {
	root := threatModelFixture(t)
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: strings.Repeat("x", 20000)}, nil
	})
	got, err := a.ThreatModel(context.Background(), root)
	if err != nil {
		t.Fatalf("ThreatModel: %v", err)
	}
	if len(got) > maxThreatModelBytes {
		t.Fatalf("threat model not capped: %d bytes", len(got))
	}
}

func TestThreatModelNilClient(t *testing.T) {
	a := New(config.Defaults(), nil, nil)
	if _, err := a.ThreatModel(context.Background(), t.TempDir()); !errors.Is(err, ErrLLMNotConfigured) {
		t.Fatalf("error = %v", err)
	}
}

func TestThreatModelRejectsMissingRoot(t *testing.T) {
	a, _ := newTestAnalyzer(nil)
	if _, err := a.ThreatModel(context.Background(), t.TempDir()+"/does-not-exist"); err == nil {
		t.Fatal("expected an error for a missing root")
	}
}

func TestThreatModelEmptyResponse(t *testing.T) {
	root := threatModelFixture(t)
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: "   "}, nil
	})
	if _, err := a.ThreatModel(context.Background(), root); err == nil {
		t.Fatal("expected an error for an empty response")
	}
}
