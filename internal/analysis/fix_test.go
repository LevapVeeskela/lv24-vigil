package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/llm"
)

const authFileContent = `package auth

var password = "hunter2"

func Login() string {
	return password
}
`

const validAuthDiff = `--- a/auth.go
+++ b/auth.go
@@ -1,7 +1,7 @@
 package auth
 
-var password = "hunter2"
+var password = os.Getenv("AUTH_PASSWORD")
 
 func Login() string {
 	return password
 }
`

const absoluteDiff = `--- /etc/passwd
+++ /etc/passwd
@@ -1 +1 @@
-old
+new
`

func fixFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	writeRepoFile(t, root, "auth.go", authFileContent)
	return root, "auth.go"
}

func TestProposeFixParsesFencedDiff(t *testing.T) {
	root, rel := fixFixture(t)
	f := testFinding("VGL-1", rel, 3, "Hardcoded password", `var password = "hunter2"`)

	a, fc := newTestAnalyzer(func(_ context.Context, req llm.Request) (llm.Response, error) {
		if !req.JSON {
			t.Fatal("fix request must ask for JSON")
		}
		return llm.Response{Text: "Here is the fix:\n```diff\n" + validAuthDiff + "```\n"}, nil
	})

	fix, err := a.ProposeFix(context.Background(), f, root)
	if err != nil {
		t.Fatalf("ProposeFix: %v", err)
	}
	if fix == nil {
		t.Fatal("nil fix")
	}
	if !strings.Contains(fix.Diff, "--- a/auth.go") || !strings.Contains(fix.Diff, `+var password = os.Getenv("AUTH_PASSWORD")`) {
		t.Fatalf("unexpected diff:\n%s", fix.Diff)
	}
	if len(fix.Files) != 1 || fix.Files[0] != "auth.go" {
		t.Fatalf("files = %v", fix.Files)
	}
	if !strings.Contains(fix.Description, "Fix for SEC-001") {
		t.Fatalf("description = %q", fix.Description)
	}
	if fc.calls != 1 {
		t.Fatalf("calls = %d", fc.calls)
	}
	if !strings.Contains(fc.last.Messages[0].Content, "hunter2") {
		t.Fatal("code context missing from the fix prompt")
	}
}

func TestProposeFixParsesJSONDiff(t *testing.T) {
	root, rel := fixFixture(t)
	f := testFinding("VGL-1", rel, 3, "Hardcoded password", `var password = "hunter2"`)

	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: fmt.Sprintf(`{"description":"Load the password from the environment","diff":%q}`, validAuthDiff)}, nil
	})

	fix, err := a.ProposeFix(context.Background(), f, root)
	if err != nil {
		t.Fatalf("ProposeFix: %v", err)
	}
	if fix.Description != "Load the password from the environment" {
		t.Fatalf("description = %q", fix.Description)
	}
	if !strings.Contains(fix.Diff, "@@ -1,7 +1,7 @@") {
		t.Fatalf("diff missing hunk:\n%s", fix.Diff)
	}
}

func TestProposeFixRetriesOnceWithValidationError(t *testing.T) {
	root, rel := fixFixture(t)
	f := testFinding("VGL-1", rel, 3, "Hardcoded password", `var password = "hunter2"`)

	call := 0
	var prompts []string
	a, _ := newTestAnalyzer(func(_ context.Context, req llm.Request) (llm.Response, error) {
		call++
		prompts = append(prompts, req.Messages[0].Content)
		if call == 1 {
			return llm.Response{Text: absoluteDiff}, nil
		}
		return llm.Response{Text: validAuthDiff}, nil
	})

	fix, err := a.ProposeFix(context.Background(), f, root)
	if err != nil {
		t.Fatalf("ProposeFix: %v", err)
	}
	if fix == nil {
		t.Fatal("nil fix after retry")
	}
	if call != 2 {
		t.Fatalf("calls = %d, want 2", call)
	}
	if !strings.Contains(prompts[1], "rejected") || !strings.Contains(prompts[1], "unsafe diff path") {
		t.Fatalf("retry prompt did not include the validation error:\n%s", prompts[1])
	}
}

func TestProposeFixFailsAfterRetry(t *testing.T) {
	root, rel := fixFixture(t)
	f := testFinding("VGL-1", rel, 3, "Hardcoded password", `var password = "hunter2"`)

	a, fc := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: absoluteDiff}, nil
	})
	fix, err := a.ProposeFix(context.Background(), f, root)
	if err == nil {
		t.Fatal("expected an error")
	}
	if fix != nil {
		t.Fatalf("expected nil fix, got %+v", fix)
	}
	if fc.calls != 2 {
		t.Fatalf("calls = %d, want 2", fc.calls)
	}
}

func TestProposeFixRejectsUnsafeFindingPath(t *testing.T) {
	root, _ := fixFixture(t)
	f := testFinding("VGL-1", "../secret.go", 1, "issue", "evidence")
	a, fc := newTestAnalyzer(nil)
	if _, err := a.ProposeFix(context.Background(), f, root); err == nil {
		t.Fatal("expected an error for a traversal path")
	}
	if fc.calls != 0 {
		t.Fatalf("model was called for an unsafe path: %d", fc.calls)
	}
}

func TestProposeFixRejectsMissingFile(t *testing.T) {
	root, _ := fixFixture(t)
	f := testFinding("VGL-1", "missing.go", 1, "issue", "evidence")
	a, fc := newTestAnalyzer(nil)
	if _, err := a.ProposeFix(context.Background(), f, root); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if fc.calls != 0 {
		t.Fatalf("model was called for a missing file: %d", fc.calls)
	}
}

func TestProposeFixNilClient(t *testing.T) {
	a := New(config.Defaults(), nil, nil)
	f := testFinding("VGL-1", "auth.go", 3, "issue", "evidence")
	if _, err := a.ProposeFix(context.Background(), f, t.TempDir()); !errors.Is(err, ErrLLMNotConfigured) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFixResponseRejectsNoDiff(t *testing.T) {
	if _, _, err := parseFixResponse("I could not find a safe fix."); err == nil {
		t.Fatal("expected an error for a response without a diff")
	}
}
