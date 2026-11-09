package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/llm"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

const deepReviewFileContent = `package auth

func Login(user string) {
	query := "SELECT * FROM users WHERE name = '" + user + "'"
	_ = query
}
`

func deepReviewJSON(path string, start, end int, title, severity string, confidence float64) string {
	return fmt.Sprintf(
		`[{"path":%q,"startLine":%d,"endLine":%d,"title":%q,"description":"user input reaches a query","severity":%q,"confidence":%g,"cwe":["89","CWE-89"],"remediation":"use parameters","evidence":"query line"}]`,
		path, start, end, title, severity, confidence)
}

func TestDeepReviewHappyPath(t *testing.T) {
	root := t.TempDir()
	file := testFile("auth.go", "package auth", "", "func Login(user string) {", `	query := "SELECT * FROM users WHERE name = '" + user + "'"`, "	_ = query", "}")
	a, fc := newTestAnalyzer(func(_ context.Context, req llm.Request) (llm.Response, error) {
		if !req.JSON {
			t.Fatal("deep review must ask for JSON")
		}
		return llm.Response{Text: deepReviewJSON("auth.go", 4, 4, "SQL injection in login", "critical", 0.3)}, nil
	})

	got, err := a.DeepReview(context.Background(), root, []*rules.File{file}, nil)
	if err != nil {
		t.Fatalf("DeepReview: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Source != model.SourceLLM {
		t.Errorf("source = %q", f.Source)
	}
	if f.RuleID != aiRuleID {
		t.Errorf("rule = %q", f.RuleID)
	}
	if f.Category != model.CategoryLogic {
		t.Errorf("category = %q", f.Category)
	}
	if f.Location.Path != "auth.go" || f.Location.StartLine != 4 || f.Location.EndLine != 4 {
		t.Errorf("location = %+v", f.Location)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("low-confidence critical was not capped: %q", f.Severity)
	}
	if f.Confidence != model.ConfidenceLow {
		t.Errorf("confidence = %q", f.Confidence)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
		t.Errorf("cwe = %v", f.CWE)
	}
	if !strings.Contains(f.Evidence, "SELECT") {
		t.Errorf("evidence not taken from the file: %q", f.Evidence)
	}
	if f.ID == "" || f.Fingerprint == "" {
		t.Errorf("finding was not normalized: %+v", f)
	}
	if fc.calls != 1 {
		t.Errorf("calls = %d", fc.calls)
	}
}

func TestDeepReviewHighConfidenceKeepsCritical(t *testing.T) {
	root := t.TempDir()
	file := testFile("auth.go", "package auth", "", "func Login() {}", "}")
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: deepReviewJSON("auth.go", 3, 3, "Missing auth check", "critical", 0.9)}, nil
	})
	got, err := a.DeepReview(context.Background(), root, []*rules.File{file}, nil)
	if err != nil {
		t.Fatalf("DeepReview: %v", err)
	}
	if len(got) != 1 || got[0].Severity != model.SeverityCritical || got[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("unexpected finding: %+v", got)
	}
}

func TestDeepReviewRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	file := testFile("auth.go", "package auth", "", "func Login() {}", "}")
	items := []string{
		deepReviewJSON("../secret.go", 3, 3, "traversal", "high", 0.9),
		deepReviewJSON("/etc/passwd", 3, 3, "absolute", "high", 0.9),
		deepReviewJSON(`C:\Windows\win.ini`, 3, 3, "windows absolute", "high", 0.9),
		deepReviewJSON("other.go", 3, 3, "not provided", "high", 0.9),
	}
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: mergeJSONArrays(items)}, nil
	})
	got, err := a.DeepReview(context.Background(), root, []*rules.File{file}, nil)
	if err != nil {
		t.Fatalf("DeepReview: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unsafe paths produced findings: %+v", got)
	}
}

func TestDeepReviewRejectsOutOfRangeLines(t *testing.T) {
	root := t.TempDir()
	file := testFile("auth.go", "package auth", "", "func Login() {}", "}")
	items := []string{
		deepReviewJSON("auth.go", 999, 1000, "too far", "high", 0.9),
		deepReviewJSON("auth.go", 3, 999, "end too far", "high", 0.9),
		deepReviewJSON("auth.go", 0, 0, "zero", "high", 0.9),
		deepReviewJSON("auth.go", 4, 3, "reversed", "high", 0.9),
	}
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{Text: mergeJSONArrays(items)}, nil
	})
	got, err := a.DeepReview(context.Background(), root, []*rules.File{file}, nil)
	if err != nil {
		t.Fatalf("DeepReview: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("out-of-range lines produced findings: %+v", got)
	}
}

func TestDeepReviewSuppressesDuplicates(t *testing.T) {
	root := t.TempDir()
	file := testFile("auth.go", "package auth", "", "func Login() {}", "}")
	existing := []model.Finding{
		testFinding("VGL-OLD", "auth.go", 3, "SQL injection in login", "SELECT"),
	}

	t.Run("same title and line", func(t *testing.T) {
		a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
			return llm.Response{Text: deepReviewJSON("auth.go", 3, 3, "SQL injection in login", "high", 0.9)}, nil
		})
		got, err := a.DeepReview(context.Background(), root, []*rules.File{file}, existing)
		if err != nil {
			t.Fatalf("DeepReview: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("duplicate was not suppressed: %+v", got)
		}
	})

	t.Run("overlapping line different issue", func(t *testing.T) {
		a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
			return llm.Response{Text: deepReviewJSON("auth.go", 3, 3, "Missing authorization check", "high", 0.9)}, nil
		})
		got, err := a.DeepReview(context.Background(), root, []*rules.File{file}, existing)
		if err != nil {
			t.Fatalf("DeepReview: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("distinct issue was suppressed: %+v", got)
		}
	})
}

func TestDeepReviewSelectsAtMostEightAndSkipsTests(t *testing.T) {
	root := t.TempDir()
	var files []*rules.File
	for i := 0; i < 9; i++ {
		files = append(files, testFile(fmt.Sprintf("internal/auth/login%d.go", i), "package auth", "", "func Login() {}", "}"))
	}
	files = append(files, testFile("internal/auth/login_test.go", "package auth", "", "func TestLogin() {}", "}"))
	files = append(files, testFile(".env", "SUPER_SECRET=do-not-send"))

	var prompts []string
	a, _ := newTestAnalyzer(func(_ context.Context, req llm.Request) (llm.Response, error) {
		prompts = append(prompts, req.Messages[0].Content)
		return llm.Response{Text: "[]"}, nil
	})
	got, err := a.DeepReview(context.Background(), root, files, nil)
	if err != nil {
		t.Fatalf("DeepReview: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no findings, got %+v", got)
	}
	if len(prompts) != maxDeepReviewFiles {
		t.Fatalf("reviewed %d files, want %d", len(prompts), maxDeepReviewFiles)
	}
	for _, p := range prompts {
		if strings.Contains(p, "login_test.go") {
			t.Fatal("test file was reviewed")
		}
		if strings.Contains(p, "SUPER_SECRET") {
			t.Fatal("credential file was reviewed")
		}
	}
}

func TestDeepReviewAllWindowsFail(t *testing.T) {
	root := t.TempDir()
	file := testFile("auth.go", "package auth", "", "func Login() {}", "}")
	a, _ := newTestAnalyzer(func(context.Context, llm.Request) (llm.Response, error) {
		return llm.Response{}, errors.New("model down")
	})
	got, err := a.DeepReview(context.Background(), root, []*rules.File{file}, nil)
	if err == nil {
		t.Fatal("expected an error when every window fails")
	}
	if got != nil {
		t.Fatalf("expected nil findings, got %+v", got)
	}
}

func TestParseDeepReviewResponseSingleObject(t *testing.T) {
	items, err := parseDeepReviewResponse(`{"path":"auth.go","startLine":1,"endLine":1,"title":"issue"}`)
	if err != nil {
		t.Fatalf("parseDeepReviewResponse: %v", err)
	}
	if len(items) != 1 || items[0].Path != "auth.go" {
		t.Fatalf("unexpected items: %+v", items)
	}
}

func TestDeepReviewNoFiles(t *testing.T) {
	a, _ := newTestAnalyzer(nil)
	got, err := a.DeepReview(context.Background(), t.TempDir(), nil, nil)
	if err != nil || got != nil {
		t.Fatalf("DeepReview = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestChunkFileBoundsAndOverlap(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = "0123456789"
	}
	f := testFile("big.go", lines...)
	chunks := chunkFile(f, 1000, 20)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c.text) > 1000 {
			t.Errorf("chunk %d is %d bytes", i, len(c.text))
		}
	}
	if chunks[len(chunks)-1].endLine != 100 {
		t.Errorf("last chunk ends at %d", chunks[len(chunks)-1].endLine)
	}
	if chunks[1].startLine != chunks[0].endLine-19 {
		t.Errorf("overlap wrong: first ends %d, second starts %d", chunks[0].endLine, chunks[1].startLine)
	}
}

func TestChunkFileSplitsHugeLine(t *testing.T) {
	f := testFile("bundle.js", strings.Repeat("x", 5000))
	chunks := chunkFile(f, 1000, 20)
	if len(chunks) < 5 {
		t.Fatalf("expected the huge line to be split, got %d chunks", len(chunks))
	}
	for i, c := range chunks {
		if len(c.text) > 1000 {
			t.Errorf("chunk %d is %d bytes", i, len(c.text))
		}
		if c.startLine != 1 || c.endLine != 1 {
			t.Errorf("chunk %d line range = %d-%d", i, c.startLine, c.endLine)
		}
	}
}

func mergeJSONArrays(items []string) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(item), "["), "]"))
	}
	return "[" + strings.Join(parts, ",") + "]"
}
