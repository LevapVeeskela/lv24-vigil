package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testGitHubToken matches the VGL-SEC-003 pattern and is not a placeholder, so
// the deterministic rules must report it.
const testGitHubToken = "ghp_9fK2mQ7pR4tX8vN3bC6dF1gH5jL0sW2aE7uI"

// testAWSKeyID matches VGL-SEC-001 (high severity).
const testAWSKeyID = "AKIAZ7Q2W5N8R3T6Y9UP"

func newTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".vigil"), 0o755); err != nil {
		t.Fatalf("create .vigil: %v", err)
	}
	writeTestFile(t, dir, "config.go", "package config\n\nconst githubToken = \""+testGitHubToken+"\"\nconst awsKeyID = \""+testAWSKeyID+"\"\n")
	writeTestFile(t, dir, "README.md", "# demo\n")

	t.Chdir(dir)
	t.Setenv("VIGIL_NO_LLM", "1")
	t.Setenv("VIGIL_CONFIG", filepath.Join(dir, "missing-config.yaml"))
	clearProviderEnv(t)
	return dir
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// clearProviderEnv keeps the developer's real environment from changing what a
// test scans or which model it thinks is configured.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"VIGIL_PROVIDER", "VIGIL_MODEL", "VIGIL_API_KEY", "VIGIL_BASE_URL",
		"VIGIL_FORMAT", "VIGIL_MODE", "VIGIL_MIN_SEVERITY", "VIGIL_USE_LLM",
		"VIGIL_MAX_FINDINGS", "VIGIL_CONCURRENCY", "VIGIL_TIMEOUT",
		"VIGIL_MAX_TOKENS", "VIGIL_TEMPERATURE", "VIGIL_MAX_STEPS",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
		"OPENROUTER_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY",
		"MISTRAL_API_KEY", "XAI_API_KEY", "OLLAMA_HOST", "NO_COLOR",
	} {
		t.Setenv(key, "")
	}
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	err = runWithIO(args, &out, &errBuf)
	return out.String(), errBuf.String(), err
}

type scanJSON struct {
	SchemaVersion string `json:"schemaVersion"`
	ID            string `json:"id"`
	Mode          string `json:"mode"`
	Findings      []struct {
		ID       string `json:"id"`
		RuleID   string `json:"ruleId"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Evidence string `json:"evidence"`
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"startLine"`
		} `json:"location"`
	} `json:"findings"`
	Suppressed []struct {
		ID string `json:"id"`
	} `json:"suppressed"`
	Stats struct {
		FilesScanned int `json:"filesScanned"`
	} `json:"stats"`
}

func decodeScan(t *testing.T, stdout string) scanJSON {
	t.Helper()
	var res scanJSON
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not valid scan JSON: %v\n%s", err, stdout)
	}
	return res
}

func findRule(res scanJSON, ruleID string) bool {
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
