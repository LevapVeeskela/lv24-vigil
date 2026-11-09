package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// clearEnv makes every test independent of the developer's environment and
// of any real user config file.
func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv("VIGIL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	for _, env := range []string{
		"VIGIL_PROVIDER", "VIGIL_MODEL", "VIGIL_BASE_URL", "VIGIL_API_KEY",
		"VIGIL_MAX_TOKENS", "VIGIL_TEMPERATURE", "VIGIL_MAX_STEPS", "VIGIL_TIMEOUT",
		"VIGIL_MODE", "VIGIL_MIN_SEVERITY", "VIGIL_MAX_FINDINGS", "VIGIL_CONCURRENCY",
		"VIGIL_FORMAT", "VIGIL_USE_LLM", "VIGIL_NO_LLM",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
		"OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY",
		"XAI_API_KEY", "OLLAMA_HOST",
	} {
		t.Setenv(env, "")
	}
}

func writeConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Provider != "" || cfg.Model != "" || cfg.BaseURL != "" || cfg.APIKey != "" {
		t.Fatalf("defaults have a provider configured: %+v", cfg)
	}
	if cfg.MaxTokens != 4096 {
		t.Errorf("MaxTokens = %d, want 4096", cfg.MaxTokens)
	}
	if cfg.Temperature != 0.1 {
		t.Errorf("Temperature = %v, want 0.1", cfg.Temperature)
	}
	if cfg.Timeout != 120*time.Second {
		t.Errorf("Timeout = %v, want 120s", cfg.Timeout)
	}
	if cfg.MaxSteps != 12 {
		t.Errorf("MaxSteps = %d, want 12", cfg.MaxSteps)
	}
	if cfg.Scan.Mode != "standard" || cfg.Scan.MinSeverity != string(model.SeverityLow) {
		t.Errorf("scan defaults = %+v", cfg.Scan)
	}
	if cfg.Scan.MaxFindings != 200 {
		t.Errorf("MaxFindings = %d, want 200", cfg.Scan.MaxFindings)
	}
	if cfg.Scan.Concurrency < 1 || cfg.Scan.Concurrency > 16 {
		t.Errorf("Concurrency = %d, want 1..16", cfg.Scan.Concurrency)
	}
	if cfg.Scan.Baseline != ".vigil-baseline.json" {
		t.Errorf("Baseline = %q", cfg.Scan.Baseline)
	}
	if cfg.Scan.MaxFileBytes != 2<<20 {
		t.Errorf("MaxFileBytes = %d, want 2 MiB", cfg.Scan.MaxFileBytes)
	}
	if cfg.Output.Format != "md" || cfg.Output.Color != "auto" || !cfg.Output.ShowFix {
		t.Errorf("output defaults = %+v", cfg.Output)
	}
	if cfg.Sources == nil {
		t.Error("Sources map is nil")
	}
}

func TestLoadProjectFileMerge(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	writeConfig(t, root, ".vigil.yaml", `timeout: 45s
scan:
  mode: quick
  min_severity: high
  max_findings: 7
  concurrency: 3
  exclude:
    - "fixtures/**"
  disable_rules:
    - VGL-SEC-001
  deep_review: true
  max_file_bytes: 12345
  baseline: custom-baseline.json
output:
  format: json
  color: never
  show_fix: false
`)

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout = %v, want 45s", cfg.Timeout)
	}
	if cfg.Scan.Mode != "quick" || cfg.Scan.MinSeverity != "high" {
		t.Errorf("scan mode/severity = %q/%q", cfg.Scan.Mode, cfg.Scan.MinSeverity)
	}
	if cfg.Scan.MaxFindings != 7 || cfg.Scan.Concurrency != 3 {
		t.Errorf("maxFindings/concurrency = %d/%d", cfg.Scan.MaxFindings, cfg.Scan.Concurrency)
	}
	if len(cfg.Scan.Exclude) != 1 || cfg.Scan.Exclude[0] != "fixtures/**" {
		t.Errorf("Exclude = %v", cfg.Scan.Exclude)
	}
	if len(cfg.Scan.DisableRules) != 1 || cfg.Scan.DisableRules[0] != "VGL-SEC-001" {
		t.Errorf("DisableRules = %v", cfg.Scan.DisableRules)
	}
	if !cfg.Scan.DeepReview {
		t.Error("DeepReview was not parsed")
	}
	if cfg.Scan.MaxFileBytes != 12345 {
		t.Errorf("MaxFileBytes = %d", cfg.Scan.MaxFileBytes)
	}
	if cfg.Scan.Baseline != "custom-baseline.json" {
		t.Errorf("Baseline = %q", cfg.Scan.Baseline)
	}
	if cfg.Output.Format != "json" || cfg.Output.Color != "never" || cfg.Output.ShowFix {
		t.Errorf("output = %+v", cfg.Output)
	}
	if cfg.Sources["scan.mode"] == "" || cfg.Sources["timeout"] == "" {
		t.Errorf("Sources did not record the project file: %v", cfg.Sources)
	}
}

func TestProjectFileRejectsSecretsAndEgress(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"api key", "api_key: sk-test\n", "api_key"},
		{"base url", "base_url: https://attacker.example/v1\n", "base_url"},
		{"absolute output", "output:\n  path: /tmp/report.md\n", "output.path"},
		{"traversal output", "output:\n  path: ../report.md\n", "output.path"},
		{"git output", "output:\n  path: .GIT/hooks/pre-commit\n", "output.path"},
		{"absolute baseline", "scan:\n  baseline: /tmp/base.json\n", "scan.baseline"},
		{"traversal baseline", "scan:\n  baseline: ../../base.json\n", "scan.baseline"},
		{"follow symlinks", "scan:\n  follow_symlinks: true\n", "follow_symlinks"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			root := t.TempDir()
			writeConfig(t, root, ".vigil.yaml", tc.body)
			_, err := Load(root)
			if err == nil {
				t.Fatalf("Load accepted %q", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestProjectFileAcceptsSafePaths(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	writeConfig(t, root, ".vigil.yaml", `scan:
  baseline: reports/base.json
  follow_symlinks: false
output:
  path: reports/vigil.md
`)
	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.Baseline != "reports/base.json" || cfg.Output.Path != "reports/vigil.md" {
		t.Fatalf("paths were not merged: %+v %+v", cfg.Scan.Baseline, cfg.Output.Path)
	}
}

func TestOversizedProjectConfigRejected(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".vigil.yaml"), make([]byte, maxConfigBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Load accepted an oversized config: %v", err)
	}
}

func TestProjectConfigSymlinkOutsideRejected(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(outside, []byte("scan:\n  mode: quick\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".vigil.yaml")); err != nil {
		t.Skipf("cannot create a symlink on this host: %v", err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("Load accepted a project config symlink that leaves the root")
	}
}

func TestEnvOverridesProjectFile(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	writeConfig(t, root, ".vigil.yaml", "scan:\n  mode: quick\n  max_findings: 4\n")
	t.Setenv("VIGIL_MODE", "deep")
	t.Setenv("VIGIL_MAX_FINDINGS", "11")

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.Mode != "deep" || cfg.Scan.MaxFindings != 11 {
		t.Errorf("mode/maxFindings = %q/%d, want env values", cfg.Scan.Mode, cfg.Scan.MaxFindings)
	}
	if cfg.Sources["mode"] != "env:VIGIL_MODE" {
		t.Errorf("mode source = %q", cfg.Sources["mode"])
	}
}

func TestProviderInference(t *testing.T) {
	t.Run("openai", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("OPENAI_API_KEY", "sk-test-openai")
		cfg, err := Load(t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Provider != ProviderOpenAI || cfg.APIKey != "sk-test-openai" {
			t.Fatalf("provider/key = %q/%q", cfg.Provider, cfg.APIKey)
		}
		if cfg.Model != DefaultModel {
			t.Errorf("Model = %q, want %q", cfg.Model, DefaultModel)
		}
	})

	t.Run("anthropic wins over openai", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
		t.Setenv("OPENAI_API_KEY", "sk-test-openai")
		cfg, err := Load(t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Provider != ProviderAnthropic {
			t.Errorf("Provider = %q, want anthropic", cfg.Provider)
		}
	})

	t.Run("google fallback", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("GOOGLE_API_KEY", "google-test")
		cfg, err := Load(t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Provider != ProviderGemini || cfg.APIKey != "google-test" {
			t.Errorf("provider/key = %q/%q", cfg.Provider, cfg.APIKey)
		}
		if cfg.Sources["api_key"] != "env:GOOGLE_API_KEY" {
			t.Errorf("api_key source = %q, want env:GOOGLE_API_KEY", cfg.Sources["api_key"])
		}
	})
}

func TestOllamaNeedsNoKey(t *testing.T) {
	clearEnv(t)
	t.Setenv("VIGIL_PROVIDER", ProviderOllama)
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "" {
		t.Errorf("APIKey = %q, want empty", cfg.APIKey)
	}
	if cfg.Model != "qwen2.5-coder:14b" {
		t.Errorf("Model = %q", cfg.Model)
	}
	if cfg.BaseURL != "http://localhost:11434/v1" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
}

func TestCustomRequiresBaseURL(t *testing.T) {
	clearEnv(t)
	t.Setenv("VIGIL_PROVIDER", ProviderCustom)
	t.Setenv("VIGIL_MODEL", "my-model")
	t.Setenv("VIGIL_API_KEY", "placeholder")
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("Load without base_url = %v, want a base_url error", err)
	}

	t.Setenv("VIGIL_BASE_URL", "https://llm.example/v1")
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load with base_url: %v", err)
	}
	if cfg.BaseURL != "https://llm.example/v1" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
}

func TestInvalidValuesRejected(t *testing.T) {
	cases := []struct {
		env   string
		value string
	}{
		{"VIGIL_MODE", "turbo"},
		{"VIGIL_MIN_SEVERITY", "urgent"},
		{"VIGIL_FORMAT", "xml"},
		{"VIGIL_TEMPERATURE", "3"},
		{"VIGIL_MAX_FINDINGS", "-1"},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(tc.env, tc.value)
			if _, err := Load(t.TempDir()); err == nil {
				t.Fatalf("Load accepted %s=%q", tc.env, tc.value)
			}
		})
	}
}

func TestRedactedHidesKeyAndURLSecrets(t *testing.T) {
	cfg := Defaults()
	cfg.APIKey = "sk-super-secret"
	cfg.BaseURL = "https://user:password@example.test/v1?api_key=sk-in-url&safe=1"

	red := cfg.Redacted()
	if red.APIKey != "***" {
		t.Errorf("Redacted APIKey = %q", red.APIKey)
	}
	if strings.Contains(red.BaseURL, "super-secret") || strings.Contains(red.BaseURL, "password") ||
		strings.Contains(red.BaseURL, "sk-in-url") {
		t.Errorf("Redacted BaseURL leaks a secret: %q", red.BaseURL)
	}
	if cfg.APIKey != "sk-super-secret" {
		t.Error("Redacted mutated the original config")
	}
}

func TestVIGILCONFIGPath(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml", "scan:\n  mode: quick\n")
	t.Setenv("VIGIL_CONFIG", path)

	got, err := UserConfigPath()
	if err != nil {
		t.Fatalf("UserConfigPath: %v", err)
	}
	if got != path {
		t.Fatalf("UserConfigPath = %q, want %q", got, path)
	}
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.Mode != "quick" {
		t.Errorf("user config was not merged: mode = %q", cfg.Scan.Mode)
	}
}

func TestTimeoutParsing(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	writeConfig(t, root, ".vigil.yaml", "timeout: 45s\n")
	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout = %v, want 45s", cfg.Timeout)
	}

	t.Setenv("VIGIL_TIMEOUT", "1m")
	cfg, err = Load(root)
	if err != nil {
		t.Fatalf("Load with env timeout: %v", err)
	}
	if cfg.Timeout != time.Minute {
		t.Errorf("Timeout = %v, want 1m", cfg.Timeout)
	}

	t.Setenv("VIGIL_TIMEOUT", "not-a-duration")
	cfg, err = Load(root)
	if err != nil {
		t.Fatalf("Load with invalid env timeout: %v", err)
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("invalid env timeout changed the value to %v", cfg.Timeout)
	}
}

func TestInvalidNumericEnvIsIgnored(t *testing.T) {
	clearEnv(t)
	t.Setenv("VIGIL_MAX_TOKENS", "12abc")
	t.Setenv("VIGIL_TEMPERATURE", "0.5junk")
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MaxTokens != 4096 {
		t.Errorf("MaxTokens = %d, want the default 4096", cfg.MaxTokens)
	}
	if cfg.Temperature != 0.1 {
		t.Errorf("Temperature = %v, want the default 0.1", cfg.Temperature)
	}
}
