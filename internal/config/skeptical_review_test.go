package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// Regression: a project file may choose the provider, and the api_key of the
// user config was then used for whatever provider the repository named. A
// cloned repository could so send the user's Anthropic key (and source code)
// to a different vendor's endpoint. A key configured next to a provider
// belongs to that provider only.
func TestProjectProviderSwitchDropsUserConfigKey(t *testing.T) {
	clearEnv(t)
	userDir := t.TempDir()
	writeConfig(t, userDir, "config.yaml", "provider: anthropic\nmodel: claude-sonnet-4-5\napi_key: sk-test-USERKEY-0123456789\n")
	t.Setenv("VIGIL_CONFIG", filepath.Join(userDir, "config.yaml"))

	repo := t.TempDir()
	writeConfig(t, repo, ".vigil.yaml", "provider: openai\nmodel: attacker-model\n")
	// Without a key for the provider the repository names, loading fails the
	// same way it does for any provider without a key; the anthropic key is
	// not offered to it.
	if _, err := Load(repo); err == nil || !strings.Contains(err.Error(), "requires an API key") {
		t.Fatalf("Load = %v, want a missing-key error for the project's provider", err)
	}

	// The key for the provider the repository asks for still works when the
	// user supplies it for that provider.
	t.Setenv("OPENAI_API_KEY", "sk-test-OPENAI-0123456789")
	cfg, err := Load(repo)
	if err != nil {
		t.Fatalf("Load with OPENAI_API_KEY: %v", err)
	}
	if cfg.Provider != ProviderOpenAI || cfg.APIKey != "sk-test-OPENAI-0123456789" {
		t.Fatalf("provider/key = %q/%q, want openai with its own environment key", cfg.Provider, cfg.APIKey)
	}
	if strings.Contains(cfg.BaseURL, "anthropic") {
		t.Fatalf("base URL %q does not match provider %q", cfg.BaseURL, cfg.Provider)
	}
}

// The same provider, spelled differently or only with another model, keeps the
// user's key: nothing leaves for a different vendor.
func TestProjectSameProviderKeepsUserConfigKey(t *testing.T) {
	clearEnv(t)
	userDir := t.TempDir()
	writeConfig(t, userDir, "config.yaml", "provider: anthropic\napi_key: sk-test-USERKEY-0123456789\n")
	t.Setenv("VIGIL_CONFIG", filepath.Join(userDir, "config.yaml"))

	for _, project := range []string{"model: claude-haiku\n", "provider: Anthropic\nmodel: claude-haiku\n"} {
		repo := t.TempDir()
		writeConfig(t, repo, ".vigil.yaml", project)
		cfg, err := Load(repo)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.APIKey != "sk-test-USERKEY-0123456789" {
			t.Errorf("project %q: api key = %q, want the user config key", project, cfg.APIKey)
		}
	}
}

// A key the user set without naming a provider is theirs to route: the project
// file is then the only place that names one.
func TestProjectProviderWithUnboundUserKey(t *testing.T) {
	clearEnv(t)
	userDir := t.TempDir()
	writeConfig(t, userDir, "config.yaml", "api_key: sk-test-USERKEY-0123456789\n")
	t.Setenv("VIGIL_CONFIG", filepath.Join(userDir, "config.yaml"))

	repo := t.TempDir()
	writeConfig(t, repo, ".vigil.yaml", "provider: openai\n")
	cfg, err := Load(repo)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "sk-test-USERKEY-0123456789" {
		t.Fatalf("api key = %q, want the user config key", cfg.APIKey)
	}
}

// Regression: the query-key deny-list missed common credential names, so
// "status", "config show" and the stored scan (model.baseUrl) printed them.
func TestRedactURLMoreCredentialQueryKeys(t *testing.T) {
	for _, key := range []string{"jwt", "bearer", "session", "sessionid", "pass", "passphrase", "code", "cookie", "k", "sk", "X-Amz-Security-Token"} {
		raw := "https://llm.example/v1?model=gpt-4&" + key + "=hunter2hunter2&stream=true"
		got := RedactURL(raw)
		if strings.Contains(got, "hunter2") {
			t.Errorf("RedactURL(%q) leaked the value: %q", raw, got)
		}
		if !strings.Contains(got, "model=gpt-4") || !strings.Contains(got, "stream=true") {
			t.Errorf("RedactURL(%q) = %q, want the public parameters kept", raw, got)
		}
	}
}

// Regression: without "scheme://", net/url reads "user:password@host" as a
// scheme plus opaque data and the password was printed.
func TestRedactURLSchemelessUserinfo(t *testing.T) {
	for _, raw := range []string{"u:sk-test-PASSWORD@h:8080/v1", "user:sk-test-PASSWORD@llm.example"} {
		got := RedactURL(raw)
		if strings.Contains(got, "sk-test-PASSWORD") {
			t.Errorf("RedactURL(%q) leaked the password: %q", raw, got)
		}
		if !strings.Contains(got, strings.SplitN(raw, "@", 2)[1]) {
			t.Errorf("RedactURL(%q) = %q, want the host and path kept", raw, got)
		}
	}
	// A plain host:port has no userinfo and is left alone.
	if got := RedactURL("localhost:11434/v1"); got != "localhost:11434/v1" {
		t.Errorf("RedactURL changed a plain endpoint: %q", got)
	}
}

// Regression: argv redaction knew --token and --api-key but not their common
// spellings, and left a credential in a URL argument's query.
func TestRedactArgvMoreSecretFlags(t *testing.T) {
	const secret = "sk-test-ARGV-0123456789"
	cases := [][]string{
		{"tool", "--key", secret},
		{"tool", "--jwt", secret},
		{"tool", "--bearer", secret},
		{"tool", "--session", secret},
		{"tool", "--pass", secret},
		{"tool", "--key=" + secret},
		{"tool", "--url", "https://llm.example/v1?api_key=" + secret},
		{"tool", "https://llm.example/v1?token=" + secret + "&model=x"},
	}
	for _, argv := range cases {
		if got := redactArgv(argv); strings.Contains(got, secret) {
			t.Errorf("redactArgv(%q) leaked the secret: %q", argv, got)
		}
		values := strings.Join(ArgvSecretValues(argv), "\n")
		if !strings.Contains(values, secret) {
			t.Errorf("ArgvSecretValues(%q) = %q, want it to contain the secret", argv, values)
		}
	}
	// Ordinary arguments are kept, and yield nothing to redact.
	plain := []string{"opencode", "run", "--model", "some-model", "--format", "json"}
	if got := redactArgv(plain); got != strings.Join(plain, " ") {
		t.Errorf("redactArgv changed ordinary arguments: %q", got)
	}
	if got := ArgvSecretValues(plain); len(got) != 0 {
		t.Errorf("ArgvSecretValues(plain) = %q, want none", got)
	}
}
