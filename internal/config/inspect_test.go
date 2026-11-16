package config

import (
	"reflect"
	"strings"
	"testing"
)

func inspectEntry(t *testing.T, entries []Entry, key string) Entry {
	t.Helper()
	for _, entry := range entries {
		if entry.Key == key {
			return entry
		}
	}
	t.Fatalf("entry %q is missing", key)
	return Entry{}
}

func TestSecretKeyNames(t *testing.T) {
	cases := map[string]bool{
		"api_key":         true,
		"API_KEY":         true,
		"api-key":         true,
		"token":           true,
		"github_token":    true,
		"password":        true,
		"db_password":     true,
		"secret":          true,
		"client_secret":   true,
		"headers":         true,
		"HTTP_HEADERS":    true,
		"authorization":   true,
		"max_tokens":      false,
		"provider":        false,
		"base_url":        false,
		"output.path":     false,
		"":                false,
		"scan.exclude":    false,
		"command_timeout": false,
	}
	for name, want := range cases {
		if got := SecretKey(name); got != want {
			t.Errorf("SecretKey(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestRedactValueKeepsUnsetEmpty(t *testing.T) {
	if got := RedactValue("api_key", "sk-live"); got != "***" {
		t.Errorf("RedactValue(api_key) = %q, want ***", got)
	}
	if got := RedactValue("api_key", ""); got != "" {
		t.Errorf("RedactValue(empty) = %q, want empty", got)
	}
	if got := RedactValue("provider", "openai"); got != "openai" {
		t.Errorf("RedactValue(provider) = %q, want openai", got)
	}
	if got := RedactValue("max_tokens", "4096"); got != "4096" {
		t.Errorf("RedactValue(max_tokens) = %q, want 4096", got)
	}
}

func TestEntriesDefaults(t *testing.T) {
	entries := Defaults().Entries()
	if len(entries) < 20 {
		t.Fatalf("Entries() returned %d values, want the effective config", len(entries))
	}
	for _, entry := range entries {
		if entry.Key == "" || entry.Source == "" {
			t.Fatalf("incomplete entry: %+v", entry)
		}
		if entry.Source != SourceDefaults {
			t.Errorf("%s source = %q, want %q", entry.Key, entry.Source, SourceDefaults)
		}
	}

	if e := inspectEntry(t, entries, "provider"); e.Value != "" || e.Secret {
		t.Errorf("provider = %+v", e)
	}
	if e := inspectEntry(t, entries, "api_key"); e.Value != "" || !e.Secret {
		t.Errorf("api_key = %+v, want an empty secret", e)
	}
	if e := inspectEntry(t, entries, "max_tokens"); e.Value != "4096" || e.Secret {
		t.Errorf("max_tokens = %+v, want 4096 and not secret", e)
	}
	if e := inspectEntry(t, entries, "timeout"); e.Value != "2m0s" {
		t.Errorf("timeout = %q", e.Value)
	}
	if e := inspectEntry(t, entries, "scan.use_llm"); e.Value != "auto" {
		t.Errorf("scan.use_llm = %q, want auto", e.Value)
	}
	if e := inspectEntry(t, entries, "scan.inline_suppressions"); e.Value != "true" {
		t.Errorf("scan.inline_suppressions = %q", e.Value)
	}
	if e := inspectEntry(t, entries, "output.format"); e.Value != "md" {
		t.Errorf("output.format = %q", e.Value)
	}
}

func TestEntriesRedactsSecretsAndRecordsSources(t *testing.T) {
	cfg := Defaults()
	cfg.APIKey = "sk-live-secret"
	cfg.Sources["api_key"] = "/home/user/.config/vigil/config.yaml"
	cfg.CommandEnv = map[string]string{"GITHUB_TOKEN": "ghp_live_secret", "SAFE_VALUE": "ok"}
	cfg.Sources["command_env"] = "/home/user/.config/vigil/config.yaml"

	entries := cfg.Entries()

	key := inspectEntry(t, entries, "api_key")
	if key.Value != "***" || !key.Secret {
		t.Errorf("api_key = %+v, want a redacted secret", key)
	}
	if key.Source != "/home/user/.config/vigil/config.yaml" {
		t.Errorf("api_key source = %q", key.Source)
	}

	env := inspectEntry(t, entries, "command_env")
	want := "GITHUB_TOKEN=***, SAFE_VALUE=***"
	if env.Value != want {
		t.Errorf("command_env = %q, want %q", env.Value, want)
	}
	if !env.Secret {
		t.Error("command_env must be marked secret")
	}

	for _, entry := range entries {
		if strings.Contains(entry.Value, "sk-live-secret") || strings.Contains(entry.Value, "ghp_live_secret") {
			t.Errorf("%s leaked a secret: %q", entry.Key, entry.Value)
		}
	}
}

func TestEntriesKeepsBaseURLHostButNotCredentials(t *testing.T) {
	cfg := Defaults()
	cfg.BaseURL = "https://user:pw@llm.example/v1?token=hidden"

	entries := cfg.Entries()
	base := inspectEntry(t, entries, "base_url")
	if !strings.Contains(base.Value, "llm.example") {
		t.Errorf("base_url lost the host: %q", base.Value)
	}
	if strings.Contains(base.Value, "pw@") || strings.Contains(base.Value, "hidden") {
		t.Errorf("base_url leaked credentials: %q", base.Value)
	}
}

func TestEntriesRedactsInlineCommandKeys(t *testing.T) {
	cfg := Defaults()
	cfg.Command = []string{"agent", "--api-key=sk-argv-secret", "--token", "plain-secret", "run"}

	value := inspectEntry(t, cfg.Entries(), "command").Value
	if strings.Contains(value, "sk-argv-secret") || strings.Contains(value, "plain-secret") {
		t.Errorf("command leaked a key: %q", value)
	}
	if !strings.Contains(value, "--api-key=***") {
		t.Errorf("command did not redact the inline key: %q", value)
	}
	if !strings.Contains(value, "--token ***") {
		t.Errorf("command did not redact the separate-argument key: %q", value)
	}
	if !strings.Contains(value, "run") {
		t.Errorf("command lost its arguments: %q", value)
	}
}

func TestLoadRecordsEnvSourceForCanonicalKeys(t *testing.T) {
	clearEnv(t)
	t.Setenv("VIGIL_FORMAT", "html")
	t.Setenv("VIGIL_MODE", "deep")
	root := t.TempDir()
	writeConfig(t, root, ".vigil.yaml", "scan:\n  mode: quick\noutput:\n  format: sarif\n")

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output.Format != "html" || cfg.Scan.Mode != "deep" {
		t.Fatalf("env did not win: format %q, mode %q", cfg.Output.Format, cfg.Scan.Mode)
	}
	if cfg.Sources["output.format"] != "env:VIGIL_FORMAT" {
		t.Errorf("output.format source = %q, want env:VIGIL_FORMAT", cfg.Sources["output.format"])
	}
	if cfg.Sources["scan.mode"] != "env:VIGIL_MODE" {
		t.Errorf("scan.mode source = %q, want env:VIGIL_MODE", cfg.Sources["scan.mode"])
	}

	entries := cfg.Entries()
	if entry := inspectEntry(t, entries, "output.format"); entry.Source != "env:VIGIL_FORMAT" {
		t.Errorf("output.format entry source = %q", entry.Source)
	}
	if entry := inspectEntry(t, entries, "scan.mode"); entry.Source != "env:VIGIL_MODE" {
		t.Errorf("scan.mode entry source = %q", entry.Source)
	}
}

func TestRedactURLCredentialQueryKeys(t *testing.T) {
	keys := []string{
		"password", "passwd", "pwd", "secret", "token", "access_token",
		"api_key", "apikey", "key", "auth", "credential", "signature", "sig",
	}
	for _, key := range keys {
		raw := "https://llm.example/v1?model=gpt-4&" + key + "=hunter2&stream=true"
		got := RedactURL(raw)
		if strings.Contains(got, "hunter2") {
			t.Errorf("RedactURL(%q) leaked the value: %q", raw, got)
		}
		if !strings.Contains(got, key+"=REDACTED") {
			t.Errorf("RedactURL(%q) = %q, want %s=REDACTED", raw, got, key)
		}
		if !strings.Contains(got, "model=gpt-4") || !strings.Contains(got, "stream=true") {
			t.Errorf("RedactURL(%q) = %q, want the public parameters kept", raw, got)
		}
	}
}

func TestRedactURLDropsFragmentAndUserinfo(t *testing.T) {
	got := RedactURL("https://user:hunter2@llm.example/v1#access_token=frag-secret")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "frag-secret") {
		t.Errorf("RedactURL leaked a credential: %q", got)
	}
	if strings.Contains(got, "#") {
		t.Errorf("RedactURL kept the fragment: %q", got)
	}
	if !strings.Contains(got, "REDACTED@llm.example/v1") {
		t.Errorf("RedactURL = %q, want the userinfo redacted and the host kept", got)
	}
	if got := RedactURL(""); got != "" {
		t.Errorf("RedactURL(empty) = %q, want empty", got)
	}
}

func TestRedactURLMalformedRedactsWholeQuery(t *testing.T) {
	raw := "http://[::1]:namedport/v1?password=hunter2&token=hidden#secret-fragment"
	got := RedactURL(raw)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "hidden") || strings.Contains(got, "secret-fragment") {
		t.Fatalf("RedactURL(%q) leaked a credential: %q", raw, got)
	}
	if !strings.Contains(got, "?REDACTED") {
		t.Errorf("RedactURL(%q) = %q, want the whole query redacted", raw, got)
	}
	if strings.Contains(got, "#") {
		t.Errorf("RedactURL(%q) kept the fragment: %q", raw, got)
	}
}

// Regression: url.Parse accepts the URL but url.Query() swallowed the
// ParseQuery error, so an invalid percent escape kept the secret in `config
// show` and `status` output.
func TestRedactURLMalformedPercentEscape(t *testing.T) {
	raw := "https://llm.example/v1?password=p%ss&model=gpt-4#access_token=frag-secret"
	got := RedactURL(raw)
	for _, secret := range []string{"p%ss", "frag-secret", "password="} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactURL(%q) leaked %q: %q", raw, secret, got)
		}
	}
	if !strings.Contains(got, "?REDACTED") {
		t.Errorf("RedactURL(%q) = %q, want the unparsable query redacted whole", raw, got)
	}
	if strings.Contains(got, "#") {
		t.Errorf("RedactURL(%q) kept the fragment: %q", raw, got)
	}
	if !strings.Contains(got, "llm.example/v1") {
		t.Errorf("RedactURL(%q) = %q, want the endpoint kept", raw, got)
	}
}

func TestRedactArgvHidesCredentialValues(t *testing.T) {
	cases := []struct {
		name   string
		argv   []string
		secret []string
		want   []string
	}{
		{
			name:   "curl user",
			argv:   []string{"curl", "-u", "user:hunter2", "https://api.example/v1"},
			secret: []string{"hunter2"},
			want:   []string{"-u ***", "https://api.example/v1"},
		},
		{
			name:   "curl long user",
			argv:   []string{"curl", "--user", "user:hunter2", "https://api.example/v1"},
			secret: []string{"hunter2"},
			want:   []string{"--user ***"},
		},
		{
			name:   "attached short user",
			argv:   []string{"curl", "-uuser:hunter2", "https://api.example/v1"},
			secret: []string{"hunter2"},
			want:   []string{"-u***"},
		},
		{
			name:   "authorization header",
			argv:   []string{"curl", "-H", "Authorization: Bearer sk-header-secret", "https://api.example/v1"},
			secret: []string{"sk-header-secret"},
			want:   []string{"-H ***", "https://api.example/v1"},
		},
		{
			name:   "inline header",
			argv:   []string{"curl", "--header=Authorization: Bearer sk-header-secret", "https://api.example/v1"},
			secret: []string{"sk-header-secret"},
			want:   []string{"--header=***", "https://api.example/v1"},
		},
		{
			name:   "password token and api key",
			argv:   []string{"tool", "--password", "hunter2", "--api-key=sk-inline-secret", "--token", "tok-secret"},
			secret: []string{"hunter2", "sk-inline-secret", "tok-secret"},
			want:   []string{"--password ***", "--api-key=***", "--token ***"},
		},
		{
			name:   "url userinfo",
			argv:   []string{"curl", "https://user:hunter2@llm.example/v1"},
			secret: []string{"hunter2"},
			want:   []string{"https://REDACTED@llm.example/v1"},
		},
		{
			name: "flag without a value",
			argv: []string{"tool", "--token"},
			want: []string{"--token"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactArgv(tc.argv)
			for _, secret := range tc.secret {
				if strings.Contains(got, secret) {
					t.Errorf("redactArgv(%v) leaked %q: %q", tc.argv, secret, got)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("redactArgv(%v) = %q, want it to contain %q", tc.argv, got, want)
				}
			}
		})
	}
}

func TestRedactArgvKeepsOrdinaryArguments(t *testing.T) {
	ordinary := []string{"vigil", "scan", ".", "--fail-on", "high", "--format", "json"}
	if got, want := redactArgv(ordinary), strings.Join(ordinary, " "); got != want {
		t.Errorf("redactArgv(%v) = %q, want %q", ordinary, got, want)
	}

	// Only an actual flag hides the argument after it: a bare word that merely
	// looks like a secret name must not blank unrelated arguments.
	if got, want := redactArgv([]string{"env", "TOKEN", "scan", "."}), "env TOKEN scan ."; got != want {
		t.Errorf("redactArgv consumed a value after a bare word: %q, want %q", got, want)
	}

	// One header value is consumed; the URL after it is kept.
	got := redactArgv([]string{"curl", "-H", "X-Trace: abc", "https://api.example/v1"})
	if got != "curl -H *** https://api.example/v1" {
		t.Errorf("redactArgv = %q, want only the header value redacted", got)
	}

	// A non-secret inline assignment keeps its value.
	if got, want := redactArgv([]string{"tool", "--fail-on=high", "scan", "."}), "tool --fail-on=high scan ."; got != want {
		t.Errorf("redactArgv = %q, want %q", got, want)
	}
}

func TestScrubQuotedScalars(t *testing.T) {
	cases := []struct{ message, want string }{
		{`time: invalid duration "sk-duration-secret"`, `time: invalid duration "***"`},
		{
			"yaml: unmarshal errors:\n  line 3: cannot unmarshal !!str `sk-yaml-secret` into int",
			"yaml: unmarshal errors:\n  line 3: cannot unmarshal !!str `***` into int",
		},
		{`time: invalid duration "sk-\"quoted"`, `time: invalid duration "***"`},
		{`no quotes here`, `no quotes here`},
		{`empty "" quotes`, `empty "" quotes`},
		{`unterminated "value`, `unterminated "value`},
	}
	for _, tc := range cases {
		if got := scrubQuotedScalars(tc.message); got != tc.want {
			t.Errorf("scrubQuotedScalars(%q) = %q, want %q", tc.message, got, tc.want)
		}
	}
}

func TestEntriesDeterministic(t *testing.T) {
	cfg := Defaults()
	cfg.Scan.Exclude = []string{"b/**", "a/**"}
	cfg.CommandEnv = map[string]string{"B": "2", "A": "1"}

	first := cfg.Entries()
	second := cfg.Entries()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Entries() is not deterministic")
	}
	if first[0].Key != "provider" {
		t.Fatalf("first entry = %q, want provider", first[0].Key)
	}
	if len(first) != len(Defaults().Entries()) {
		t.Fatalf("Entries() returned %d values, want a fixed set", len(first))
	}
	wantOrder := []string{"api_key", "max_tokens", "command_env", "scan.mode", "output.format"}
	index := make(map[string]int, len(first))
	for i, entry := range first {
		index[entry.Key] = i
	}
	for i := 1; i < len(wantOrder); i++ {
		if index[wantOrder[i-1]] >= index[wantOrder[i]] {
			t.Fatalf("%s must come before %s", wantOrder[i-1], wantOrder[i])
		}
	}
}
