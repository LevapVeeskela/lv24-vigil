package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type configValidateJSON struct {
	OK    bool         `json:"ok"`
	Files []string     `json:"files"`
	Error *configIssue `json:"error"`
}

type configShowJSON struct {
	Files   []string `json:"files"`
	Entries []struct {
		Key    string `json:"key"`
		Value  string `json:"value"`
		Source string `json:"source"`
		Secret bool   `json:"secret"`
	} `json:"entries"`
}

func decodeConfigShow(t *testing.T, out string) configShowJSON {
	t.Helper()
	var report configShowJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("config show --json is not valid JSON: %v\n%s", err, out)
	}
	return report
}

func configShowEntry(t *testing.T, report configShowJSON, key string) (string, string, bool) {
	t.Helper()
	for _, entry := range report.Entries {
		if entry.Key == key {
			return entry.Value, entry.Source, entry.Secret
		}
	}
	t.Fatalf("config show is missing %q", key)
	return "", "", false
}

func TestConfigValidateOK(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, ".vigil.yaml", "scan:\n  mode: quick\n")

	out, stderr, err := runCLI(t, "config", "validate")

	if err != nil {
		t.Fatalf("config validate: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(out, "config OK") {
		t.Errorf("output missing config OK:\n%s", out)
	}
	if !strings.Contains(out, ".vigil.yaml") {
		t.Errorf("output does not name the resolved project file:\n%s", out)
	}

	// The optional path selects the project root, exactly like a scan path.
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("create sub: %v", err)
	}
	writeTestFile(t, dir, filepath.Join("sub", ".vigil.yaml"), "scan:\n  mode: deep\n")
	subOut, _, subErr := runCLI(t, "config", "validate", "sub", "--json")
	if subErr != nil {
		t.Fatalf("config validate sub: %v", subErr)
	}
	var subReport configValidateJSON
	if jerr := json.Unmarshal([]byte(subOut), &subReport); jerr != nil {
		t.Fatalf("not valid JSON: %v\n%s", jerr, subOut)
	}
	if !subReport.OK || len(subReport.Files) != 1 || !strings.HasSuffix(subReport.Files[0], filepath.Join("sub", ".vigil.yaml")) {
		t.Errorf("sub report = %+v, want the subproject config", subReport)
	}
}

func TestConfigValidateJSONShape(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, ".vigil.yaml", "scan:\n  mode: quick\n")

	out, _, err := runCLI(t, "config", "validate", ".", "--json")
	if err != nil {
		t.Fatalf("config validate --json: %v", err)
	}
	var report configValidateJSON
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
		t.Fatalf("not valid JSON: %v\n%s", jerr, out)
	}
	if !report.OK {
		t.Error("ok = false, want true")
	}
	if report.Error != nil {
		t.Errorf("error = %+v, want null", report.Error)
	}
	if len(report.Files) != 1 || filepath.Base(report.Files[0]) != ".vigil.yaml" {
		t.Errorf("files = %v, want the project config", report.Files)
	}

	// error must be present as null, not omitted, so consumers can rely on it.
	var raw map[string]json.RawMessage
	if jerr := json.Unmarshal([]byte(out), &raw); jerr != nil {
		t.Fatal(jerr)
	}
	if value, ok := raw["error"]; !ok || string(value) != "null" {
		t.Errorf("error = %s (present=%v), want null", value, ok)
	}
	if _, ok := raw["ok"]; !ok {
		t.Error("JSON is missing ok")
	}
	if _, ok := raw["files"]; !ok {
		t.Error("JSON is missing files")
	}
}

func TestConfigValidateBrokenYAML(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, ".vigil.yaml", "scan: [unclosed\n")

	out, _, err := runCLI(t, "config", "validate")
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("err = %v, want errConfigInvalid (non-zero exit)", err)
	}
	for _, want := range []string{"config error", "file", ".vigil.yaml", "message", "fix", "vigil config validate"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	jsonOut, _, jsonErr := runCLI(t, "config", "validate", "--json")
	if !errors.Is(jsonErr, errConfigInvalid) {
		t.Fatalf("json err = %v", jsonErr)
	}
	var report configValidateJSON
	if jerr := json.Unmarshal([]byte(jsonOut), &report); jerr != nil {
		t.Fatalf("not valid JSON: %v\n%s", jerr, jsonOut)
	}
	if report.OK {
		t.Error("ok = true for a broken file")
	}
	if report.Error == nil {
		t.Fatal("error = null for a broken file")
	}
	if !strings.HasSuffix(report.Error.File, ".vigil.yaml") {
		t.Errorf("error.file = %q, want the project config", report.Error.File)
	}
	if report.Error.Message == "" || report.Error.Fix == "" {
		t.Errorf("error = %+v, want message and fix", report.Error)
	}
}

func TestConfigValidateRejectedKeyNeverPrintsValue(t *testing.T) {
	const secret = "sk-config-validate-must-never-print"
	dir := newTestRepo(t)
	writeTestFile(t, dir, ".vigil.yaml", "api_key: "+secret+"\n")

	out, _, err := runCLI(t, "config", "validate", "--json")
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("err = %v, want errConfigInvalid", err)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("config validate leaked the configured value:\n%s", out)
	}

	var report configValidateJSON
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
		t.Fatalf("not valid JSON: %v\n%s", jerr, out)
	}
	if report.OK || report.Error == nil {
		t.Fatalf("report = %+v, want ok=false with an error", report)
	}
	if report.Error.Key != "api_key" {
		t.Errorf("error.key = %q, want api_key", report.Error.Key)
	}
	if !strings.HasSuffix(report.Error.File, ".vigil.yaml") {
		t.Errorf("error.file = %q, want the project config", report.Error.File)
	}
	if !strings.Contains(report.Error.Fix, "VIGIL_API_KEY") {
		t.Errorf("fix does not name the replacement variable: %q", report.Error.Fix)
	}

	human, _, herr := runCLI(t, "config", "validate")
	if !errors.Is(herr, errConfigInvalid) {
		t.Fatalf("human err = %v", herr)
	}
	if strings.Contains(human, secret) {
		t.Fatalf("human output leaked the configured value:\n%s", human)
	}
	for _, want := range []string{"api_key", "file", "key", "message", "fix"} {
		if !strings.Contains(human, want) {
			t.Errorf("human output missing %q:\n%s", want, human)
		}
	}
}

func TestConfigValidateScrubsLoaderValues(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		secret string
		want   string
	}{
		{"duration", "timeout: sk-duration-secret\n", "sk-duration-secret", `invalid duration "***"`},
		{"command timeout", "command_timeout: sk-command-secret\n", "sk-command-secret", `invalid duration "***"`},
		// The YAML error truncates long values, so the secret is short enough
		// that an unscrubbed message would still print it in full.
		{"yaml unmarshal", "max_tokens: sk-yaml9\n", "sk-yaml9", "cannot unmarshal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := newTestRepo(t)
			writeTestFile(t, dir, ".vigil.yaml", tc.body)

			out, _, err := runCLI(t, "config", "validate", "--json")
			if !errors.Is(err, errConfigInvalid) {
				t.Fatalf("err = %v, want errConfigInvalid", err)
			}
			if strings.Contains(out, tc.secret) {
				t.Fatalf("config validate --json leaked the configured value:\n%s", out)
			}
			var report configValidateJSON
			if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
				t.Fatalf("not valid JSON: %v\n%s", jerr, out)
			}
			if report.OK || report.Error == nil {
				t.Fatalf("report = %+v, want ok=false with an error", report)
			}
			if !strings.HasSuffix(report.Error.File, ".vigil.yaml") {
				t.Errorf("error.file = %q, want the project config", report.Error.File)
			}
			if !strings.Contains(report.Error.Message, tc.want) {
				t.Errorf("error.message = %q, want it to contain %q", report.Error.Message, tc.want)
			}
			if report.Error.Fix == "" {
				t.Error("error.fix is empty")
			}

			human, _, herr := runCLI(t, "config", "validate")
			if !errors.Is(herr, errConfigInvalid) {
				t.Fatalf("human err = %v", herr)
			}
			if strings.Contains(human, tc.secret) {
				t.Fatalf("config validate leaked the configured value:\n%s", human)
			}
			for _, want := range []string{"config error", "message", "fix"} {
				if !strings.Contains(human, want) {
					t.Errorf("human output missing %q:\n%s", want, human)
				}
			}
		})
	}
}

func TestConfigShowRedactsURLSecrets(t *testing.T) {
	dir := newTestRepo(t)
	user := filepath.Join(dir, "user-config.yaml")
	writeTestFile(t, dir, "user-config.yaml", `provider: openai
model: gpt-test
api_key: sk-show-url-secret
base_url: https://user:hunter2@llm.example/v1?password=hunter2&model=gpt-4#access_token=frag-secret
`)
	t.Setenv("VIGIL_CONFIG", user)

	out, stderr, err := runCLI(t, "config", "show", "--json")
	if err != nil {
		t.Fatalf("config show --json: %v\nstderr:\n%s", err, stderr)
	}
	for _, leaked := range []string{"hunter2", "frag-secret", "sk-show-url-secret"} {
		if strings.Contains(out, leaked) {
			t.Errorf("config show leaked %q:\n%s", leaked, out)
		}
	}

	report := decodeConfigShow(t, out)
	baseURL, _, _ := configShowEntry(t, report, "base_url")
	if !strings.Contains(baseURL, "llm.example/v1") {
		t.Errorf("base_url = %q, want the endpoint kept", baseURL)
	}
	if !strings.Contains(baseURL, "password=REDACTED") || !strings.Contains(baseURL, "model=gpt-4") {
		t.Errorf("base_url = %q, want only the password redacted", baseURL)
	}
	if strings.Contains(baseURL, "#") {
		t.Errorf("base_url kept the fragment: %q", baseURL)
	}
}

func TestScanRejectsJUnitFormat(t *testing.T) {
	newTestRepo(t)

	_, _, err := runCLI(t, "scan", ".", "--format", "junit")
	if err == nil {
		t.Fatal("scan --format junit was accepted")
	}
	for _, want := range []string{"JUnit is report-only", "vigil report --format junit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("scan --format junit error = %v, want %q", err, want)
		}
	}
}

func TestConfigShowRedactsSecrets(t *testing.T) {
	dir := newTestRepo(t)
	user := filepath.Join(dir, "user-config.yaml")
	writeTestFile(t, dir, "user-config.yaml", `provider: openai
model: gpt-test
api_key: sk-show-secret-value
base_url: https://user:pw@llm.example/v1?token=hidden
command_env:
  GITHUB_TOKEN: ghp_show_secret
`)
	t.Setenv("VIGIL_CONFIG", user)
	writeTestFile(t, dir, ".vigil.yaml", "scan:\n  mode: quick\n")

	out, stderr, err := runCLI(t, "config", "show")
	if err != nil {
		t.Fatalf("config show: %v\nstderr:\n%s", err, stderr)
	}
	for _, leaked := range []string{"sk-show-secret-value", "user:pw", "token=hidden", "ghp_show_secret"} {
		if strings.Contains(out, leaked) {
			t.Errorf("config show leaked %q:\n%s", leaked, out)
		}
	}
	for _, want := range []string{"api_key", "***", "scan.mode", "defaults", ".vigil.yaml", "user-config.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("config show missing %q:\n%s", want, out)
		}
	}

	jsonOut, _, jsonErr := runCLI(t, "config", "show", "--json")
	if jsonErr != nil {
		t.Fatalf("config show --json: %v", jsonErr)
	}
	report := decodeConfigShow(t, jsonOut)
	keyValue, keySource, keySecret := configShowEntry(t, report, "api_key")
	if keyValue != "***" || !keySecret {
		t.Errorf("api_key = %q (secret=%v), want a redacted secret", keyValue, keySecret)
	}
	if !strings.HasSuffix(keySource, "user-config.yaml") {
		t.Errorf("api_key source = %q, want the user config", keySource)
	}
	baseURL, _, _ := configShowEntry(t, report, "base_url")
	if !strings.Contains(baseURL, "llm.example") || strings.Contains(baseURL, "pw@") || strings.Contains(baseURL, "hidden") {
		t.Errorf("base_url = %q, want the host with credentials redacted", baseURL)
	}
	env, _, envSecret := configShowEntry(t, report, "command_env")
	if env != "GITHUB_TOKEN=***" || !envSecret {
		t.Errorf("command_env = %q (secret=%v)", env, envSecret)
	}
	if strings.Contains(jsonOut, "sk-show-secret-value") || strings.Contains(jsonOut, "ghp_show_secret") {
		t.Errorf("config show --json leaked a secret:\n%s", jsonOut)
	}
}

func TestConfigShowPrecedence(t *testing.T) {
	dir := newTestRepo(t)
	user := filepath.Join(dir, "user-config.yaml")
	writeTestFile(t, dir, "user-config.yaml", "output:\n  format: json\n  color: never\n")
	t.Setenv("VIGIL_CONFIG", user)
	writeTestFile(t, dir, ".vigil.yaml", "output:\n  format: sarif\nscan:\n  mode: quick\n")
	t.Setenv("VIGIL_FORMAT", "html")

	out, _, err := runCLI(t, "config", "show", "--json")
	if err != nil {
		t.Fatalf("config show --json: %v", err)
	}
	report := decodeConfigShow(t, out)

	format, source, _ := configShowEntry(t, report, "output.format")
	if format != "html" || source != "env:VIGIL_FORMAT" {
		t.Errorf("output.format = %q from %q, want env:VIGIL_FORMAT to win", format, source)
	}
	color, colorSource, _ := configShowEntry(t, report, "output.color")
	if color != "never" || !strings.HasSuffix(colorSource, "user-config.yaml") {
		t.Errorf("output.color = %q from %q, want the user config", color, colorSource)
	}
	mode, modeSource, _ := configShowEntry(t, report, "scan.mode")
	if mode != "quick" || !strings.HasSuffix(modeSource, ".vigil.yaml") {
		t.Errorf("scan.mode = %q from %q, want the project config", mode, modeSource)
	}
	findings, findingsSource, _ := configShowEntry(t, report, "scan.max_findings")
	if findings != "200" || findingsSource != "defaults" {
		t.Errorf("scan.max_findings = %q from %q, want the default", findings, findingsSource)
	}

	if len(report.Files) != 2 {
		t.Fatalf("files = %v, want user and project config", report.Files)
	}
	if !strings.HasSuffix(report.Files[0], "user-config.yaml") || !strings.HasSuffix(report.Files[1], ".vigil.yaml") {
		t.Errorf("files are not in precedence order: %v", report.Files)
	}
}

func TestConfigShowRefusesInvalidConfig(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, ".vigil.yaml", "scan: [unclosed\n")

	out, _, err := runCLI(t, "config", "show")
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("err = %v, want errConfigInvalid", err)
	}
	if !strings.Contains(out, "config error") || !strings.Contains(out, ".vigil.yaml") {
		t.Errorf("output does not explain the failure:\n%s", out)
	}

	jsonOut, _, jsonErr := runCLI(t, "config", "show", "--json")
	if !errors.Is(jsonErr, errConfigInvalid) {
		t.Fatalf("json err = %v, want errConfigInvalid", jsonErr)
	}
	var report struct {
		Entries []json.RawMessage `json:"entries"`
		Error   *configIssue      `json:"error"`
	}
	if jerr := json.Unmarshal([]byte(jsonOut), &report); jerr != nil {
		t.Fatalf("config show --json is not valid JSON: %v\n%s", jerr, jsonOut)
	}
	if report.Error == nil || !strings.HasSuffix(report.Error.File, ".vigil.yaml") {
		t.Errorf("error = %+v, want the project config", report.Error)
	}
	if len(report.Entries) != 0 {
		t.Errorf("entries = %d, want none for an invalid config", len(report.Entries))
	}
}

func TestConfigHelpIsDispatched(t *testing.T) {
	out, _, err := runCLI(t, "config", "help")
	if err != nil {
		t.Fatalf("config help: %v", err)
	}
	for _, want := range []string{"vigil config <command>", "validate", "show"} {
		if !strings.Contains(out, want) {
			t.Errorf("config help missing %q:\n%s", want, out)
		}
	}

	help, _, err := runCLI(t, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(help, "vigil config validate") || !strings.Contains(help, "vigil config show") {
		t.Errorf("top-level help does not list config:\n%s", help)
	}
}

func TestConfigFileFromMessage(t *testing.T) {
	cases := []struct {
		message string
		want    string
	}{
		{`parse config C:\repo\.vigil.yaml: yaml: line 2: bad`, `C:\repo\.vigil.yaml`},
		{`stat config C:\repo\.vigil.yaml: permission denied`, `C:\repo\.vigil.yaml`},
		{`config C:\repo\.vigil.yaml is not a regular file`, `C:\repo\.vigil.yaml`},
		{`config C:\repo\.vigil.yaml is larger than 1048576 bytes`, `C:\repo\.vigil.yaml`},
		{`yaml: line 1: did not find expected node content`, ""},
	}
	for _, tc := range cases {
		if got := configFileFromMessage(tc.message); got != tc.want {
			t.Errorf("configFileFromMessage(%q) = %q, want %q", tc.message, got, tc.want)
		}
	}
}

func TestConfigSubcommandErrors(t *testing.T) {
	newTestRepo(t)

	if _, _, err := runCLI(t, "config"); err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("bare config err = %v", err)
	}
	if _, _, err := runCLI(t, "config", "frobnicate"); err == nil || !strings.Contains(err.Error(), "unknown config subcommand") {
		t.Fatalf("unknown subcommand err = %v", err)
	}
	if _, _, err := runCLI(t, "config", "show", "extra"); err == nil || !strings.Contains(err.Error(), "takes no arguments") {
		t.Fatalf("show with an argument err = %v", err)
	}
	if _, _, err := runCLI(t, "config", "validate", "a", "b"); err == nil || !strings.Contains(err.Error(), "at most one path") {
		t.Fatalf("validate with two paths err = %v", err)
	}
}
