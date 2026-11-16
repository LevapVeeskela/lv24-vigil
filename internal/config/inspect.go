package config

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// SourceDefaults marks a value that no config file or environment variable set.
const SourceDefaults = "defaults"

// Entry is one resolved configuration value and where it came from. Entries
// are emitted in a fixed order, so `vigil config show` is byte-stable.
type Entry struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
	// Secret is true when the value is a credential and has been replaced
	// with "***" (or left empty when unset).
	Secret bool `json:"secret"`
}

// secretKeyParts are the name fragments that mark a value as a credential.
var secretKeyParts = []string{
	"api_key", "api-key", "apikey", "token", "password", "passwd", "secret",
	"header", "credential", "authorization", "auth",
	"key", "jwt", "bearer", "session", "pass", "cookie",
}

// nonSecretKeys are configuration keys whose names contain a secret-looking
// fragment but which hold a public limit, not a credential.
var nonSecretKeys = map[string]bool{
	"max_tokens": true,
}

// SecretKey reports whether a key name looks like it carries a credential.
// It is deliberately conservative: a false positive hides a harmless value,
// while a false negative would print a secret.
func SecretKey(name string) bool {
	k := strings.ToLower(strings.TrimSpace(name))
	if k == "" || nonSecretKeys[k] {
		return false
	}
	for _, part := range secretKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// RedactValue hides the value of a secret-looking key. An unset value stays
// empty so "not configured" stays distinguishable from "configured".
func RedactValue(name, value string) string {
	if strings.TrimSpace(value) == "" || !SecretKey(name) {
		return value
	}
	return "***"
}

// Entries returns the effective configuration with the source of every value.
// A value absent from Sources comes from the built-in defaults. Secret values
// are always redacted; no model API key is ever returned.
func (c Config) Entries() []Entry {
	out := make([]Entry, 0, 40)

	sourceOf := func(key string) string {
		if source := strings.TrimSpace(c.Sources[key]); source != "" {
			return source
		}
		return SourceDefaults
	}
	add := func(key, value string, secret bool) {
		if secret {
			value = RedactValue(key, value)
		}
		out = append(out, Entry{Key: key, Value: value, Source: sourceOf(key), Secret: secret})
	}

	add("provider", c.Provider, false)
	add("model", c.Model, false)
	add("base_url", RedactURL(c.BaseURL), false)
	add("api_key", c.APIKey, true)
	add("max_tokens", strconv.Itoa(c.MaxTokens), false)
	add("temperature", strconv.FormatFloat(c.Temperature, 'g', -1, 64), false)
	add("timeout", c.Timeout.String(), false)
	add("max_steps", strconv.Itoa(c.MaxSteps), false)
	add("command", redactArgv(c.Command), false)
	add("command_prompt_mode", c.CommandPromptMode, false)
	add("command_output", c.CommandOutput, false)
	add("command_timeout", c.CommandTimeout.String(), false)
	add("command_max_output_bytes", strconv.Itoa(c.CommandMaxOutputBytes), false)

	// Every command environment value is treated as a credential, matching
	// the policy already applied to status output and reports.
	if len(c.CommandEnv) > 0 {
		names := make([]string, 0, len(c.CommandEnv))
		for name := range c.CommandEnv {
			names = append(names, name)
		}
		sort.Strings(names)
		pairs := make([]string, 0, len(names))
		for _, name := range names {
			pairs = append(pairs, name+"=***")
		}
		out = append(out, Entry{
			Key:    "command_env",
			Value:  strings.Join(pairs, ", "),
			Source: sourceOf("command_env"),
			Secret: true,
		})
	} else {
		add("command_env", "", true)
	}

	add("scan.mode", c.Scan.Mode, false)
	add("scan.min_severity", c.Scan.MinSeverity, false)
	add("scan.max_findings", strconv.Itoa(c.Scan.MaxFindings), false)
	add("scan.concurrency", strconv.Itoa(c.Scan.Concurrency), false)
	add("scan.exclude", strings.Join(c.Scan.Exclude, ", "), false)
	add("scan.include", strings.Join(c.Scan.Include, ", "), false)
	add("scan.disable_rules", strings.Join(c.Scan.DisableRules, ", "), false)
	add("scan.use_llm", useLLMValue(c.Scan.UseLLM), false)
	add("scan.deep_review", strconv.FormatBool(c.Scan.DeepReview), false)
	add("scan.max_file_bytes", strconv.FormatInt(c.Scan.MaxFileBytes, 10), false)
	add("scan.follow_symlinks", strconv.FormatBool(c.Scan.FollowLinks), false)
	add("scan.baseline", c.Scan.Baseline, false)
	add("scan.inline_suppressions", strconv.FormatBool(c.Scan.InlineSuppressions), false)
	add("scan.osv", strconv.FormatBool(c.Scan.OSV), false)
	add("scan.osv_base_url", RedactURL(c.Scan.OSVBaseURL), false)

	add("output.format", c.Output.Format, false)
	add("output.path", c.Output.Path, false)
	add("output.color", c.Output.Color, false)
	add("output.show_fix", strconv.FormatBool(c.Output.ShowFix), false)

	return out
}

// canonicalSourceKeys maps the names the VIGIL_* helpers derive from the
// environment variable to the keys config files use. Without this, a value
// overridden by the environment would report the source of the file it
// replaced, which is the opposite of the effective precedence.
var canonicalSourceKeys = map[string]string{
	"mode":         "scan.mode",
	"min_severity": "scan.min_severity",
	"osv_base_url": "scan.osv_base_url",
	"max_findings": "scan.max_findings",
	"concurrency":  "scan.concurrency",
	"format":       "output.format",
}

// recordCanonicalSourceKeys copies an environment source to the canonical
// key. The short key is kept for callers that already read it.
func recordCanonicalSourceKeys(sources map[string]string) {
	for short, key := range canonicalSourceKeys {
		if source := strings.TrimSpace(sources[short]); source != "" {
			sources[key] = source
		}
	}
}

// useLLMValue reports the configured tri-state: nil means "follow whether a
// provider is configured".
func useLLMValue(v *bool) string {
	if v == nil {
		return "auto"
	}
	return strconv.FormatBool(*v)
}

// argvSecretValueFlags are the flags whose next argument is a credential value.
// Only these (plus any other flag whose *name* says it carries a secret) consume
// the following element, so a header line, a path or a URL is never mistaken
// for a flag or silently blanked.
var argvSecretValueFlags = map[string]bool{
	"-u": true, "--user": true,
	"-H": true, "--header": true,
	"-p": true, "--password": true, "--passwd": true, "--pwd": true,
	"--token": true, "--access-token": true,
	"--api-key": true, "--apikey": true, "--secret": true, "--credential": true,
}

// isArgvFlag reports whether s is a flag rather than a value. A lone "-" is the
// conventional stdin/stdout marker, not a flag.
func isArgvFlag(s string) bool {
	return len(s) > 1 && s[0] == '-'
}

// argvFlagTakesSecretValue reports whether a flag's value is a credential.
func argvFlagTakesSecretValue(flag string) bool {
	if !isArgvFlag(flag) {
		return false
	}
	if argvSecretValueFlags[flag] {
		return true
	}
	// Tool-specific flags such as --github-token are not in the table, so a
	// secret-looking name still counts as a value-taking flag.
	return SecretKey(strings.TrimLeft(flag, "-"))
}

// splitArgvAssignment splits the name=value form. A header value such as
// "Authorization: Bearer abc==" contains a space or a colon on the left, so it
// is an opaque argument, never an assignment.
func splitArgvAssignment(arg string) (name, value string, ok bool) {
	name, value, ok = strings.Cut(arg, "=")
	if !ok || name == "" || strings.ContainsAny(name, " \t:") {
		return "", "", false
	}
	return name, value, true
}

// attachedShortValue hides a credential attached to a curl-style short flag,
// such as -uuser:pw or -HAuthorization:Bearer+x. Ordinary arguments are left
// alone, and a bare -u/-H/-p is handled by the separate-argument form.
func attachedShortValue(arg string) (string, bool) {
	if len(arg) < 3 || arg[0] != '-' || arg[1] == '-' {
		return "", false
	}
	switch arg[1] {
	case 'u', 'H', 'p':
		return arg[:2] + "***", true
	default:
		return "", false
	}
}

// redactArgv joins an executable and its arguments, hiding credential values
// such as `-u user:pw`, `-H 'Authorization: Bearer ...'`, `--token VALUE`,
// `--api-key=VALUE` and userinfo inside a URL, so a printed command line never
// leaks a key. Flag names and ordinary arguments are kept.
func redactArgv(argv []string) string {
	out, _ := redactArgvParts(argv)
	return strings.Join(out, " ")
}

// ArgvSecretValues returns the argument values redactArgv hides. A caller that
// echoes the output of the command (its stderr, for example) uses them to mask
// the same credentials there, because a failing tool often prints its own
// command line.
func ArgvSecretValues(argv []string) []string {
	_, hidden := redactArgvParts(argv)
	return hidden
}

// redactArgvParts returns the printable form of every argument and the
// credential values that were hidden while producing it.
func redactArgvParts(argv []string) (out, hidden []string) {
	out = make([]string, len(argv))
	redactNext := false
	for i, arg := range argv {
		if redactNext {
			out[i] = "***"
			hidden = append(hidden, arg)
			redactNext = false
			continue
		}
		if name, value, ok := splitArgvAssignment(arg); ok && strings.TrimSpace(value) != "" {
			// The inline form keeps the flag or variable name and hides the
			// value. A project path such as scan.exclude=*.go is not secret.
			if argvFlagTakesSecretValue(name) || SecretKey(strings.TrimLeft(name, "-")) {
				out[i] = name + "=***"
				hidden = append(hidden, value)
				continue
			}
		}
		if attached, ok := attachedShortValue(arg); ok {
			out[i] = attached
			hidden = append(hidden, arg[2:])
			continue
		}
		out[i] = redactArgvURL(arg)
		if out[i] != arg {
			hidden = append(hidden, urlCredentialValues(arg)...)
		}
		if argvFlagTakesSecretValue(arg) && i+1 < len(argv) {
			redactNext = true
		}
	}
	return out, hidden
}

// redactArgvURL hides the credentials of an argument that is a URL: userinfo,
// credential query parameters and the fragment. Anything else only has URL
// userinfo masked, so free text is never rewritten.
func redactArgvURL(arg string) string {
	if strings.ContainsAny(arg, " \t") || !strings.Contains(arg, "://") {
		return redactURLUserinfo(arg)
	}
	return RedactURL(arg)
}

// urlCredentialValues lists the userinfo password and the credential query
// values of a URL argument.
func urlCredentialValues(arg string) []string {
	u, err := url.Parse(arg)
	if err != nil {
		return nil
	}
	var values []string
	if u.User != nil {
		if password, ok := u.User.Password(); ok && password != "" {
			values = append(values, password)
		}
	}
	if q, err := url.ParseQuery(u.RawQuery); err == nil {
		for key, vals := range q {
			if looksSecretQueryKey(key) {
				values = append(values, vals...)
			}
		}
	}
	return values
}
