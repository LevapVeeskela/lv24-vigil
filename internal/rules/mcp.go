package rules

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// MCP configuration rules. Everything here is bounded line or JSON-adjacent
// matching: no config is parsed into a DOM, no referenced process is started
// and no network endpoint is contacted. The rules only reason about the text
// of a config file that the scanner already classified as an MCP config.

var (
	mcpCommandKeyRe     = regexp.MustCompile(`(?i)["']?command["']?\s*:`)
	mcpEnvKeyRe         = regexp.MustCompile(`(?i)["']?(?:env|environment|headers)["']?\s*:`)
	mcpServerKeyRe      = regexp.MustCompile(`^\s*["'][^"']+["']\s*:\s*\{`)
	mcpOpenCodeKeyRe    = regexp.MustCompile(`(?i)["']mcp["']\s*:`)
	mcpDescriptionKeyRe = regexp.MustCompile(`(?i)["']?(?:description|tool_?description)["']?\s*:`)
	mcpAutoApproveKeyRe = regexp.MustCompile(`(?i)["']?(?:auto[-_]?approve(?:d)?|always[-_]?allow(?:ed)?|auto[-_]?approval)["']?\s*:`)
	mcpImageKeyRe       = regexp.MustCompile(`(?i)(?:["']image["']\s*:|^\s*-?\s*image\s*:)\s*["']?([^"'\s,#{}\[\]]+)["']?`)
	mcpURLKeyRe         = regexp.MustCompile(`(?i)["']?(?:url|uri|endpoint|server_?url|base_?url)["']?\s*[:=]\s*["']?(https?://[^"'\s,}\]]+)`)
	mcpTLSDisableRe     = regexp.MustCompile(`(?i)(?:NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY|GIT_SSL_NO_VERIFY)\s*["']?\s*[:=]\s*["']?(?:0|false)\b|\bverify(?:_ssl|_tls|_peer)?\s*["']?\s*[:=]\s*["']?(?:false|0|no)\b|\brejectUnauthorized\s*["']?\s*[:=]\s*["']?false\b`)
	mcpWindowsHomeRe    = regexp.MustCompile(`(?i)^[a-z]:[\\/]users[\\/][^\\/]+[\\/]?$`)
	mcpPercentVarRe     = regexp.MustCompile(`%[A-Za-z_][A-Za-z0-9_]*%`)

	// One token is either a double-quoted string or a run of JSON/YAML
	// punctuation-free text. Quoted strings keep colons, so volume specs and
	// URLs survive tokenisation.
	mcpTokenRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,\[\]{}"']+`)

	mcpSecretKVRe = regexp.MustCompile(`(?i)["']?([A-Za-z0-9_.-]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTHORIZATION|COOKIE|AUTH)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*(?:["']([^"']{8,200})["']|([A-Za-z0-9+/=_.,\-]{8,200}))`)
	mcpSecretEnRe = regexp.MustCompile(`(?i)["']([A-Za-z0-9_.-]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTHORIZATION|COOKIE|AUTH)[A-Za-z0-9_.-]*)=([^"'=\s]{8,200})["']`)
	mcpSecretArRe = regexp.MustCompile(`(?i)["'](--?[A-Za-z0-9-]*(?:token|key|secret|passw(?:or)?d|credential)[A-Za-z0-9-]*)["']?\s*[,:=]\s*["']([^"']{8,200})["']`)
	// A scheme-prefixed credential ("Authorization: Bearer <token>") needs no
	// credential-looking key next to it, so it is masked wherever it occurs.
	// The token class excludes quotes, commas and closing braces so a JSON
	// value keeps its structure when the mask is written back.
	mcpAuthSchemeRe = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+([^\s"',}\]]{12,})`)

	mcpCurlPipeShellRe = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`)
)

const mcpRemediationPin = "Pin the package to an exact version (or a digest where the registry supports one) and review updates before bumping it. An unpinned MCP server is code from a mutable tag that runs with your local privileges."

// MCPRules returns the MCP server configuration rules.
func MCPRules() []Rule {
	return []Rule{
		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-001",
			Title:       "MCP server package is installed without a pinned version",
			Description: "npx or uvx resolves an unpinned package name at startup, so the server that ran yesterday may be a different, compromised release today. Pin an exact version or digest in the MCP configuration.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-1357"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"mcp", "supply-chain", "dependency"},
			References: []string{
				"https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
				"https://cwe.mitre.org/data/definitions/1357.html",
			},
		}, mcpUnpinnedServerPackage),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-002",
			Title:       "Literal secret in MCP environment, argument or header",
			Description: "A credential-looking key is assigned a high-entropy literal in an MCP server definition. The value is stored in a config file that is often committed or synced, and every process the server spawns inherits it. Use an environment reference, a secret store or the OS keychain instead.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-798"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"mcp", "secret", "credential"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/798.html",
				"https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
			},
		}, mcpLiteralSecret),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-003",
			Title:       "MCP container escapes its isolation boundary",
			Description: "The MCP server starts a container with the Docker socket, --privileged or a host root volume. Any of these gives the server, and anything that can prompt it, control over the host rather than a sandbox. Drop the mount and capability, or run the server as an unprivileged process.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"mcp", "container", "docker"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/250.html",
				"https://docs.docker.com/engine/security/",
			},
		}, mcpContainerEscape),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-004",
			Title:       "Remote MCP endpoint uses plaintext HTTP",
			Description: "An MCP endpoint outside loopback is configured with http://, so tool calls and their results cross the network in cleartext and can be read or modified by anyone on the path. Use https:// or a local transport.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-319"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"mcp", "transport", "tls"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/319.html",
				"https://modelcontextprotocol.io/specification/2025-06-18/basic/transports",
			},
		}, mcpPlaintextEndpoint),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-005",
			Title:       "MCP filesystem server is rooted at the whole disk or home directory",
			Description: "A filesystem MCP server given /, a drive root or the user's home can read and overwrite every file that user can reach, including SSH keys and cloud credentials. Point it at the project directory or another narrow allow-listed root.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-732"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"mcp", "filesystem", "least-privilege"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/732.html",
				"https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
			},
		}, mcpFilesystemRoot),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-006",
			Title:       "MCP auto-approve list allows every tool",
			Description: "A wildcard in autoApprove or alwaysAllow lets the model call any tool the MCP server exposes without confirmation, including destructive or exfiltrating tools added by an update. Name the tools that are safe to run unattended.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-284"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"mcp", "permissions", "approval"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/284.html",
				"https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
			},
		}, mcpAutoApproveWildcard),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-007",
			Title:       "Tool description contains prompt-injection instructions",
			Description: "A tool or server description carries instructions aimed at the model rather than the user: ignoring earlier instructions, hiding actions, reading SSH keys or piping a download into a shell. Descriptions are untrusted input and can steer the agent even when the user never asked for that tool.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-1427"},
			OWASP:       []string{"LLM01:2025"},
			Tags:        []string{"mcp", "prompt-injection", "llm"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/1427.html",
				"https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
			},
		}, mcpDescriptionInjection),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-008",
			Title:       "MCP container image is not pinned to a version",
			Description: "An MCP server image uses :latest or no tag, so a rebuild or restart can pull a different image with the same access to your tools and data. Pin a version tag or a digest.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"mcp", "container", "supply-chain"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/1104.html",
				"https://docs.docker.com/engine/security/",
			},
		}, mcpUnpinnedImage),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-009",
			Title:       "MCP configuration disables TLS certificate verification",
			Description: "NODE_TLS_REJECT_UNAUTHORIZED=0, --insecure or verify=false turns off certificate validation for the MCP server, so a machine-in-the-middle can impersonate the endpoint and read or alter tool traffic. Remove the override and trust the issuing CA instead.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"mcp", "tls", "transport"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/295.html",
				"https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue",
			},
		}, mcpTLSVerifyDisabled),

		mcpRule(model.RuleMeta{
			ID:          "VGL-MCP-010",
			Title:       "MCP server command runs a shell with interpolated arguments",
			Description: "The server is launched through sh -c, bash -c, cmd /c or powershell -Command and the command string expands variables. Arguments that reach that string can break out of it and execute arbitrary commands with the MCP server's privileges. Invoke the executable directly or pass fixed arguments.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"json", "yaml"},
			CWE:         []string{"CWE-78"},
			OWASP:       []string{"A03:2021"},
			Tags:        []string{"mcp", "shell", "injection"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/78.html",
				"https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
			},
		}, mcpShellInterpolation),
	}
}

// mcpRule builds a rule and stamps its references onto findings, because the
// generic finding defaults only carry CWE and OWASP.
func mcpRule(meta model.RuleMeta, fn func(*File) []model.Finding) Rule {
	refs := append([]string(nil), meta.References...)
	return New(meta, func(f *File) []model.Finding {
		out := fn(f)
		for i := range out {
			if len(out[i].References) == 0 && len(refs) > 0 {
				out[i].References = append([]string(nil), refs...)
			}
		}
		return out
	})
}

// mcpFinding builds a normal finding with a bounded single-line snippet.
func mcpFinding(f *File, line int, evidence string) model.Finding {
	if line < 1 {
		line = 1
	}
	return model.Finding{
		Location: model.Location{
			Path:      f.Path,
			StartLine: line,
			EndLine:   line,
			Snippet:   mcpRedactSecrets(strings.TrimSpace(f.Line(line))),
		},
		Evidence: Truncate(mcpRedactSecrets(strings.TrimSpace(evidence)), 240),
	}
}

// mcpRedactSecrets masks literal credentials in bounded MCP config text. The
// shared hard redactor knows provider token shapes only; an MCP env, header or
// argument map can assign any credential-looking key, and a compact one-line
// config would otherwise copy that value verbatim into a snippet or evidence.
func mcpRedactSecrets(text string) string {
	if text == "" {
		return text
	}
	text = secHardRedactor.ReplaceAllStringFunc(text, MaskSecret)
	text = mcpMaskSecretMatches(text, mcpSecretKVRe, 2, 3)
	text = mcpMaskSecretMatches(text, mcpSecretEnRe, 2)
	text = mcpMaskSecretMatches(text, mcpSecretArRe, 2)
	return mcpMaskSecretMatches(text, mcpAuthSchemeRe, 1)
}

// mcpMaskSecretMatches replaces the captured value groups of re with a masked
// form. Groups are 1-based; the first non-empty group that holds a literal is
// kept and the rest of that match is left untouched.
func mcpMaskSecretMatches(text string, re *regexp.Regexp, groups ...int) string {
	matches := re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		for _, g := range groups {
			if 2*g+1 >= len(m) || m[2*g] < 0 || m[2*g+1] <= m[2*g] {
				continue
			}
			value := text[m[2*g]:m[2*g+1]]
			if !mcpSecretNeedsMask(value) {
				continue
			}
			b.WriteString(text[last:m[2*g]])
			b.WriteString(MaskSecret(value))
			last = m[2*g+1]
			break
		}
	}
	if last == 0 {
		return text
	}
	b.WriteString(text[last:])
	return b.String()
}

// mcpSecretNeedsMask reports whether a matched value is a literal credential
// rather than a placeholder or an indirection the config resolves at runtime.
func mcpSecretNeedsMask(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || LooksLikePlaceholder(v) {
		return false
	}
	if strings.Contains(v, "${") || strings.Contains(v, "{{") || strings.Contains(v, "$(") {
		return false
	}
	if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "%") || strings.HasPrefix(v, "<") {
		return false
	}
	lv := strings.ToLower(v)
	for _, prefix := range []string{"env:", "secret:", "vault:", "file:", "ref:", "op://"} {
		if strings.HasPrefix(lv, prefix) {
			return false
		}
	}
	// A URL without userinfo is an endpoint reference, not a credential.
	if strings.Contains(v, "://") && !strings.Contains(v, "@") {
		return false
	}
	return true
}

// mcpScopeLines returns the lines the rules may inspect. For ordinary MCP
// configs that is the whole file; for opencode.json only the "mcp" object is
// copied and every other byte is blanked, so a token or URL elsewhere in the
// editor config cannot produce an MCP finding.
func mcpScopeLines(f *File) []string {
	if !mcpConfigFile(f) {
		return nil
	}
	var lines []string
	if mcpOpenCodeName(pbBaseLower(f.Path)) {
		lines = mcpOpenCodeScope(f.Lines)
	} else {
		lines = append([]string(nil), f.Lines...)
	}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") {
			lines[i] = ""
		}
	}
	return lines
}

// mcpConfigFile reports whether f is a supported MCP configuration. Docs, test
// fixtures and examples are excluded: they describe configs, they do not load
// them.
func mcpConfigFile(f *File) bool {
	if f == nil {
		return false
	}
	p := strings.ToLower(strings.ReplaceAll(f.Path, "\\", "/"))
	if p == "" || isDocsPath(p) || isTestPath(p) {
		return false
	}
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	if !mcpConfigBase(base) && !strings.Contains(p, "/.config/mcp/") && !strings.HasPrefix(p, ".config/mcp/") {
		return false
	}
	lang := strings.ToLower(strings.TrimSpace(f.Language))
	if lang == "" || lang == "other" {
		switch {
		case strings.HasSuffix(base, ".json"), strings.HasSuffix(base, ".jsonc"):
			lang = "json"
		case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"):
			lang = "yaml"
		}
	}
	return lang == "json" || lang == "yaml"
}

// MCPConfigFile reports whether f is a configuration file the VGL-MCP rules
// inspect. Callers that count or display scanned configs use it, so a
// documentation, fixture or example file is never reported as scanned.
func MCPConfigFile(f *File) bool {
	return mcpConfigFile(f)
}

func mcpConfigBase(base string) bool {
	switch base {
	case ".mcp.json", "mcp.json", "mcp-config.json", "claude_desktop_config.json",
		"opencode.json", "opencode.jsonc",
		"mcp.yaml", "mcp.yml", "mcp-config.yaml", "mcp-config.yml":
		return true
	}
	for _, suffix := range []string{".mcp.json", ".mcp.jsonc", ".mcp.yaml", ".mcp.yml"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// mcpOpenCodeName reports whether a base name is an opencode config. Both the
// JSON and JSONC variants carry the same top-level "mcp" object.
func mcpOpenCodeName(base string) bool {
	return base == "opencode.json" || base == "opencode.jsonc"
}

// mcpOpenCodeScope blanks everything except the top-level "mcp" object. The
// brace scan is bounded by the file and ignores braces inside strings and
// comments, so a nested configuration value cannot end the section early.
func mcpOpenCodeScope(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = strings.Repeat(" ", len(line))
	}
	startLine, startCol := mcpOpenCodeStart(lines)
	if startLine < 0 {
		return out
	}
	depth := 0
	inString, escaped := false, false
	lineComment, blockComment := false, false
	for li := startLine; li < len(lines); li++ {
		s := lines[li]
		from := 0
		if li == startLine {
			from = startCol
		}
		for ci := from; ci < len(s); ci++ {
			c := s[ci]
			if blockComment {
				if c == '*' && ci+1 < len(s) && s[ci+1] == '/' {
					blockComment = false
					ci++
				}
				continue
			}
			if lineComment {
				continue
			}
			if inString {
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					inString = false
				}
				continue
			}
			switch c {
			case '"':
				inString = true
			case '/':
				if ci+1 < len(s) {
					switch s[ci+1] {
					case '/':
						lineComment = true
						ci++
					case '*':
						blockComment = true
						ci++
					}
				}
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					mcpCopySpan(out, lines, startLine, startCol, li, ci+1)
					return out
				}
			}
		}
		lineComment = false
	}
	mcpCopySpan(out, lines, startLine, startCol, startLine, len(lines[startLine]))
	return out
}

// mcpOpenCodeStart locates the opening brace of the top-level mcp object. Only
// a key at brace depth 1 counts: a nested object that happens to be named mcp
// (a provider or plugin option) must not shadow the real server map.
func mcpOpenCodeStart(lines []string) (int, int) {
	depth := 0
	inString, escaped := false, false
	blockComment := false
	for li, line := range lines {
		lineComment := false
		for ci := 0; ci < len(line); ci++ {
			c := line[ci]
			if blockComment {
				if c == '*' && ci+1 < len(line) && line[ci+1] == '/' {
					blockComment = false
					ci++
				}
				continue
			}
			if lineComment {
				continue
			}
			if inString {
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					inString = false
				}
				continue
			}
			switch c {
			case '"':
				if depth == 1 {
					if col, ok := mcpOpenCodeValueBrace(lines, li, ci); ok {
						return li, col
					}
				}
				inString = true
			case '/':
				if ci+1 < len(line) {
					switch line[ci+1] {
					case '/':
						lineComment = true
						ci++
					case '*':
						blockComment = true
						ci++
					}
				}
			case '{':
				depth++
			case '}':
				if depth > 0 {
					depth--
				}
			}
		}
	}
	return -1, -1
}

// mcpOpenCodeValueBrace returns the column of the brace that opens the value of
// an mcp key starting at lines[li][ci], or false when that key does not start
// there or its value is not an object.
func mcpOpenCodeValueBrace(lines []string, li, ci int) (int, bool) {
	line := lines[li]
	loc := mcpOpenCodeKeyRe.FindStringIndex(line[ci:])
	if loc == nil || loc[0] != 0 {
		return 0, false
	}
	after := ci + loc[1]
	rest := strings.TrimSpace(line[after:])
	if strings.HasPrefix(rest, "{") {
		return after + strings.Index(line[after:], "{"), true
	}
	if rest != "" {
		// The mcp value is not an object; keep looking for the real one.
		return 0, false
	}
	for next := li + 1; next < len(lines) && next <= li+3; next++ {
		t := strings.TrimSpace(lines[next])
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "{") {
			return strings.Index(lines[next], "{"), true
		}
		break
	}
	return 0, false
}

func mcpCopySpan(out, lines []string, startLine, startCol, endLine, endCol int) {
	if startLine == endLine {
		if startCol > len(lines[startLine]) {
			return
		}
		if endCol > len(lines[startLine]) {
			endCol = len(lines[startLine])
		}
		out[startLine] = strings.Repeat(" ", startCol) +
			lines[startLine][startCol:endCol] +
			strings.Repeat(" ", len(lines[startLine])-endCol)
		return
	}
	if startCol <= len(lines[startLine]) {
		out[startLine] = strings.Repeat(" ", startCol) + lines[startLine][startCol:]
	}
	for i := startLine + 1; i < endLine; i++ {
		out[i] = lines[i]
	}
	if endLine >= 0 && endLine < len(lines) && endCol <= len(lines[endLine]) {
		out[endLine] = lines[endLine][:endCol] + strings.Repeat(" ", len(lines[endLine])-endCol)
	}
}

// mcpTokens tokenises a bounded text region. Splitting quoted strings on
// whitespace is deliberate: a config may hold "npx -y pkg" as one JSON string.
func mcpTokens(s string) []string {
	var out []string
	for _, raw := range mcpTokenRe.FindAllString(s, -1) {
		t := strings.TrimSpace(raw)
		if len(t) >= 2 && ((t[0] == '"' && t[len(t)-1] == '"') || (t[0] == '\'' && t[len(t)-1] == '\'')) {
			t = t[1 : len(t)-1]
		}
		t = strings.ReplaceAll(t, `\"`, `"`)
		t = strings.ReplaceAll(t, `\\`, `\`)
		if t == "" || t == ":" || t == "," || t == "=" {
			continue
		}
		out = append(out, strings.Fields(t)...)
	}
	return out
}

// mcpBlockTokens returns one token set per server definition found at line i.
// On a compact config line every balanced command object is scoped and returned
// separately, so a second server on the same line is checked instead of being
// hidden behind the first one. A line whose object does not close on the same
// line falls back to the bounded multi-line window as a single set.
func mcpBlockTokens(lines []string, i, maxLines int) [][]string {
	if i < 0 || i >= len(lines) {
		return nil
	}
	if scopes := mcpLineObjectScopes(lines[i]); len(scopes) > 0 {
		return scopes
	}
	return [][]string{mcpMultilineBlockTokens(lines, i, maxLines)}
}

// mcpMultilineBlockTokens collects the tokens of one server's command/args
// block. The scan is bounded and stops at the next command, environment/header
// map or sibling server definition.
func mcpMultilineBlockTokens(lines []string, i, maxLines int) []string {
	baseIndent := mcpIndent(lines[i])
	end := i + maxLines
	if end >= len(lines) {
		end = len(lines) - 1
	}
	var out []string
	for j := i; j <= end; j++ {
		line := lines[j]
		if j > i {
			t := strings.TrimSpace(line)
			if t == "" {
				continue
			}
			if mcpCommandKeyRe.MatchString(line) || mcpEnvKeyRe.MatchString(line) {
				break
			}
			if mcpServerKeyRe.MatchString(line) && mcpIndent(line) <= baseIndent {
				break
			}
		}
		out = append(out, mcpTokens(line)...)
	}
	return out
}

func mcpIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// mcpLineObjectScopes returns the tokens of every innermost JSON object that
// contains an mcp command key on a single line and closes on that line. Compact
// configs often place several servers on one line; without per-object scopes a
// flag from a sibling server would be attributed to the wrong command, and only
// the first server on the line would be inspected at all.
func mcpLineObjectScopes(line string) [][]string {
	var out [][]string
	for offset := 0; offset < len(line); {
		loc := mcpCommandKeyRe.FindStringIndex(line[offset:])
		if loc == nil {
			break
		}
		keyStart := offset + loc[0]
		keyEnd := offset + loc[1]
		open := mcpLineObjectOpen(line, keyStart)
		if open < 0 {
			offset = keyEnd
			continue
		}
		closePos := mcpMatchingBrace(line, open)
		if closePos < 0 {
			offset = keyEnd
			continue
		}
		out = append(out, mcpTokens(line[open:closePos+1]))
		next := closePos + 1
		if next <= offset {
			next = keyEnd
		}
		offset = next
	}
	return out
}

// mcpLineObjectOpen returns the index of the brace that opens the innermost
// object containing the command key at pos, or -1 when that object does not
// open on the line.
func mcpLineObjectOpen(line string, pos int) int {
	if pos > len(line) {
		pos = len(line)
	}
	for i := strings.LastIndexByte(line[:pos], '{'); i >= 0; i = strings.LastIndexByte(line[:i], '{') {
		if mcpBraceDepth(line[i:pos]) == 1 {
			return i
		}
	}
	return -1
}

// mcpBraceDepth counts braces outside double-quoted strings in s.
func mcpBraceDepth(s string) int {
	depth := 0
	inString, escaped := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth
}

// mcpMatchingBrace returns the index of the brace that closes open, or -1.
func mcpMatchingBrace(line string, open int) int {
	depth := 0
	inString, escaped := false, false
	for i := open; i < len(line); i++ {
		c := line[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func mcpHasToken(tokens []string, want ...string) bool {
	for _, tok := range tokens {
		lt := strings.ToLower(strings.Trim(tok, `"'`))
		for _, w := range want {
			if lt == w {
				return true
			}
		}
	}
	return false
}

func mcpAnyTokenContains(tokens []string, sub string) bool {
	sub = strings.ToLower(sub)
	for _, tok := range tokens {
		if strings.Contains(strings.ToLower(tok), sub) {
			return true
		}
	}
	return false
}

// mcpUnpinnedServerPackage implements VGL-MCP-001.
func mcpUnpinnedServerPackage(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	seen := map[string]bool{}
	for i, line := range lines {
		if !mcpCommandKeyRe.MatchString(line) {
			continue
		}
		for _, scope := range mcpBlockTokens(lines, i, 12) {
			for k, tok := range scope {
				if !mcpRunnerToken(tok) {
					continue
				}
				pkg := mcpNextPackageToken(scope[k+1:])
				if pkg == "" || mcpPackagePinned(pkg) {
					continue
				}
				key := fmt.Sprintf("%d/%s", i+1, pkg)
				if seen[key] {
					continue
				}
				seen[key] = true
				fd := mcpFinding(f, i+1, line)
				fd.Confidence = model.ConfidenceHigh
				fd.Remediation = mcpRemediationPin
				out = append(out, fd)
			}
		}
	}
	return out
}

func mcpRunnerToken(tok string) bool {
	t := strings.ToLower(strings.Trim(tok, `"'`))
	if i := strings.LastIndexAny(t, `/\`); i >= 0 {
		t = t[i+1:]
	}
	switch t {
	case "npx", "npx.cmd", "npx.exe", "uvx", "uvx.cmd", "uvx.exe":
		return true
	}
	return false
}

func mcpNextPackageToken(tokens []string) string {
	for i := 0; i < len(tokens); i++ {
		t := strings.TrimSpace(tokens[i])
		if t == "" {
			continue
		}
		lt := strings.ToLower(t)
		switch lt {
		case "args", "arguments", "command", "env", "environment", "headers", "type", "url", "image", "server", "mcp", "local", "remote":
			continue
		}
		if strings.HasPrefix(t, "-") {
			switch {
			case lt == "-p" || lt == "--package":
				if i+1 < len(tokens) {
					return strings.Trim(tokens[i+1], `"'`)
				}
				return ""
			case strings.HasPrefix(lt, "--package="):
				return strings.Trim(t[len("--package="):], `"'`)
			}
			continue
		}
		return strings.Trim(t, `"'`)
	}
	return ""
}

func mcpPackagePinned(spec string) bool {
	spec = strings.Trim(strings.TrimSpace(spec), `"'`)
	if spec == "" || strings.HasPrefix(spec, "-") {
		return false
	}
	if idx := strings.Index(spec, "=="); idx >= 0 {
		v := strings.ToLower(strings.TrimSpace(spec[idx+2:]))
		return v != "" && !strings.HasPrefix(v, "latest")
	}
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(spec[at+1:]))
	return v != "" && !strings.HasPrefix(v, "latest")
}

// mcpLiteralSecret implements VGL-MCP-002.
func mcpLiteralSecret(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	seen := map[string]bool{}
	for i, line := range lines {
		type candidate struct{ key, value string }
		var candidates []candidate
		for _, m := range mcpSecretKVRe.FindAllStringSubmatch(line, -1) {
			value := m[2]
			if value == "" {
				value = m[3]
			}
			candidates = append(candidates, candidate{m[1], value})
		}
		for _, m := range mcpSecretEnRe.FindAllStringSubmatch(line, -1) {
			candidates = append(candidates, candidate{m[1], m[2]})
		}
		for _, m := range mcpSecretArRe.FindAllStringSubmatch(line, -1) {
			candidates = append(candidates, candidate{m[1], m[2]})
		}
		for _, c := range candidates {
			value := strings.TrimSpace(c.value)
			if !mcpSecretCandidate(c.key, value) {
				continue
			}
			key := fmt.Sprintf("%d/%s", i+1, value)
			if seen[key] {
				continue
			}
			seen[key] = true
			fd := mcpFinding(f, i+1, c.key+"="+MaskSecret(value))
			fd.Location.Snippet = mcpRedactSecrets(
				strings.ReplaceAll(strings.TrimSpace(f.Line(i+1)), value, MaskSecret(value)))
			fd.Confidence = model.ConfidenceMedium
			if len(value) >= 20 && Entropy(value) >= 4 {
				fd.Confidence = model.ConfidenceHigh
			}
			fd.Remediation = "Remove the literal and reference a secret store or an environment variable that the launcher sets outside the committed config. Rotate the exposed credential."
			out = append(out, fd)
		}
	}
	return out
}

func mcpSecretCandidate(key, value string) bool {
	if len(value) < 12 || len(value) > 200 {
		return false
	}
	if strings.ContainsAny(value, " \t") {
		return false
	}
	if !mcpSecretNeedsMask(value) {
		return false
	}
	lu := strings.ToLower(key)
	if strings.Contains(lu, "url") || strings.Contains(lu, "path") {
		return false
	}
	return Entropy(value) >= 3.2
}

// mcpContainerEscape implements VGL-MCP-003.
func mcpContainerEscape(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	seen := map[string]bool{}
	for i, line := range lines {
		if !mcpCommandKeyRe.MatchString(line) {
			continue
		}
		for si, tokens := range mcpBlockTokens(lines, i, 16) {
			if !mcpHasToken(tokens, "docker", "docker.exe", "podman", "podman.exe", "nerdctl") {
				continue
			}
			key := fmt.Sprintf("%d/%d", i+1, si)
			for k := 0; k < len(tokens); k++ {
				t := strings.Trim(tokens[k], `"'`)
				lt := strings.ToLower(t)
				escape := lt == "--privileged" || lt == "--privileged=true" ||
					strings.Contains(t, "/var/run/docker.sock") ||
					strings.Contains(lt, `\\.\pipe\docker_engine`)
				if !escape {
					switch {
					case lt == "-v" || lt == "--volume":
						if k+1 < len(tokens) && mcpVolumeSourceRoot(tokens[k+1]) {
							escape = true
						}
					case strings.HasPrefix(lt, "--volume="):
						if mcpVolumeSourceRoot(t[len("--volume="):]) {
							escape = true
						}
					case strings.HasPrefix(lt, "-v="):
						if mcpVolumeSourceRoot(t[len("-v="):]) {
							escape = true
						}
					case lt == "--mount":
						if k+1 < len(tokens) && mcpMountSourceRoot(tokens[k+1]) {
							escape = true
						}
					case strings.HasPrefix(lt, "--mount="):
						if mcpMountSourceRoot(t[len("--mount="):]) {
							escape = true
						}
					}
				}
				if !escape || seen[key] {
					continue
				}
				seen[key] = true
				fd := mcpFinding(f, i+1, line)
				fd.Confidence = model.ConfidenceHigh
				fd.Remediation = "Run the MCP server without --privileged, without the Docker socket and without a host root mount. Mount only the directory the server needs."
				out = append(out, fd)
			}
		}
	}
	return out
}

func mcpVolumeSourceRoot(spec string) bool {
	spec = strings.Trim(strings.TrimSpace(spec), `"'`)
	if spec == "" {
		return false
	}
	start := 0
	if len(spec) >= 3 && mcpIsAlpha(spec[0]) && spec[1] == ':' && (spec[2] == '\\' || spec[2] == '/') {
		start = 2
	}
	if idx := strings.IndexByte(spec[start:], ':'); idx >= 0 {
		return mcpRootPathToken(spec[:start+idx])
	}
	return false
}

func mcpMountSourceRoot(spec string) bool {
	spec = strings.Trim(strings.TrimSpace(spec), `"'`)
	for _, part := range strings.Split(spec, ",") {
		p := strings.TrimSpace(part)
		lower := strings.ToLower(p)
		if strings.HasPrefix(lower, "source=") || strings.HasPrefix(lower, "src=") {
			return mcpRootPathToken(p[strings.IndexByte(p, '=')+1:])
		}
	}
	return false
}

func mcpRootPathToken(tok string) bool {
	t := strings.Trim(strings.TrimSpace(tok), `"'`)
	if t == "" {
		return false
	}
	if t == "/" || t == `\` {
		return true
	}
	if len(t) == 2 && mcpIsAlpha(t[0]) && t[1] == ':' {
		return true
	}
	if len(t) == 3 && mcpIsAlpha(t[0]) && t[1] == ':' && (t[2] == '\\' || t[2] == '/') {
		return true
	}
	return false
}

func mcpIsAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// mcpPlaintextEndpoint implements VGL-MCP-004.
func mcpPlaintextEndpoint(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	for i, line := range lines {
		flagged := false
		for _, m := range mcpURLKeyRe.FindAllStringSubmatch(line, -1) {
			u, err := url.Parse(m[1])
			if err != nil || !strings.EqualFold(u.Scheme, "http") || mcpLoopbackHost(u.Hostname()) {
				continue
			}
			flagged = true
			break
		}
		if !flagged {
			continue
		}
		fd := mcpFinding(f, i+1, line)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Use an https:// endpoint with a valid certificate, or a local stdio/loopback transport. Do not send tool traffic over plaintext HTTP."
		out = append(out, fd)
	}
	return out
}

func mcpLoopbackHost(host string) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "localhost" || h == "::1" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// mcpFilesystemRoot implements VGL-MCP-005.
func mcpFilesystemRoot(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	for i, line := range lines {
		if !mcpCommandKeyRe.MatchString(line) {
			continue
		}
		scopes := mcpBlockTokens(lines, i, 12)
		// The filesystem package usually appears in args, but a config may
		// name the server "filesystem" with a generic command.
		var nameTokens []string
		for j := i - 1; j >= 0 && j >= i-2; j-- {
			if !mcpServerKeyRe.MatchString(lines[j]) {
				continue
			}
			if nt := mcpTokens(lines[j]); mcpAnyTokenContains(nt, "filesystem") {
				nameTokens = nt
			}
			break
		}
		for _, scope := range scopes {
			all := scope
			if len(nameTokens) > 0 {
				all = append(append([]string{}, nameTokens...), scope...)
			}
			if !mcpAnyTokenContains(all, "filesystem") {
				continue
			}
			for _, tok := range all {
				cand := strings.Trim(tok, `"'`)
				if strings.HasPrefix(cand, "--") {
					if eq := strings.IndexByte(cand, '='); eq >= 0 {
						cand = cand[eq+1:]
					} else {
						continue
					}
				}
				if !mcpRootOrHomePath(cand) {
					continue
				}
				fd := mcpFinding(f, i+1, line)
				fd.Confidence = model.ConfidenceHigh
				fd.Remediation = "Root the filesystem server at the specific project or workspace directory it needs, not at /, a drive root or the user's home."
				out = append(out, fd)
				break
			}
		}
	}
	return out
}

func mcpRootOrHomePath(tok string) bool {
	t := strings.Trim(strings.TrimSpace(tok), `"'`)
	if t == "" {
		return false
	}
	switch t {
	case "/", `\`, "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "%HOMEPATH%":
		return true
	}
	if len(t) == 2 && mcpIsAlpha(t[0]) && t[1] == ':' {
		return true
	}
	if len(t) == 3 && mcpIsAlpha(t[0]) && t[1] == ':' && (t[2] == '\\' || t[2] == '/') {
		return true
	}
	for _, root := range []string{"/home/", "/Users/", "/root"} {
		if !strings.HasPrefix(t, root) {
			continue
		}
		rest := strings.Trim(strings.TrimPrefix(t, root), "/")
		if root == "/root" {
			if rest == "" {
				return true
			}
			continue
		}
		if rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	}
	return mcpWindowsHomeRe.MatchString(t)
}

// mcpAutoApproveWildcard implements VGL-MCP-006.
func mcpAutoApproveWildcard(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	for i, line := range lines {
		if !mcpAutoApproveKeyRe.MatchString(line) {
			continue
		}
		end := i + 6
		if end >= len(lines) {
			end = len(lines) - 1
		}
		found := false
		for j := i; j <= end && !found; j++ {
			if j > i && mcpAutoApproveKeyRe.MatchString(lines[j]) {
				break
			}
			for _, tok := range mcpTokens(lines[j]) {
				if tok == "*" {
					found = true
					break
				}
			}
			if j > i && strings.Contains(lines[j], "]") {
				break
			}
		}
		if !found {
			continue
		}
		fd := mcpFinding(f, i+1, line)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Replace the wildcard with the exact tool names that are safe to run without confirmation; keep destructive or network-capable tools behind approval."
		out = append(out, fd)
	}
	return out
}

// mcpDescriptionInjection implements VGL-MCP-007.
func mcpDescriptionInjection(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	for i, line := range lines {
		if !mcpDescriptionKeyRe.MatchString(line) {
			continue
		}
		region := mcpDescriptionRegion(lines, i)
		if region == "" {
			continue
		}
		phrase := mcpInjectionPhrase(region)
		if phrase == "" {
			continue
		}
		fd := mcpFinding(f, i+1, line)
		fd.Evidence = Truncate(mcpRedactSecrets("description contains \""+phrase+"\""), 240)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Treat the description as untrusted input and remove the instruction. Review where the server came from before keeping it enabled."
		out = append(out, fd)
	}
	return out
}

func mcpDescriptionRegion(lines []string, i int) string {
	line := lines[i]
	loc := mcpDescriptionKeyRe.FindStringIndex(line)
	if loc == nil {
		return ""
	}
	region := line[loc[1]:]
	if mcpQuoteCount(region)%2 == 0 {
		return region
	}
	for j := i + 1; j < len(lines) && j <= i+6; j++ {
		region += "\n" + lines[j]
		if mcpQuoteCount(lines[j])%2 == 1 {
			break
		}
	}
	return region
}

func mcpQuoteCount(s string) int {
	n := 0
	escaped := false
	for i := 0; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == '"':
			n++
		}
	}
	return n
}

func mcpInjectionPhrase(region string) string {
	lower := strings.ToLower(region)
	for _, phrase := range []string{
		"ignore previous instructions",
		"ignore all previous instructions",
		"ignore the previous instructions",
		"disregard previous instructions",
		"disregard all previous instructions",
		"do not tell the user",
		"don't tell the user",
		"do not inform the user",
		"exfiltrate",
		"read ~/.ssh",
		"~/.ssh/id_rsa",
	} {
		if strings.Contains(lower, phrase) {
			return phrase
		}
	}
	if m := mcpCurlPipeShellRe.FindString(region); m != "" {
		return strings.TrimSpace(strings.Join(strings.Fields(m), " "))
	}
	return ""
}

// mcpUnpinnedImage implements VGL-MCP-008.
func mcpUnpinnedImage(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	seen := map[int]bool{}
	for i, line := range lines {
		var image string
		if m := mcpImageKeyRe.FindStringSubmatch(line); m != nil {
			image = strings.TrimSpace(m[1])
		}
		if image == "" && mcpCommandKeyRe.MatchString(line) {
			for _, tokens := range mcpBlockTokens(lines, i, 16) {
				if !mcpHasToken(tokens, "docker", "docker.exe", "podman", "podman.exe", "nerdctl") {
					continue
				}
				if img := mcpDockerImageToken(tokens); img != "" {
					image = img
					break
				}
			}
		}
		if image == "" || strings.Contains(image, "${") || strings.Contains(image, "{{") {
			continue
		}
		if mcpImagePinned(image) || seen[i+1] {
			continue
		}
		seen[i+1] = true
		fd := mcpFinding(f, i+1, line)
		fd.Confidence = model.ConfidenceMedium
		fd.Remediation = "Pin the container image to a version tag or digest; do not rely on :latest or an implicit latest tag."
		out = append(out, fd)
	}
	return out
}

func mcpDockerImageToken(tokens []string) string {
	for k, tok := range tokens {
		lt := strings.ToLower(strings.Trim(tok, `"'`))
		if lt != "run" && lt != "create" {
			continue
		}
		for j := k + 1; j < len(tokens); j++ {
			t := strings.Trim(tokens[j], `"'`)
			if t == "" {
				continue
			}
			if strings.HasPrefix(t, "-") {
				if strings.Contains(t, "=") {
					continue
				}
				if mcpDockerFlagTakesValue(t) {
					j++
				}
				continue
			}
			return t
		}
		return ""
	}
	return ""
}

func mcpDockerFlagTakesValue(flag string) bool {
	switch strings.ToLower(flag) {
	case "-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net",
		"--mount", "--user", "-u", "-w", "--workdir", "--entrypoint", "--label", "-l",
		"--restart", "--platform", "--pull", "--log-driver", "--cap-add", "--cap-drop",
		"--security-opt", "--device", "--hostname", "-h", "--add-host", "--dns", "--env-file",
		"--memory", "-m", "--cpus", "--pid", "--ipc", "--uts", "--tmpfs", "--ulimit",
		"--userns", "--runtime", "-a", "--attach":
		return true
	}
	return false
}

func mcpImagePinned(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return true
	}
	if strings.Contains(image, "@sha256:") || strings.Contains(image, "@sha512:") {
		return true
	}
	lastSlash := strings.LastIndexByte(image, '/')
	lastColon := strings.LastIndexByte(image, ':')
	if lastColon <= lastSlash {
		return false
	}
	tag := image[lastColon+1:]
	return tag != "" && !strings.EqualFold(tag, "latest")
}

// mcpTLSVerifyDisabled implements VGL-MCP-009.
func mcpTLSVerifyDisabled(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	for i, line := range lines {
		hit := mcpTLSDisableRe.MatchString(line)
		if !hit {
			tokens := mcpTokens(line)
			for _, tok := range tokens {
				lt := strings.ToLower(strings.Trim(tok, `"'`))
				if lt == "--insecure" || lt == "--no-verify" {
					hit = true
					break
				}
				if lt == "-k" && mcpHasToken(tokens, "curl", "wget") {
					hit = true
					break
				}
			}
		}
		if !hit {
			continue
		}
		fd := mcpFinding(f, i+1, line)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Remove the TLS override. If the endpoint uses a private CA, install that CA in the trust store instead of disabling verification."
		out = append(out, fd)
	}
	return out
}

// mcpShellInterpolation implements VGL-MCP-010.
func mcpShellInterpolation(f *File) []model.Finding {
	lines := mcpScopeLines(f)
	var out []model.Finding
	for i, line := range lines {
		if !mcpCommandKeyRe.MatchString(line) {
			continue
		}
		hit := false
		for _, tokens := range mcpBlockTokens(lines, i, 12) {
			if !mcpHasToken(tokens, "sh", "sh.exe", "bash", "bash.exe", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe") {
				continue
			}
			if !mcpHasToken(tokens, "-c", "/c", "-command", "/command") {
				continue
			}
			joined := strings.Join(tokens, " ")
			if !strings.Contains(joined, "$") && !mcpPercentVarRe.MatchString(joined) && !strings.Contains(joined, "{{") {
				continue
			}
			hit = true
			break
		}
		if !hit {
			continue
		}
		fd := mcpFinding(f, i+1, line)
		fd.Confidence = model.ConfidenceMedium
		fd.Remediation = "Invoke the server executable directly with fixed arguments, or pass interpolated values through a structured argument list instead of a shell string."
		out = append(out, fd)
	}
	return out
}
