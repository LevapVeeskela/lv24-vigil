package rules

import (
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	pbUserSourceRe = regexp.MustCompile(`(?i)req\.(?:query|body|params|headers)|request\.(?:args|form|json|values|GET|POST|query_params)|r\.URL\.Query\(\)|r\.FormValue\(|r\.Form\.Get\(|ctx\.(?:Query|Param|FormValue)\(|params\[|event\.(?:queryStringParameters|body)`)
	pbAssignRe     = regexp.MustCompile(`(?:=|:=)`)

	pbSSRFSinkRe = regexp.MustCompile(`(?i)\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|requests\.(?:get|post|put|request)|http\.(?:Get|Post|Do)|urllib\.request\.urlopen|urlopen|httpx\.(?:get|post)|got(?:\.get)?|superagent\.(?:get|post))\s*\(`)
	pbSSRFArgRe  = regexp.MustCompile(`(?i)\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post)|http\.(?:Get|Post)|urlopen|httpx\.(?:get|post))\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]`)

	pbTraversalSinkRe = regexp.MustCompile(`(?i)\b(?:filepath\.Join|path\.Join|os\.path\.join|Path\(|path\.resolve|fs\.(?:readFile|readFileSync|createReadStream)|os\.Open|open|sendFile|send_file)\s*\(`)
	pbTraversalCallRe = regexp.MustCompile(`(?i)\b(?:filepath\.Join|path\.Join|os\.path\.join|Path\(|path\.resolve|fs\.(?:readFile|readFileSync|createReadStream)|os\.Open|open|sendFile|send_file)\s*\(([^)]*)\)`)

	pbRedirectSinkRe = regexp.MustCompile(`(?i)(?:res\.redirect\s*\(|response\.redirect\s*\(|http\.Redirect\s*\(|RedirectResponse\s*\(|\bredirect\s*\(|location\.href\s*=|window\.location\s*=|location\.assign\s*\(|header\(\s*["']Location["'])`)
	pbRedirectArgRe  = regexp.MustCompile(`(?i)(?:res\.redirect|response\.redirect|http\.Redirect|RedirectResponse|\bredirect)\s*\(([^)]*)\)`)

	pbCORSAnyRe = regexp.MustCompile(`(?i)Access-Control-Allow-Origin["']?\s*[:=]\s*["']?\*|allow_origins\s*=\s*\[\s*["']\*|origin\s*:\s*["']\*["']|\bcors\s*\(\s*\)|\bCORS\s*\(\s*app\s*\)`)

	pbServerSetupRe = regexp.MustCompile(`(?i)\bexpress\s*\(\s*\)|\bFlask\s*\(\s*__name__\s*\)|\bFastAPI\s*\(|\bhttp\.ListenAndServe\s*\(|\bgin\.Default\s*\(|\bhttp\.NewServeMux\s*\(|\bKoa\s*\(|\bHapi\.server\s*\(`)
	pbServerRouteRe = regexp.MustCompile(`(?i)\bapp\.(?:get|post|put|delete|use)\s*\(|@app\.(?:route|get|post|put|delete)\b|\bHandleFunc\s*\(|\brouter\.(?:get|post|put|delete|use)\s*\(|\.Use\s*\(`)
	pbHeaderCfgRe   = regexp.MustCompile(`(?i)helmet|secure[_-]?headers|talisman|SecurityMiddleware|Strict[-_]Transport[-_]Security|X[-_]Content[-_]Type[-_]Options|Content[-_]Security[-_]Policy|secureheaders`)

	pbGraphQLIntrospectionRe = regexp.MustCompile(`(?i)\bintrospection\s*:\s*true|\bintrospectionEnabled\s*[:=]\s*true|GRAPHQL_INTROSPECTION\s*=\s*True|\bplayground\s*:\s*true|\bgraphiql\s*:\s*true`)
	pbDebugEndpointRe        = regexp.MustCompile("(?i)[\"'`]?/(?:debug|actuator/(?:env|heapdump|jolokia|beans|configprops|threaddump)|console|_debug)\\b")
	pbDirListingRe           = regexp.MustCompile(`(?i)Options\s+\+Indexes|serveIndex\s*\(|serve-index|directoryListing\s*:\s*true|list_directory|directory_listing`)
	pbHTTPAuthURLRe          = regexp.MustCompile(`(?i)http://[^\s"'<>]*\b(?:auth|login|oauth|token|sso|password|session|signin|signup)[^\s"'<>]*`)
	pbHostHeaderRe           = regexp.MustCompile(`(?i)req(?:uest)?\.(?:headers\.host|get\(\s*["']host["']\s*\)|headers\[\s*["']host["']\s*\])|r\.Host\b|request\.get_host\(\)`)
	pbHostHeaderContextRe    = regexp.MustCompile(`(?i)url|link|redirect|reset|invite|verify|callback|http`)
	// Debug mode is a server/config switch, not any object literal with a
	// `debug` key. app.run(debug=True), DEBUG=True and app.debug are
	// unambiguous; a bare `debug: true` is only meaningful in a config file.
	pbDebugModeRe = regexp.MustCompile(`(?i)\bapp\.run\s*\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*(?:True|true|1)\b|^\s*FLASK_DEBUG\s*=\s*1\b|\bapp\.debug\s*[:=]\s*true\b`)
	pbDebugFlagRe = regexp.MustCompile(`(?i)\bdebug\s*[:=]\s*true\b`)

	// VGL-WEB-020: Spring Boot actuator exposure.
	pbSpringExposureIncludeRe  = regexp.MustCompile(`(?i)^\s*management\.endpoints\.web\.exposure\.include\s*[:=]\s*(.+?)\s*$`)
	pbSpringSecurityDisabledRe = regexp.MustCompile(`(?i)^\s*management\.security\.enabled\s*[:=]\s*["']?false["']?\s*$`)
	pbSpringShutdownEnabledRe  = regexp.MustCompile(`(?i)^\s*management\.endpoint\.shutdown\.enabled\s*[:=]\s*["']?true["']?\s*$`)
	pbSpringYAMLIncludeRe      = regexp.MustCompile(`(?i)^\s*include\s*:\s*(.+?)\s*$`)
	pbSpringYAMLBoolRe         = regexp.MustCompile(`(?i)^\s*enabled\s*:\s*["']?(true|false)["']?\s*$`)
)

// pbSpringDangerousEndpoints are the actuator endpoints that leak credentials,
// configuration or a shutdown switch.
var pbSpringDangerousEndpoints = []string{
	"env", "heapdump", "jolokia", "threaddump", "configprops", "beans",
	"logfile", "shutdown", "mappings", "sessions", "httptrace",
	"auditevents", "quartz",
}

// WebRules returns the web application security rules.
func WebRules() []Rule {
	return []Rule{
		New(model.RuleMeta{
			ID:          "VGL-WEB-001",
			Title:       "Server-side request forgery through a user-controlled URL",
			Description: "Passing request data directly to an HTTP client lets an attacker reach internal services and cloud metadata endpoints. Validate against an allow-list and block private address ranges.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-918"},
			OWASP:       []string{"A10:2021"},
			Tags:        []string{"ssrf", "web"},
		}, pbSSRFRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-002",
			Title:       "Path traversal through user-controlled file path",
			Description: "Joining or opening a path built from request data allows ../ escapes and arbitrary file reads. Resolve the path, then verify it stays inside the intended base directory.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-22"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"traversal", "web"},
		}, pbTraversalRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-003",
			Title:       "Open redirect through user-controlled destination",
			Description: "Redirecting to a URL taken from the request enables phishing under the trusted domain. Accept only relative paths or allow-listed hosts.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-601"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"redirect", "web"},
		}, pbOpenRedirectRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-004",
			Title:       "Permissive CORS policy",
			Description: "Allowing every origin exposes public endpoints to cross-origin reads. Echo only explicitly allow-listed origins; combine credentials only with a specific origin.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-942"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"cors", "web"},
		}, pbPermissiveCORSRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-005",
			Title:       "Server framework configured without security headers",
			Description: "Responses should set Content-Security-Policy, X-Content-Type-Options, Referrer-Policy and HSTS (over HTTPS). Add helmet, secure_headers, Talisman or equivalent middleware.",
			Severity:    model.SeverityInfo,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"headers", "web"},
		}, pbMissingHeadersRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-006",
			Title:       "GraphQL introspection or playground enabled",
			Description: "Introspection and interactive playgrounds should be disabled in production; they disclose the full schema and invite abuse.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-200"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"graphql", "web"},
		}, pbGraphQLIntrospectionRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-007",
			Title:       "Debug or actuator endpoint exposed",
			Description: "Endpoints such as /debug, /actuator/env or /console expose configuration and secrets. Remove them from production or require strong authentication.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"debug", "web"},
		}, pbDebugEndpointRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-008",
			Title:       "Directory listing enabled",
			Description: "Directory indexes reveal file names and sometimes backups or credentials. Disable listing and serve explicit routes only.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-548"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"listing", "web"},
		}, pbDirListingRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-009",
			Title:       "Authentication endpoint uses plain HTTP",
			Description: "Credentials sent over HTTP can be read or modified by any network observer. Use HTTPS for every authentication, token and session endpoint.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-319"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"tls", "auth"},
		}, pbHTTPAuthURLRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-010",
			Title:       "Localhost address hardcoded in production configuration",
			Description: "A localhost endpoint in a production config usually means a broken deployment or an unintended local dependency. Use environment-specific service discovery.",
			Severity:    model.SeverityInfo,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-1188"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"config", "web"},
		}, pbLocalhostConfigRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-011",
			Title:       "Host header used to build a URL",
			Description: "The Host header is attacker-controlled unless the edge validates it. Use a configured canonical base URL for password-reset and callback links.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-644"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"host-header", "web"},
		}, pbHostHeaderRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-012",
			Title:       "Debug mode enabled",
			Description: "Framework debug mode exposes stack traces, source and configuration, and in some frameworks enables an interactive console. Disable it in production.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"debug", "web"},
		}, pbDebugModeRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-020",
			Title:       "Spring Boot actuator endpoints exposed without auth",
			Description: "Exposing every actuator endpoint (include=*) publishes /actuator/env, /actuator/heapdump and /actuator/configprops, which leak credentials and configuration. Expose only health and info unless Spring Security restricts these endpoints.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryWeb,
			Languages:   []string{"yaml", "properties"},
			CWE:         []string{"CWE-489", "CWE-306", "CWE-200"},
			OWASP:       []string{"A01:2021", "A05:2021"},
			Tags:        []string{"spring", "actuator", "config"},
		}, pbSpringActuatorExposureRule),
	}
}

// pbTaintedArg reports whether arg is assigned from request data in the few
// lines before idx. This is deliberately shallow: it catches the common
// "read request value, pass it to a sink" pattern without a full dataflow.
func pbTaintedArg(f *File, idx int, arg string) bool {
	start := idx - 8
	if start < 0 {
		start = 0
	}
	for j := start; j < idx; j++ {
		line := f.Lines[j]
		if !strings.Contains(line, arg) || !pbAssignRe.MatchString(line) {
			continue
		}
		if pbUserSourceRe.MatchString(line) {
			return true
		}
	}
	return false
}

func pbCallArgsTainted(f *File, idx int, callRe *regexp.Regexp, line string) bool {
	m := callRe.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	for _, ident := range pbIdentRe.FindAllString(m[1], -1) {
		if ident == "req" || ident == "request" || ident == "r" || ident == "ctx" {
			continue
		}
		if pbTaintedArg(f, idx, ident) {
			return true
		}
	}
	return false
}

var pbIdentRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

func pbSSRFRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbSSRFSinkRe.MatchString(line) {
			continue
		}
		hit := pbUserSourceRe.MatchString(line) || pbCallArgsTainted(f, i, pbSSRFArgRe, line)
		if !hit {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbTraversalRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbTraversalSinkRe.MatchString(line) {
			continue
		}
		hit := pbUserSourceRe.MatchString(line)
		if !hit {
			hit = pbCallArgsTainted(f, i, pbTraversalCallRe, line)
		}
		if !hit {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

func pbOpenRedirectRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbRedirectSinkRe.MatchString(line) {
			continue
		}
		hit := pbUserSourceRe.MatchString(line) || pbCallArgsTainted(f, i, pbRedirectArgRe, line)
		if !hit {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

func pbPermissiveCORSRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || pbCORSCredsRe.MatchString(string(f.Content)) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbCORSAnyRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

func pbMissingHeadersRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	content := string(f.Content)
	if pbHeaderCfgRe.MatchString(content) {
		return nil
	}
	setupLine := 0
	routeSeen := false
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		if setupLine == 0 && pbServerSetupRe.MatchString(line) {
			setupLine = i + 1
		}
		if pbServerRouteRe.MatchString(line) {
			routeSeen = true
		}
	}
	if setupLine == 0 || !routeSeen {
		return nil
	}
	fd := pbFinding(f, setupLine, "server framework has routes but no security-header middleware")
	fd.Severity = pbSev(f, model.SeverityInfo)
	fd.Confidence = model.ConfidenceLow
	return []model.Finding{fd}
}

func pbGraphQLIntrospectionRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		loc := pbGraphQLIntrospectionRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		// A DTO/controller description may mention "playground:true" as prose.
		if IsInsideStringLiteral(line, loc[0]) {
			continue
		}
		if !pbGraphQLContext(f, i) && !strings.Contains(line, "/playground") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

// pbGraphQLContext reports whether the GraphQL server is configured on this
// line or within the previous five lines.
func pbGraphQLContext(f *File, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	for j := start; j <= idx; j++ {
		if pbHasAnyFold(f.Lines[j], "graphql", "apollo", "gql", "typedefs", "resolvers") {
			return true
		}
	}
	return false
}

func pbDebugEndpointRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		loc := pbDebugEndpointRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		// https://console.example is a documentation link, not a route.
		if loc[0] > 0 && (line[loc[0]-1] == '/' || line[loc[0]-1] == ':') {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

func pbDirListingRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbDirListingRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbHTTPAuthURLRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || isTestPath(strings.ToLower(strings.ReplaceAll(f.Path, "\\", "/"))) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pbHTTPAuthURLRe.FindString(line)
		if m == "" {
			continue
		}
		if pbHasAnyFold(m, "localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "${") {
			continue
		}
		if pbReservedHTTPHost(m) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

// pbReservedHTTPHost reports whether a URL points at a test/reserved host such
// as cinema.test, auth.example or localhost.
func pbReservedHTTPHost(raw string) bool {
	lower := strings.ToLower(raw)
	if i := strings.Index(lower, "://"); i >= 0 {
		lower = lower[i+3:]
	}
	for _, stop := range []string{"/", "?", "#"} {
		if i := strings.Index(lower, stop); i >= 0 {
			lower = lower[:i]
		}
	}
	if i := strings.LastIndex(lower, "@"); i >= 0 {
		lower = lower[i+1:]
	}
	if strings.HasPrefix(lower, "[") {
		if i := strings.Index(lower, "]"); i >= 0 {
			lower = lower[:i+1]
		}
	} else if i := strings.Index(lower, ":"); i >= 0 {
		lower = lower[:i]
	}
	if lower == "localhost" || lower == "127.0.0.1" || lower == "0.0.0.0" || lower == "[::1]" {
		return true
	}
	for _, suffix := range []string{".test", ".example", ".invalid", ".localhost", ".local"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func pbLocalhostConfigRule(f *File) []model.Finding {
	path := pbPathLower(f)
	if pbDocsPath(path) {
		return nil
	}
	prodish := pbHasAnyFold(path, "prod", "config", "settings", "application", "values", "deploy", "manifest")
	devish := pbHasAnyFold(path, "dev", "test", "local", "example", "sample", "fixture")
	if !prodish || devish {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbHasAnyFold(line, "localhost", "127.0.0.1") {
			continue
		}
		if !pbHasAnyFold(line, "host", "url", "dsn", "endpoint", "db", "redis", "mongo", "postgres", "mysql", "server") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityInfo)
		fd.Confidence = model.ConfidenceLow
		out = append(out, fd)
	}
	return out
}

func pbHostHeaderRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbHostHeaderRe.MatchString(line) {
			continue
		}
		if !pbHostHeaderContextRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceLow
		out = append(out, fd)
	}
	return out
}

func pbDebugModeRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || (!pbCodeLanguage(f.Language) && f.Language != "yaml" &&
		f.Language != "json" && f.Language != "toml" && f.Language != "other") {
		return nil
	}
	configShaped := pbConfigShapedPath(f.Path)
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		sev := model.SeverityHigh
		switch {
		case pbDebugModeRe.MatchString(line):
			if pbHasAnyFold(line, "debug: true", "debug:true") {
				sev = model.SeverityMedium
			}
		case configShaped && pbDebugFlagRe.MatchString(line):
			sev = model.SeverityMedium
		default:
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, sev)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

// pbConfigShapedPath reports whether path is a settings/config file where a
// bare `debug: true` really does enable framework debug mode.
func pbConfigShapedPath(p string) bool {
	lower := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	base := lower
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	configName := strings.Contains(base, "config") || strings.Contains(base, "settings") ||
		strings.Contains(base, "application") || base == ".env" || strings.HasPrefix(base, ".env.")
	if !configName {
		return false
	}
	for _, ext := range []string{".yml", ".yaml", ".json", ".toml", ".env", ".ini", ".properties"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return base == ".env" || strings.HasPrefix(base, ".env.")
}

// ---------------------------------------------------------------------------
// VGL-WEB-020 — Spring Boot actuator endpoints exposed
// ---------------------------------------------------------------------------

func pbSpringActuatorExposureRule(f *File) []model.Finding {
	path := strings.ToLower(strings.ReplaceAll(f.Path, "\\", "/"))
	if pbDocsPath(path) || !pbSpringConfigPath(path) {
		return nil
	}
	content := strings.ToLower(string(f.Content))
	hasManagement := strings.Contains(content, "management:")
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		var hit bool
		switch {
		case pbSpringExposureIncludeRe.MatchString(line):
			m := pbSpringExposureIncludeRe.FindStringSubmatch(line)
			hit = pbSpringExposureDangerous(m[1])
		case pbSpringYAMLIncludeRe.MatchString(line):
			if hasManagement {
				m := pbSpringYAMLIncludeRe.FindStringSubmatch(line)
				hit = pbSpringExposureDangerous(m[1]) && pbSpringExposureBlock(f, i)
			}
		case pbSpringSecurityDisabledRe.MatchString(line), pbSpringShutdownEnabledRe.MatchString(line):
			hit = true
		case pbSpringYAMLBoolRe.MatchString(line):
			m := pbSpringYAMLBoolRe.FindStringSubmatch(line)
			hit = pbSpringYAMLManagementSwitch(f, i, strings.ToLower(m[1]))
		}
		if !hit {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSpringSeverity(f, path)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

// pbSpringConfigPath reports whether path is a Spring Boot configuration file.
func pbSpringConfigPath(p string) bool {
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	ext := ""
	if i := strings.LastIndex(base, "."); i >= 0 {
		ext = base[i:]
	}
	switch ext {
	case ".properties", ".yml", ".yaml":
	default:
		return false
	}
	if strings.HasPrefix(base, "application") || strings.HasPrefix(base, "bootstrap") {
		return true
	}
	return strings.Contains(p, "src/main/resources/")
}

// pbSpringExposureBlock reports whether a YAML `include:` line is nested under
// the actuator exposure block (include -> exposure -> ... -> management).
func pbSpringExposureBlock(f *File, idx int) bool {
	chain := pbYAMLKeyChain(f, idx)
	if len(chain) == 0 {
		return false
	}
	parent := chain[0]
	if parent != "exposure" && !strings.HasSuffix(parent, ".exposure") {
		return false
	}
	return pbChainIndex(chain, "management") > 0 || strings.HasPrefix(parent, "management.")
}

// pbSpringExposureDangerous reports whether an exposure include value enables
// every endpoint or a credential/configuration-leaking one.
func pbSpringExposureDangerous(raw string) bool {
	v := pbSpringTrimValue(raw)
	if v == "" {
		return false
	}
	if v == "*" {
		return true
	}
	tokens := strings.FieldsFunc(strings.ToLower(v), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' ||
			r == '[' || r == ']' || r == '"' || r == '\''
	})
	for _, token := range tokens {
		for _, endpoint := range pbSpringDangerousEndpoints {
			if token == endpoint {
				return true
			}
		}
	}
	return false
}

func pbSpringTrimValue(raw string) string {
	v := strings.TrimSpace(raw)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimSuffix(v, ";")
	v = strings.TrimSpace(v)
	return strings.Trim(v, `"'`)
}

// pbSpringYAMLManagementSwitch reports whether a YAML `enabled:` value turns
// off management security or turns on the shutdown endpoint.
func pbSpringYAMLManagementSwitch(f *File, idx int, value string) bool {
	chain := pbYAMLKeyChain(f, idx)
	switch value {
	case "true":
		return pbChainIndex(chain, "shutdown") == 0 &&
			pbChainIndex(chain, "endpoint") == 1 &&
			pbChainIndex(chain, "management") == 2
	case "false":
		return pbChainIndex(chain, "security") == 0 &&
			pbChainIndex(chain, "management") == 1
	default:
		return false
	}
}

// pbYAMLKeyChain returns the keys of the enclosing YAML blocks, nearest first.
// It is a bounded indentation scan, not a YAML parser: rules use it to confirm
// that a leaf key really sits under the expected parent.
func pbYAMLKeyChain(f *File, idx int) []string {
	indent := pbYAMLIndent(f.Lines[idx])
	var chain []string
	for j := idx - 1; j >= 0 && len(chain) < 6; j-- {
		line := f.Lines[j]
		if strings.TrimSpace(line) == "" || pbComment(f, line) {
			continue
		}
		ind := pbYAMLIndent(line)
		if ind >= indent {
			continue
		}
		key, ok := pbYAMLKey(line)
		if !ok {
			continue
		}
		chain = append(chain, key)
		indent = ind
	}
	return chain
}

func pbYAMLIndent(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// pbYAMLKey returns the lower-cased mapping key of a YAML line.
func pbYAMLKey(line string) (string, bool) {
	t := strings.TrimSpace(line)
	t = strings.TrimPrefix(t, "- ")
	i := strings.Index(t, ":")
	if i <= 0 {
		return "", false
	}
	key := t[:i]
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return "", false
	}
	return strings.ToLower(key), true
}

func pbChainIndex(chain []string, key string) int {
	for i, k := range chain {
		if k == key {
			return i
		}
	}
	return -1
}

// pbSpringSeverity caps Spring findings in local/dev/test profiles, where the
// exposure is not reachable from production.
func pbSpringSeverity(f *File, path string) model.Severity {
	sev := pbSev(f, model.SeverityHigh)
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	for _, marker := range []string{"-test", "-local", "-dev"} {
		if strings.Contains(base, marker) {
			return capSeverity(sev, model.SeverityMedium)
		}
	}
	return sev
}
