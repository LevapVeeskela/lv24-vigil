package rules

import (
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	pbUserSourceRe = regexp.MustCompile(`(?i)req\.(?:query|body|params|headers)|request\.(?:args|form|json|values|GET|POST|query_params)|r\.URL\.Query\(\)|r\.FormValue\(|r\.Form\.Get\(|ctx\.(?:Query|Param|FormValue)\(|params\[|event\.(?:queryStringParameters|body)|request\.get(?:Parameter|Header)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|Request\.(?:QueryString|Form|Query|Headers)\s*\[`)
	pbAssignRe     = regexp.MustCompile(`(?:=|:=)`)

	pbSSRFSinkRe = regexp.MustCompile(`(?i)\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|requests\.(?:get|post|put|request)|http\.(?:Get|Post|Do)|urllib\.request\.urlopen|urlopen|httpx\.(?:get|post)|got(?:\.get)?|superagent\.(?:get|post))\s*\(`)
	pbSSRFArgRe  = regexp.MustCompile(`(?i)\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post)|http\.(?:Get|Post)|urlopen|httpx\.(?:get|post))\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]`)

	pbTraversalSinkRe = regexp.MustCompile(`(?i)\b(?:filepath\.Join|path\.Join|os\.path\.join|Paths\.get|Path\(|path\.resolve|fs\.(?:readFile|readFileSync|createReadStream)|os\.Open|new\s+File|FileInputStream|file_get_contents|fopen|readfile|open|sendFile|send_file)\s*\(`)
	pbTraversalCallRe = regexp.MustCompile(`(?i)\b(?:filepath\.Join|path\.Join|os\.path\.join|Paths\.get|Path\(|path\.resolve|fs\.(?:readFile|readFileSync|createReadStream)|os\.Open|new\s+File|FileInputStream|file_get_contents|fopen|readfile|open|sendFile|send_file)\s*\(([^)]*)\)`)

	pbRedirectSinkRe   = regexp.MustCompile(`(?i)(?:res\.redirect\s*\(|response\.redirect\s*\(|response\.sendRedirect\s*\(|http\.Redirect\s*\(|RedirectResponse\s*\(|\bredirect\s*\(|return\s+["']redirect:|location\.href\s*=|window\.location\s*=|location\.assign\s*\(|header\(\s*["']Location["'])`)
	pbRedirectArgRe    = regexp.MustCompile(`(?i)(?:res\.redirect|response\.redirect|response\.sendRedirect|http\.Redirect|RedirectResponse|\bredirect)\s*\(([^)]*)\)`)
	pbSpringRedirectRe = regexp.MustCompile(`(?i)["']redirect:["']?\s*\+\s*([^;]+)`)

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

	// VGL-WEB-023: phpinfo() exposed.
	pbPHPInfoRe = regexp.MustCompile(`(?i)\bphpinfo\s*\(`)

	// VGL-WEB-024: archive extraction path traversal. PHP member calls use ->,
	// Java NIO builds targets with resolve()/Paths.get(), and Ruby with
	// File.join.
	pbZipSlipSinkRe    = regexp.MustCompile(`(?i)\b(?:filepath\.Join|path\.Join|os\.path\.join|File\.join|new\s+File|Paths\.get)\s*\(|(?:\.|->)resolve\s*\(|(?:\.|->)extract(?:all|To)?\s*\(`)
	pbZipSlipMemberRe  = regexp.MustCompile(`(?i)\b(?:entry|zipEntry|ze|member|info|header|hdr|f|file|item)\.(?:Name|name|FileName|filename|full_name|getName\s*\(\s*\)|entryName|fileName)`)
	pbZipSlipExtractRe = regexp.MustCompile(`(?i)(?:\.|->)extract(?:all|To)?\s*\(`)
	// A containment guard must compare the joined target with the destination
	// root. Clean, realpath and basename alone only normalise a name; they do
	// not prove that it stayed inside the extraction directory.
	pbZipSlipSafeRe = regexp.MustCompile(`(?i)secure_filename|\bIsSubPath`)
	// tarfile restricts extraction through arguments of the same call, so
	// filter=/members= count only inside the extraction call span. A local
	// variable with either name elsewhere in the function is not a guard.
	pbZipSlipSafeArgRe = regexp.MustCompile(`(?i)\b(?:filter|members)\s*=`)
	pbZipSlipJoinRe    = regexp.MustCompile(`(?i)\b(?:filepath\.Join|path\.Join|os\.path\.join|File\.join|Paths\.get)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)`)
	// The destination root of a resolve() call is its receiver.
	pbZipSlipResolveRe = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.|->)\s*resolve\s*\(`)
	pbZipSlipNewFileRe = regexp.MustCompile(`(?i)\bnew\s+File\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)`)
	// pbZipSlipWriteRe names writes and moves, not reads. A join followed only
	// by a read (open for reading, FileInputStream, readFile) is not an
	// extraction write.
	pbZipSlipWriteRe   = regexp.MustCompile(`(?i)\b(?:os\.Create|os\.OpenFile|os\.WriteFile|ioutil\.WriteFile|io\.Copy(?:N)?|fs\.(?:writeFile|writeFileSync|createWriteStream)|Files\.(?:copy|write|move)|FileOutputStream|FileWriter|fopen|file_put_contents|fwrite|shutil\.(?:copy|copy2|copyfile|copyfileobj|move)|os\.(?:rename|replace)|\.transferTo|\.save|\.write)\s*\(|\bopen\s*\([^)]*,\s*["'][^"']*[wax+][^"']*["']`)
	pbArchiveContextRe = regexp.MustCompile(`(?i)\b(?:zip\w*|tarfile|tar\.|\.tar|tar|untar|unzip|archive)\b`)

	// VGL-WEB-025: uploaded filename used as a destination path.
	// res.download() is deliberately absent: it serves (reads) a file and
	// writes nothing, so the upload destination rules do not apply to it.
	pbUploadSinkRe = regexp.MustCompile(`(?i)\b(?:move_uploaded_file|file_put_contents|fopen|rename|copy|os\.path\.join|shutil\.copy(?:file)?|path\.join|fs\.(?:writeFile|writeFileSync|createWriteStream)|new\s+File|Files\.(?:copy|write|move)|Paths\.get|transferTo|filepath\.Join|os\.Create|os\.WriteFile|ioutil\.WriteFile)\s*\(|\bopen\s*\(`)
	// ESM named imports drop the fs./path. prefix, so a bare writeFile(...) or
	// join(...) is a sink too. Method calls such as buf.join(...) are not.
	pbUploadESSinkRe   = regexp.MustCompile(`(?i)(?:^|[^.\w])(?:writeFile|writeFileSync|createWriteStream|appendFile|join)\s*\(`)
	pbUploadSanitizeRe = regexp.MustCompile(`(?i)secure_filename|uuid|randomUUID|sanitize|basename|filepath\.Base|path\.Base|generateFileName`)
	pbUploadAssignRe   = regexp.MustCompile(`^\s*(?:(?:final|var|let|const|String|Path|File)\s+)*\$?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=(?:[^=]|$))`)

	// pbUploadJoinSinkRe names path construction only: a join or File
	// constructor does not move an upload, so it needs a write or move nearby.
	pbUploadJoinSinkRe = regexp.MustCompile(`(?i)\b(?:filepath\.Join|path\.Join|os\.path\.join|File\.join|new\s+File|Paths\.get)\s*\(|(?:^|[^.\w])join\s*\(`)
	// pbUploadWriteRe names writes and moves of the uploaded bytes. Serving a
	// file back (res.download) reads it, so it is not a write or a move.
	pbUploadWriteRe = regexp.MustCompile(`(?i)\b(?:os\.WriteFile|os\.Create|ioutil\.WriteFile|Files\.(?:copy|move|write)|new\s+FileOutputStream|FileOutputStream|FileWriter|fs\.(?:writeFile|writeFileSync|createWriteStream|appendFile)|writeFile|writeFileSync|createWriteStream|shutil\.(?:copy|copy2|copyfile|copyfileobj|move)|os\.(?:rename|replace|renames)|Path\.write_(?:text|bytes)|transferTo|move_uploaded_file|file_put_contents|fwrite|\.save)\s*\(`)
	// PHP moves a temporary upload with rename()/copy(), which are ordinary
	// functions there; in other languages those names are unrelated builtins.
	// A stream only counts when fopen() asks for a write mode.
	pbUploadPHPMoveRe = regexp.MustCompile(`(?i)\b(?:rename|copy)\s*\(|\bfopen\s*\([^)]*,\s*["'][^"']*[wax+][^"']*["']`)

	// VGL-WEB-025 source accessors, one per language family.
	pbUploadPHPNameRe = regexp.MustCompile(`(?i)\$_FILES\s*\[[^\]]*\]\s*\[\s*["']name["']\s*\]`)
	pbUploadPyNameRe  = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*|[\])])\s*\.\s*filename\b`)
	// Django's UploadedFile exposes the client filename as .name. The match is
	// only a source when the receiver came from request.FILES or a FileStorage
	// value, because .name is an ordinary attribute everywhere else.
	pbUploadPyDjangoRe  = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*|[\])])\s*\.\s*name\b`)
	pbUploadPyRequestRe = regexp.MustCompile(`(?i)\brequest\s*\.\s*files\b|\b(?:FileStorage|UploadedFile|InMemoryUploadedFile|TemporaryUploadedFile)\b`)
	pbUploadPyWriteRe   = regexp.MustCompile(`(?i)\bshutil\.(?:copy|copy2|copyfile|copyfileobj|move)\s*\(|\bos\.(?:rename|replace|renames)\s*\(|\.write_(?:text|bytes)\s*\(|\bopen\s*\((?:[^()]|\([^()]*\))*,\s*(?:mode\s*=\s*)?["'][^"']*[wax+][^"']*["']\s*\)|\.save\s*\(|\.write\s*\(`)
	pbUploadJSNameRe    = regexp.MustCompile(`(?i)\b[A-Za-z_$][A-Za-z0-9_$]*\.originalname\b`)
	pbUploadJavaNameRe  = regexp.MustCompile(`(?i)\bget(?:OriginalFilename|SubmittedFileName)\s*\(`)
	pbUploadGoNameRe    = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\.Filename\b`)
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

		New(model.RuleMeta{
			ID:          "VGL-WEB-023",
			Title:       "phpinfo() exposed by the application",
			Description: "phpinfo() prints the PHP version, loaded extensions, DOCUMENT_ROOT, environment variables and sometimes database credentials. It is a debug page, never a production endpoint.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			Languages:   []string{"php"},
			CWE:         []string{"CWE-200", "CWE-489"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"php", "info-disclosure", "web"},
			References: []string{
				"https://www.php.net/manual/en/function.phpinfo.php",
				"https://cwe.mitre.org/data/definitions/200.html",
				"https://cwe.mitre.org/data/definitions/489.html",
			},
		}, pbPHPInfoRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-024",
			Title:       "Archive extraction path traversal (zip slip)",
			Description: "Extracting an archive entry whose name is joined to a destination directory without a containment check lets a crafted ../../ entry write outside that directory. Resolve the target and verify it stays below the destination before creating the file.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryWeb,
			Languages:   []string{"go", "python", "java", "php", "ruby", "javascript", "typescript"},
			CWE:         []string{"CWE-22"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"zip-slip", "traversal", "archive", "web"},
			References: []string{
				"https://cwe.mitre.org/data/definitions/22.html",
				"https://security.snyk.io/vuln/SNYK-JAVA-ORGAPACHECOMMONS-3165679",
				"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
			},
		}, pbZipSlipRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-025",
			Title:       "Uploaded filename used as the destination path",
			Description: "Writing or moving an upload to a path built from the client-supplied filename lets an attacker choose the location (path traversal) or overwrite files. Generate a server-side name and validate the extension; keep the original name only as metadata.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryWeb,
			Languages:   []string{"php", "python", "javascript", "typescript", "java", "go"},
			CWE:         []string{"CWE-434", "CWE-22"},
			OWASP:       []string{"A04:2021", "A01:2021"},
			Tags:        []string{"upload", "traversal", "web"},
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
				"https://cwe.mitre.org/data/definitions/434.html",
				"https://cwe.mitre.org/data/definitions/22.html",
			},
		}, pbUploadFilenameRule),
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
			hit = pbCallArgsTainted(f, i, pbSpringRedirectRe, line)
		}
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

// ---------------------------------------------------------------------------
// Wave-1 SAST rules (VGL-WEB-023..025)
// ---------------------------------------------------------------------------

// pbPHPInfoRule flags phpinfo() calls in PHP code. String literals and line
// comments (including PHP's # form) are ignored, and the language gate keeps
// prose in other file types quiet.
func pbPHPInfoRule(f *File) []model.Finding {
	if f == nil || f.Language != "php" || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		code := StripInlineHashComment(line, f.Language)
		if pbComment(f, line) || strings.HasPrefix(strings.TrimSpace(code), "#") ||
			!injCodeMatch(pbPHPInfoRe, code) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

// pbZipSlipGuardNear reports whether a containment check compares the joined
// target with the extraction destination root close enough to the sink. A
// path-normalisation call such as Clean or realpath is not a containment check
// on its own. The tarfile filter=/members= arguments only count inside the
// extraction call itself: a local variable with either name is not a guard.
func pbZipSlipGuardNear(f *File, idx int, dest, target string) bool {
	for j := idx - 3; j <= idx+6; j++ {
		if j < 0 || j >= len(f.Lines) {
			continue
		}
		if pbComment(f, f.Lines[j]) {
			continue
		}
		line := f.Lines[j]
		if pbZipSlipSafeRe.MatchString(line) {
			return true
		}
		if j == idx && pbZipSlipSafeArgNear(f, idx, line) {
			return true
		}
		if pbZipSlipContainmentLine(line, dest, target) {
			return true
		}
	}
	return false
}

// pbZipSlipSafeArgNear reports whether filter=/members= appears inside the
// arguments of the extraction or path-building call that starts on line idx.
// The arguments may continue on the next lines, but statements outside the
// call do not restrict what the archive API consumes.
func pbZipSlipSafeArgNear(f *File, idx int, line string) bool {
	loc := pbFirstCodeMatch(pbZipSlipSinkRe, line)
	if loc < 0 {
		return false
	}
	return pbZipSlipSafeArgRe.MatchString(pbParenSpan(f, idx, loc))
}

// pbParenSpan returns the text of the call whose opening parenthesis follows
// start, following a balanced parenthesis across at most six lines. Lines that
// follow a complete call are not part of the span.
func pbParenSpan(f *File, idx, start int) string {
	if f == nil || idx < 0 || idx >= len(f.Lines) || start < 0 {
		return ""
	}
	if start >= len(f.Lines[idx]) {
		return ""
	}
	var b strings.Builder
	depth := 0
	var quote byte
	escaped := false
	for j := idx; j < len(f.Lines) && j <= idx+5; j++ {
		text := f.Lines[j]
		if j == idx {
			text = text[start:]
		}
		for i := 0; i < len(text); i++ {
			c := text[i]
			if quote != 0 {
				if escaped {
					escaped = false
					continue
				}
				switch c {
				case '\\':
					escaped = true
				case quote:
					quote = 0
				}
				continue
			}
			switch c {
			case '\'', '"', '`':
				quote = c
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					b.WriteString(text[:i+1])
					return b.String()
				}
			}
		}
		b.WriteString(text)
		b.WriteByte('\n')
	}
	return b.String()
}

// pbZipSlipContainmentLine reports whether line compares target against dest
// with a separator-aware check (filepath.Rel, HasPrefix(target, dest+sep) or
// startswith(dest + os.sep)).
func pbZipSlipContainmentLine(line, dest, target string) bool {
	if dest == "" || target == "" {
		return false
	}
	for _, fn := range []string{"filepath.Rel", "filepath.rel", "os.path.relpath", "relpath"} {
		args := pbCallArgsNamed(line, fn)
		if len(args) >= 2 && strings.Contains(args[0], dest) && strings.Contains(args[1], target) {
			return true
		}
	}
	for _, fn := range []string{"strings.HasPrefix", "HasPrefix", "hasPrefix"} {
		args := pbCallArgsNamed(line, fn)
		if len(args) >= 2 && strings.Contains(args[0], target) && pbZipSlipDestRoot(args[1], dest) {
			return true
		}
	}
	for _, fn := range []string{"startswith"} {
		args := pbCallArgsNamed(line, fn)
		if len(args) >= 1 && pbZipSlipDestRoot(args[0], dest) && strings.Contains(line, target) {
			return true
		}
	}
	if args := pbCallArgsNamed(line, "os.path.commonpath"); len(args) >= 1 {
		joined := strings.Join(args, ",")
		if strings.Contains(joined, dest) && strings.Contains(joined, target) &&
			(strings.Contains(line, "==") || strings.Contains(line, "!=")) {
			return true
		}
	}
	return false
}

// pbCallArgsNamed returns the top-level arguments of fn(...) in line.
func pbCallArgsNamed(line, fn string) []string {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(fn) + `\s*\(`)
	loc := re.FindStringIndex(line)
	if loc == nil {
		return nil
	}
	return injCallArgs(line, loc[1]-1)
}

// pbZipSlipDestRoot reports whether arg is the destination root plus a path
// separator, optionally wrapped in filepath.Clean or filepath.Abs.
func pbZipSlipDestRoot(arg, dest string) bool {
	s := strings.TrimSpace(arg)
	if !strings.Contains(s, dest) || !strings.Contains(s, "+") {
		return false
	}
	rest := s[strings.Index(s, "+"):]
	for _, sep := range []string{"os.PathSeparator", "os.sep", "PathSeparator", "separator", `"` + "/" + `"`, `'` + "/" + `'`, `"` + `\\` + `"`, `'` + `\\` + `'`, "/"} {
		if strings.Contains(rest, sep) {
			return true
		}
	}
	return false
}

// pbZipSlipDest returns the destination root identifier of a path-building
// sink, or "" when the line does not expose one.
func pbZipSlipDest(line string) string {
	if m := pbZipSlipJoinRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := pbZipSlipResolveRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := pbZipSlipNewFileRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// pbZipSlipTarget returns the variable that receives the joined path.
func pbZipSlipTarget(line string) string {
	if m := pbUploadAssignRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// pbZipSlipWriteNear reports whether a write or move sink uses target within
// a few lines of the path construction. A read-only sink does not count.
func pbZipSlipWriteNear(f *File, idx int, target string) bool {
	for j := idx; j <= idx+3 && j < len(f.Lines); j++ {
		if pbComment(f, f.Lines[j]) {
			continue
		}
		line := f.Lines[j]
		if !pbZipSlipWriteRe.MatchString(line) {
			continue
		}
		if j == idx {
			return true
		}
		if target == "" {
			continue
		}
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(target) + `\b`).MatchString(line) {
			return true
		}
	}
	return false
}

// pbZipSlipRule flags archive extraction sinks that build a path from an entry
// name without a containment guard. High confidence when the entry name is
// visible in the sink call; medium for extract-all APIs that iterate members
// internally and carry no filter/members restriction.
func pbZipSlipRule(f *File) []model.Finding {
	if f == nil || !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	if !pbArchiveContextRe.MatchString(string(f.Content)) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbZipSlipSinkRe.MatchString(line) {
			continue
		}
		dest := pbZipSlipDest(line)
		target := pbZipSlipTarget(line)
		if pbZipSlipGuardNear(f, i, dest, target) {
			continue
		}
		confidence := model.ConfidenceHigh
		extraction := pbZipSlipExtractRe.MatchString(line)
		if !extraction {
			if !pbZipSlipMemberRe.MatchString(line) {
				continue
			}
			// Path construction alone is not an extraction write: require a
			// write or move sink that uses the constructed target.
			if !pbZipSlipWriteNear(f, i, target) {
				continue
			}
		} else if !pbZipSlipMemberRe.MatchString(line) {
			confidence = model.ConfidenceMedium
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = confidence
		out = append(out, fd)
	}
	return out
}

// pbUploadSourceRe returns the client-supplied filename accessor for a
// language. Multer's server-generated file.filename is deliberately not a
// source; originalname is.
func pbUploadSourceRe(language string) *regexp.Regexp {
	switch language {
	case "php":
		return pbUploadPHPNameRe
	case "python":
		return pbUploadPyNameRe
	case "javascript", "typescript":
		return pbUploadJSNameRe
	case "java":
		return pbUploadJavaNameRe
	case "go":
		return pbUploadGoNameRe
	default:
		return nil
	}
}

// pbUploadFilenameRule flags a client-supplied upload filename that reaches a
// write, move or join sink on the same line or through one variable within
// three lines. A sanitizer/generated name in that span suppresses the finding.
// In Python, a bare X.filename is not a source: only request.files,
// FileStorage, a file/upload parameter or a request-derived variable count.
func pbUploadFilenameRule(f *File) []model.Finding {
	if f == nil || !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	if pbUploadSourceRe(f.Language) == nil && f.Language != "python" {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbUploadSourceLine(f, i, line) {
			continue
		}
		if pbUploadSanitizeRe.MatchString(line) {
			continue
		}
		if pbUploadSinkLine(f, line) && pbUploadSinkApplies(f, i, line) {
			same := pbUploadSameExpression(f, i, line)
			if !same && !pbUploadStatementLink(f, i, line) {
				continue
			}
			fd := pbFinding(f, i+1, line)
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			if !same {
				fd.Confidence = model.ConfidenceMedium
			}
			out = append(out, fd)
			continue
		}
		name := ""
		if m := pbUploadAssignRe.FindStringSubmatch(line); m != nil {
			name = m[1]
		}
		if name == "" {
			continue
		}
		word := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		for j := i + 1; j <= i+3 && j < len(f.Lines); j++ {
			next := f.Lines[j]
			if pbComment(f, next) {
				continue
			}
			if pbUploadSanitizeRe.MatchString(next) {
				break
			}
			if !pbUploadSinkLine(f, next) || !word.MatchString(next) {
				continue
			}
			if !pbUploadSinkApplies(f, j, next) {
				continue
			}
			fd := pbFinding(f, j+1, next)
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceMedium
			out = append(out, fd)
			break
		}
	}
	return out
}

// pbUploadSourceLine reports whether line carries a client-supplied filename
// from an upload request. Python needs the stricter origin check.
func pbUploadSourceLine(f *File, idx int, line string) bool {
	if f.Language == "python" {
		return pbPyUploadSource(f, idx, line)
	}
	source := pbUploadSourceRe(f.Language)
	return source != nil && injCodeMatch(source, line)
}

// pbPyUploadSource reports whether line reads a client-supplied upload
// filename. A bare self.filename or user.name is not an upload; the receiver
// must be request.files, a FileStorage/UploadedFile value, a parameter named
// file/upload/filename, or a variable assigned from one of those earlier in
// the function. Django exposes the client filename as .name.
func pbPyUploadSource(f *File, idx int, line string) bool {
	for _, re := range []*regexp.Regexp{pbUploadPyNameRe, pbUploadPyDjangoRe} {
		if pbPyUploadSourceMatch(f, idx, line, re) {
			return true
		}
	}
	return false
}

// pbPyUploadSourceMatch reports whether one filename accessor on line is an
// upload source.
func pbPyUploadSourceMatch(f *File, idx int, line string, re *regexp.Regexp) bool {
	for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
		if len(m) < 4 {
			continue
		}
		if inString, inComment := codeContextAt(line, m[2]); inString || inComment {
			continue
		}
		recv := line[m[2]:m[3]]
		switch strings.ToLower(recv) {
		case "file", "upload", "filename":
			return true
		case "]", ")":
			if injCodeMatch(pbUploadPyRequestRe, line[:m[0]]) {
				return true
			}
			continue
		}
		if pbPyUploadOrigin(f, idx, recv) {
			return true
		}
	}
	return false
}

// pbPyUploadOrigin reports whether name was declared as a FileStorage or
// UploadedFile upload, or assigned from request.files, in the lines just above
// idx.
func pbPyUploadOrigin(f *File, idx int, name string) bool {
	word := regexp.QuoteMeta(name)
	assign := regexp.MustCompile(`(?i)\b` + word + `\s*=\s*(?:[A-Za-z_][\w]*\.)*(?:request\s*\.\s*files|FileStorage|UploadedFile|InMemoryUploadedFile|TemporaryUploadedFile|UploadFile|file|upload)\b`)
	typed := regexp.MustCompile(`(?i)\b` + word + `\s*:\s*(?:[A-Za-z_][\w]*\.)*(?:FileStorage|UploadedFile|InMemoryUploadedFile|TemporaryUploadedFile|UploadFile)\b`)
	for j := idx; j >= 0 && j >= idx-10; j-- {
		line := f.Lines[j]
		if IsCommentLine(line, f.Language) {
			continue
		}
		if assign.MatchString(line) || typed.MatchString(line) {
			return true
		}
	}
	return false
}

// pbUploadSinkLine reports whether line contains an upload write/move sink.
// Python's Path.write_* and os.replace are not in the generic sink list, and
// ESM imports drop the fs./path. prefix in JavaScript and TypeScript.
func pbUploadSinkLine(f *File, line string) bool {
	if pbUploadSinkRe.MatchString(line) {
		return true
	}
	if pbUploadESSink(f, line) {
		return true
	}
	return f.Language == "python" && pbUploadPyWriteRe.MatchString(line)
}

// pbUploadESSink reports whether line calls a bare ESM fs/path import.
func pbUploadESSink(f *File, line string) bool {
	if f.Language != "javascript" && f.Language != "typescript" {
		return false
	}
	return injCodeMatch(pbUploadESSinkRe, line)
}

// pbUploadSinkIndex returns the first sink offset on line, outside strings and
// comments, including the language-specific sinks.
func pbUploadSinkIndex(f *File, line string) int {
	best := pbFirstCodeMatch(pbUploadSinkRe, line)
	if py := pbFirstCodeMatch(pbUploadPyWriteRe, line); py >= 0 && (best < 0 || py < best) {
		best = py
	}
	if es := pbFirstCodeMatch(pbUploadESSinkRe, line); es >= 0 && (best < 0 || es < best) && pbUploadESSink(f, line) {
		best = es
	}
	return best
}

// pbUploadLineWrites reports whether line writes or moves the uploaded bytes.
// Path construction alone (join, new File, Paths.get) is not a write.
func pbUploadLineWrites(f *File, line string) bool {
	if pbUploadWriteRe.MatchString(line) {
		return true
	}
	if f.Language == "php" && pbUploadPHPMoveRe.MatchString(line) {
		return true
	}
	return f.Language == "python" && pbUploadPyWriteRe.MatchString(line)
}

// pbUploadSinkApplies reports whether the sink line actually writes or moves
// the upload. In every language a bare join or File constructor needs a
// write/move of the constructed target nearby: stat, read-only open and other
// lookups are not upload writes. Python's open() only counts with a
// write/append mode.
func pbUploadSinkApplies(f *File, idx int, line string) bool {
	if pbUploadLineWrites(f, line) {
		return true
	}
	if !pbUploadJoinSinkRe.MatchString(line) {
		return false
	}
	return pbUploadWriteNear(f, idx, line)
}

// pbUploadWriteNear reports whether line writes or moves, or the path it
// assigns is written or moved within three lines.
func pbUploadWriteNear(f *File, idx int, line string) bool {
	if pbUploadLineWrites(f, line) {
		return true
	}
	name := ""
	if m := pbUploadAssignRe.FindStringSubmatch(line); m != nil {
		name = m[1]
	}
	if name == "" {
		return false
	}
	word := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	for j := idx + 1; j <= idx+3 && j < len(f.Lines); j++ {
		next := f.Lines[j]
		if pbComment(f, next) {
			continue
		}
		if pbUploadLineWrites(f, next) && word.MatchString(next) {
			return true
		}
	}
	return false
}

// pbUploadSameExpression reports whether a source and sink on one line are
// part of the same expression (no top-level statement separator between them).
func pbUploadSameExpression(f *File, idx int, line string) bool {
	sink := pbUploadSinkIndex(f, line)
	if sink < 0 {
		return true
	}
	for _, src := range pbUploadSourceIndexes(f, idx, line) {
		lo, hi := src, sink
		if lo > hi {
			lo, hi = hi, lo
		}
		same := true
		for i := lo; i < hi; i++ {
			if line[i] != ';' {
				continue
			}
			if inString, _ := codeContextAt(line, i); !inString {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// pbUploadStatementLink reports whether a source on the same minified line is
// assigned to a variable that the later sink statement uses. It keeps
// `const n=file.originalname;fs.writeFileSync(p,n)` detectable at medium
// confidence while dropping unrelated statements.
func pbUploadStatementLink(f *File, idx int, line string) bool {
	src, sink := pbUploadSourceSinkIndex(f, idx, line)
	if src < 0 || sink < 0 {
		return false
	}
	segStart := strings.LastIndex(line[:src], ";") + 1
	segEnd := len(line)
	for i := src; i < len(line); i++ {
		if line[i] == ';' {
			segEnd = i
			break
		}
	}
	name := ""
	if m := pbUploadAssignRe.FindStringSubmatch(line[segStart:segEnd]); m != nil {
		name = m[1]
	}
	if name == "" {
		return false
	}
	sinkStart := sink
	if sink < src {
		sinkStart = src
	}
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(line[sinkStart:])
}

// pbUploadSourceSinkIndex returns the first source and sink offsets on line.
func pbUploadSourceSinkIndex(f *File, idx int, line string) (int, int) {
	srcs := pbUploadSourceIndexes(f, idx, line)
	src := -1
	if len(srcs) > 0 {
		src = srcs[0]
	}
	return src, pbUploadSinkIndex(f, line)
}

// pbUploadSourceIndexes returns every source offset on line, outside strings
// and comments. Python needs the same upload-origin check as the rule body:
// .filename is only a source on an upload, and Django's .name only on one.
func pbUploadSourceIndexes(f *File, idx int, line string) []int {
	var out []int
	add := func(re *regexp.Regexp) {
		for _, loc := range re.FindAllStringIndex(line, -1) {
			if inString, inComment := codeContextAt(line, loc[0]); !inString && !inComment {
				out = append(out, loc[0])
			}
		}
	}
	if f.Language == "python" {
		add(pbUploadPyNameRe)
		if pbPyUploadSourceMatch(f, idx, line, pbUploadPyDjangoRe) {
			add(pbUploadPyDjangoRe)
		}
		if len(out) == 0 {
			add(pbUploadPyRequestRe)
		}
		return out
	}
	if source := pbUploadSourceRe(f.Language); source != nil {
		add(source)
	}
	return out
}

// pbFirstCodeMatch returns the first index of re outside strings and comments.
func pbFirstCodeMatch(re *regexp.Regexp, line string) int {
	for _, loc := range re.FindAllStringIndex(line, -1) {
		if inString, inComment := codeContextAt(line, loc[0]); !inString && !inComment {
			return loc[0]
		}
	}
	return -1
}
