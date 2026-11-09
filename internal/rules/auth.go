package rules

import (
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	pbJSJWTDecodeRe     = regexp.MustCompile(`(?i)\b(?:jwt|jsonwebtoken)\.decode\s*\(`)
	pbPyJWTUnverifiedRe = regexp.MustCompile(`(?i)\bget_unverified_claims\s*\(|\bget_unverified_header\s*\(|\bparse_unverified\s*\(`)
	pbGoJWTUnverifiedRe = regexp.MustCompile(`(?i)\bParseUnverified\s*\(|\bParseWithClaims\s*\([^)]*nil\s*\)`)
	pbJavaJWTUnverified = regexp.MustCompile(`(?i)\bparseClaimsJwt\s*\(|\bparseUnverified\s*\(`)
	pbJWTVerifyOffRe    = regexp.MustCompile(`(?i)\bverify\s*=\s*False\b|["']verify["']\s*:\s*false|verify_signature["']?\s*[:=]\s*(?:False|false)|["']verify_signature["']\s*:\s*False|options\s*=\s*\{[^}]*verify[^}]*[Ff]alse`)

	pbCookieInsecureRe = regexp.MustCompile(`(?i)\bhttpOnly\s*:\s*false|\bsecure\s*:\s*false|\bhttponly\s*=\s*False|\bsecure\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False`)
	pbSameSiteNoneRe   = regexp.MustCompile(`(?i)sameSite\s*:\s*["']none["']|SameSite=None`)
	pbSetCookieRe      = regexp.MustCompile(`(?i)Set-Cookie|set_cookie\s*\(|res\.cookie\s*\(|response\.set_cookie\s*\(`)

	pbCORSStarRe  = regexp.MustCompile(`(?i)Access-Control-Allow-Origin["']?\s*[:=]\s*["']?\*|origin\s*:\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*`)
	pbCORSCredsRe = regexp.MustCompile(`(?i)Access-Control-Allow-Credentials["']?\s*[:=]\s*["']?true|credentials\s*:\s*true|allow_credentials\s*=\s*True|supports_credentials\s*=\s*True`)

	pbCSRFDisabledRe = regexp.MustCompile(`(?i)@csrf_exempt|csrf_exempt\s*\(|CSRF_ENABLED\s*=\s*False|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*\([^)]*\)\s*\.\s*disable\s*\(|csrf\s*\.\s*disable\s*\(|csrf\s*:\s*false|csrfProtection\s*:\s*false|csrf_exempt\s*=\s*True`)

	pbDefaultPasswordRe = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])([A-Za-z0-9_]*(?:password|passwd|pwd))\s*["']?\s*[:=]\s*["']?(admin123|admin|root|password|passw0rd|12345678|123456|letmein|qwerty|welcome|changeme|secret|default)\b["']?`)
	pbDefaultDBRe       = regexp.MustCompile(`(?i)(?:mysql|postgres(?:ql)?|mongodb|redis)://[^:\s/@]+:(admin|root|password|123456|changeme)@`)

	pbCompareOpRe  = regexp.MustCompile(`(?:===|!==|==|!=)`)
	pbTimingSafeRe = regexp.MustCompile(`(?i)compare_digest|ConstantTimeCompare|timingSafeEqual|hmac\.Equal|secure_compare|subtle\.ConstantTimeByteEq`)

	pbOAuthAuthorizeRe = regexp.MustCompile(`(?i)response_type\s*[:=]\s*["']?code|/oauth(?:2)?/authorize|/authorize\?|authorizeUrl|authorizationUrl|authorize_url`)
	pbOAuthStateRe     = regexp.MustCompile(`(?i)\bstate\b\s*[:=]`)

	pbClientRoleRe = regexp.MustCompile(`(?i)(?:req|request)\.(?:headers|query|body)\s*[\[.]\s*["']?(?:x-(?:user|admin|role|forwarded-user|remote-user)|role|is_?admin|admin)["']?|r\.Header\.Get\(\s*"(?:X-User-Role|X-Admin|X-Forwarded-User|X-Remote-User)"\s*\)|request\.headers\.get\(\s*["']X-(?:User|Admin|Forwarded-User|Remote-User)`)
)

// AuthRules returns the authentication and session rules.
func AuthRules() []Rule {
	return []Rule{
		New(model.RuleMeta{
			ID:          "VGL-AUTH-001",
			Title:       "JWT decoded without signature verification",
			Description: "Decoding a JWT without verifying its signature trusts attacker-controlled claims. Always call the verifying API with an explicit algorithm allow-list.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-347"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"jwt", "auth"},
		}, pbJWTDecodeRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-002",
			Title:       "JWT signature verification explicitly disabled",
			Description: "Options such as verify=False or verify_signature:false turn JWT authentication into an unauthenticated parse. Remove them and pin the expected algorithms.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-347"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"jwt", "auth"},
		}, pbJWTVerifyOffRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-003",
			Title:       "Session cookie missing Secure, HttpOnly or SameSite",
			Description: "Session cookies need HttpOnly (no script access), Secure (HTTPS only) and an explicit SameSite policy. SameSite=None additionally requires Secure.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-614", "CWE-1004"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"session", "cookie"},
		}, pbCookieFlagsRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-004",
			Title:       "CORS wildcard combined with credentials",
			Description: "Access-Control-Allow-Origin:* together with Access-Control-Allow-Credentials:true lets any site read authenticated responses. Echo only an allow-listed origin.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-942"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"cors", "auth"},
		}, pbCORSCredentialsRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-005",
			Title:       "CSRF protection disabled",
			Description: "Disabling CSRF protection on cookie-authenticated endpoints allows cross-site requests to perform state changes as the victim.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-352"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"csrf", "auth"},
		}, pbCSRFDisabledRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-006",
			Title:       "Default or well-known administrative password",
			Description: "Default credentials such as admin/admin are the first thing attackers try. Require a unique password or bootstrap secret and force rotation.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-1392", "CWE-798"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"password", "default"},
		}, pbDefaultPasswordRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-007",
			Title:       "Timing-unsafe comparison of a secret",
			Description: "Comparing passwords, tokens or signatures with == leaks timing information. Use a constant-time comparison such as hmac.compare_digest or crypto/subtle.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-208"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"auth", "timing"},
		}, pbTimingCompareRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-008",
			Title:       "OAuth authorization request without state parameter",
			Description: "An authorization request without a state value is open to login CSRF. Generate a random state, bind it to the session and verify it on callback.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-352"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"oauth", "csrf"},
		}, pbOAuthStateRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-009",
			Title:       "Authorization decision trusts a client-controlled role header",
			Description: "Reading roles from request headers, query parameters or the body lets a caller grant themselves privileges unless a trusted proxy strips and re-adds the value.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-639"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"authz", "headers"},
		}, pbClientRoleRule),
	}
}

func pbJWTDecodeRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		var hit bool
		switch f.Language {
		case "javascript", "typescript":
			hit = pbJSJWTDecodeRe.MatchString(line)
		case "python":
			hit = pbPyJWTUnverifiedRe.MatchString(line)
		case "go":
			hit = pbGoJWTUnverifiedRe.MatchString(line)
		case "java":
			hit = pbJavaJWTUnverified.MatchString(line)
		default:
			hit = pbPyJWTUnverifiedRe.MatchString(line) || pbGoJWTUnverifiedRe.MatchString(line) || pbJavaJWTUnverified.MatchString(line)
		}
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

func pbJWTVerifyOffRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbJWTVerifyOffRe.MatchString(line) {
			continue
		}
		// A bare verify=False is a requests/SSL option, not JWT. Require JWT
		// context for that form; verify_signature is unambiguous on its own.
		if !pbHasAnyFold(line, "jwt", "jsonwebtoken", "jose", "verify_signature", "decode") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbCookieFlagsRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		if pbCookieInsecureRe.MatchString(line) {
			fd := pbFinding(f, i+1, line)
			fd.Severity = pbSev(f, model.SeverityMedium)
			fd.Confidence = model.ConfidenceHigh
			out = append(out, fd)
			continue
		}
		if pbSameSiteNoneRe.MatchString(line) && !pbHasAnyFold(line, "secure") {
			fd := pbFinding(f, i+1, line)
			fd.Severity = pbSev(f, model.SeverityMedium)
			fd.Confidence = model.ConfidenceHigh
			out = append(out, fd)
			continue
		}
		if !pbSetCookieRe.MatchString(line) {
			continue
		}
		window := strings.ToLower(f.Window(i+1, 2))
		if strings.Contains(window, "httponly") && strings.Contains(window, "secure") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

func pbCORSCredentialsRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	starLine := 0
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		if pbCORSStarRe.MatchString(line) {
			starLine = i + 1
			break
		}
	}
	if starLine == 0 || !pbCORSCredsRe.MatchString(string(f.Content)) {
		return nil
	}
	fd := pbFinding(f, starLine, f.Line(starLine))
	fd.Severity = pbSev(f, model.SeverityHigh)
	fd.Confidence = model.ConfidenceHigh
	return []model.Finding{fd}
}

func pbCSRFDisabledRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbCSRFDisabledRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbDefaultPasswordRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || pbTranslationCatalog(f.Path) {
		return nil
	}
	typeOnly := pbTypeOnlyLines(f)
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || typeOnly[i+1] {
			continue
		}
		trimmed := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(trimmed, "type ") || strings.HasPrefix(trimmed, "export type ") ||
			strings.HasPrefix(trimmed, "declare type ") {
			continue
		}
		lhs, value := "", ""
		quoted := false
		if m := pbDefaultPasswordRe.FindStringSubmatch(line); m != nil {
			lhs, value = m[1], m[2]
			quoted = strings.Contains(m[0], `"`+value) || strings.Contains(m[0], `'`+value)
		} else if m := pbDefaultDBRe.FindStringSubmatch(line); m != nil {
			value = m[1]
			quoted = true
		}
		if value == "" {
			continue
		}
		// In a programming language a bare identifier on the right is a
		// variable, not a literal default ("currentPassword: password").
		// Shell, .env and config formats treat it as a literal.
		if !quoted && !pbUnquotedDefaultAllowed(f.Language) {
			continue
		}
		// Enum members map an ALL_CAPS name to the same lower-case word:
		// PASSWORD = 'password'. A real default such as
		// DEFAULT_PASSWORD = 'admin' does not satisfy this shape.
		if lhs != "" && pbIsAllCaps(lhs) && strings.EqualFold(value, lhs) {
			continue
		}
		evidence := line
		if idx := strings.LastIndex(evidence, value); idx >= 0 {
			evidence = evidence[:idx] + MaskSecret(value) + evidence[idx+len(value):]
		}
		fd := pbFinding(f, i+1, evidence)
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbTimingCompareRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	authPath := pbTimingAuthPath(f.Path)
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || pbTimingSafeRe.MatchString(line) {
			continue
		}
		if !pbTimingComparisonLine(line, authPath) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

// pbTypeOnlyLines marks lines that live inside an enum, interface or type
// alias block. A string literal there is a type member, not a runtime default.
func pbTypeOnlyLines(f *File) map[int]bool {
	out := map[int]bool{}
	depth := 0
	blockDepth := -1
	for i, line := range f.Lines {
		if blockDepth < 0 && pbOpensTypeOnlyBlock(line) {
			blockDepth = depth + 1
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if blockDepth >= 0 {
			out[i+1] = true
			if depth < blockDepth {
				blockDepth = -1
			}
		}
	}
	return out
}

func pbOpensTypeOnlyBlock(line string) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.Contains(trimmed, "{") {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "enum ") {
		return true
	}
	for _, prefix := range []string{"interface ", "export interface ", "declare interface "} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, prefix := range []string{"type ", "export type ", "declare type "} {
		if strings.HasPrefix(lower, prefix) && strings.Contains(lower, "=") {
			return true
		}
	}
	return false
}

func pbIsAllCaps(s string) bool {
	hasLetter := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= 'A' && r <= 'Z' {
			hasLetter = true
		}
	}
	return hasLetter
}

// pbTranslationCatalog reports whether path is a UI translation catalog. A
// locale entry such as "auth.login.password": "Password" is a label, not a
// default credential; flagging it as a critical finding is pure noise.
func pbTranslationCatalog(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, marker := range []string{
		"i18n/", "locales/", "locale/", "translations/", "translation/",
		"l10n/", "lang/", "langs/",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

// pbUnquotedDefaultAllowed reports whether a bare word on the right of an
// assignment is a literal in this language. In Python/JS/Go a bare identifier
// is a variable reference, so "currentPassword: password" is not a default.
func pbUnquotedDefaultAllowed(language string) bool {
	switch language {
	case "shell", "yaml", "json", "toml", "other", "dockerfile":
		return true
	default:
		return false
	}
}

// pbTimingComparisonLine reports whether line contains a comparison that is
// plausibly a secret check rather than a type guard, a length check or an
// overloaded "token"/"hash" identity comparison.
func pbTimingComparisonLine(line string, authPath bool) bool {
	for _, loc := range pbCompareOpRe.FindAllStringIndex(line, -1) {
		if inString, inComment := codeContextAt(line, loc[0]); inString || inComment {
			continue
		}
		left := pbLeftOperand(line, loc[0])
		right := pbRightOperand(line, loc[1])
		if left == "" || right == "" {
			continue
		}
		if pbTimingSkipOperand(left) || pbTimingSkipOperand(right) {
			continue
		}
		// Byte-wise comparisons of two indexed values are usually format or
		// magic-byte checks (bytes[i] !== signature[i]), not secret checks.
		if strings.Contains(left, "[") && strings.Contains(right, "[") {
			continue
		}
		leftLit, leftVal := pbOperandLiteral(left)
		rightLit, rightVal := pbOperandLiteral(right)
		if leftLit && !pbCredentialLikeValue(leftVal) {
			continue
		}
		if rightLit && !pbCredentialLikeValue(rightVal) {
			continue
		}
		leftName, rightName := pbOperandName(left), pbOperandName(right)
		// Comparing the same field on two objects (r.secretKey ===
		// criteria.secretKey) is an identity filter, not a secret check.
		if leftName != "" && strings.EqualFold(leftName, rightName) {
			continue
		}
		leftStrong, leftToken, leftWeak := pbOperandSecretClass(left)
		rightStrong, rightToken, rightWeak := pbOperandSecretClass(right)
		if !leftStrong && !leftToken && !leftWeak && !rightStrong && !rightToken && !rightWeak {
			continue
		}
		if leftStrong || rightStrong {
			return true
		}
		// A bare token/key/hash is heavily overloaded: word tokens, cache
		// digests, day keys and dedupe claims all use those names. Only treat a
		// weak match as a secret when it is a token comparison in auth code or
		// the other side is a credential literal.
		if (leftToken || rightToken) && (authPath || leftLit || rightLit) {
			return true
		}
	}
	return false
}

func pbTimingSkipOperand(op string) bool {
	s := strings.ToLower(strings.TrimSpace(op))
	if strings.HasPrefix(s, "typeof ") {
		return true
	}
	if strings.Contains(s, ".length") || strings.Contains(s, ".size") {
		return true
	}
	if strings.Contains(s, "sentinel") || strings.Contains(s, "placeholder") {
		return true
	}
	// ALL_CAPS operands are enum members or constants (UserAuthProvider.PASSWORD,
	// IDP_PASSWORD_SET_SENTINEL), not runtime secret values.
	return pbIsAllCaps(pbOperandName(op))
}

func pbLeftOperand(line string, end int) string {
	if end > len(line) {
		end = len(line)
	}
	s := line[:end]
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ',', ';', '{', '}', '?', '=', ':':
			return strings.TrimSpace(s[i+1:])
		case '&', '|':
			if i > 0 && s[i-1] == s[i] {
				return strings.TrimSpace(s[i+1:])
			}
		}
	}
	return strings.TrimSpace(s)
}

func pbRightOperand(line string, start int) string {
	if start >= len(line) {
		return ""
	}
	s := line[start:]
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ')', ',', ';', '?', '&', '|', '}', '{':
			return strings.TrimSpace(s[:i])
		case '=':
			if i+1 < len(s) && s[i+1] == '>' {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return strings.TrimSpace(s)
}

func pbOperandLiteral(op string) (bool, string) {
	s := strings.TrimSpace(op)
	s = strings.TrimLeft(s, "!&|+- ")
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		switch s[0] {
		case '\'', '"', '`':
			if end := strings.LastIndexByte(s[1:], s[0]); end >= 0 {
				return true, s[1 : 1+end]
			}
			return true, s[1:]
		}
	}
	switch strings.ToLower(s) {
	case "null", "undefined", "none", "nil", "true", "false", "0":
		return true, s
	}
	if pbNumericLiteral(s) {
		return true, s
	}
	return false, ""
}

func pbNumericLiteral(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		if i == 0 && (r == '-' || r == '+') {
			continue
		}
		if r == '.' {
			continue
		}
		return false
	}
	return true
}

func pbOperandName(op string) string {
	s := strings.TrimSpace(op)
	s = strings.TrimLeft(s, "!&|+- ")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	switch s[0] {
	case '\'', '"', '`':
		return ""
	}
	s = pbTrimTrailingGroup(s, '[', ']')
	s = pbTrimTrailingGroup(s, '(', ')')
	if s == "" {
		return ""
	}
	switch s[0] {
	case '\'', '"', '`':
		return ""
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	// The operand may still contain a keyword ("return password") or an
	// operator. The secret-bearing identifier is the last one.
	last := ""
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			last = cur.String()
			cur.Reset()
		}
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '$' {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return last
}

// pbTrimTrailingGroup removes balanced trailing groups such as the arguments of
// lastUsedWrites.get(tokenId) or the index of rightTokens[index].
func pbTrimTrailingGroup(s string, open, close byte) string {
	for {
		s = strings.TrimSpace(s)
		if s == "" || s[len(s)-1] != close {
			return s
		}
		depth := 0
		start := -1
		for i := len(s) - 1; i >= 0; i-- {
			switch s[i] {
			case close:
				depth++
			case open:
				depth--
				if depth == 0 {
					start = i
				}
			}
			if start >= 0 {
				break
			}
		}
		if start < 0 {
			return s
		}
		s = s[:start]
	}
}

func pbOperandSecretClass(op string) (strong, token, weak bool) {
	words := pbSplitIdentifierWords(pbOperandName(op))
	for _, w := range words {
		switch w {
		case "password", "passwd", "passphrase", "secret", "signature", "hmac", "credential", "apikey":
			strong = true
		case "token":
			token = true
		case "key", "hash", "digest", "mac", "otp":
			weak = true
		}
	}
	for _, pair := range [][2]string{
		{"api", "key"}, {"private", "key"}, {"access", "key"}, {"secret", "key"},
		{"auth", "key"}, {"signing", "key"},
		{"auth", "token"}, {"access", "token"}, {"refresh", "token"}, {"csrf", "token"},
		{"session", "token"}, {"bearer", "token"}, {"id", "token"},
		{"verification", "token"}, {"reset", "token"}, {"signing", "token"},
		{"webhook", "token"}, {"claim", "token"}, {"bot", "token"}, {"api", "token"},
	} {
		if pbHasWordPair(words, pair[0], pair[1]) {
			strong = true
		}
	}
	return strong, token, weak
}

func pbHasWordPair(words []string, first, second string) bool {
	for i := 0; i+1 < len(words); i++ {
		if words[i] == first && words[i+1] == second {
			return true
		}
	}
	return false
}

func pbSplitIdentifierWords(name string) []string {
	runes := []rune(name)
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	for i, r := range runes {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '$') {
			flush()
			continue
		}
		if r == '_' || r == '-' || r == '$' {
			flush()
			continue
		}
		if r >= 'A' && r <= 'Z' && i > 0 {
			prev := runes[i-1]
			if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') {
				flush()
			} else if prev >= 'A' && prev <= 'Z' && i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z' {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

func pbTimingAuthPath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, marker := range []string{
		"auth", "security", "password", "secret", "token", "session", "mfa",
		"otp", "csrf", "login", "credential", "jwt", "crypto", "webhook",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func pbCredentialLikeValue(v string) bool {
	return len(v) >= 8 && !secLooksLikeNameOrLabel(v)
}

func pbOAuthStateRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || !pbCodeLanguage(f.Language) {
		return nil
	}
	authorizeLine := 0
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		if pbOAuthAuthorizeRe.MatchString(line) {
			authorizeLine = i + 1
			break
		}
	}
	if authorizeLine == 0 || pbOAuthStateRe.MatchString(string(f.Content)) {
		return nil
	}
	fd := pbFinding(f, authorizeLine, f.Line(authorizeLine))
	fd.Severity = pbSev(f, model.SeverityMedium)
	fd.Confidence = model.ConfidenceLow
	return []model.Finding{fd}
}

func pbClientRoleRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || !pbCodeLanguage(f.Language) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbClientRoleRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceLow
		out = append(out, fd)
	}
	return out
}
