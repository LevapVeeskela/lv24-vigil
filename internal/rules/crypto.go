package rules

import (
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ---------------------------------------------------------------------------
// Shared helpers for the pack-B rule families (crypto, auth, web, config, CI
// and dependencies). Names are prefixed with "pb" so they cannot collide with
// helpers introduced by other rule packs in this package.
// ---------------------------------------------------------------------------

// pbFinding builds a finding at a 1-based line with the standard snippet.
func pbFinding(f *File, line int, evidence string) model.Finding {
	if line < 1 {
		line = 1
	}
	return model.Finding{
		Location: model.Location{
			Path:      f.Path,
			StartLine: line,
			EndLine:   line,
			Snippet:   Snippet(f, line, 1),
		},
		Evidence: Truncate(strings.TrimSpace(evidence), 240),
	}
}

// pbSev lowers severity for documentation and fixture paths.
func pbSev(f *File, base model.Severity) model.Severity {
	return SeverityForLanguage(base, f.Path)
}

// pbCodeLanguage reports whether lang is a source language these packs reason
// about. "other" is included because small projects often have extensionless
// scripts; findings there are still evidence-based.
func pbCodeLanguage(lang string) bool {
	switch lang {
	case "go", "python", "javascript", "typescript", "java", "php", "ruby",
		"csharp", "rust", "shell", "other":
		return true
	default:
		return false
	}
}

// pbHasAny reports whether s contains any of subs (case-sensitive).
func pbHasAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// pbHasAnyFold reports whether s contains any of subs, ignoring case.
func pbHasAnyFold(s string, subs ...string) bool {
	l := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(l, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// pbDocsPath reports whether path is documentation, where most runtime rules
// should stay quiet or be downgraded.
func pbDocsPath(path string) bool {
	return isDocsPath(strings.ToLower(strings.ReplaceAll(path, "\\", "/")))
}

// pbComment reports whether line is a comment in the file's language.
func pbComment(f *File, line string) bool {
	return IsCommentLine(line, f.Language)
}

// ---------------------------------------------------------------------------
// Crypto rules
// ---------------------------------------------------------------------------

var (
	pbWeakHashRe        = regexp.MustCompile(`(?i)\b(md5|sha1)\b`)
	pbWeakHashContextRe = regexp.MustCompile(`(?i)password|passwd|passphrase|signature|hmac|token|secret|credential|\bsign\s*\(`)
	// HMAC-SHA1 is the required primitive for TOTP/HOTP (RFC 6238 / RFC 4226),
	// and PBKDF2-SHA1 is a legacy-but-not-broken KDF choice. Those lines are
	// not password hashing even though they mention SHA1.
	pbWeakHashAllowedRe = regexp.MustCompile(`(?i)\bhmac\b|createHmac|HmacSHA|otpauth|\btotp\b|\bhotp\b|pbkdf2|algorithm=SHA1`)
	pbWeakCipherRe      = regexp.MustCompile(`(?i:\b(?:3des|tripledes|desede|rc4)\b)|crypto/(?:des|rc4)\b|\bDES\b|\bRC4\b|\b(?:des|rc4)\.New(?:Cipher|TripleDESCipher)`)
	pbECBRe             = regexp.MustCompile(`(?i)\bECB\b|/ECB/|mode\.ECB|MODE_ECB`)
	pbStaticIVRe        = regexp.MustCompile(`(?i)\b(?:iv|initialization_?vector|nonce)\b\s*[:=]\s*(?:\[\]byte\()?[bB]?["'][0-9a-fA-F]{8,}["']|IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{|\b(?:iv|nonce)\s*=\s*bytes\(\s*["'][0-9a-fA-F]{8,}["']`)
	pbInsecureRandRe    = regexp.MustCompile(`(?i)\bmath/rand\b|\brand\.(?:Intn|Int31|Int63|Float32|Float64|New|Seed|Shuffle|Perm)\s*\(|\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|shuffle|sample)\s*\(|Math\.random\s*\(|crypto\.pseudoRandomBytes\s*\(|\bpseudoRandomBytes\s*\(`)
	pbSecretContextRe   = regexp.MustCompile(`(?i)token|password|passwd|secret|nonce|session|api_?key|otp|reset|salt|csrf|verification`)
	pbBcryptRe          = regexp.MustCompile(`(?i)\bbcrypt\b|gensalt|bcryptpasswordencoder`)
	pbBcryptCostRe      = regexp.MustCompile(`(?i)(?:gensalt\s*\(\s*(?:rounds\s*=\s*)?|generatefrompassword\s*\([^,]+,\s*|bcryptpasswordencoder\s*\(\s*|cost\s*[:=]\s*|rounds\s*[:=]\s*|workfactor\s*[:=]\s*)([0-9]{1,2})`)
	pbGoTLSRe           = regexp.MustCompile(`(?i)InsecureSkipVerify\s*:\s*true|InsecureSkipVerify\s*=\s*true`)
	pbPyTLSRe           = regexp.MustCompile(`(?i)\bverify\s*=\s*False\b|ssl\.CERT_NONE\b|_create_unverified_context\s*\(`)
	pbNodeTLSRe         = regexp.MustCompile(`(?i)rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|strictSSL\s*:\s*false`)
	pbCurlInsecureRe    = regexp.MustCompile(`(?i)\bcurl\b[^\n|]*\s(?:-[a-zA-Z]*k[a-zA-Z]*|--insecure)\b|\bwget\b[^\n|]*--no-check-certificate\b`)
	pbJWTNoneRe         = regexp.MustCompile(`(?i)["']?alg["']?\s*[:=]\s*["']none["']|algorithms?\s*[:=]\s*\[[^\]]*["']none["']`)
	pbRSAWeakRe         = regexp.MustCompile(`(?i)(?:generatekey|genrsa|rsa[_-]?key[_-]?size|keysize|key_size|bits|initialize)\D{0,24}(512|1024|1536)\b|rsa\.GenerateKey\([^,]+,\s*(512|1024|1536)\)`)

	// VGL-CRY-013: Java trust-all TrustManager / HostnameVerifier.
	pbJavaTrustAllNameRe        = regexp.MustCompile(`(?i)\b(?:TrustAllCerts|TrustAllManager|TrustAllTrustManager|AllTrustingTrustManager|AcceptAllTrustManager)\b`)
	pbJavaX509TrustManagerRe    = regexp.MustCompile(`(?i)\b(?:implements\s+X509TrustManager|new\s+X509TrustManager\s*\()`)
	pbJavaCheckServerTrustedRe  = regexp.MustCompile(`(?i)\bvoid\s+checkServerTrusted\s*\(`)
	pbJavaHostnameVerifierRe    = regexp.MustCompile(`(?i)\bverify\s*\(\s*(?:final\s+)?String\s+\w+\s*,\s*(?:final\s+)?SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;`)
	pbJavaHostnameVerifierClsRe = regexp.MustCompile(`(?i)\bnew\s+HostnameVerifier\s*\(`)
	pbJavaVerifyMethodRe        = regexp.MustCompile(`(?i)\bboolean\s+verify\s*\(`)

	// VGL-CRY-014: .NET certificate validation callbacks.
	pbDotNetCertCallbackRe  = regexp.MustCompile(`(?i)\b(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|RemoteCertificateValidationCallback)\s*\+?=`)
	pbDotNetCertTrueArrowRe = regexp.MustCompile(`(?i)\b(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|RemoteCertificateValidationCallback)\s*\+?=\s*(?:delegate\s*)?(?:\([^)]*\)|\w+)\s*=>\s*true\b`)
	pbDotNetDangerousCertRe = regexp.MustCompile(`(?i)\bDangerousAcceptAnyServerCertificateValidator\b`)
	pbDotNetCertSafeTokenRe = regexp.MustCompile(`(?i)SslPolicyErrors|ValidateCertificate|CustomValidator|X509Chain|chain\.Build|==|!=|\bif\s*\(`)

	// VGL-CRY-015: PHP / Ruby TLS verification disabled.
	pbPHPTLSVerifyOffRe    = regexp.MustCompile(`(?i)CURLOPT_SSL_VERIFYPEER\s*=>\s*(?:false|0)\b|CURLOPT_SSL_VERIFYHOST\s*=>\s*(?:0|false)\b|curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYHOST\s*,\s*(?:0|false)\b|["']verify_peer(?:_?name)?["']\s*=>\s*false\b`)
	pbPHPVerifyPeerOffRe   = regexp.MustCompile(`(?i)["']verify_peer(?:_?name)?["']\s*=>\s*(?:false|0)\b`)
	pbPHPAllowSelfSignedRe = regexp.MustCompile(`(?i)["']allow_self_signed["']\s*=>\s*true\b`)
	pbRubyTLSVerifyOffRe   = regexp.MustCompile(`(?i)\bOpenSSL::SSL::VERIFY_NONE\b|\bverify_mode\s*[:=]\s*(?:OpenSSL::SSL::)?VERIFY_NONE\b|\bssl_verify_mode\s*[:=]\s*(?:0|:none)\b`)
	pbRubyVerifyFalseRe    = regexp.MustCompile(`(?i)\bverify\s*:\s*false\b`)
	pbRubyTLSContextRe     = regexp.MustCompile(`(?i)\bssl\b|\btls\b|faraday|httparty|net::http|rest-client`)

	// VGL-CRY-017: legacy SSLv3 / TLS 1.0 / TLS 1.1 pinned in code.
	pbGoLegacyTLSRe     = regexp.MustCompile(`(?i)\b(?:MinVersion|MaxVersion)\s*:\s*tls\.Version(?:SSL30|TLS10|TLS11)\b`)
	pbGoLegacyTLSBareRe = regexp.MustCompile(`(?i)\btls\.Version(?:SSL30|TLS10|TLS11)\b`)
	pbPyLegacyTLSRe     = regexp.MustCompile(`(?i)\bssl\.PROTOCOL_(?:SSLv3|TLSv1|TLSv1_1)\b`)
	pbJavaLegacyTLSRe   = regexp.MustCompile(`(?i)SSLContext\.getInstance\(\s*"(?:SSLv3|TLSv1|TLSv1\.1)"\s*\)|setEnabledProtocols\s*\([^)]*"(?:SSLv3|TLSv1|TLSv1\.1)"`)
	pbCSharpLegacyTLSRe = regexp.MustCompile(`(?i)\bSslProtocols\.(?:Ssl3|Tls|Tls11)\b|\bSecurityProtocolType\.(?:Ssl3|Tls|Tls11)\b`)
	pbNodeLegacyTLSRe   = regexp.MustCompile(`(?i)\bminVersion\s*:\s*["'](?:SSLv3|TLSv1|TLSv1\.1)["']|\bsecureProtocol\s*:\s*["'](?:SSLv3|TLSv1|TLSv1_1)_method["']`)
	pbRubyLegacyTLSRe   = regexp.MustCompile(`(?i)\bssl_version\s*[:=]\s*["']?:?(?:SSLv3|TLSv1_1|TLSv1)\b`)
	pbPHPLegacyTLSRe    = regexp.MustCompile(`(?i)CURLOPT_SSLVERSION\s*=>\s*CURL_SSLVERSION_(?:SSLv3|TLSv1(?:_0|_1)?)\b|STREAM_CRYPTO_METHOD_(?:SSLv3|TLSv1_0|TLSv1_1)_CLIENT`)
)

// CryptoRules returns the cryptographic hygiene rules.
func CryptoRules() []Rule {
	return []Rule{
		New(model.RuleMeta{
			ID:          "VGL-CRY-001",
			Title:       "Weak hash algorithm used for passwords or signatures",
			Description: "MD5 and SHA-1 are not collision resistant and are far too fast for password storage. Use Argon2id, scrypt or bcrypt for passwords and SHA-256+ for signatures.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-328", "CWE-916"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"crypto", "hashing"},
		}, pbWeakHashRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-002",
			Title:       "Broken or legacy cipher (DES, RC4 or 3DES)",
			Description: "DES and RC4 are broken; 3DES is deprecated and vulnerable to Sweet32. Use AES-GCM or ChaCha20-Poly1305.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-327"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"crypto", "cipher"},
		}, pbWeakCipherRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-003",
			Title:       "AES ECB mode used",
			Description: "ECB encrypts identical blocks identically and leaks plaintext structure. Use an authenticated mode such as AES-GCM.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-327"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"crypto", "aes"},
		}, pbECBRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-004",
			Title:       "Hardcoded initialization vector or nonce",
			Description: "A constant IV/nonce makes encryption deterministic and can break confidentiality. Generate a fresh random IV per message and store it with the ciphertext.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-329"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"crypto", "iv"},
		}, pbStaticIVRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-005",
			Title:       "Insecure randomness used for security values",
			Description: "math/rand, Python random, Math.random and crypto.pseudoRandomBytes are predictable and must not generate tokens, passwords, nonces or session identifiers. Use a CSPRNG.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-338"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"crypto", "random"},
		}, pbInsecureRandRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-006",
			Title:       "Weak bcrypt work factor",
			Description: "A bcrypt cost below 10 is cheap to brute force on modern hardware. Use a cost of at least 10, ideally 12 or higher.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-916"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"crypto", "password"},
		}, pbBcryptCostRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-007",
			Title:       "TLS certificate verification disabled (Go)",
			Description: "InsecureSkipVerify disables certificate validation and makes the client vulnerable to man-in-the-middle attacks.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			Languages:   []string{"go"},
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"tls", "go"},
		}, pbGoTLSRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-008",
			Title:       "TLS certificate verification disabled (Python)",
			Description: "verify=False and ssl.CERT_NONE disable certificate validation and expose requests to interception.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			Languages:   []string{"python"},
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"tls", "python"},
		}, pbPyTLSRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-009",
			Title:       "TLS certificate verification disabled (Node.js)",
			Description: "rejectUnauthorized:false or NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate validation for the whole process.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			Languages:   []string{"javascript", "typescript"},
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"tls", "nodejs"},
		}, pbNodeTLSRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-010",
			Title:       "TLS verification disabled in curl or wget",
			Description: "curl -k / --insecure and wget --no-check-certificate skip certificate validation and enable interception.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"tls", "shell"},
		}, pbCurlInsecureRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-011",
			Title:       "JWT 'none' algorithm accepted",
			Description: "Accepting alg=none lets anyone forge tokens. Pin an explicit allow-list of signed algorithms and reject none.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-347"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"jwt", "crypto"},
		}, pbJWTNoneRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-012",
			Title:       "RSA key shorter than 2048 bits",
			Description: "RSA keys below 2048 bits are considered weak. Generate at least 2048-bit keys (3072 or 4096 preferred for long-lived keys).",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-326"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"crypto", "rsa"},
		}, pbRSAWeakRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-013",
			Title:       "TLS certificate verification disabled (Java trust-all TrustManager)",
			Description: "An X509TrustManager with an empty checkServerTrusted accepts every certificate, and a HostnameVerifier that returns true accepts every host. Use the platform TrustManagerFactory and the default hostname verifier.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryCrypto,
			Languages:   []string{"java"},
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021", "A07:2021"},
			Tags:        []string{"tls", "java"},
		}, pbJavaTrustAllRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-014",
			Title:       "TLS certificate verification disabled (.NET validation callback)",
			Description: "A certificate validation callback that returns true unconditionally disables chain and hostname validation for HttpClient and ServicePointManager. Check SslPolicyErrors or delegate to a real validator.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			Languages:   []string{"csharp"},
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021", "A07:2021"},
			Tags:        []string{"tls", "dotnet"},
		}, pbDotNetTrustAllRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-015",
			Title:       "TLS certificate verification disabled (PHP or Ruby)",
			Description: "CURLOPT_SSL_VERIFYPEER=false, CURLOPT_SSL_VERIFYHOST=0 and OpenSSL VERIFY_NONE disable certificate validation, making every HTTPS call interceptable. Keep verification on and configure a CA bundle instead.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			Languages:   []string{"php", "ruby"},
			CWE:         []string{"CWE-295"},
			OWASP:       []string{"A02:2021", "A07:2021"},
			Tags:        []string{"tls", "php", "ruby"},
		}, pbPHPRubyTLSRule),

		New(model.RuleMeta{
			ID:          "VGL-CRY-017",
			Title:       "Legacy SSLv3, TLS 1.0 or TLS 1.1 pinned in code",
			Description: "SSLv3 is broken (POODLE) and RFC 8996 deprecates TLS 1.0 and TLS 1.1. Pin TLS 1.2 or newer instead of an exact legacy protocol version.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCrypto,
			CWE:         []string{"CWE-326", "CWE-327"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"tls", "protocol"},
		}, pbLegacyTLSVersionRule),
	}
}

func pbWeakHashRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbWeakHashRe.MatchString(line) || !pbWeakHashContextRe.MatchString(line) {
			continue
		}
		if pbWeakHashAllowedRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbWeakCipherRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbWeakCipherRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbECBRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbECBRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbStaticIVRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbStaticIVRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

func pbInsecureRandRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbInsecureRandRe.MatchString(line) {
			continue
		}
		// pseudoRandomBytes is predictable regardless of the surrounding name.
		if !pbHasAnyFold(line, "pseudorandombytes") && !pbSecretContextRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbBcryptCostRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbBcryptRe.MatchString(line) {
			continue
		}
		weak := pbHasAnyFold(line, "mincost")
		if !weak {
			if m := pbBcryptCostRe.FindStringSubmatch(line); m != nil {
				cost := 0
				for _, r := range m[1] {
					cost = cost*10 + int(r-'0')
				}
				weak = cost > 0 && cost < 10
			}
		}
		if !weak {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbGoTLSRule(f *File) []model.Finding {
	if f.Language != "go" || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbGoTLSRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbPyTLSRule(f *File) []model.Finding {
	if f.Language != "python" || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbPyTLSRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbNodeTLSRule(f *File) []model.Finding {
	if f.Language != "javascript" && f.Language != "typescript" {
		return nil
	}
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbNodeTLSRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbCurlInsecureRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbCurlInsecureRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbJWTNoneRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbJWTNoneRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbRSAWeakRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbRSAWeakRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// VGL-CRY-013 — Java trust-all TrustManager / HostnameVerifier
// ---------------------------------------------------------------------------

func pbJavaTrustAllRule(f *File) []model.Finding {
	if f.Language != "java" || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	reported := map[int]bool{}
	add := func(line int, evidence string, conf model.Confidence) {
		if line < 1 || reported[line] {
			return
		}
		reported[line] = true
		fd := pbFinding(f, line, evidence)
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = conf
		out = append(out, fd)
	}
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if pbJavaTrustAllNameRe.MatchString(line) &&
			!strings.HasPrefix(trimmed, "import ") && !strings.HasPrefix(trimmed, "package ") {
			add(i+1, line, model.ConfidenceHigh)
		}
		if pbJavaHostnameVerifierRe.MatchString(line) {
			add(i+1, line, model.ConfidenceHigh)
		}
		if pbJavaX509TrustManagerRe.MatchString(line) {
			for _, j := range pbJavaEmptyCheckServerTrusted(f, i) {
				add(j+1, f.Line(j+1), model.ConfidenceHigh)
			}
		}
		if pbJavaHostnameVerifierClsRe.MatchString(line) {
			if j, ok := pbJavaHostnameVerifierTrustAll(f, i); ok {
				add(j+1, f.Line(j+1), model.ConfidenceHigh)
			}
		}
	}
	return out
}

// pbJavaEmptyCheckServerTrusted scans up to 40 lines after an X509TrustManager
// declaration for checkServerTrusted implementations with an empty body.
func pbJavaEmptyCheckServerTrusted(f *File, idx int) []int {
	var out []int
	limit := idx + 40
	if limit >= len(f.Lines) {
		limit = len(f.Lines) - 1
	}
	for j := idx; j <= limit; j++ {
		if pbComment(f, f.Lines[j]) || !pbJavaCheckServerTrustedRe.MatchString(f.Lines[j]) {
			continue
		}
		stmt, ok := pbJavaMethodBodyFirstStatement(f, j, 6)
		if ok && pbJavaBodyIsEmpty(stmt) {
			out = append(out, j)
		}
	}
	return out
}

// pbJavaHostnameVerifierTrustAll scans a `new HostnameVerifier()` block for a
// verify method whose only statement is `return true;`.
func pbJavaHostnameVerifierTrustAll(f *File, idx int) (int, bool) {
	limit := idx + 10
	if limit >= len(f.Lines) {
		limit = len(f.Lines) - 1
	}
	for j := idx; j <= limit; j++ {
		if pbComment(f, f.Lines[j]) || !pbJavaVerifyMethodRe.MatchString(f.Lines[j]) {
			continue
		}
		stmt, ok := pbJavaMethodBodyFirstStatement(f, j, 6)
		if !ok {
			return 0, false
		}
		return j, strings.HasPrefix(strings.ToLower(strings.TrimSpace(stmt)), "return true")
	}
	return 0, false
}

// pbJavaMethodBodyFirstStatement returns the first non-blank, non-comment line
// of the Java method body that opens on line idx (or on one of the following
// lines). A body that closes on the same line returns the text before `}`.
// The second result is false for an abstract/interface declaration, which has
// no body and must not be treated as an empty implementation.
func pbJavaMethodBodyFirstStatement(f *File, idx, lookahead int) (string, bool) {
	line := f.Lines[idx]
	if strings.HasSuffix(strings.TrimSpace(line), ";") {
		return "", false
	}
	open := strings.Index(line, "{")
	if open < 0 {
		for j := idx + 1; j <= idx+lookahead && j < len(f.Lines); j++ {
			candidate := strings.TrimSpace(f.Lines[j])
			if candidate == "" || pbComment(f, f.Lines[j]) {
				continue
			}
			if i := strings.Index(candidate, "{"); i >= 0 {
				idx = j
				line = f.Lines[j]
				open = i
				break
			}
			if strings.Contains(candidate, ";") || strings.HasPrefix(candidate, "}") {
				return "", false
			}
		}
	}
	if open < 0 {
		return "", false
	}
	rest := line[open+1:]
	if end := strings.Index(rest, "}"); end >= 0 {
		return strings.TrimSpace(rest[:end]), true
	}
	for j := idx + 1; j <= idx+lookahead && j < len(f.Lines); j++ {
		candidate := strings.TrimSpace(f.Lines[j])
		if candidate == "" || pbComment(f, f.Lines[j]) {
			continue
		}
		return candidate, true
	}
	// The body did not start within the lookahead window; do not guess that it
	// is empty.
	return "", false
}

// pbJavaBodyIsEmpty reports whether the inspected body statement is absent or
// is the closing brace of an empty method.
func pbJavaBodyIsEmpty(stmt string) bool {
	stmt = strings.TrimSpace(stmt)
	return stmt == "" || strings.HasPrefix(stmt, "}")
}

// ---------------------------------------------------------------------------
// VGL-CRY-014 — .NET certificate validation callback
// ---------------------------------------------------------------------------

func pbDotNetTrustAllRule(f *File) []model.Finding {
	if f.Language != "csharp" || pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		sev := pbSev(f, model.SeverityHigh)
		switch {
		case pbDotNetCertTrueArrowRe.MatchString(line), pbDotNetDangerousCertRe.MatchString(line):
			fd := pbFinding(f, i+1, line)
			fd.Severity = sev
			fd.Confidence = model.ConfidenceHigh
			out = append(out, fd)
		case pbDotNetCertCallbackRe.MatchString(line) && pbDotNetBlockArrow(line):
			window := strings.Join(f.Lines[i+1:min(i+6, len(f.Lines))], "\n")
			if !pbHasAnyFold(window, "return true") || pbDotNetCertSafeTokenRe.MatchString(window) {
				continue
			}
			fd := pbFinding(f, i+1, line)
			fd.Severity = sev
			fd.Confidence = model.ConfidenceMedium
			out = append(out, fd)
		}
	}
	return out
}

// pbDotNetBlockArrow reports whether an assignment line ends with `=>` or
// `=> {`, meaning the callback body starts on a following line.
func pbDotNetBlockArrow(line string) bool {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimSuffix(trimmed, "{")
	return strings.HasSuffix(strings.TrimSpace(trimmed), "=>")
}

// ---------------------------------------------------------------------------
// VGL-CRY-015 — PHP / Ruby TLS verification disabled
// ---------------------------------------------------------------------------

func pbPHPRubyTLSRule(f *File) []model.Finding {
	if f.Language != "php" && f.Language != "ruby" {
		return nil
	}
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
		case "php":
			hit = pbPHPTLSVerifyOffRe.MatchString(line)
			if !hit && pbPHPAllowSelfSignedRe.MatchString(line) {
				hit = pbPHPStreamContextDisablesVerify(f, i)
			}
		case "ruby":
			hit = pbRubyTLSVerifyOffRe.MatchString(line)
			if !hit && pbRubyVerifyFalseRe.MatchString(line) {
				hit = pbRubyTLSContextWindow(f, i)
			}
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

// pbPHPStreamContextDisablesVerify reports whether the surrounding
// stream_context_create window also turns verify_peer off.
func pbPHPStreamContextDisablesVerify(f *File, idx int) bool {
	start := idx - 10
	if start < 0 {
		start = 0
	}
	end := idx + 10
	if end >= len(f.Lines) {
		end = len(f.Lines) - 1
	}
	window := strings.Join(f.Lines[start:end+1], "\n")
	return pbHasAnyFold(window, "stream_context_create") && pbPHPVerifyPeerOffRe.MatchString(window)
}

// pbRubyTLSContextWindow reports whether `verify: false` belongs to an SSL
// client configuration rather than an unrelated option hash.
func pbRubyTLSContextWindow(f *File, idx int) bool {
	start := idx - 2
	if start < 0 {
		start = 0
	}
	for j := start; j <= idx; j++ {
		if pbRubyTLSContextRe.MatchString(f.Lines[j]) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// VGL-CRY-017 — legacy TLS protocol versions pinned in code
// ---------------------------------------------------------------------------

func pbLegacyTLSVersionRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var re *regexp.Regexp
	switch f.Language {
	case "go":
		re = pbGoLegacyTLSRe
	case "python":
		re = pbPyLegacyTLSRe
	case "java":
		re = pbJavaLegacyTLSRe
	case "csharp":
		re = pbCSharpLegacyTLSRe
	case "javascript", "typescript":
		re = pbNodeLegacyTLSRe
	case "ruby":
		re = pbRubyLegacyTLSRe
	case "php":
		re = pbPHPLegacyTLSRe
	default:
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		hit := re.MatchString(line)
		if !hit && f.Language == "go" && pbGoLegacyTLSBareRe.MatchString(line) {
			hit = pbGoTLSConfigWindow(f, i)
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

// pbGoTLSConfigWindow reports whether a tls.Config literal is in scope on the
// current line or within the previous five lines.
func pbGoTLSConfigWindow(f *File, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	for j := start; j <= idx; j++ {
		if strings.Contains(f.Lines[j], "tls.Config") {
			return true
		}
	}
	return false
}
