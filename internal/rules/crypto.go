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
