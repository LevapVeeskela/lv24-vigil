package rules

import (
	"strings"
	"testing"
)

// RedactSecrets fixtures are assembled at runtime so this test file never
// contains a contiguous live-looking credential.
var (
	redactTestAWSKey = "AKIA" + "Z7Q2LMN4RSTUVWXY"
	redactTestGitHub = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUvWxYz1Bc2D"
	redactTestJWT    = strings.Join([]string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"eyJzdWIiOiIxMjM0NTY3ODkwIn0",
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}, ".")
)

// TestRedactSecretsMasksWellKnownShapes: arbitrary text keeps its non-secret
// content while every credential shape is replaced with its MaskSecret form.
func TestRedactSecretsMasksWellKnownShapes(t *testing.T) {
	input := strings.Join([]string{
		"aws=" + redactTestAWSKey,
		"github=" + redactTestGitHub,
		"jwt=" + redactTestJWT,
		"note=plain text",
	}, " ")

	got := RedactSecrets(input, nil)

	for _, raw := range []string{redactTestAWSKey, redactTestGitHub, redactTestJWT} {
		if strings.Contains(got, raw) {
			t.Errorf("RedactSecrets left %q in the output", raw)
		}
	}
	for _, want := range []string{
		MaskSecret(redactTestAWSKey),
		MaskSecret(redactTestGitHub),
		MaskSecret(redactTestJWT),
		"note=plain text",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RedactSecrets output missing %q: %q", want, got)
		}
	}
}

// TestRedactSecretsLeavesOrdinaryText: the hard redactor must not rewrite text
// that carries no credential shape.
func TestRedactSecretsLeavesOrdinaryText(t *testing.T) {
	for _, input := range []string{
		"",
		"plain error message",
		"key = value",
		"https://example.com/path?query=1",
		"AKIA is a prefix, not a key",
	} {
		if got := RedactSecrets(input, nil); got != input {
			t.Errorf("RedactSecrets(%q) = %q, want it unchanged", input, got)
		}
	}
}

// TestMaskSecretShape pins the existing masking contract: a short prefix, a
// fixed mask and a short suffix, never the value itself.
func TestMaskSecretShape(t *testing.T) {
	got := MaskSecret(redactTestAWSKey)
	if got != "AKIA********XY" {
		t.Errorf("MaskSecret(%q) = %q, want the 4+8+2 shape", redactTestAWSKey, got)
	}
	if got := MaskSecret("short"); got != "********" {
		t.Errorf("MaskSecret(short value) = %q, want all stars", got)
	}
}
