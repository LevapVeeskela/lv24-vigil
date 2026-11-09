package gitutil

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzGitRefValidation checks that arbitrary base refs cannot panic the
// validator and that the security contract holds for every input:
//
//   - a ref that starts with '-' is rejected (git would parse it as an option,
//     for example --output=... or --ext-diff);
//   - a ref containing whitespace or a control character is rejected;
//   - every other ref is accepted (the caller turns an empty ref into HEAD).
//
// validateRef is unexported, so this fuzz target lives in-package and exercises
// the real helper instead of paying for a git subprocess per input.
func FuzzGitRefValidation(f *testing.F) {
	f.Add("HEAD")
	f.Add("main")
	f.Add("origin/main")
	f.Add("v1.2.3")
	f.Add("HEAD~3")
	f.Add("HEAD^2")
	f.Add("refs/heads/feature/x")
	f.Add("")
	f.Add("-")
	f.Add("--output=/tmp/pwned")
	f.Add("--ext-diff")
	f.Add("-c")
	f.Add("HEAD extra")
	f.Add("HEAD\n--output=/tmp/pwned")
	f.Add("HEAD\t")
	f.Add("HEAD\x00")
	f.Add("\x1b[31m")
	f.Add("ветка")
	f.Add("a:b")
	f.Add(strings.Repeat("a", 512))

	f.Fuzz(func(t *testing.T, ref string) {
		if len(ref) > 4096 {
			return
		}
		err := validateRef(ref)
		if ref == "" {
			if err != nil {
				t.Fatalf("validateRef(%q) = %v, want nil (callers default an empty ref to HEAD)", ref, err)
			}
			return
		}
		if strings.HasPrefix(ref, "-") {
			if err == nil {
				t.Fatalf("validateRef(%q) accepted an option-like ref", ref)
			}
			return
		}
		for _, r := range ref {
			if unicode.IsSpace(r) || unicode.IsControl(r) {
				if err == nil {
					t.Fatalf("validateRef(%q) accepted a ref with whitespace or a control character", ref)
				}
				return
			}
		}
		if err != nil {
			t.Fatalf("validateRef(%q) = %v, want nil for a ref without whitespace, control characters or a leading '-'", ref, err)
		}
	})
}

// TestValidateRefContract pins the table of accepted and rejected refs.
func TestValidateRefContract(t *testing.T) {
	accepted := []string{
		"",
		"HEAD",
		"main",
		"origin/main",
		"v1.2.3",
		"HEAD~3",
		"HEAD^2",
		"refs/heads/feature/x",
		"a:b",
		"ветка",
	}
	for _, ref := range accepted {
		if err := validateRef(ref); err != nil {
			t.Errorf("validateRef(%q) = %v, want nil", ref, err)
		}
	}

	rejected := []string{
		"-",
		"-c",
		"--ext-diff",
		"--output=/tmp/pwned",
		"--upload-pack=evil",
		"HEAD extra",
		"HEAD\t",
		"HEAD\n--output=/tmp/pwned",
		"HEAD\x00",
		"\x1b[31m",
		" ",
	}
	for _, ref := range rejected {
		if err := validateRef(ref); err == nil {
			t.Errorf("validateRef(%q) = nil, want an error", ref)
		}
	}
}
