package scanner

import (
	"strings"
	"testing"
)

// fuzzDiffMaxBytes keeps one fuzz iteration cheap. ParseDiff is linear in the
// input, but the fuzzer would otherwise spend its budget on multi-megabyte
// strings instead of exploring the hunk-header state machine.
const fuzzDiffMaxBytes = 64 << 10

// FuzzParseDiff checks that arbitrary bytes never panic the unified-diff
// parser and that every returned range is a sane, bounded, 1-based range.
//
// Contract: ParseDiff may return an error for malformed input, but every range
// it returns (with or without an error) must be sane: Start >= 1,
// End >= Start, and End no larger than the padded-line budget plus the number
// of lines actually present in the diff (a hunk advances at most one line per
// diff line).
func FuzzParseDiff(f *testing.F) {
	f.Add("")
	f.Add("   \n\n")
	f.Add("--- a/main.go\n+++ b/main.go\n@@ -1 +1,2 @@\n package main\n+var x int\n")
	f.Add("diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -0,0 +1,4 @@\n+a\n+b\n+c\n+d\n")
	f.Add("--- a/main.go\n+++ b/main.go\n@@ -1,2 +0,0 @@\n-a\n-b\n")
	f.Add("--- /dev/null\n+++ b/new.go\n@@ -0,0 +1,2 @@\n+package new\n+var y int\n")
	f.Add("--- a/a.go\n+++ b/a.go\n@@ -1,2 +1,3 @@\n a\n+b\n c\n")
	f.Add("--- \"a/a b.go\"\n+++ \"b/a b.go\"\n@@ -1 +1 @@\n-x\n+y\n")
	f.Add("--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-x\n\\ No newline at end of file\n+y\n")
	// Out-of-range hunk starts must be rejected, not turned into line 0 or an
	// enormous line number (regression for the ParseDiff range guard).
	f.Add("--- a/x.go\n+++ b/x.go\n@@ -0,0 +0,1 @@\n+x\n")
	f.Add("--- a/x.go\n+++ b/x.go\n@@ -0,0 +99999999999999999999,1 @@\n+x\n")
	f.Add("--- a/x.go\n+++ b/x.go\n@@ -0,0 +99999999,1 @@\n+x\n")
	f.Add("@@ malformed @@\n")
	f.Add("@@ -1 +1 @@\n+unterminated")

	f.Fuzz(func(t *testing.T, diff string) {
		if len(diff) > fuzzDiffMaxBytes {
			return
		}
		// A parse error is allowed (malformed input fails closed), but any
		// ranges returned alongside the error must still be valid.
		ranges, _ := ParseDiff(diff)
		// Every recorded addition consumes at most one diff line, so the
		// header start plus the diff line count is a hard upper bound.
		maxLine := maxDiffPaddedLines + strings.Count(diff, "\n") + 1
		for path, rs := range ranges {
			if path == "" {
				t.Fatalf("range for an empty path: %#v", rs)
			}
			for _, r := range rs {
				if r.Start < 1 {
					t.Fatalf("path %q: Start = %d, want >= 1 (range %#v)", path, r.Start, r)
				}
				if r.End < r.Start {
					t.Fatalf("path %q: End = %d < Start = %d (range %#v)", path, r.End, r.Start, r)
				}
				if r.End > maxLine {
					t.Fatalf("path %q: End = %d exceeds the bound %d (range %#v)", path, r.End, maxLine, r)
				}
			}
		}
	})
}

// TestParseDiffLineRangesArePositive is the explicit regression test for the
// range guard: a hunk that adds lines must not report line 0 (Atoi overflow or
// "+0,N") and must not report a line beyond the padded-line budget.
func TestParseDiffLineRangesArePositive(t *testing.T) {
	rejected := []string{
		"--- a/x.go\n+++ b/x.go\n@@ -0,0 +0,1 @@\n+x\n",
		"--- a/x.go\n+++ b/x.go\n@@ -0,0 +99999999999999999999,1 @@\n+x\n",
		"--- a/x.go\n+++ b/x.go\n@@ -0,0 +99999999,1 @@\n+x\n",
	}
	for _, diff := range rejected {
		if _, err := ParseDiff(diff); err == nil {
			t.Errorf("ParseDiff accepted an out-of-range hunk header:\n%s", diff)
		}
	}

	// A pure deletion legitimately uses "+0,0"; it records no additions and
	// must keep parsing without an error.
	got, err := ParseDiff("--- a/x.go\n+++ b/x.go\n@@ -1,2 +0,0 @@\n-a\n-b\n")
	if err != nil {
		t.Fatalf("ParseDiff(deletion): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("deletion produced ranges: %#v", got)
	}

	// The largest accepted hunk start is still reported verbatim.
	got, err = ParseDiff("--- a/x.go\n+++ b/x.go\n@@ -0,0 +1999999,1 @@\n+x\n")
	if err != nil {
		t.Fatalf("ParseDiff(large start): %v", err)
	}
	rs := got["x.go"]
	if len(rs) != 1 || rs[0] != (LineRange{Start: 1999999, End: 1999999}) {
		t.Fatalf("large start ranges = %#v", rs)
	}
}

// FuzzGlobMatch checks that arbitrary patterns and paths cannot panic the
// ignore matcher and that exclude/include matching stays deterministic.
//
// Semantics (see compileGlob): patterns are slash-normalised, only '*', '**'
// and '?' are wildcards, every other character is literal (no character
// classes and no escaping), a pattern without a slash matches a base name at
// any depth, and a trailing slash makes the pattern directory-only. A pattern
// that normalises to nothing is dropped: it excludes nothing and, if it was
// the only include pattern, includes everything (fail open).
func FuzzGlobMatch(f *testing.F) {
	f.Add("*.go", "internal/main.go")
	f.Add("**/*.lock", "a/b/c.lock")
	f.Add("src/**/generated/*.go", "src/a/b/generated/x.go")
	f.Add("build/", "build")
	f.Add("file?.txt", "file1.txt")
	f.Add("a+b.txt", "a+b.txt")
	f.Add("x[1].txt", "x[1].txt")
	f.Add("", "")
	f.Add("   ", "a/b")
	f.Add("./node_modules/**", "node_modules/pkg/index.js")
	f.Add(`vendor\**`, `vendor\pkg\x.go`)
	f.Add("**", "deep/nested/path")
	f.Add("?", "")

	f.Fuzz(func(t *testing.T, pattern, path string) {
		if len(pattern) > 4096 || len(path) > 4096 {
			return
		}
		compiled := compileGlob(pattern)
		m := newIgnoreMatcher([]string{pattern}, []string{pattern})

		ignored := m.ignored(path, false)
		included := m.included(path)
		if compiled != nil && ignored != included {
			t.Fatalf("pattern %q path %q: ignored=%v included=%v, want the same decision",
				pattern, path, ignored, included)
		}
		if got := m.ignored(path, false); got != ignored {
			t.Fatalf("pattern %q path %q: non-deterministic decision %v then %v",
				pattern, path, ignored, got)
		}
	})
}
