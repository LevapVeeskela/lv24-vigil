package tools

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// testProposal builds a proposal as proposeFix would, without a model.
func testProposal(t *testing.T, root, diff string, targets map[string]string) *pendingProposal {
	t.Helper()
	createdAt := time.Now().UTC()
	return &pendingProposal{
		Version:     pendingProposalVersion,
		FixID:       proposalID(diff, createdAt),
		FindingID:   "VGL-TESTFINDING",
		ScanID:      "scan-test",
		Root:        root,
		Description: "test fix",
		Diff:        diff,
		DiffSHA256:  sha256Hex(diff),
		Files:       []string{"a.txt"},
		Targets:     targets,
		CreatedAt:   createdAt,
		ExpiresAt:   createdAt.Add(pendingProposalTTL),
	}
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", want)
	}
	te := asToolError(err)
	if te == nil {
		t.Fatalf("error is not typed: %v", err)
	}
	if te.Code != want {
		t.Fatalf("code = %q, want %q (message: %s)", te.Code, want, te.Message)
	}
}

const targetDiff = `diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-one
+two
`

func TestPendingProposalRoundTrip(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	targets, err := targetsFromDiff(root, targetDiff)
	if err != nil {
		t.Fatalf("targetsFromDiff: %v", err)
	}
	wantHash := sha256Hex("one\n")
	if targets["a.txt"] != wantHash {
		t.Fatalf("target hash = %q, want %q", targets["a.txt"], wantHash)
	}

	p := testProposal(t, root, targetDiff, targets)
	if err := savePending(root, p); err != nil {
		t.Fatalf("savePending: %v", err)
	}
	path := filepath.Join(pendingDir(root), p.FixID+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("proposal file: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("proposal mode = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(pendingDir(root))
	if err != nil {
		t.Fatalf("read pending dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("pending dir has %d entries, want the proposal only", len(entries))
	}

	loaded, err := loadPending(root, p.FixID)
	if err != nil {
		t.Fatalf("loadPending: %v", err)
	}
	if loaded.Diff != p.Diff || loaded.DiffSHA256 != p.DiffSHA256 {
		t.Errorf("round trip lost the diff or its hash")
	}
	if loaded.FindingID != p.FindingID || loaded.ScanID != p.ScanID {
		t.Errorf("round trip lost the finding or scan identity")
	}
	if loaded.Targets["a.txt"] != wantHash {
		t.Errorf("round trip lost the target hash: %#v", loaded.Targets)
	}
	if loaded.ConsumedAt != nil {
		t.Errorf("fresh proposal is marked consumed")
	}
}

func TestPendingProposalRejectsUnsafeFixID(t *testing.T) {
	root := t.TempDir()
	p := testProposal(t, root, targetDiff, map[string]string{})
	for _, id := range []string{
		"",
		"../escape",
		"fx_../../escape",
		"fx_1234567",                    // shorter than 8 hex
		"fx_" + strings.Repeat("a", 33), // longer than 32 hex
		"fx_ABCDEF12",                   // uppercase is not generated
		"fx_gggggggg",                   // not hex
		"fx_1234/5678",
		`fx_..\escape`,
		"/tmp/fx_12345678",
	} {
		p.FixID = id
		if err := savePending(root, p); err == nil {
			t.Errorf("savePending accepted fixId %q", id)
		}
		if _, err := loadPending(root, id); err == nil {
			t.Errorf("loadPending accepted fixId %q", id)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".vigil", "escape.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unsafe fixId wrote outside the pending directory")
	}
}

func TestPendingProposalExpiryAndConsumed(t *testing.T) {
	root := t.TempDir()
	p := testProposal(t, root, targetDiff, map[string]string{})
	if err := savePending(root, p); err != nil {
		t.Fatalf("savePending: %v", err)
	}

	now := time.Now().UTC()
	if err := pendingUsable(p, now); err != nil {
		t.Fatalf("fresh proposal is unusable: %v", err)
	}
	requireCode(t, pendingUsable(p, p.ExpiresAt), CodeFixExpired)
	requireCode(t, pendingUsable(p, p.ExpiresAt.Add(time.Second)), CodeFixExpired)

	consumed := now
	p.ConsumedAt = &consumed
	requireCode(t, pendingUsable(p, now), CodeFixConsumed)
}

func TestPendingProposalDetectsStoredDiffMismatch(t *testing.T) {
	root := t.TempDir()
	p := testProposal(t, root, targetDiff, map[string]string{})
	if err := savePending(root, p); err != nil {
		t.Fatalf("savePending: %v", err)
	}
	p.Diff += "tampered\n"
	if err := savePending(root, p); err != nil {
		t.Fatalf("savePending tampered: %v", err)
	}
	_, err := loadPending(root, p.FixID)
	requireCode(t, err, CodeFixMismatch)
}

func TestPendingProposalDetectsUnsupportedVersion(t *testing.T) {
	root := t.TempDir()
	p := testProposal(t, root, targetDiff, map[string]string{})
	p.Version = pendingProposalVersion + 1
	if err := savePending(root, p); err != nil {
		t.Fatalf("savePending: %v", err)
	}
	_, err := loadPending(root, p.FixID)
	requireCode(t, err, CodeFixMismatch)
}

func TestPendingTargetsDetectChanges(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	targets, err := targetsFromDiff(root, targetDiff)
	if err != nil {
		t.Fatalf("targetsFromDiff: %v", err)
	}
	p := testProposal(t, root, targetDiff, targets)
	if err := verifyPendingTargets(root, p); err != nil {
		t.Fatalf("unchanged targets rejected: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatalf("rewrite a.txt: %v", err)
	}
	requireCode(t, verifyPendingTargets(root, p), CodeFileChanged)
}

func TestPendingTargetsCoverNewFiles(t *testing.T) {
	root := t.TempDir()
	diff := `diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+hello
`
	targets, err := targetsFromDiff(root, diff)
	if err != nil {
		t.Fatalf("targetsFromDiff: %v", err)
	}
	if targets["new.txt"] != absentTarget {
		t.Fatalf("new-file target = %q, want %q", targets["new.txt"], absentTarget)
	}
	p := testProposal(t, root, diff, targets)
	if err := verifyPendingTargets(root, p); err != nil {
		t.Fatalf("absent target rejected: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("create new.txt: %v", err)
	}
	requireCode(t, verifyPendingTargets(root, p), CodeFileChanged)
}

func TestPendingTargetsRejectTraversal(t *testing.T) {
	root := t.TempDir()
	diff := `diff --git a/../outside.txt b/../outside.txt
--- a/../outside.txt
+++ b/../outside.txt
@@ -1 +1 @@
-one
+two
`
	_, err := targetsFromDiff(root, diff)
	requireCode(t, err, CodeBadPath)
}

func TestPendingTargetsPreferGitHeaders(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// The header names a.txt; a bogus fix.Files entry must not be used instead.
	diff := `diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-a.txt
+b.txt
`
	targets, err := targetsFromDiff(root, diff)
	if err != nil {
		t.Fatalf("targetsFromDiff: %v", err)
	}
	if len(targets) != 1 || targets["a.txt"] != sha256Hex("a.txt\n") {
		t.Fatalf("targets = %#v, want only a.txt", targets)
	}
}

func TestDiffTargetPathsKeepNestedPrefixLikeSegments(t *testing.T) {
	diff := `diff --git a/pkg/b/data.txt b/pkg/b/data.txt
--- a/pkg/b/data.txt
+++ b/pkg/b/data.txt
@@ -1 +1 @@
-one
+two
`
	rels, err := diffTargetPaths(diff)
	if err != nil {
		t.Fatalf("diffTargetPaths: %v", err)
	}
	if len(rels) != 1 || rels[0] != "pkg/b/data.txt" {
		t.Fatalf("targets = %v, want [pkg/b/data.txt]", rels)
	}
}

func TestPendingCleanupRemovesOldProposals(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()

	old := testProposal(t, root, targetDiff, map[string]string{})
	old.CreatedAt = now.Add(-25 * time.Hour)
	old.ExpiresAt = old.CreatedAt.Add(pendingProposalTTL)
	if err := savePending(root, old); err != nil {
		t.Fatalf("save old proposal: %v", err)
	}
	fresh := testProposal(t, root, targetDiff+"# fresh\n", map[string]string{})
	if err := savePending(root, fresh); err != nil {
		t.Fatalf("save fresh proposal: %v", err)
	}

	cleanupPending(root, now)

	if _, err := os.Stat(filepath.Join(pendingDir(root), old.FixID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cleanup kept a 25-hour-old proposal")
	}
	if _, err := os.Stat(filepath.Join(pendingDir(root), fresh.FixID+".json")); err != nil {
		t.Errorf("cleanup removed the fresh proposal: %v", err)
	}
}

func TestFindingDeterministicallyCorroborated(t *testing.T) {
	llmOnly := model.Finding{
		ID:       "VGL-LLM0000001",
		RuleID:   "LLM-1",
		Source:   model.SourceLLM,
		Location: model.Location{Path: "config.py", StartLine: 10, EndLine: 12},
	}
	rule := func(path string, start, end int, source model.Source) model.Finding {
		return model.Finding{
			ID:       "VGL-RULE00001",
			RuleID:   "VGL-TEST-001",
			Source:   source,
			Location: model.Location{Path: path, StartLine: start, EndLine: end},
		}
	}

	cases := []struct {
		name     string
		scan     *model.ScanResult
		finding  model.Finding
		expected bool
	}{
		{
			name:     "rule finding is its own evidence",
			scan:     nil,
			finding:  rule("config.py", 1, 1, model.SourceRule),
			expected: true,
		},
		{
			name:     "model-only finding with no corroboration",
			scan:     &model.ScanResult{Findings: []model.Finding{llmOnly}},
			finding:  llmOnly,
			expected: false,
		},
		{
			name: "overlapping deterministic finding",
			scan: &model.ScanResult{Findings: []model.Finding{
				llmOnly, rule("config.py", 12, 15, model.SourceRule),
			}},
			finding:  llmOnly,
			expected: true,
		},
		{
			name: "non-overlapping deterministic finding",
			scan: &model.ScanResult{Findings: []model.Finding{
				llmOnly, rule("config.py", 20, 22, model.SourceRule),
			}},
			finding:  llmOnly,
			expected: false,
		},
		{
			name: "deterministic finding on another path",
			scan: &model.ScanResult{Findings: []model.Finding{
				llmOnly, rule("other.py", 10, 12, model.SourceRule),
			}},
			finding:  llmOnly,
			expected: false,
		},
		{
			name: "suppressed deterministic finding still corroborates",
			scan: &model.ScanResult{Suppressed: []model.Finding{
				rule("config.py", 11, 11, model.SourceRule),
			}},
			finding:  llmOnly,
			expected: true,
		},
		{
			name: "another model finding is not corroboration",
			scan: &model.ScanResult{Findings: []model.Finding{
				llmOnly, rule("config.py", 10, 12, model.SourceLLM),
			}},
			finding:  llmOnly,
			expected: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findingDeterministicallyCorroborated(tc.scan, tc.finding); got != tc.expected {
				t.Errorf("corroborated = %v, want %v", got, tc.expected)
			}
		})
	}
}
