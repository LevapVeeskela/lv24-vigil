package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// A pending proposal binds a reviewed diff to the tree it was generated for.
// vigil_fix apply=true requires the fixId and diffSha256 returned by propose, so
// a caller cannot smuggle in a different diff between review and apply.
const (
	pendingProposalVersion = 1
	// pendingProposalTTL bounds how long a proposal can be applied. It is short
	// because the stored target hashes are only meaningful while the working
	// tree is unchanged.
	pendingProposalTTL = 15 * time.Minute
	// pendingProposalRetention is how long an exhausted proposal is kept before
	// a later propose removes it. It is longer than the TTL so a client can
	// still see why a fixId is gone.
	pendingProposalRetention = 24 * time.Hour
	// absentTarget marks a file the diff creates: it must not exist yet.
	absentTarget = "absent"
)

// fixIDPattern is deliberately strict: an ID becomes a file name, so a
// caller-supplied value must never contain a separator, a dot segment or an
// absolute path. Generated IDs use 16 lowercase hex characters.
var fixIDPattern = regexp.MustCompile(`^fx_[a-f0-9]{8,32}$`)

// pendingProposal is the on-disk form of a reviewed fix. Diff is stored so an
// apply never asks the model again and can never see a different diff.
type pendingProposal struct {
	Version     int               `json:"version"`
	FixID       string            `json:"fixId"`
	FindingID   string            `json:"findingId"`
	ScanID      string            `json:"scanId"`
	Root        string            `json:"root"`
	Description string            `json:"description"`
	Diff        string            `json:"diff"`
	DiffSHA256  string            `json:"diffSha256"`
	Files       []string          `json:"files"`
	Targets     map[string]string `json:"targets"`
	CreatedAt   time.Time         `json:"createdAt"`
	ExpiresAt   time.Time         `json:"expiresAt"`
	ConsumedAt  *time.Time        `json:"consumedAt,omitempty"`
}

// validFixID reports whether id is safe to use as a proposal file name.
func validFixID(id string) bool {
	return fixIDPattern.MatchString(id)
}

// proposalID derives a deterministic-but-unique ID from the diff and its
// creation time. The diff alone is not enough: re-proposing the same fix must
// yield a distinguishable approval request.
func proposalID(diff string, createdAt time.Time) string {
	sum := sha256.Sum256([]byte(diff + "\n" + createdAt.UTC().Format(time.RFC3339Nano)))
	return "fx_" + hex.EncodeToString(sum[:])[:16]
}

// sha256Hex hashes s exactly, without newline normalisation: the stored
// diffSha256 must change if a single byte changes.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// preImageHash returns the sha256 of the file at abs, or absentTarget when the
// file does not exist yet.
func preImageHash(abs string) (string, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return absentTarget, nil
		}
		return "", fmt.Errorf("read target %s: %w", abs, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// pendingDir is the proposal directory for a project root. It is created
// lazily by savePending.
func pendingDir(root string) string {
	return filepath.Join(root, ".vigil", "pending")
}

// savePending writes a proposal atomically (temp file + rename) with mode 0600
// so the stored diff is not readable by other users on POSIX.
func savePending(root string, p *pendingProposal) error {
	if p == nil {
		return errors.New("pending proposal: nil")
	}
	if !validFixID(p.FixID) {
		return toolErrorf(CodeFixNotFound, "fixId %q is not a proposal id; propose the fix first", p.FixID)
	}
	dir := pendingDir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("pending proposal: create %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("pending proposal: encode: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pending-*.json")
	if err != nil {
		return fmt.Errorf("pending proposal: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("pending proposal: set mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("pending proposal: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pending proposal: close: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, p.FixID+".json")); err != nil {
		return fmt.Errorf("pending proposal: publish: %w", err)
	}
	return nil
}

// loadPending reads a proposal and verifies that it is internally consistent.
// It does not check expiry, consumption or target hashes; apply does that in a
// fixed order so each failure gets its own typed code.
func loadPending(root, fixID string) (*pendingProposal, error) {
	if !validFixID(fixID) {
		return nil, toolErrorf(CodeFixNotFound,
			"fixId %q is not a pending proposal id; call vigil_fix with mode=propose first", fixID)
	}
	data, err := os.ReadFile(filepath.Join(pendingDir(root), fixID+".json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, toolErrorf(CodeFixNotFound,
				"no pending proposal %s; it may have expired, been applied already or been cleaned up. Propose the fix again.", fixID)
		}
		return nil, fmt.Errorf("pending proposal %s: %w", fixID, err)
	}
	var p pendingProposal
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, toolErrorf(CodeFixNotFound,
			"pending proposal %s is unreadable; propose the fix again", fixID)
	}
	if p.FixID != fixID {
		return nil, toolErrorf(CodeFixNotFound,
			"pending proposal %s belongs to a different proposal; propose the fix again", fixID)
	}
	if p.Version != pendingProposalVersion {
		return nil, toolErrorf(CodeFixMismatch,
			"pending proposal %s uses unsupported version %d; propose the fix again", fixID, p.Version)
	}
	if p.DiffSHA256 == "" || sha256Hex(p.Diff) != p.DiffSHA256 {
		return nil, toolErrorf(CodeFixMismatch,
			"the stored diff for %s does not match diffSha256; propose the fix again", fixID)
	}
	return &p, nil
}

// pendingUsable rejects an expired or already consumed proposal.
func pendingUsable(p *pendingProposal, now time.Time) error {
	if p.ConsumedAt != nil {
		return toolErrorf(CodeFixConsumed,
			"proposal %s was already applied at %s; propose a new fix instead of replaying it",
			p.FixID, p.ConsumedAt.UTC().Format(time.RFC3339))
	}
	if !p.ExpiresAt.IsZero() && !now.Before(p.ExpiresAt) {
		return toolErrorf(CodeFixExpired,
			"proposal %s expired at %s; propose the fix again",
			p.FixID, p.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// verifyPendingTargets checks every pre-image recorded when the diff was
// proposed. A changed, created or removed target means the reviewed diff no
// longer describes the tree and must not be applied.
func verifyPendingTargets(root string, p *pendingProposal) error {
	if strings.TrimSpace(p.Root) != "" && !samePath(p.Root, root) {
		return toolErrorf(CodeFileChanged,
			"proposal %s was created for %s but this server is rooted at %s; apply it from the repository it was proposed in",
			p.FixID, p.Root, root)
	}
	paths := make([]string, 0, len(p.Targets))
	for rel := range p.Targets {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	for _, rel := range paths {
		abs, err := resolveInsideRoot(root, rel)
		if err != nil {
			return toolErrorf(CodeBadPath, "target %q is not a safe path: %v", rel, err)
		}
		got, err := preImageHash(abs)
		if err != nil {
			return toolErrorf(CodeFileChanged, "target %q cannot be read: %v", rel, err)
		}
		if got != p.Targets[rel] {
			return toolErrorf(CodeFileChanged,
				"%s changed since the fix was proposed; review a fresh proposal instead of applying the old diff", rel)
		}
	}
	return nil
}

// markPendingConsumed records consumption before ApplyFix runs, so a failed
// apply cannot be replayed with a second attempt.
func markPendingConsumed(root string, p *pendingProposal, now time.Time) error {
	consumed := now.UTC()
	p.ConsumedAt = &consumed
	if err := savePending(root, p); err != nil {
		return fmt.Errorf("pending proposal %s: mark consumed: %w", p.FixID, err)
	}
	return nil
}

// claimPending takes an exclusive lock file so two concurrent apply requests
// cannot both pass the consumed check. The returned release function removes
// the lock; it is safe to call more than once.
func claimPending(root, fixID string) (func(), error) {
	if !validFixID(fixID) {
		return func() {}, toolErrorf(CodeFixNotFound, "fixId %q is not a proposal id", fixID)
	}
	dir := pendingDir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return func() {}, fmt.Errorf("pending proposal: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, fixID+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil && errors.Is(err, os.ErrExist) {
		// A process that crashed mid-apply leaves a lock behind. It is stale
		// after an hour; remove it and retry once.
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > time.Hour {
			_ = os.Remove(path)
			f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		}
	}
	if err != nil {
		return func() {}, toolErrorf(CodeFixConsumed,
			"proposal %s is being applied by another request; retry after that finishes", fixID)
	}
	_ = f.Close()
	released := false
	return func() {
		if released {
			return
		}
		released = true
		_ = os.Remove(path)
	}, nil
}

// cleanupPending removes exhausted proposals older than the retention window.
// It runs best effort on propose: a cleanup failure must not fail the proposal.
func cleanupPending(root string, now time.Time) {
	dir := pendingDir(root)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := now.Add(-pendingProposalRetention)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".lock") &&
			!strings.HasPrefix(name, ".pending-") {
			continue
		}
		path := filepath.Join(dir, name)
		created := time.Time{}
		if strings.HasSuffix(name, ".json") {
			if data, err := os.ReadFile(path); err == nil {
				var p pendingProposal
				if json.Unmarshal(data, &p) == nil {
					created = p.CreatedAt
				}
			}
		}
		if created.IsZero() {
			if info, err := entry.Info(); err == nil {
				created = info.ModTime()
			}
		}
		if !created.IsZero() && created.Before(cutoff) {
			_ = os.Remove(path)
		}
	}
}

// targetsFromDiff records the pre-image of every path named by the diff's git
// headers. fix.Files is not trusted for this: the diff itself must name the
// files that will be written.
func targetsFromDiff(root, diff string) (map[string]string, error) {
	rels, err := diffTargetPaths(diff)
	if err != nil {
		return nil, err
	}
	targets := make(map[string]string, len(rels))
	for _, rel := range rels {
		abs, err := resolveInsideRoot(root, rel)
		if err != nil {
			return nil, toolErrorf(CodeBadPath, "diff path %q is unsafe: %v", rel, err)
		}
		want, err := preImageHash(abs)
		if err != nil {
			return nil, err
		}
		targets[rel] = want
	}
	return targets, nil
}

// diffTargetPaths extracts the repository-relative paths a unified diff
// touches, preferring `diff --git a/X b/X` headers and falling back to a
// ---/+++ pair only when the diff has no git header at all.
func diffTargetPaths(diff string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	var raws []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "diff --git ") {
			continue
		}
		oldPath, newPath, ok := parseGitDiffHeader(line)
		if !ok {
			return nil, toolErrorf(CodeBadPath, "cannot parse diff header %q", truncateRunes(line, 200))
		}
		raws = append(raws, oldPath, newPath)
	}
	if len(raws) == 0 {
		for _, line := range lines {
			if !strings.HasPrefix(line, "--- ") && !strings.HasPrefix(line, "+++ ") {
				continue
			}
			p, ok := diffHeaderPath(line)
			if !ok {
				return nil, toolErrorf(CodeBadPath, "cannot parse diff header %q", truncateRunes(line, 200))
			}
			raws = append(raws, p)
		}
	}

	seen := make(map[string]bool, len(raws))
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		rel, ok, err := normalizeDiffTarget(raw)
		if err != nil {
			return nil, err
		}
		if !ok || seen[rel] {
			continue
		}
		seen[rel] = true
		out = append(out, rel)
	}
	if len(out) == 0 {
		return nil, toolErrorf(CodeBadPath, "diff does not name a file to write")
	}
	sort.Strings(out)
	return out, nil
}

// normalizeDiffTarget turns one diff header path into a safe repository-relative
// path. /dev/null names an absent side and is skipped.
func normalizeDiffTarget(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/dev/null" {
		return "", false, nil
	}
	// Strip exactly one conventional prefix: a path that itself starts with
	// "b/" must not lose a second segment.
	if strings.HasPrefix(raw, "a/") || strings.HasPrefix(raw, "b/") {
		raw = raw[2:]
	}
	rel, err := cleanRelPath(raw)
	if err != nil {
		return "", false, toolErrorf(CodeBadPath, "diff path %q is unsafe: %v", raw, err)
	}
	return rel, true, nil
}

// parseGitDiffHeader splits `diff --git a/X b/X`. Git quotes a path that
// contains characters needing escaping; the quoted form is unquoted here.
func parseGitDiffHeader(line string) (string, string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "diff --git "))
	return splitGitDiffPaths(rest)
}

func splitGitDiffPaths(rest string) (string, string, bool) {
	if rest == "" {
		return "", "", false
	}
	if strings.HasPrefix(rest, `"`) {
		first, after, ok := unquoteGitPath(rest)
		if !ok {
			return "", "", false
		}
		after = strings.TrimLeft(after, " \t")
		if !strings.HasPrefix(after, `"`) {
			return "", "", false
		}
		second, _, ok := unquoteGitPath(after)
		if !ok {
			return "", "", false
		}
		return first, second, true
	}
	// The common unquoted form: split at the space before the b/ side. Git
	// quotes a path only when it contains control or non-ASCII bytes, so this
	// handles the ordinary spelling produced by the fix prompt.
	if i := strings.Index(rest, " b/"); i > 0 {
		return rest[:i], rest[i+1:], true
	}
	return "", "", false
}

// unquoteGitPath decodes one git-quoted path and returns the remaining text.
func unquoteGitPath(s string) (string, string, bool) {
	if !strings.HasPrefix(s, `"`) {
		return "", "", false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			p, err := strconv.Unquote(s[:i+1])
			if err != nil {
				return "", "", false
			}
			return p, s[i+1:], true
		}
	}
	return "", "", false
}

// diffHeaderPath extracts the path from a --- or +++ line, including git's
// quoted form and an optional tab-separated timestamp.
func diffHeaderPath(line string) (string, bool) {
	if len(line) < 4 {
		return "", false
	}
	rest := strings.TrimRight(line[4:], " \t")
	if rest == "" {
		return "", false
	}
	if strings.HasPrefix(rest, `"`) {
		if p, _, ok := unquoteGitPath(rest); ok {
			return p, true
		}
	}
	if i := strings.IndexByte(rest, '\t'); i >= 0 {
		rest = strings.TrimSpace(rest[:i])
	}
	return rest, rest != ""
}

// findingDeterministicallyCorroborated reports whether a finding is backed by
// deterministic evidence. A rule finding is evidence itself; an LLM-only
// finding needs another finding in the same scan (active or suppressed) with
// the same path and an overlapping line range whose source is not the model.
func findingDeterministicallyCorroborated(scan *model.ScanResult, f model.Finding) bool {
	if f.Source != model.SourceLLM {
		return true
	}
	if scan == nil {
		return false
	}
	want := normalizeFindingPath(f.Location.Path)
	for _, other := range scan.Findings {
		if corroboratesFinding(other, f, want) {
			return true
		}
	}
	for _, other := range scan.Suppressed {
		if corroboratesFinding(other, f, want) {
			return true
		}
	}
	return false
}

func corroboratesFinding(other, target model.Finding, wantPath string) bool {
	if other.Source == model.SourceLLM {
		return false
	}
	if !sameFindingPath(normalizeFindingPath(other.Location.Path), wantPath) {
		return false
	}
	return findingRangesOverlap(other.Location, target.Location)
}

// findingRangesOverlap compares two inclusive line ranges. A finding without a
// start line covers its whole path, so a same-path deterministic finding still
// corroborates it.
func findingRangesOverlap(a, b model.Location) bool {
	aStart, aEnd := findingRange(a)
	bStart, bEnd := findingRange(b)
	if aStart <= 0 || bStart <= 0 {
		return true
	}
	return aStart <= bEnd && bStart <= aEnd
}

func findingRange(l model.Location) (int, int) {
	start := l.StartLine
	end := l.EndLine
	if end < start {
		end = start
	}
	return start, end
}

// deterministicFixGate refuses to propose or apply a fix for model-only
// evidence that no deterministic rule corroborates.
func deterministicFixGate(scan *model.ScanResult, f model.Finding) error {
	if findingDeterministicallyCorroborated(scan, f) {
		return nil
	}
	return toolErrorf(CodeFixNondeterministic,
		"finding %s comes from the model only and no deterministic rule corroborates it at %s. "+
			"Model-only evidence is not enough to generate and apply a fix automatically: confirm the issue "+
			"manually or add a deterministic rule for it, then retry.",
		findingID(f), locationString(f.Location))
}

// sortedKeys returns the sorted keys of a target map for stable output.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
