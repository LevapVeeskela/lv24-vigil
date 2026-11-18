package tools

import (
	"crypto/hmac"
	"crypto/rand"
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
	"sync"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
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
	// maxPendingProposalBytes bounds a proposal file and its diff. A proposal is
	// a model output stored for at most 15 minutes, not an arbitrary payload.
	maxPendingProposalBytes = 1 << 20
)

// pendingMACKey is a per-process key. It makes a proposal file authentic only
// for the server process that created it, so a repository cannot ship a
// ready-made proposal that an agent is tricked into applying. A restart
// invalidates outstanding proposals; the 15-minute TTL makes that acceptable.
var (
	pendingKeyOnce sync.Once
	pendingKey     []byte
	pendingKeyErr  error
)

func pendingMACKey() ([]byte, error) {
	pendingKeyOnce.Do(func() {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			pendingKeyErr = err
			return
		}
		pendingKey = key
	})
	return pendingKey, pendingKeyErr
}

// pendingNow is time.Now. Tests replace it to exercise expiry without waiting.
var pendingNow = time.Now

// proposalMAC authenticates every field of a proposal except the MAC itself.
// encoding/json sorts map keys, so Targets has a stable encoding.
func proposalMAC(p *pendingProposal) (string, error) {
	key, err := pendingMACKey()
	if err != nil {
		return "", fmt.Errorf("pending proposal: no signing key: %w", err)
	}
	clone := *p
	clone.MAC = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("pending proposal: encode MAC input: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

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
	MAC         string            `json:"mac,omitempty"`
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

// pendingDir is the proposal directory for a project root. It uses
// .vigil/pending only when that path resolves inside the project: a hostile
// repository can commit .vigil as a symlink or junction, and a proposal write
// or cleanup must not escape the tree. Otherwise it falls back to the user
// cache, keyed by the absolute root, like the scan store.
func pendingDir(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("pending proposal: resolve root: %w", err)
	}
	abs = filepath.Clean(abs)

	vigilPath := filepath.Join(abs, ".vigil")
	safe := true
	if info, err := os.Lstat(vigilPath); err == nil {
		isLink := info.Mode()&os.ModeSymlink != 0
		if !isLink {
			// Windows junctions are reparse points but not ModeSymlink.
			if _, rerr := os.Readlink(vigilPath); rerr == nil {
				isLink = true
			}
		}
		if isLink || !info.IsDir() {
			safe = false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("pending proposal: inspect %s: %w", vigilPath, err)
	}

	if safe {
		if err := os.MkdirAll(vigilPath, 0o700); err == nil {
			if resolved, rerr := safepath.Resolve(abs, ".vigil/pending"); rerr == nil {
				if err := os.MkdirAll(resolved, 0o700); err == nil {
					return resolved, nil
				}
			}
		}
	}

	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("pending proposal: resolve cache directory: %w", err)
	}
	sum := sha256.Sum256([]byte(abs))
	dir := filepath.Join(cache, "vigil", "pending", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("pending proposal: create %s: %w", dir, err)
	}
	if info, err := os.Lstat(dir); err != nil {
		return "", fmt.Errorf("pending proposal: inspect %s: %w", dir, err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("pending proposal: cache directory %s is a symlink", dir)
	}
	return dir, nil
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
	if len(p.Diff) > maxPendingProposalBytes {
		return fmt.Errorf("pending proposal: diff is %d bytes, above the %d-byte limit", len(p.Diff), maxPendingProposalBytes)
	}
	mac, err := proposalMAC(p)
	if err != nil {
		return err
	}
	p.MAC = mac
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("pending proposal: encode: %w", err)
	}
	if len(data) > maxPendingProposalBytes {
		return fmt.Errorf("pending proposal: encoded proposal is %d bytes, above the %d-byte limit", len(data), maxPendingProposalBytes)
	}
	dir, err := pendingDir(root)
	if err != nil {
		return err
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

// loadPending reads a proposal and verifies that it is authentic and internally
// consistent. It does not check expiry, consumption or target hashes; apply
// does that in a fixed order so each failure gets its own typed code.
func loadPending(root, fixID string) (*pendingProposal, error) {
	if !validFixID(fixID) {
		return nil, toolErrorf(CodeFixNotFound,
			"fixId %q is not a pending proposal id; call vigil_fix with mode=propose first", fixID)
	}
	dir, err := pendingDir(root)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, fixID+".json")
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, toolErrorf(CodeFixNotFound,
				"no pending proposal %s; it may have expired, been applied already or been cleaned up. Propose the fix again.", fixID)
		}
		return nil, fmt.Errorf("pending proposal %s: %w", fixID, err)
	}
	if info.Size() > maxPendingProposalBytes {
		return nil, toolErrorf(CodeFixNotFound,
			"pending proposal %s is too large; propose the fix again", fixID)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pending proposal %s: %w", fixID, err)
	}
	var p pendingProposal
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, toolErrorf(CodeFixNotFound,
			"pending proposal %s is unreadable; propose the fix again", fixID)
	}
	if p.MAC == "" {
		return nil, toolErrorf(CodeFixNotFound,
			"pending proposal %s was not created by this server process; propose the fix again", fixID)
	}
	want, err := proposalMAC(&p)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(p.MAC), []byte(want)) {
		return nil, toolErrorf(CodeFixNotFound,
			"pending proposal %s is not authentic (changed on disk or created by another process); propose the fix again", fixID)
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
	// Re-derive the target set from the stored diff. The stored map is signed,
	// but a mixed diff must not name a file that the pre-image map omits.
	derived, err := diffTargetPaths(p.Diff)
	if err != nil {
		return err
	}
	if len(derived) != len(p.Targets) {
		return toolErrorf(CodeFixMismatch,
			"proposal %s targets %d file(s) but the stored diff touches %d; propose the fix again",
			p.FixID, len(p.Targets), len(derived))
	}
	for _, rel := range derived {
		if _, ok := p.Targets[rel]; !ok {
			return toolErrorf(CodeFixMismatch,
				"proposal %s does not record a pre-image for %s; propose the fix again", p.FixID, rel)
		}
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
	dir, err := pendingDir(root)
	if err != nil {
		return func() {}, err
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
	dir, err := pendingDir(root)
	if err != nil {
		return
	}
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
		isJSON := strings.HasSuffix(name, ".json")
		isLock := strings.HasSuffix(name, ".lock")
		if !isJSON && !isLock && !strings.HasPrefix(name, ".pending-") {
			continue
		}
		// Only remove files this package created. A stray fixture in a
		// hostile .vigil/pending must not be deleted by cleanup.
		if (isJSON || isLock) && !validFixID(strings.TrimSuffix(name, filepath.Ext(name))) {
			continue
		}
		path := filepath.Join(dir, name)
		created := time.Time{}
		if strings.HasSuffix(name, ".json") {
			if info, err := entry.Info(); err == nil && info.Size() <= maxPendingProposalBytes {
				if data, err := os.ReadFile(path); err == nil {
					var p pendingProposal
					if json.Unmarshal(data, &p) == nil {
						created = p.CreatedAt
					}
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

// targetsFromDiff records the pre-image of every path named by the diff. A
// git header is not the only source: bare ---/+++ pairs count too. fix.Files is
// not trusted for this: the diff itself must name the files that will be
// written.
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

// hunkHeaderRe matches the standard unified-diff hunk header and captures the
// old and new line counts. A missing count means one line.
var hunkHeaderRe = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@`)

// diffTargetPaths extracts the repository-relative paths a unified diff
// touches, from `diff --git a/X b/X` headers and bare ---/+++ pairs. Hunk
// bodies are consumed by their declared line counts, so a removed line such as
// "--- not a header" is never mistaken for a file header.
func diffTargetPaths(diff string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	var raws []string
	inHunk := false
	oldLeft, newLeft := 0, 0
	for _, line := range lines {
		if inHunk {
			if oldLeft <= 0 && newLeft <= 0 {
				inHunk = false
			} else {
				switch {
				case strings.HasPrefix(line, "\\"):
					continue
				case line == "":
					inHunk = false
				case line[0] == ' ':
					oldLeft--
					newLeft--
					continue
				case line[0] == '-':
					oldLeft--
					continue
				case line[0] == '+':
					newLeft--
					continue
				default:
					inHunk = false
				}
			}
		}
		switch {
		case strings.HasPrefix(line, "rename "), strings.HasPrefix(line, "copy "):
			// git apply honours these headers and can create a path that is
			// not in the pre-image map. A fix diff must not rename or copy.
			return nil, toolErrorf(CodeBadPath, "rename and copy patches are not accepted")
		case strings.HasPrefix(line, "diff --git "):
			oldPath, newPath, ok := parseGitDiffHeader(line)
			if !ok {
				return nil, toolErrorf(CodeBadPath, "cannot parse diff header %q", truncateRunes(line, 200))
			}
			raws = append(raws, oldPath, newPath)
		case strings.HasPrefix(line, "@@ "):
			oldCount, newCount, ok := parseHunkHeader(line)
			if !ok {
				return nil, toolErrorf(CodeBadPath, "cannot parse hunk header %q", truncateRunes(line, 200))
			}
			inHunk = true
			oldLeft, newLeft = oldCount, newCount
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			// Every file git apply can touch must be in the pre-image map, not
			// only files with a git header. A crafted diff can mix a git header
			// with a bare ---/+++ pair for another file.
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

// parseHunkHeader reads the old and new line counts from a hunk header.
func parseHunkHeader(line string) (oldCount, newCount int, ok bool) {
	m := hunkHeaderRe.FindStringSubmatch(line)
	if m == nil {
		return 0, 0, false
	}
	count := func(s string) int {
		if s == "" {
			return 1
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return 0
		}
		return n
	}
	return count(m[2]), count(m[4]), true
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
