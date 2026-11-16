package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// DefaultBaselineFile is the per-project baseline used when no explicit path
// is configured.
const DefaultBaselineFile = ".vigil-baseline.json"

// BaselineVersion is the on-disk schema version. Version-1 files are still
// readable: LoadBaseline accepts them and normalizes the result to version 2.
const BaselineVersion = 2

// baselineVersionLegacy is the pre-expiry schema. It has no per-entry
// fingerprint, rule, path, ticket or expiry fields.
const baselineVersionLegacy = 1

// legacyFingerprintReason labels an entry materialized from the version-1
// top-level fingerprint list. Those fingerprints never expire, so they become
// ordinary no-expiry entries that `list` shows and `remove` can delete.
const legacyFingerprintReason = "legacy fingerprint"

// BaselineDateLayout is the format of BaselineFinding.Expires.
const BaselineDateLayout = "2006-01-02"

// maxBaselineBytes bounds a baseline file before it is read into memory.
const maxBaselineBytes = 8 << 20

// Baseline records findings that have been reviewed and accepted. Matching is
// intentionally loose: a fingerprint survives small line moves, an ID is an
// exact match.
type Baseline struct {
	Version      int               `json:"version"`
	Fingerprints []string          `json:"fingerprints"`
	Findings     []BaselineFinding `json:"findings"`
}

// BaselineFinding is one accepted finding entry. Fingerprint, RuleID, Path,
// Ticket and Expires are optional version-2 additions; older files simply
// leave them empty.
type BaselineFinding struct {
	ID          string `json:"id"`
	Reason      string `json:"reason,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	RuleID      string `json:"ruleId,omitempty"`
	Path        string `json:"path,omitempty"`
	Ticket      string `json:"ticket,omitempty"`
	// Expires is a YYYY-MM-DD UTC date. The entry stops suppressing findings
	// when the date is before today; an empty value never expires.
	Expires string `json:"expires,omitempty"`
}

// UnmarshalJSON rejects keys this build does not know. A silently ignored key
// is dangerous here: an expiry written as "expiry" or "until" instead of
// "expires" would otherwise yield an entry that never expires.
func (f *BaselineFinding) UnmarshalJSON(data []byte) error {
	type plain BaselineFinding
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var entry plain
	if err := dec.Decode(&entry); err != nil {
		return fmt.Errorf("baseline entry: %w", err)
	}
	*f = BaselineFinding(entry)
	return nil
}

// MatchResult describes how a finding relates to the baseline.
type MatchResult struct {
	// Matched is true when a non-expired entry suppresses the finding.
	Matched bool
	// Reason is the entry's reason, or "baseline" when it has none.
	Reason string
	// Expired is true when the best matching entry has expired. The finding is
	// not suppressed in that case.
	Expired bool
	// Expires is the raw expiry date of the expired entry.
	Expires string
	// Path is the path scope of the expired entry, when it had one.
	Path string
	// Ticket is the ticket of the matched or expired entry.
	Ticket string
	// EntryID is the baseline entry ID of the matched or expired entry.
	EntryID string
}

// NewBaseline returns an empty version-2 baseline.
func NewBaseline() *Baseline {
	return &Baseline{
		Version:      BaselineVersion,
		Fingerprints: []string{},
		Findings:     []BaselineFinding{},
	}
}

// BaselineToday returns the current UTC date at midnight. Expiry checks compare
// against it, matching the inline-suppression semantics.
func BaselineToday() time.Time {
	return todayUTC()
}

// ParseBaselineDate parses a strict YYYY-MM-DD date.
func ParseBaselineDate(value string) (time.Time, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return time.Time{}, errors.New("date is empty")
	}
	t, err := time.Parse(BaselineDateLayout, v)
	if err != nil || t.Format(BaselineDateLayout) != v {
		return time.Time{}, fmt.Errorf("date %q must be YYYY-MM-DD", value)
	}
	return t, nil
}

// ExpiryDate returns the entry's parsed expiry. ok is false when the entry does
// not expire.
func (e BaselineFinding) ExpiryDate() (time.Time, bool, error) {
	if strings.TrimSpace(e.Expires) == "" {
		return time.Time{}, false, nil
	}
	t, err := ParseBaselineDate(e.Expires)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

// Expired reports whether the entry's date is before today (UTC). An
// unparsable date counts as expired so a typo cannot suppress forever.
func (e BaselineFinding) Expired(today time.Time) bool {
	t, ok, err := e.ExpiryDate()
	if err != nil {
		return true
	}
	return ok && t.Before(dateOnly(today))
}

// LoadBaseline reads a baseline file. A missing or empty file is an empty
// baseline, not an error, so first runs do not need special cases. Version 1
// files are accepted and upgraded in memory to version 2.
func LoadBaseline(path string) (*Baseline, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewBaseline(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat baseline %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("baseline %s is not a regular file", path)
	}
	if info.Size() > maxBaselineBytes {
		return nil, fmt.Errorf("baseline %s is larger than %d bytes", path, maxBaselineBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return NewBaseline(), nil
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	switch b.Version {
	case 0, baselineVersionLegacy, BaselineVersion:
		b.Version = BaselineVersion
	default:
		return nil, fmt.Errorf("baseline %s: unsupported version %d (this build understands versions 1 and %d)", path, b.Version, BaselineVersion)
	}
	b.normalize()
	if err := b.validate(); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return &b, nil
}

// SaveBaseline writes b atomically as indented version-2 JSON with mode 0644.
func SaveBaseline(path string, b *Baseline) error {
	if b == nil {
		b = NewBaseline()
	}
	out := &Baseline{
		Version:      BaselineVersion,
		Fingerprints: append([]string(nil), b.Fingerprints...),
		Findings:     append([]BaselineFinding(nil), b.Findings...),
	}
	out.normalize()
	if err := out.validate(); err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create baseline directory %s: %w", dir, err)
	}
	return writeFileAtomic(path, data, 0o644)
}

// Match reports whether f is suppressed by a non-expired baseline entry, and
// why. Expired entries never suppress; use MatchFinding to observe them.
func (b *Baseline) Match(f model.Finding) (bool, string) {
	result := b.MatchFinding(f)
	if !result.Matched {
		return false, ""
	}
	return true, result.Reason
}

// MatchFinding compares f with the baseline, including path and rule scopes
// and expiry. An entry whose Expires date is before today (UTC) is reported as
// expired instead of suppressing the finding. Version-1 fingerprints are
// materialized as entries by normalize, so the legacy list is never consulted
// here.
func (b *Baseline) MatchFinding(f model.Finding) MatchResult {
	if b == nil {
		return MatchResult{}
	}
	fp := f.Fingerprint
	if fp == "" {
		fp = f.ComputeFingerprint()
	}
	id := f.ID
	if id == "" {
		id = f.ComputeID()
	}
	today := BaselineToday()

	var expired *BaselineFinding
	for i := range b.Findings {
		entry := &b.Findings[i]
		if !entry.matches(f, id, fp) {
			continue
		}
		if entry.Expired(today) {
			// Keep the entry with the latest expiry so the warning is stable
			// when a finding has several stale acceptances.
			if expired == nil || entry.Expires > expired.Expires {
				expired = entry
			}
			continue
		}
		return MatchResult{
			Matched: true,
			Reason:  baselineReason(entry),
			Ticket:  entry.Ticket,
			EntryID: entry.ID,
		}
	}
	if expired != nil {
		return MatchResult{
			Expired: true,
			Expires: expired.Expires,
			Path:    expired.Path,
			Ticket:  expired.Ticket,
			EntryID: expired.ID,
		}
	}
	return MatchResult{}
}

// Add records f in the baseline. Duplicate fingerprints and IDs are ignored.
func (b *Baseline) Add(f model.Finding, reason string) {
	if b == nil {
		return
	}
	fp := f.Fingerprint
	if fp == "" {
		fp = f.ComputeFingerprint()
	}
	id := f.ID
	if id == "" {
		id = f.ComputeID()
	}
	b.AddEntry(BaselineFinding{ID: id, Reason: reason, Fingerprint: fp})
}

// AddEntry records or updates one entry. IDs and fingerprints are matched
// case-insensitively; non-empty incoming metadata replaces stored metadata and
// an existing non-empty reason is kept, matching Add's historical behaviour.
func (b *Baseline) AddEntry(entry BaselineFinding) {
	if b == nil {
		return
	}
	entry = normalizeBaselineFinding(entry)
	if entry.ID == "" && entry.Fingerprint == "" {
		return
	}

	for i := range b.Findings {
		stored := &b.Findings[i]
		if !sameBaselineEntry(*stored, entry) {
			continue
		}
		mergeBaselineEntry(stored, entry)
		if usesLegacyFingerprint(*stored) {
			b.addFingerprint(stored.Fingerprint)
		}
		return
	}

	b.Findings = append(b.Findings, entry)
	if usesLegacyFingerprint(entry) {
		b.addFingerprint(entry.Fingerprint)
	}
}

// PruneExpired removes entries whose expiry is before today (UTC) and returns
// them. Legacy fingerprints are materialized first, so an entry removed here
// cannot leave the finding suppressed through the top-level fingerprint list.
// A materialized legacy entry has no expiry and normally survives; only an
// entry that explicitly carries a date is pruned.
func (b *Baseline) PruneExpired(today time.Time) []BaselineFinding {
	if b == nil {
		return nil
	}
	b.materializeLegacyFingerprints()
	if len(b.Findings) == 0 {
		return nil
	}
	today = dateOnly(today)

	removed := make([]BaselineFinding, 0)
	kept := make([]BaselineFinding, 0, len(b.Findings))
	for _, entry := range b.Findings {
		if entry.Expired(today) {
			removed = append(removed, entry)
			continue
		}
		kept = append(kept, entry)
	}
	if len(removed) == 0 {
		return nil
	}
	b.Findings = kept

	stillUsed := make(map[string]bool, len(kept))
	for _, entry := range kept {
		if entry.Fingerprint != "" {
			stillUsed[strings.ToLower(entry.Fingerprint)] = true
		}
	}
	fingerprints := b.Fingerprints[:0]
	for _, fp := range b.Fingerprints {
		if stillUsed[strings.ToLower(fp)] || !fingerprintRemoved(fp, removed) {
			fingerprints = append(fingerprints, fp)
		}
	}
	b.Fingerprints = fingerprints
	return removed
}

func (b *Baseline) validate() error {
	for _, entry := range b.Findings {
		if strings.TrimSpace(entry.Expires) == "" {
			continue
		}
		if _, err := ParseBaselineDate(entry.Expires); err != nil {
			label := entry.ID
			if label == "" {
				label = entry.Fingerprint
			}
			return fmt.Errorf("finding %s: %w", label, err)
		}
	}
	return nil
}

func (b *Baseline) empty() bool {
	return b == nil || (len(b.Fingerprints) == 0 && len(b.Findings) == 0)
}

func (b *Baseline) addFingerprint(fp string) {
	fp = strings.TrimSpace(fp)
	if fp == "" || containsFingerprint(b.Fingerprints, fp) {
		return
	}
	b.Fingerprints = append(b.Fingerprints, fp)
}

func (b *Baseline) normalize() {
	if b.Version == 0 {
		b.Version = BaselineVersion
	}
	if b.Fingerprints == nil {
		b.Fingerprints = []string{}
	}
	if b.Findings == nil {
		b.Findings = []BaselineFinding{}
	}

	seenFP := make(map[string]bool, len(b.Fingerprints))
	fps := b.Fingerprints[:0]
	for _, fp := range b.Fingerprints {
		fp = strings.TrimSpace(fp)
		key := strings.ToLower(fp)
		if fp == "" || seenFP[key] {
			continue
		}
		seenFP[key] = true
		fps = append(fps, fp)
	}
	b.Fingerprints = fps
	sort.Strings(b.Fingerprints)

	seenEntry := make(map[string]bool, len(b.Findings))
	findings := b.Findings[:0]
	for _, entry := range b.Findings {
		entry = normalizeBaselineFinding(entry)
		key := baselineEntryKey(entry)
		if key == "" || seenEntry[key] {
			continue
		}
		seenEntry[key] = true
		findings = append(findings, entry)
	}
	b.Findings = findings

	b.materializeLegacyFingerprints()

	sort.SliceStable(b.Findings, func(i, j int) bool {
		return baselineEntryKey(b.Findings[i]) < baselineEntryKey(b.Findings[j])
	})
}

// materializeLegacyFingerprints turns every top-level fingerprint that no
// entry references into a fingerprint-only entry. The legacy list has no
// expiry and used to be a hidden second match channel, so pruning an expired
// entry could leave the finding suppressed forever. As entries they appear in
// `list`, `remove` can delete them by fingerprint, and prune sees them. An
// entry that already carries the fingerprint (even an expired one) owns it, so
// no duplicate entry is created and its expiry scope is preserved.
func (b *Baseline) materializeLegacyFingerprints() {
	if b == nil || len(b.Fingerprints) == 0 {
		return
	}
	used := make(map[string]bool, len(b.Findings))
	for _, entry := range b.Findings {
		if entry.Fingerprint != "" {
			used[strings.ToLower(entry.Fingerprint)] = true
		}
	}
	for _, fp := range b.Fingerprints {
		fp = strings.TrimSpace(fp)
		key := strings.ToLower(fp)
		if key == "" || used[key] {
			continue
		}
		used[key] = true
		b.Findings = append(b.Findings, BaselineFinding{
			Fingerprint: fp,
			Reason:      legacyFingerprintReason,
		})
	}
}

func containsFingerprint(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// matches applies the optional path and rule scopes before comparing identity.
// An empty scope matches everything, preserving version-1 semantics.
func (e *BaselineFinding) matches(f model.Finding, id, fp string) bool {
	if e == nil {
		return false
	}
	if e.Path != "" && !sameBaselinePath(e.Path, f.Location.Path) {
		return false
	}
	if e.RuleID != "" && !strings.EqualFold(strings.TrimSpace(e.RuleID), strings.TrimSpace(f.RuleID)) {
		return false
	}
	if e.ID != "" && strings.EqualFold(strings.TrimSpace(e.ID), id) {
		return true
	}
	return e.Fingerprint != "" && fp != "" && strings.EqualFold(strings.TrimSpace(e.Fingerprint), fp)
}

func sameBaselineEntry(a, b BaselineFinding) bool {
	if a.ID != "" && b.ID != "" && strings.EqualFold(a.ID, b.ID) {
		return true
	}
	return a.Fingerprint != "" && b.Fingerprint != "" && strings.EqualFold(a.Fingerprint, b.Fingerprint)
}

func usesLegacyFingerprint(entry BaselineFinding) bool {
	return entry.Fingerprint != "" && entry.Expires == ""
}

func mergeBaselineEntry(dst *BaselineFinding, src BaselineFinding) {
	if dst.Reason == "" && src.Reason != "" {
		dst.Reason = src.Reason
	}
	if dst.ID == "" && src.ID != "" {
		dst.ID = src.ID
	}
	if src.Fingerprint != "" {
		dst.Fingerprint = src.Fingerprint
	}
	if src.RuleID != "" {
		dst.RuleID = src.RuleID
	}
	if src.Path != "" {
		dst.Path = src.Path
	}
	if src.Ticket != "" {
		dst.Ticket = src.Ticket
	}
	if src.Expires != "" {
		dst.Expires = src.Expires
	}
}

func normalizeBaselineFinding(entry BaselineFinding) BaselineFinding {
	entry.ID = strings.TrimSpace(entry.ID)
	entry.Reason = strings.TrimSpace(entry.Reason)
	entry.Fingerprint = strings.TrimSpace(entry.Fingerprint)
	entry.RuleID = strings.TrimSpace(entry.RuleID)
	entry.Path = normalizeBaselinePath(entry.Path)
	entry.Ticket = strings.TrimSpace(entry.Ticket)
	entry.Expires = strings.TrimSpace(entry.Expires)
	return entry
}

func baselineEntryKey(entry BaselineFinding) string {
	if entry.ID != "" {
		return "0:" + strings.ToUpper(entry.ID)
	}
	if entry.Fingerprint != "" {
		return "1:" + strings.ToLower(entry.Fingerprint)
	}
	return ""
}

func baselineReason(entry *BaselineFinding) string {
	reason := strings.TrimSpace(entry.Reason)
	if reason == "" {
		reason = "baseline"
	}
	return reason
}

func normalizeBaselinePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.TrimPrefix(value, "./")
	if value == "" {
		return ""
	}
	cleaned := path.Clean(value)
	if cleaned == "." {
		return ""
	}
	return cleaned
}

func sameBaselinePath(a, b string) bool {
	a, b = normalizeBaselinePath(a), normalizeBaselinePath(b)
	return a != "" && b != "" && strings.EqualFold(a, b)
}

func fingerprintRemoved(fp string, removed []BaselineFinding) bool {
	for _, entry := range removed {
		if entry.Fingerprint != "" && strings.EqualFold(entry.Fingerprint, fp) {
			return true
		}
	}
	return false
}

func dateOnly(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// writeFileAtomic writes data to a temporary file in the destination directory
// and renames it into place, so readers never observe a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vigil-tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	remove = false
	return nil
}
