package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// DefaultBaselineFile is the per-project baseline used when no explicit path
// is configured.
const DefaultBaselineFile = ".vigil-baseline.json"

// BaselineVersion is the on-disk schema version.
const BaselineVersion = 1

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

// BaselineFinding is one accepted finding entry.
type BaselineFinding struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// NewBaseline returns an empty version-1 baseline.
func NewBaseline() *Baseline {
	return &Baseline{
		Version:      BaselineVersion,
		Fingerprints: []string{},
		Findings:     []BaselineFinding{},
	}
}

// LoadBaseline reads a baseline file. A missing or empty file is an empty
// baseline, not an error, so first runs do not need special cases.
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
	if b.Version == 0 {
		b.Version = BaselineVersion
	}
	if b.Version != BaselineVersion {
		return nil, fmt.Errorf("baseline %s: unsupported version %d (this build understands version %d)", path, b.Version, BaselineVersion)
	}
	b.normalize()
	return &b, nil
}

// SaveBaseline writes b atomically as indented JSON with mode 0644.
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

// Match reports whether f is already accepted by the baseline, and why.
func (b *Baseline) Match(f model.Finding) (bool, string) {
	if b == nil {
		return false, ""
	}
	fp := f.Fingerprint
	if fp == "" {
		fp = f.ComputeFingerprint()
	}
	id := f.ID
	if id == "" {
		id = f.ComputeID()
	}

	for _, candidate := range b.Findings {
		if candidate.ID == "" || candidate.ID != id {
			continue
		}
		reason := strings.TrimSpace(candidate.Reason)
		if reason == "" {
			reason = "baseline"
		}
		return true, reason
	}
	if fp != "" {
		for _, candidate := range b.Fingerprints {
			if candidate == fp {
				return true, "baseline fingerprint"
			}
		}
	}
	return false, ""
}

// Add records f in the baseline. Duplicate fingerprints and IDs are ignored.
func (b *Baseline) Add(f model.Finding, reason string) {
	if b == nil {
		return
	}
	if b.Version == 0 {
		b.Version = BaselineVersion
	}
	reason = strings.TrimSpace(reason)

	fp := f.Fingerprint
	if fp == "" {
		fp = f.ComputeFingerprint()
	}
	if fp != "" && !containsString(b.Fingerprints, fp) {
		b.Fingerprints = append(b.Fingerprints, fp)
	}

	id := f.ID
	if id == "" {
		id = f.ComputeID()
	}
	if id == "" {
		return
	}
	for i := range b.Findings {
		if b.Findings[i].ID != id {
			continue
		}
		if b.Findings[i].Reason == "" && reason != "" {
			b.Findings[i].Reason = reason
		}
		return
	}
	b.Findings = append(b.Findings, BaselineFinding{ID: id, Reason: reason})
}

func (b *Baseline) empty() bool {
	return b == nil || (len(b.Fingerprints) == 0 && len(b.Findings) == 0)
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
		if fp == "" || seenFP[fp] {
			continue
		}
		seenFP[fp] = true
		fps = append(fps, fp)
	}
	b.Fingerprints = fps
	sort.Strings(b.Fingerprints)

	seenID := make(map[string]bool, len(b.Findings))
	findings := b.Findings[:0]
	for _, f := range b.Findings {
		f.ID = strings.TrimSpace(f.ID)
		if f.ID == "" || seenID[f.ID] {
			continue
		}
		seenID[f.ID] = true
		findings = append(findings, f)
	}
	b.Findings = findings
	sort.Slice(b.Findings, func(i, j int) bool { return b.Findings[i].ID < b.Findings[j].ID })
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
