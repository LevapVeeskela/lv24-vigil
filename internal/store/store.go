// Package store persists scan history on disk.
//
// In a project (a directory containing .vigil/ or a git repository) history
// lives in <root>/.vigil/scans. Elsewhere it falls back to the user cache
// directory so a one-off scan does not litter an unrelated directory.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/gitutil"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

const (
	defaultKeep = 50
	scanPrefix  = "scan_"
	lastFile    = "last.json"
)

// Store is a scan history directory.
type Store struct {
	dir string
}

// Summary is a lightweight entry for history listings.
type Summary struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	Findings  int       `json:"findings"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
}

// Open resolves the history directory for root and creates it if needed.
func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("store: resolve root %s: %w", root, err)
	}
	abs = filepath.Clean(abs)

	var dir string
	if info, err := os.Stat(filepath.Join(abs, ".vigil")); err == nil && info.IsDir() {
		dir = filepath.Join(abs, ".vigil", "scans")
	} else if isGitRoot(abs) {
		dir = filepath.Join(abs, ".vigil", "scans")
	} else {
		cache, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("store: resolve cache directory: %w", err)
		}
		dir = filepath.Join(cache, "vigil", "scans")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the resolved history directory.
func (s *Store) Dir() string { return s.dir }

func isGitRoot(root string) bool {
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		return true
	}
	if _, err := gitutil.RepoRoot(root); err == nil {
		return true
	}
	return false
}

// Save writes the full scan result, updates last.json and prunes old scans.
// A missing ID is generated in the canonical scan_<timestamp>_<hex> format.
func (s *Store) Save(res *model.ScanResult) error {
	if res == nil {
		return errors.New("store: nil scan result")
	}
	id := strings.TrimSpace(res.ID)
	if id == "" {
		var err error
		id, err = s.uniqueID()
		if err != nil {
			return err
		}
		res.ID = id
	}
	if !validID(id) {
		return fmt.Errorf("store: invalid scan id %q", id)
	}
	if res.StartedAt.IsZero() {
		res.StartedAt = time.Now().UTC()
	}
	if res.FinishedAt.IsZero() {
		res.FinishedAt = res.StartedAt
	}

	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode scan %s: %w", id, err)
	}
	data = append(data, '\n')
	if err := writeAtomic(filepath.Join(s.dir, id+".json"), data, 0o644); err != nil {
		return err
	}
	if err := s.writeLast(id); err != nil {
		return err
	}
	return s.Prune(defaultKeep)
}

// Last returns the scan referenced by last.json, or the newest scan when the
// pointer is missing or stale.
func (s *Store) Last() (*model.ScanResult, error) {
	if id, err := s.readLastID(); err == nil {
		if res, err := s.Get(id); err == nil {
			return res, nil
		}
	}

	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, e := range entries {
		res, err := s.Get(e.id)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("store: no scans: %w", os.ErrNotExist)
}

// Get loads one scan by ID.
func (s *Store) Get(id string) (*model.ScanResult, error) {
	if !validID(id) {
		return nil, fmt.Errorf("store: invalid scan id %q", id)
	}
	data, err := os.ReadFile(filepath.Join(s.dir, id+".json"))
	if err != nil {
		return nil, fmt.Errorf("store: read scan %s: %w", id, err)
	}
	var res model.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: parse scan %s: %w", id, err)
	}
	if res.ID == "" {
		res.ID = id
	}
	return &res, nil
}

// List returns up to limit summaries, newest first. limit <= 0 means all.
func (s *Store) List(limit int) ([]Summary, error) {
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	out := make([]Summary, 0, len(entries))
	for _, e := range entries {
		res, err := s.Get(e.id)
		if err != nil {
			continue
		}
		sum := Summary{
			ID:        res.ID,
			StartedAt: res.StartedAt,
			Findings:  len(res.Findings),
		}
		if sum.StartedAt.IsZero() {
			sum.StartedAt = e.started
		}
		for _, f := range res.Findings {
			switch f.Severity {
			case model.SeverityCritical:
				sum.Critical++
			case model.SeverityHigh:
				sum.High++
			}
		}
		out = append(out, sum)
	}
	return out, nil
}

// Prune keeps the newest keep scans and removes the rest. keep <= 0 removes
// every scan. last.json is repointed or removed as needed.
func (s *Store) Prune(keep int) error {
	if keep < 0 {
		keep = 0
	}
	entries, err := s.entries()
	if err != nil {
		return err
	}
	if len(entries) <= keep {
		if keep == 0 && len(entries) == 0 {
			_ = os.Remove(filepath.Join(s.dir, lastFile))
		}
		return nil
	}

	for _, e := range entries[keep:] {
		if err := os.Remove(filepath.Join(s.dir, e.id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("store: remove scan %s: %w", e.id, err)
		}
	}

	if keep == 0 {
		_ = os.Remove(filepath.Join(s.dir, lastFile))
		return nil
	}
	if err := s.ensureLast(entries[:keep]); err != nil {
		return err
	}
	return nil
}

type scanEntry struct {
	id      string
	started time.Time
}

func (s *Store) entries() ([]scanEntry, error) {
	dirEntries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list %s: %w", s.dir, err)
	}

	entries := make([]scanEntry, 0, len(dirEntries))
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !strings.HasPrefix(name, scanPrefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !validID(id) {
			continue
		}

		started := time.Time{}
		if info, err := de.Info(); err == nil {
			started = info.ModTime()
		}
		if data, err := os.ReadFile(filepath.Join(s.dir, name)); err == nil {
			var head struct {
				StartedAt time.Time `json:"startedAt"`
			}
			if json.Unmarshal(data, &head) == nil && !head.StartedAt.IsZero() {
				started = head.StartedAt
			}
		}
		entries = append(entries, scanEntry{id: id, started: started})
	}

	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].started.Equal(entries[j].started) {
			return entries[i].started.After(entries[j].started)
		}
		return entries[i].id > entries[j].id
	})
	return entries, nil
}

func (s *Store) ensureLast(kept []scanEntry) error {
	lastPath := filepath.Join(s.dir, lastFile)
	if id, err := s.readLastID(); err == nil {
		for _, e := range kept {
			if e.id == id {
				return nil
			}
		}
	}
	if len(kept) == 0 {
		_ = os.Remove(lastPath)
		return nil
	}
	return s.writeLast(kept[0].id)
}

func (s *Store) readLastID() (string, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, lastFile))
	if err != nil {
		return "", err
	}
	var ptr struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &ptr) == nil && validID(ptr.ID) {
		return ptr.ID, nil
	}
	// Tolerate a plain-text pointer written by an older build.
	if id := strings.TrimSpace(string(data)); validID(id) {
		return id, nil
	}
	return "", errors.New("store: invalid last pointer")
}

func (s *Store) writeLast(id string) error {
	data, err := json.Marshal(struct {
		ID string `json:"id"`
	}{ID: id})
	if err != nil {
		return fmt.Errorf("store: encode last pointer: %w", err)
	}
	data = append(data, '\n')
	return writeAtomic(filepath.Join(s.dir, lastFile), data, 0o644)
}

func (s *Store) uniqueID() (string, error) {
	for i := 0; i < 10; i++ {
		id := newScanID()
		if _, err := os.Stat(filepath.Join(s.dir, id+".json")); errors.Is(err, os.ErrNotExist) {
			return id, nil
		}
	}
	return "", errors.New("store: could not allocate a unique scan id")
}

func validID(id string) bool {
	if !strings.HasPrefix(id, scanPrefix) || len(id) <= len(scanPrefix) {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func newScanID() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "scan_" + time.Now().UTC().Format("20060102T150405") + "_" +
			fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return "scan_" + time.Now().UTC().Format("20060102T150405") + "_" + hex.EncodeToString(b[:])
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vigil-*.tmp")
	if err != nil {
		return fmt.Errorf("store: create temporary file in %s: %w", dir, err)
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
		return fmt.Errorf("store: write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: chmod %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("store: rename %s to %s: %w", tmpName, path, err)
	}
	remove = false
	return nil
}
