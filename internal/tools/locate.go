package tools

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// findingRef addresses one finding in a scan: either by ID or fingerprint, or
// by a repository-relative path with an optional line.
type findingRef struct {
	FindingID string
	Path      string
	Line      int
}

// resolution reports how a findingRef was matched, so a client can display the
// choice and retry deterministically.
type resolution struct {
	MatchedBy string `json:"matchedBy"`
	Path      string `json:"path,omitempty"`
	Line      int    `json:"line,omitempty"`
}

// resolveFinding resolves ref inside scanID (or the latest scan) without ever
// guessing between several matches.
func resolveFinding(d Deps, scanID string, ref findingRef) (*model.ScanResult, *model.Finding, resolution, error) {
	id := strings.TrimSpace(ref.FindingID)
	path := strings.TrimSpace(ref.Path)
	switch {
	case id != "" && path != "":
		return nil, nil, resolution{}, toolErrorf(CodeArgs,
			"pass either findingId or path+line, not both")
	case id == "" && path == "":
		return nil, nil, resolution{}, toolErrorf(CodeArgs,
			"findingId or path is required")
	}

	if id != "" {
		scan, f, err := lookupFinding(d, scanID, id)
		if err != nil {
			return scan, nil, resolution{}, err
		}
		return scan, f, resolution{
			MatchedBy: idMatchKind(*f, id),
			Path:      f.Location.Path,
			Line:      f.Location.StartLine,
		}, nil
	}
	return resolveByLocation(d, scanID, path, ref.Line)
}

// idMatchKind names how a findingId resolved: an exact ID, an exact
// fingerprint, or a unique prefix of either.
func idMatchKind(f model.Finding, requested string) string {
	if strings.EqualFold(findingID(f), requested) {
		return "id"
	}
	if strings.EqualFold(findingFingerprint(f), requested) {
		return "fingerprint"
	}
	if strings.HasPrefix(strings.ToLower(findingID(f)), strings.ToLower(requested)) {
		return "id"
	}
	return "fingerprint"
}

// resolveByLocation resolves a repository-relative path and optional line.
// A line inside a finding's range wins; otherwise the nearest finding on that
// path is used, and a tie is an error rather than an arbitrary choice.
func resolveByLocation(d Deps, scanID, requestedPath string, line int) (*model.ScanResult, *model.Finding, resolution, error) {
	scan, err := loadScan(d, scanID)
	if err != nil {
		return nil, nil, resolution{}, err
	}
	want, err := normalizeRefPath(scan.Root, requestedPath)
	if err != nil {
		return scan, nil, resolution{}, err
	}

	all, active := scanFindingEntries(scan)
	all = dedupeFindings(all, active)

	onPath := make([]model.Finding, 0, 4)
	for i := range all {
		if sameFindingPath(normalizeFindingPath(all[i].Location.Path), want) {
			onPath = append(onPath, all[i])
		}
	}
	if len(onPath) == 0 {
		te := toolErrorf(CodeNotFound,
			"no finding at %q in scan %s; call vigil_scan or vigil_history, or pass findingId",
			requestedPath, scan.ID)
		te.Candidates = candidatesFor(all)
		return scan, nil, resolution{}, te
	}

	if line <= 0 {
		if len(onPath) == 1 {
			return scan, &onPath[0], locationResolution(onPath[0], "location"), nil
		}
		te := toolErrorf(CodeAmbiguous,
			"path %q matches %d findings; pass line to choose one", requestedPath, len(onPath))
		te.Candidates = candidatesFor(onPath)
		return scan, nil, resolution{}, te
	}

	inside := make([]model.Finding, 0, 2)
	for i := range onPath {
		if findingContainsLine(onPath[i], line) {
			inside = append(inside, onPath[i])
		}
	}
	if len(inside) == 1 {
		return scan, &inside[0], locationResolution(inside[0], "location"), nil
	}
	if len(inside) > 1 {
		te := toolErrorf(CodeAmbiguous,
			"line %d in %q matches %d findings; pass the full ID or a fingerprint", line, requestedPath, len(inside))
		te.Candidates = candidatesFor(inside)
		return scan, nil, resolution{}, te
	}

	nearest := make([]model.Finding, 0, 2)
	best := 0
	for i := range onPath {
		distance := absInt(onPath[i].Location.StartLine - line)
		switch {
		case len(nearest) == 0 || distance < best:
			best = distance
			nearest = append(nearest[:0], onPath[i])
		case distance == best:
			nearest = append(nearest, onPath[i])
		}
	}
	if len(nearest) == 1 {
		return scan, &nearest[0], locationResolution(nearest[0], "location-nearest"), nil
	}
	te := toolErrorf(CodeAmbiguous,
		"line %d in %q is equidistant from %d findings; pass line at or inside one of them, or the full ID",
		line, requestedPath, len(nearest))
	te.Candidates = candidatesFor(nearest)
	return scan, nil, resolution{}, te
}

// locationResolution describes a finding matched by path and line.
func locationResolution(f model.Finding, matchedBy string) resolution {
	return resolution{MatchedBy: matchedBy, Path: f.Location.Path, Line: f.Location.StartLine}
}

// findingContainsLine reports whether line falls inside the finding's range. A
// zero EndLine means the finding covers exactly its start line.
func findingContainsLine(f model.Finding, line int) bool {
	start := f.Location.StartLine
	if start <= 0 || start > line {
		return false
	}
	if f.Location.EndLine == 0 {
		return start == line
	}
	return line <= f.Location.EndLine
}

// normalizeRefPath maps a caller-supplied path onto the repository-relative
// slash form stored in findings. An absolute path is accepted only when it is
// inside root.
func normalizeRefPath(root, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", toolErrorf(CodeArgs, "path is required")
	}
	if !filepath.IsAbs(p) {
		return normalizeFindingPath(p), nil
	}
	if strings.TrimSpace(root) == "" {
		return "", toolErrorf(CodeArgs,
			"absolute path %q needs a scan root; pass a path relative to the scan root", p)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return "", toolErrorf(CodeArgs, "path %q is outside the scan root %s", p, root)
	}
	rel = normalizeFindingPath(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", toolErrorf(CodeArgs, "path %q is outside the scan root %s", p, root)
	}
	return rel, nil
}

// normalizeFindingPath puts a path into the slash-separated, cleaned form used
// for comparisons.
func normalizeFindingPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(p)), "./")
}

// sameFindingPath compares normalised paths. Windows filesystems are
// case-insensitive; elsewhere a mismatch is a mismatch.
func sameFindingPath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
