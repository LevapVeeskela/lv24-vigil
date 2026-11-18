package scanner

import (
	"errors"
	"os"
)

// Stable skip reason keys for model.Stats.SkippedReasons. They are
// deliberately low-cardinality categories: callers group and display them, so a
// new per-file value would make the map grow without bound.
const (
	skipReasonWalkError    = "walk_error"
	skipReasonPathError    = "path_error"
	skipReasonToolState    = "tool_state"
	skipReasonSymlink      = "symlink"
	skipReasonSymlinkError = "symlink_error"
	skipReasonIgnored      = "ignored"
	skipReasonNotIncluded  = "not_included"
	skipReasonBinary       = "binary"
	skipReasonTooLarge     = "too_large"
	skipReasonSpecialFile  = "special_file"
	skipReasonHardlink     = "hardlink"
	skipReasonReadError    = "read_error"
	skipReasonOutsideRoot  = "outside_root"
	skipReasonUnsafePath   = "unsafe_path"
	skipReasonMissing      = "missing"
	skipReasonDuplicate    = "duplicate"
)

// countSkip adds one file to a reason counter. A nil map is created on first
// use, so callers can thread a nil reasons map through the happy path.
func countSkip(reasons map[string]int, key string) map[string]int {
	if reasons == nil {
		reasons = make(map[string]int, 4)
	}
	reasons[key]++
	return reasons
}

// mergeReasons folds src into dst without modifying src. A nil dst is created
// on first use.
func mergeReasons(dst, src map[string]int) map[string]int {
	for key, count := range src {
		if count <= 0 {
			continue
		}
		if dst == nil {
			dst = make(map[string]int, len(src))
		}
		dst[key] += count
	}
	return dst
}

// skipReasonForErr maps a loadFile sentinel to its stable reason key. Any other
// error is an I/O failure the caller reports separately.
func skipReasonForErr(err error) string {
	switch {
	case errors.Is(err, errSkipBinary):
		return skipReasonBinary
	case errors.Is(err, errSkipTooLarge):
		return skipReasonTooLarge
	case errors.Is(err, errSkipSpecial):
		return skipReasonSpecialFile
	case errors.Is(err, errSkipSymlink):
		return skipReasonSymlink
	case errors.Is(err, errSkipHardlink):
		return skipReasonHardlink
	case errors.Is(err, os.ErrNotExist):
		return skipReasonMissing
	default:
		return skipReasonReadError
	}
}
