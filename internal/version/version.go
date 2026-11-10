// Package version holds build metadata injected by GoReleaser.
package version

import "runtime"

// Values are overridden with -ldflags "-X ...".
var (
	Version   = "0.5.0"
	Commit    = "none"
	Date      = "unknown"
	BuildRepo = "github.com/LevapVeeskela/lv24-vigil"
)

// String returns a human-readable version line.
func String() string {
	return "vigil " + Version + " (" + Commit + ", " + Date + ", " + runtime.Version() + ")"
}
