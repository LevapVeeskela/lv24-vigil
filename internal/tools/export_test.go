package tools

import "time"

// SetPendingClockForTest replaces the proposal clock and returns a restore
// function. It lives in a _test file, so it is not part of the package API.
func SetPendingClockForTest(now func() time.Time) func() {
	previous := pendingNow
	pendingNow = now
	return func() { pendingNow = previous }
}
