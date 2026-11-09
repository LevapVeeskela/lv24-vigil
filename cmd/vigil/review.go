package main

import "io"

// runReview scans only the added lines of a diff. It is the scan pipeline with
// changed-only defaults: --base defaults to HEAD and --changed does not exist
// because reviewing changes is the whole point.
func runReview(args []string, stdout, stderr io.Writer) error {
	return runScanLike("review", args, true, stdout, stderr)
}
