package main

import (
	"strings"
	"testing"
)

func TestFixWithoutScans(t *testing.T) {
	newTestRepo(t)

	_, _, err := runCLI(t, "fix", "VGL-AAAAAAAAAA")
	if err == nil {
		t.Fatal("expected an error without stored scans")
	}
	if !strings.Contains(err.Error(), "run `vigil scan`") {
		t.Fatalf("error is not actionable: %v", err)
	}
}

func TestFixWithoutModel(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if len(res.Findings) == 0 {
		t.Fatal("scan produced no findings")
	}

	_, _, err = runCLI(t, "fix", res.Findings[0].ID)
	if err == nil {
		t.Fatal("expected an error without a configured model")
	}
	if !strings.Contains(err.Error(), "no model configured") {
		t.Fatalf("error is not actionable: %v", err)
	}
}

func TestFixUnknownFinding(t *testing.T) {
	newTestRepo(t)

	if _, _, err := runCLI(t, "scan", ".", "--format", "json"); err != nil {
		t.Fatalf("scan: %v", err)
	}
	_, _, err := runCLI(t, "fix", "VGL-NOTAREALID")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want a not-found error", err)
	}
}
