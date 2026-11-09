package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitWritesStarterAndRefusesOverwrite(t *testing.T) {
	dir := newTestRepo(t)

	out, stderr, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(out, "Next steps") {
		t.Errorf("init did not print next steps: %s", out)
	}

	path := filepath.Join(dir, ".vigil.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .vigil.yaml: %v", err)
	}
	for _, want := range []string{"# provider:", "# model:", "scan:", "exclude:", "output:"} {
		if !strings.Contains(string(data), want) {
			t.Errorf(".vigil.yaml missing %q\n%s", want, data)
		}
	}

	if _, _, err := runCLI(t, "init"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second init = %v, want an already-exists error", err)
	}

	if _, _, err := runCLI(t, "init", "--force"); err != nil {
		t.Fatalf("init --force: %v", err)
	}
}
