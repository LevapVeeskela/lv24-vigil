package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: a project .vigil.yaml may set output.path, and it was only
// checked to be a relative path inside the repository. A cloned repository
// could so make a plain "vigil scan" overwrite a source file with the report,
// although a scan must never modify source files.
func TestProjectOutputPathCannotOverwriteSource(t *testing.T) {
	dir := newTestRepo(t)
	const source = "print('uncommitted work')\n"
	writeTestFile(t, dir, "app.py", source)
	writeTestFile(t, dir, ".vigil.yaml", "output:\n  path: app.py\n  format: json\n")

	_, _, err := runCLI(t, "scan", ".", "--no-llm", "--quiet")
	if err == nil {
		t.Fatal("scan succeeded, want a refusal to overwrite app.py")
	}
	if !strings.Contains(err.Error(), "output.path") || !strings.Contains(err.Error(), "app.py") {
		t.Fatalf("error does not explain the refusal: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "app.py"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != source {
		t.Fatalf("app.py was modified by the scan: %q", got)
	}
}

// The ordinary use keeps working: a committed report path is created, then
// replaced by the next scan, in every format.
func TestProjectOutputPathRewritesItsOwnReport(t *testing.T) {
	for format, name := range map[string]string{"md": "vigil-report.md", "json": "vigil-report.json", "sarif": "vigil.sarif", "html": "vigil-report.html"} {
		t.Run(format, func(t *testing.T) {
			dir := newTestRepo(t)
			writeTestFile(t, dir, ".vigil.yaml", "output:\n  path: "+name+"\n  format: "+format+"\n")
			for run := 1; run <= 2; run++ {
				if _, _, err := runCLI(t, "scan", ".", "--no-llm", "--quiet"); err != nil {
					t.Fatalf("scan %d: %v", run, err)
				}
			}
			if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Size() == 0 {
				t.Fatalf("report %s was not written: %v", name, err)
			}
		})
	}
}

// An explicit --output is the user's own choice and is not second-guessed.
func TestExplicitOutputFlagStillOverwrites(t *testing.T) {
	dir := newTestRepo(t)
	writeTestFile(t, dir, "notes.txt", "scratch\n")
	if _, _, err := runCLI(t, "scan", ".", "--no-llm", "--quiet", "--output", "notes.txt"); err != nil {
		t.Fatalf("scan --output notes.txt: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "notes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Vigil security report") {
		t.Fatalf("--output did not write the report: %q", got)
	}
}
