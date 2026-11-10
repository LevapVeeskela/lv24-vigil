package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newHookRepo creates an initialized git repository and makes it the working
// directory, because hook install resolves the hooks directory through git.
func newHookRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	cmd := exec.Command("git", "init", "-q", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	t.Chdir(dir)
	return dir
}

func hookPath(dir, mode string) string {
	return filepath.Join(dir, ".git", "hooks", mode)
}

func readHook(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestHookInstallStatusUninstall(t *testing.T) {
	dir := newHookRepo(t)

	out, _, err := runCLI(t, "hook", "install")
	if err != nil {
		t.Fatalf("hook install: %v", err)
	}
	if !strings.Contains(out, "Installed pre-commit hook") {
		t.Errorf("install output missing confirmation:\n%s", out)
	}
	if !strings.Contains(out, hookMarker) {
		t.Errorf("install output missing marker:\n%s", out)
	}

	path := hookPath(dir, "pre-commit")
	script := readHook(t, path)
	for _, want := range []string{
		"#!/bin/sh",
		hookMarker,
		`VIGIL_BIN="${VIGIL_BIN:-vigil}"`,
		`command -v "$VIGIL_BIN"`,
		`"$VIGIL_BIN" scan --changed --base "$base" --no-llm --fail-on 'high' --quiet`,
		"refusing to skip the security check",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("generated hook missing %q\n%s", want, script)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat hook: %v", err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("hook is not executable: %v", info.Mode())
		}
	}

	out, _, err = runCLI(t, "hook", "status")
	if err != nil {
		t.Fatalf("hook status: %v", err)
	}
	for _, want := range []string{"pre-commit", "installed", hookMarker, "vigil scan --changed --base HEAD"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q\n%s", want, out)
		}
	}

	out, _, err = runCLI(t, "hook", "uninstall")
	if err != nil {
		t.Fatalf("hook uninstall: %v", err)
	}
	if !strings.Contains(out, "removed") {
		t.Errorf("uninstall output missing removal:\n%s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("hook still exists after uninstall: %v", err)
	}
	out, _, err = runCLI(t, "hook", "status")
	if err != nil {
		t.Fatalf("hook status after uninstall: %v", err)
	}
	if !strings.Contains(out, "No Vigil hooks installed") {
		t.Errorf("status did not report an empty state:\n%s", out)
	}
}

func TestHookInstallRefusesForeignHook(t *testing.T) {
	dir := newHookRepo(t)
	path := hookPath(dir, "pre-commit")
	const foreign = "#!/bin/sh\necho custom-hook\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(foreign), 0o755); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, "hook", "install")
	if err == nil {
		t.Fatal("install replaced a foreign hook without --force")
	}
	if !strings.Contains(err.Error(), "not managed by lv24-vigil") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := readHook(t, path); got != foreign {
		t.Fatalf("foreign hook changed:\n%s", got)
	}

	out, _, err := runCLI(t, "hook", "status")
	if err != nil {
		t.Fatalf("hook status: %v", err)
	}
	if !strings.Contains(out, "not managed by lv24-vigil") {
		t.Errorf("status did not flag the foreign hook:\n%s", out)
	}

	out, _, err = runCLI(t, "hook", "uninstall")
	if err != nil {
		t.Fatalf("hook uninstall: %v", err)
	}
	if got := readHook(t, path); got != foreign {
		t.Fatalf("uninstall touched a foreign hook:\n%s", got)
	}
	if !strings.Contains(out, "left untouched") {
		t.Errorf("uninstall did not explain the foreign hook:\n%s", out)
	}
}

func TestHookInstallForceBacksUpAndUninstallRestores(t *testing.T) {
	dir := newHookRepo(t)
	path := hookPath(dir, "pre-commit")
	const foreign = "#!/bin/sh\necho custom-hook\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(foreign), 0o755); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCLI(t, "hook", "install", "--force")
	if err != nil {
		t.Fatalf("hook install --force: %v", err)
	}
	if !strings.Contains(out, "backed up") {
		t.Errorf("install did not report the backup:\n%s", out)
	}
	backup := path + hookBackupSuffix
	if got := readHook(t, backup); got != foreign {
		t.Fatalf("backup content = %q, want %q", got, foreign)
	}
	if got := readHook(t, path); !strings.Contains(got, hookMarker) {
		t.Fatalf("foreign hook was not replaced:\n%s", got)
	}

	if _, _, err := runCLI(t, "hook", "uninstall"); err != nil {
		t.Fatalf("hook uninstall: %v", err)
	}
	if got := readHook(t, path); got != foreign {
		t.Fatalf("uninstall did not restore the backup:\n%s", got)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup still exists after restore: %v", err)
	}
}

func TestHookInstallUpdatesManagedHookWithoutBackup(t *testing.T) {
	dir := newHookRepo(t)
	if _, _, err := runCLI(t, "hook", "install"); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if _, _, err := runCLI(t, "hook", "install", "--fail-on", "critical"); err != nil {
		t.Fatalf("second install: %v", err)
	}
	script := readHook(t, hookPath(dir, "pre-commit"))
	if !strings.Contains(script, "--fail-on 'critical'") {
		t.Fatalf("managed hook was not updated:\n%s", script)
	}
	if _, err := os.Stat(hookPath(dir, "pre-commit") + hookBackupSuffix); !os.IsNotExist(err) {
		t.Fatalf("managed update created a backup: %v", err)
	}
}

func TestHookPrePushScriptUsesUpstreamWithFallback(t *testing.T) {
	dir := newHookRepo(t)
	if _, _, err := runCLI(t, "hook", "install", "--mode", "pre-push", "--fail-on", "critical"); err != nil {
		t.Fatalf("hook install --mode pre-push: %v", err)
	}
	script := readHook(t, hookPath(dir, "pre-push"))
	for _, want := range []string{
		"# mode: pre-push",
		"base='@{upstream}'",
		"@{upstream}",
		"base='HEAD~1'",
		"base='HEAD'",
		"--fail-on 'critical'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("pre-push hook missing %q\n%s", want, script)
		}
	}

	out, _, err := runCLI(t, "hook", "status")
	if err != nil {
		t.Fatalf("hook status: %v", err)
	}
	if !strings.Contains(out, "pre-push") || !strings.Contains(out, "fallback HEAD~1") {
		t.Errorf("status missing the pre-push target:\n%s", out)
	}
}

func TestHookInstallRejectsBadInput(t *testing.T) {
	newHookRepo(t)

	if _, _, err := runCLI(t, "hook", "install", "--mode", "post-commit"); err == nil {
		t.Fatal("install accepted an unsupported mode")
	}
	if _, _, err := runCLI(t, "hook", "install", "--fail-on", "urgent"); err == nil {
		t.Fatal("install accepted an unsupported severity")
	}
	if _, _, err := runCLI(t, "hook", "install", "--no-llm=false"); err == nil {
		t.Fatal("install accepted --no-llm=false")
	}
}

// TestHookScriptExecutesDeterministicScan runs the generated script with a fake
// vigil binary and asserts the exact argv. It is POSIX-only: the hook is sh.
func TestHookScriptExecutesDeterministicScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the generated hook is a POSIX sh script")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	dir := newHookRepo(t)
	if _, _, err := runCLI(t, "hook", "install"); err != nil {
		t.Fatalf("hook install: %v", err)
	}

	argsFile := filepath.Join(dir, "args.txt")
	fake := filepath.Join(dir, "fake-vigil")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookBinaryEnv, fake)

	cmd := exec.Command("sh", hookPath(dir, "pre-commit"))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hook execution: %v\n%s", err, out)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read fake argv: %v", err)
	}
	want := "scan\n--changed\n--base\nHEAD\n--no-llm\n--fail-on\nhigh\n--quiet\n"
	if got := string(data); got != want {
		t.Fatalf("hook argv = %q, want %q", got, want)
	}
}

func TestHookScriptFailsWhenBinaryIsMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the generated hook is a POSIX sh script")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	dir := newHookRepo(t)
	if _, _, err := runCLI(t, "hook", "install"); err != nil {
		t.Fatalf("hook install: %v", err)
	}
	t.Setenv(hookBinaryEnv, filepath.Join(dir, "missing-vigil"))

	cmd := exec.Command("sh", hookPath(dir, "pre-commit"))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("hook succeeded with a missing binary:\n%s", out)
	}
	if !strings.Contains(string(out), "was not found on PATH") {
		t.Fatalf("missing-binary message is unclear:\n%s", out)
	}
}
