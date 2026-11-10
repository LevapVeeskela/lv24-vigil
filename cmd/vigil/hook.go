package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// hookMarker identifies a hook file written by Vigil. A hook without this
	// exact line is treated as user-owned and is never overwritten or removed
	// without --force.
	hookMarker = "# managed by lv24-vigil"
	// hookBackupSuffix is appended to a foreign hook before --force replaces it.
	hookBackupSuffix = ".pre-vigil.bak"
	// hookDefaultFailOn keeps the local gate aligned with the CI templates.
	hookDefaultFailOn = "high"
	// hookBinaryEnv lets a hook run a specific binary instead of PATH lookup.
	hookBinaryEnv = "VIGIL_BIN"
)

// hookModes is the supported install order and the order status/uninstall use.
var hookModes = []string{"pre-commit", "pre-push"}

type hookOptions struct {
	mode   string
	force  bool
	failOn string
	noLLM  bool
}

// runHook dispatches `vigil hook install|status|uninstall`.
func runHook(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printHookUsage(stdout)
		return nil
	}
	switch args[0] {
	case "install":
		return runHookInstall(args[1:], stdout, stderr)
	case "status":
		return runHookStatus(args[1:], stdout)
	case "uninstall":
		return runHookUninstall(args[1:], stdout)
	case "help", "--help", "-h":
		printHookUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown hook command %q (use install, status or uninstall)", args[0])
	}
}

func runHookInstall(args []string, stdout, stderr io.Writer) error {
	o := hookOptions{mode: "pre-commit", failOn: hookDefaultFailOn, noLLM: true}
	fs := newFlagSet("hook install")
	fs.StringVar(&o.mode, "mode", o.mode, "hook to install: pre-commit or pre-push")
	fs.BoolVar(&o.force, "force", false, "back up and replace a hook not managed by Vigil")
	fs.StringVar(&o.failOn, "fail-on", o.failOn, "low, medium, high or critical")
	fs.BoolVar(&o.noLLM, "no-llm", true, "deterministic rules only (hooks are always deterministic)")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printHookUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("hook install: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("hook install takes no arguments (got %q)", positional[0])
	}
	if !o.noLLM {
		return errors.New("hook scans are deterministic; --no-llm cannot be disabled")
	}
	mode, err := normalizeHookMode(o.mode)
	if err != nil {
		return err
	}
	failOn, err := parseSeverity(o.failOn)
	if err != nil {
		return fmt.Errorf("--fail-on: %w", err)
	}

	hooksDir, err := gitHooksDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}

	target := filepath.Join(hooksDir, mode)
	existing, err := os.ReadFile(target)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", target, err)
	}
	managed := exists && isVigilHook(existing)
	if exists && !managed {
		if !o.force {
			return fmt.Errorf(
				"%s already exists and is not managed by lv24-vigil; pass --force to back it up to %s and replace it",
				target, target+hookBackupSuffix,
			)
		}
		backup := target + hookBackupSuffix
		if err := copyHookFile(target, backup); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "backed up %s to %s\n", target, backup)
	}

	if err := writeFile(target, []byte(hookScript(mode, string(failOn)))); err != nil {
		return err
	}
	// Git ignores the executable bit on Windows, but every POSIX checkout needs
	// it or git silently skips the hook.
	if err := os.Chmod(target, 0o755); err != nil {
		return fmt.Errorf("make %s executable: %w", target, err)
	}

	verb := "Installed"
	if managed {
		verb = "Updated"
	}
	fmt.Fprintf(stdout, "%s %s hook at %s\n", verb, mode, target)
	fmt.Fprintf(stdout, "  target  %s\n", hookTargetCommand(mode, string(failOn)))
	fmt.Fprintf(stdout, "  marker  %s\n", hookMarker)
	fmt.Fprintln(stdout, "Remove it with `vigil hook uninstall`.")

	if bin := hookBinary(); !binaryAvailable(bin) {
		fmt.Fprintf(stderr, "vigil: warning: %s was not found on PATH; the hook will fail until it is installed (npm i -g lv24-vigil) or %s points at it\n", bin, hookBinaryEnv)
	}
	return nil
}

func runHookStatus(args []string, stdout io.Writer) error {
	fs := newFlagSet("hook status")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printHookUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("hook status: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("hook status takes no arguments (got %q)", positional[0])
	}

	hooksDir, err := gitHooksDir()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Vigil hooks in %s\n", hooksDir)

	installed := 0
	for _, mode := range hookModes {
		target := filepath.Join(hooksDir, mode)
		data, err := os.ReadFile(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", target, err)
		}
		if !isVigilHook(data) {
			fmt.Fprintf(stdout, "  %-11s present, not managed by lv24-vigil (left untouched)\n", mode)
			continue
		}
		installed++
		fmt.Fprintf(stdout, "  %-11s installed\n", mode)
		fmt.Fprintf(stdout, "  %-11s marker: %s\n", "", hookMarker)
		fmt.Fprintf(stdout, "  %-11s target: %s\n", "", hookTargetFromScript(data, mode))
		if _, err := os.Stat(target + hookBackupSuffix); err == nil {
			fmt.Fprintf(stdout, "  %-11s backup: %s\n", "", target+hookBackupSuffix)
		}
	}
	if installed == 0 {
		fmt.Fprintln(stdout, "No Vigil hooks installed. Run `vigil hook install`.")
	}
	return nil
}

func runHookUninstall(args []string, stdout io.Writer) error {
	fs := newFlagSet("hook uninstall")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printHookUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("hook uninstall: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("hook uninstall takes no arguments (got %q)", positional[0])
	}

	hooksDir, err := gitHooksDir()
	if err != nil {
		return err
	}
	removed := 0
	for _, mode := range hookModes {
		target := filepath.Join(hooksDir, mode)
		data, err := os.ReadFile(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", target, err)
		}
		if !isVigilHook(data) {
			fmt.Fprintf(stdout, "  %s left untouched (not managed by lv24-vigil)\n", mode)
			continue
		}
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("remove %s: %w", target, err)
		}
		removed++
		fmt.Fprintf(stdout, "removed %s\n", target)

		backup := target + hookBackupSuffix
		if _, err := os.Stat(backup); err == nil {
			// os.Rename cannot replace an existing file on Windows, and the
			// target was just removed, so this is safe on every platform.
			if err := os.Rename(backup, target); err != nil {
				return fmt.Errorf("restore %s: %w", target, err)
			}
			fmt.Fprintf(stdout, "restored %s\n", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check backup %s: %w", backup, err)
		}
	}
	if removed == 0 {
		fmt.Fprintln(stdout, "No Vigil hooks to remove.")
	}
	return nil
}

// gitHooksDir returns the effective hooks directory, honoring core.hooksPath
// and linked worktrees. `git rev-parse --git-path hooks` may print a relative
// path; it is relative to the current directory.
func gitHooksDir() (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", errors.New("git was not found on PATH; Vigil hooks need git")
	}
	if _, err := exec.Command("git", "rev-parse", "--show-toplevel").Output(); err != nil {
		return "", errors.New("not inside a git repository; run `vigil hook install` from a repository checkout")
	}
	out, err := exec.Command("git", "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", fmt.Errorf("find the git hooks directory: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", errors.New("git returned an empty hooks directory")
	}
	if !filepath.IsAbs(dir) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve the hooks directory: %w", err)
		}
		dir = filepath.Join(cwd, dir)
	}
	return filepath.Clean(dir), nil
}

func normalizeHookMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	for _, candidate := range hookModes {
		if mode == candidate {
			return mode, nil
		}
	}
	return "", fmt.Errorf("unsupported hook mode %q (use pre-commit or pre-push)", mode)
}

// isVigilHook requires the marker on its own line. A random file that merely
// mentions the string in prose is still user-owned.
func isVigilHook(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == hookMarker {
			return true
		}
	}
	return false
}

func hookBinary() string {
	if bin := strings.TrimSpace(os.Getenv(hookBinaryEnv)); bin != "" {
		return bin
	}
	return "vigil"
}

func binaryAvailable(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func hookTargetCommand(mode, failOn string) string {
	if mode == "pre-push" {
		return fmt.Sprintf("vigil scan --changed --base @{upstream} (fallback HEAD~1) --no-llm --fail-on %s --quiet", failOn)
	}
	return fmt.Sprintf("vigil scan --changed --base HEAD --no-llm --fail-on %s --quiet", failOn)
}

func hookTargetFromScript(data []byte, mode string) string {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# target: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# target: "))
		}
	}
	return hookTargetCommand(mode, hookDefaultFailOn)
}

// hookScript generates a POSIX sh hook. The pre-push variant diffs against the
// upstream branch; a repository without an upstream (or with a single commit)
// still gets a usable base instead of a hard failure.
func hookScript(mode, failOn string) string {
	base := "HEAD"
	upstream := ""
	if mode == "pre-push" {
		base = "@{upstream}"
		upstream = `
if ! git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' >/dev/null 2>&1; then
  base='HEAD~1'
fi
if ! git rev-parse --verify --quiet 'HEAD~1' >/dev/null 2>&1; then
  base='HEAD'
fi
`
	}
	return fmt.Sprintf(`#!/bin/sh
%s
# mode: %s
# target: %s
# Generated by vigil hook install; reinstall instead of editing.
# Remove with: vigil hook uninstall

set -eu

VIGIL_BIN="${VIGIL_BIN:-vigil}"

if ! command -v "$VIGIL_BIN" >/dev/null 2>&1; then
  echo "vigil: $VIGIL_BIN was not found on PATH." >&2
  echo "vigil: install it with 'npm i -g lv24-vigil' or set VIGIL_BIN." >&2
  echo "vigil: refusing to skip the security check." >&2
  exit 1
fi

base='%s'
%s
"$VIGIL_BIN" scan --changed --base "$base" --no-llm --fail-on '%s' --quiet
`, hookMarker, mode, hookTargetCommand(mode, failOn), base, upstream, failOn)
}

// copyHookFile preserves the original mode so restoring a backup leaves the
// foreign hook exactly as it was.
func copyHookFile(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return fmt.Errorf("read %s: %w", from, err)
	}
	info, err := os.Stat(from)
	if err != nil {
		return fmt.Errorf("stat %s: %w", from, err)
	}
	if err := writeFile(to, data); err != nil {
		return err
	}
	if err := os.Chmod(to, info.Mode().Perm()); err != nil {
		return fmt.Errorf("set mode on backup %s: %w", to, err)
	}
	return nil
}

func printHookUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  vigil hook install [--mode pre-commit|pre-push] [--force] [--fail-on LEVEL] [--no-llm]
  vigil hook status
  vigil hook uninstall

Install a local git hook that runs a deterministic scan of changed files before
a commit (default) or a push. Hooks are marked with "# managed by lv24-vigil".
A foreign hook is never replaced or removed silently: install refuses unless
--force is given, and --force saves the old hook as <hook>.pre-vigil.bak.
Uninstall removes only marked hooks and restores a saved backup.

Options:
  --mode MODE       pre-commit (default) or pre-push
  --force           back up and replace a hook not managed by Vigil
  --fail-on LEVEL   low, medium, high or critical (default high)
  --no-llm          accepted for clarity; hook scans are always deterministic

The pre-commit hook runs:
  vigil scan --changed --base HEAD --no-llm --fail-on LEVEL --quiet
The pre-push hook uses --base @{upstream}, falling back to HEAD~1.

Environment:
  VIGIL_BIN         binary the hook runs (default: vigil)
`)
}
