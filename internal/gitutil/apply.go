package gitutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Apply applies a unified diff to the working tree. It never commits and never
// touches the index beyond what `git apply` needs. The diff is first checked
// with ApplyCheck so a bad patch leaves the tree untouched.
func Apply(ctx context.Context, root, diff string) error {
	if strings.TrimSpace(diff) == "" {
		return fmt.Errorf("empty diff")
	}
	if err := ApplyCheck(ctx, root, diff); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "vigil-patch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	patch := filepath.Join(dir, "fix.patch")
	if err := os.WriteFile(patch, []byte(diff), 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "-C", root, "apply", "--whitespace=nowarn", patch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git apply: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
