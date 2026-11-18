package analysis

import (
	"strings"
	"testing"
)

// TestValidateDiffRejectsExtendedHeaders: git apply honours rename/copy headers
// and non-regular file modes. A fix diff must not be able to create a path that
// is absent from the reviewed pre-image map.
func TestValidateDiffRejectsExtendedHeaders(t *testing.T) {
	root := t.TempDir()
	cases := map[string]string{
		"rename": "diff --git a/a.txt b/b.txt\n" +
			"similarity index 100%\nrename from a.txt\nrename to b.txt\n" +
			"--- a/a.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-old\n+new\n",
		"copy": "diff --git a/a.txt b/b.txt\n" +
			"similarity index 100%\ncopy from a.txt\ncopy to b.txt\n" +
			"--- a/a.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-old\n+new\n",
		"octal symlink": "diff --git a/link b/link\n" +
			"new file mode 0120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+/etc/passwd\n",
		"mode change to symlink": "diff --git a/a.txt b/a.txt\n" +
			"old mode 100644\nnew mode 120000\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n",
	}
	for name, diff := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateDiff(root, diff); err == nil {
				t.Fatalf("ValidateDiff accepted %s:\n%s", name, diff)
			}
		})
	}

	regular := "diff --git a/a.txt b/a.txt\n" +
		"new file mode 100644\n--- /dev/null\n+++ b/a.txt\n@@ -0,0 +1 @@\n+new\n"
	if err := ValidateDiff(root, regular); err != nil {
		t.Fatalf("ValidateDiff rejected a regular new file: %v", err)
	}
}

func TestValidateDiffRejectsModeTextWithoutHeader(t *testing.T) {
	// A mode line outside a git header is still a mode declaration; do not let
	// a leading space or a crafted line bypass the regular-file check.
	root := t.TempDir()
	diff := "diff --git a/a.txt b/a.txt\n" +
		"new mode 0120777\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n"
	if err := ValidateDiff(root, diff); err == nil || !strings.Contains(err.Error(), "file mode") {
		t.Fatalf("ValidateDiff mode error = %v, want a file-mode rejection", err)
	}
}
