package scanner

import "testing"

func TestIgnoreMatcherExcludes(t *testing.T) {
	m := newIgnoreMatcher([]string{
		"node_modules/**",
		"*.lock",
		"src/**/generated/*.go",
		"?.env",
		"build/",
	}, nil)

	tests := []struct {
		path string
		dir  bool
		want bool
	}{
		{"node_modules/pkg/index.js", false, true},
		{"node_modules", true, true},
		{"a/node_modules/x.js", false, false},
		{"go.lock", false, true},
		{"a/b/go.lock", false, true},
		{"src/generated/x.go", false, true},
		{"src/a/b/generated/x.go", false, true},
		{"src/a/b/generated/x.py", false, false},
		{"x.env", false, true},
		{"a/x.env", false, true},
		{".env", false, false},
		{"build", true, true},
		{"build", false, false},
		{"build/x.go", false, true},
		{"src/main.go", false, false},
	}
	for _, tc := range tests {
		if got := m.ignored(tc.path, tc.dir); got != tc.want {
			t.Errorf("ignored(%q, dir=%v) = %v, want %v", tc.path, tc.dir, got, tc.want)
		}
	}
}

func TestIgnoreMatcherDoubleStar(t *testing.T) {
	m := newIgnoreMatcher([]string{"foo/**/bar.go", "**/*.min.js"}, nil)

	cases := map[string]bool{
		"foo/bar.go":        true,
		"foo/a/bar.go":      true,
		"foo/a/b/bar.go":    true,
		"foo/a/bar.py":      false,
		"bar.go":            false,
		"app.min.js":        true,
		"static/app.min.js": true,
		"static/app.js":     false,
	}
	for path, want := range cases {
		if got := m.ignored(path, false); got != want {
			t.Errorf("ignored(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIgnoreMatcherIncludes(t *testing.T) {
	m := newIgnoreMatcher(nil, []string{"**/*.go", "cmd/*"})
	cases := map[string]bool{
		"main.go":        true,
		"internal/x.go":  true,
		"cmd/vigil":      true,
		"cmd/vigil/main": true,
		"internal/x.py":  false,
		"README.md":      false,
	}
	for path, want := range cases {
		if got := m.included(path); got != want {
			t.Errorf("included(%q) = %v, want %v", path, got, want)
		}
	}

	empty := newIgnoreMatcher(nil, nil)
	if !empty.included("anything") {
		t.Fatal("empty include list must accept everything")
	}

	dirInclude := newIgnoreMatcher(nil, []string{"src"})
	if !dirInclude.included("src/main.go") || !dirInclude.included("src/a/b.go") {
		t.Fatal("a directory include should allow files below it")
	}
	if dirInclude.included("other/main.go") {
		t.Fatal("a directory include leaked files outside it")
	}
}

func TestGlobQuestionMarkAndLiteralMeta(t *testing.T) {
	m := newIgnoreMatcher([]string{"file?.txt", "a+b.txt", "x[1].txt"}, nil)
	cases := map[string]bool{
		"file1.txt":  true,
		"file12.txt": false,
		"a+b.txt":    true,
		"x[1].txt":   true,
		"x1.txt":     false,
	}
	for path, want := range cases {
		if got := m.ignored(path, false); got != want {
			t.Errorf("ignored(%q) = %v, want %v", path, got, want)
		}
	}
}
