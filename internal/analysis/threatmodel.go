package analysis

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/llm"
)

const (
	// maxRepoMapFiles bounds the file list in a threat-model prompt.
	maxRepoMapFiles = 200
	// maxRepoMapBytes bounds the whole repository map.
	maxRepoMapBytes = 48 << 10
	// maxRepoTreeBytes bounds the directory tree section.
	maxRepoTreeBytes = 12 << 10
	// maxRepoWalkEntries bounds the walk itself on enormous trees.
	maxRepoWalkEntries = 5000
)

// ThreatModel builds a bounded repository map and asks the model for a
// STRIDE-style markdown threat model. The result is capped at 16 KiB.
func (a *Analyzer) ThreatModel(ctx context.Context, root string) (string, error) {
	if !a.enabled() {
		return "", ErrLLMNotConfigured
	}
	repoMap, err := buildRepoMap(ctx, root)
	if err != nil {
		return "", fmt.Errorf("threat model: %w", err)
	}

	resp, err := a.complete(ctx, llm.Request{
		System:   systemThreatModel,
		Messages: []llm.Message{{Role: llm.RoleUser, Content: buildThreatModelPrompt(repoMap)}},
	})
	if err != nil {
		return "", fmt.Errorf("threat model: %w", err)
	}

	text := strings.TrimSpace(strings.TrimPrefix(llm.StripFences(resp.Text), "\ufeff"))
	if text == "" {
		return "", errors.New("threat model: model returned an empty response")
	}
	text = truncateBytes(stripControls(text), maxThreatModelBytes)
	if strings.TrimSpace(text) == "" {
		return "", errors.New("threat model: model returned an empty response")
	}
	return text, nil
}

type repoFile struct {
	rel  string
	size int64
}

// buildRepoMap walks root and renders a bounded, deterministic map: a collapsed
// directory tree, the root README, package manifests and the first chunks of
// route/auth/controller files.
func buildRepoMap(ctx context.Context, root string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", rootAbs)
	}
	if resolved, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = resolved
	}

	var entries []repoFile
	truncatedWalk := false
	err = filepath.WalkDir(rootAbs, func(p string, d fs.DirEntry, walkErr error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p == rootAbs {
				return nil
			}
			if skipRepoDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(rootAbs, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if _, ok := cleanRelativePath(rel); !ok {
			return nil
		}
		if isSensitiveRepoFile(rel) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if fi.Size() > 2<<20 {
			return nil
		}
		entries = append(entries, repoFile{rel: rel, size: fi.Size()})
		if len(entries) >= maxRepoWalkEntries {
			truncatedWalk = true
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	sort.SliceStable(entries, func(i, j int) bool {
		si := repoMapScore(entries[i])
		sj := repoMapScore(entries[j])
		if si != sj {
			return si > sj
		}
		return entries[i].rel < entries[j].rel
	})
	if len(entries) > maxRepoMapFiles {
		entries = entries[:maxRepoMapFiles]
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	var b strings.Builder
	add := func(s string) bool {
		if b.Len()+len(s) > maxRepoMapBytes {
			return false
		}
		b.WriteString(s)
		return true
	}

	add("## Directory tree (directories collapsed)\n")
	tree := renderRepoTree(entries)
	if truncatedWalk {
		tree += "\n(file list truncated at the walk limit)"
	}
	if len(tree) > maxRepoTreeBytes {
		tree = truncateBytes(tree, maxRepoTreeBytes)
	}
	add(tree + "\n")

	included := make(map[string]bool)
	readSnippet := func(rel string, max int64, heading string) bool {
		if included[rel] {
			return true
		}
		content, _, truncated, err := readFileBounded(rootAbs, rel, max)
		if err != nil {
			return true
		}
		section := "\n" + heading + "\n" + wrapUntrusted(rel, sanitizeCode(string(content), int(max)+2048))
		if truncated {
			section += "\n(truncated)"
		}
		if !add(section + "\n") {
			return false
		}
		included[rel] = true
		return true
	}

	// README first, up to 20 KiB.
	for _, e := range entries {
		if path.Dir(e.rel) != "." {
			continue
		}
		base := strings.ToLower(path.Base(e.rel))
		if base == "readme" || base == "readme.md" || base == "readme.rst" || base == "readme.txt" {
			readSnippet(e.rel, 20<<10, "## README")
			break
		}
	}

	// Package manifests, 5 KiB each, at most eight.
	manifests := 0
	for _, e := range entries {
		if manifests >= 8 {
			break
		}
		if !isManifest(e.rel) {
			continue
		}
		if !readSnippet(e.rel, 5<<10, "## Manifest: "+e.rel) {
			break
		}
		manifests++
	}

	// Route, controller, auth and middleware files, 5 KiB each, at most ten.
	keyFiles := 0
	for _, e := range entries {
		if keyFiles >= 10 {
			break
		}
		if !isKeyCodeFile(e.rel) {
			continue
		}
		if !readSnippet(e.rel, 5<<10, "## Key file: "+e.rel) {
			break
		}
		keyFiles++
	}

	return b.String(), nil
}

func repoMapScore(e repoFile) int {
	lower := strings.ToLower(e.rel)
	score := 0
	for _, kw := range []string{
		"readme", "go.mod", "package.json", "requirements", "pyproject",
		"cargo.toml", "pom.xml", "build.gradle", "gemfile", "composer.json",
		"dockerfile", "compose", "route", "controller", "handler", "auth",
		"login", "session", "middleware", "api", "server", "main.",
	} {
		if strings.Contains(lower, kw) {
			score += 4
		}
	}
	switch strings.ToLower(path.Ext(lower)) {
	case ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
		".java", ".php", ".rb", ".cs", ".rs":
		score += 3
	case ".yaml", ".yml", ".json", ".toml", ".xml", ".tf", ".sql":
		score++
	}
	switch {
	case e.size > 0 && e.size < 200<<10:
		score++
	case e.size > 2<<20:
		score -= 2
	}
	return score
}

func renderRepoTree(entries []repoFile) string {
	group := make(map[string][]string)
	var dirs []string
	for _, e := range entries {
		dir := path.Dir(e.rel)
		if dir == "." {
			dir = "./"
		} else {
			dir += "/"
		}
		if _, ok := group[dir]; !ok {
			dirs = append(dirs, dir)
		}
		group[dir] = append(group[dir], path.Base(e.rel))
	}
	sort.Strings(dirs)

	var b strings.Builder
	for _, dir := range dirs {
		names := group[dir]
		sort.Strings(names)
		fmt.Fprintf(&b, "%s (%d files): ", dir, len(names))
		limit := len(names)
		if limit > 12 {
			limit = 12
		}
		b.WriteString(strings.Join(names[:limit], ", "))
		if len(names) > limit {
			fmt.Fprintf(&b, " … +%d more", len(names)-limit)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func skipRepoDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", "node_modules", "vendor", "dist", "build", "target",
		".venv", "venv", "__pycache__", ".next", ".nuxt", "coverage",
		".idea", ".vscode", ".vigil", ".cache", "tmp", "temp", "out",
		"bin", "obj", ".terraform", "pods", "deriveddata",
		".ssh", ".aws", ".azure", ".kube", ".gnupg":
		return true
	}
	return false
}

func isManifest(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "go.mod", "package.json", "requirements.txt", "pyproject.toml",
		"setup.py", "setup.cfg", "cargo.toml", "pom.xml", "build.gradle",
		"build.gradle.kts", "gemfile", "composer.json", "dockerfile",
		"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
		"makefile", "cmakelists.txt":
		return true
	}
	return false
}

func isKeyCodeFile(rel string) bool {
	lower := strings.ToLower(rel)
	switch strings.ToLower(path.Ext(lower)) {
	case ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
		".java", ".php", ".rb", ".cs", ".rs":
	default:
		return false
	}
	for _, kw := range []string{
		"route", "controller", "handler", "auth", "login", "session",
		"middleware", "server", "api", "security", "permission", "payment",
		"upload",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
