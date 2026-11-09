package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/llm"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

// reviewChunk is one bounded window of a file.
type reviewChunk struct {
	startLine int
	endLine   int
	text      string
}

// deepReviewItem is one model-proposed finding. Both camelCase and snake_case
// line fields are accepted because providers differ.
type deepReviewItem struct {
	Path           string `json:"path"`
	StartLine      int    `json:"startLine"`
	EndLine        int    `json:"endLine"`
	StartLineSnake int    `json:"start_line"`
	EndLineSnake   int    `json:"end_line"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Confidence     any    `json:"confidence"`
	CWE            any    `json:"cwe"`
	Remediation    string `json:"remediation"`
	Evidence       string `json:"evidence"`
}

// DeepReview asks the model to find issues the deterministic rules missed. It
// selects at most eight high-risk files, reviews bounded windows and validates
// every returned path and line range against the real files.
//
// Invalid items are dropped, duplicates are suppressed and the result is
// capped. To keep a deep scan affordable, at most 10 windows per file and 40
// windows overall are reviewed. A nil client, no eligible files or no model
// findings return (nil, nil).
func (a *Analyzer) DeepReview(ctx context.Context, root string, files []*rules.File, existing []model.Finding) ([]model.Finding, error) {
	if !a.enabled() {
		return nil, nil
	}
	selected := selectReviewFiles(files, maxDeepReviewFiles)
	if len(selected) == 0 {
		return nil, nil
	}

	allowed := make(map[string]*rules.File, len(selected))
	for _, f := range selected {
		clean, ok := cleanRelativePath(f.Path)
		if !ok {
			continue
		}
		allowed[clean] = f
	}
	if len(allowed) == 0 {
		return nil, nil
	}

	var (
		findings []model.Finding
		errs     []string
		attempts int
		failed   int
		windows  int
	)

outer:
	for _, f := range selected {
		chunks := chunkFile(f, deepReviewWindowChars, deepReviewOverlapLines)
		if len(chunks) > maxDeepReviewWindowsPerFile {
			a.logger.Debug("deep review window cap reached",
				"path", f.Path, "windows", len(chunks), "reviewed", maxDeepReviewWindowsPerFile)
			chunks = chunks[:maxDeepReviewWindowsPerFile]
		}
		for _, c := range chunks {
			if windows >= maxDeepReviewWindows {
				a.logger.Debug("deep review total window cap reached", "cap", maxDeepReviewWindows)
				break outer
			}
			if len(findings) >= maxDeepReviewFindings {
				break outer
			}
			windows++
			attempts++

			if err := ctx.Err(); err != nil {
				failed++
				errs = append(errs, err.Error())
				break outer
			}

			resp, err := a.complete(ctx, llm.Request{
				System:   systemDeepReview,
				Messages: []llm.Message{{Role: llm.RoleUser, Content: buildDeepReviewPrompt(f, c, existing)}},
				JSON:     true,
			})
			if err != nil {
				failed++
				errs = append(errs, fmt.Sprintf("%s:%d-%d: %v", f.Path, c.startLine, c.endLine, err))
				continue
			}

			items, err := parseDeepReviewResponse(resp.Text)
			if err != nil {
				failed++
				errs = append(errs, fmt.Sprintf("%s:%d-%d: %v", f.Path, c.startLine, c.endLine, err))
				continue
			}

			for _, item := range items {
				nf, ok := buildLLMFinding(root, allowed, item, existing, findings)
				if !ok {
					continue
				}
				findings = append(findings, nf)
				if len(findings) >= maxDeepReviewFindings {
					break
				}
			}
		}
	}

	if attempts > 0 && failed == attempts {
		return nil, fmt.Errorf("deep review: all %d windows failed: %s", attempts, truncateBytes(strings.Join(errs, "; "), 1000))
	}
	if failed > 0 {
		a.logger.Warn("deep review partially failed", "failedWindows", failed, "windows", attempts)
	}
	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

func parseDeepReviewResponse(text string) ([]deepReviewItem, error) {
	raw, err := extractJSONArray(text)
	if err == nil {
		var items []deepReviewItem
		if unmarshalErr := json.Unmarshal(raw, &items); unmarshalErr == nil {
			return items, nil
		} else {
			err = fmt.Errorf("parse deep review JSON: %w", unmarshalErr)
		}
	}
	if obj, objErr := llm.ExtractJSONObject(text); objErr == nil {
		var single deepReviewItem
		if json.Unmarshal(obj, &single) == nil && strings.TrimSpace(single.Path) != "" {
			return []deepReviewItem{single}, nil
		}
	}
	return nil, err
}

// buildLLMFinding validates one model item and converts it into a Finding.
func buildLLMFinding(root string, allowed map[string]*rules.File, item deepReviewItem, existing, generated []model.Finding) (model.Finding, bool) {
	rel, ok := cleanRelativePath(item.Path)
	if !ok {
		return model.Finding{}, false
	}
	if filepath.IsAbs(item.Path) || path.IsAbs(strings.ReplaceAll(item.Path, "\\", "/")) {
		return model.Finding{}, false
	}
	f, ok := allowed[rel]
	if !ok {
		return model.Finding{}, false
	}
	if _, ok := insideRoot(root, rel); !ok {
		return model.Finding{}, false
	}

	start := item.StartLine
	if start == 0 {
		start = item.StartLineSnake
	}
	end := item.EndLine
	if end == 0 {
		end = item.EndLineSnake
	}
	if start < 1 || start > len(f.Lines) {
		return model.Finding{}, false
	}
	if end == 0 {
		end = start
	}
	if end < start || end > len(f.Lines) {
		return model.Finding{}, false
	}

	title := strings.TrimSpace(item.Title)
	if title == "" {
		title = "LLM-identified security issue"
	}
	if isDuplicate(rel, start, end, title, existing) || isDuplicate(rel, start, end, title, generated) {
		return model.Finding{}, false
	}

	score := clamp01(coerceFloat(item.Confidence))
	severity, ok := model.ParseSeverity(item.Severity)
	if !ok {
		severity = model.SeverityMedium
	}
	// Critical is only credible with corroborating confidence.
	if severity == model.SeverityCritical && score < 0.5 {
		severity = model.SeverityHigh
	}

	description := strings.TrimSpace(item.Description)
	if description == "" {
		description = title
	}

	nf := model.Finding{
		RuleID:      aiRuleID,
		Title:       truncateBytes(stripControls(title), 200),
		Description: truncateBytes(stripControls(description), 4000),
		Severity:    severity,
		Confidence:  confidenceFromScore(score),
		Category:    model.CategoryLogic,
		CWE:         normalizeCWE(item.CWE),
		Location: model.Location{
			Path:      rel,
			StartLine: start,
			EndLine:   end,
		},
		Evidence:    evidenceFor(f, start, end),
		Remediation: truncateBytes(stripControls(item.Remediation), 2000),
		Source:      model.SourceLLM,
		Tags:        []string{"llm", "deep-review"},
	}
	if nf.Evidence == "" {
		nf.Evidence = truncateBytes(stripControls(item.Evidence), 4000)
	}
	nf.Normalize()
	return nf, true
}

// evidenceFor copies the real file lines for a validated range.
func evidenceFor(f *rules.File, start, end int) string {
	if f == nil || start < 1 || start > len(f.Lines) {
		return ""
	}
	if end < start {
		end = start
	}
	if end > len(f.Lines) {
		end = len(f.Lines)
	}
	if end-start > 30 {
		end = start + 30
	}
	return truncateBytes(stripControls(strings.Join(f.Lines[start-1:end], "\n")), 4000)
}

// isDuplicate reports whether pool contains a finding on the same path with an
// overlapping line range and a similar title.
func isDuplicate(rel string, start, end int, title string, pool []model.Finding) bool {
	for i := range pool {
		ex := &pool[i]
		exPath, ok := cleanRelativePath(ex.Location.Path)
		if !ok || exPath != rel {
			continue
		}
		exStart := ex.Location.StartLine
		exEnd := ex.Location.EndLine
		if exEnd == 0 {
			exEnd = exStart
		}
		if exStart > end || exEnd < start {
			continue
		}
		if titlesSimilar(title, ex.Title) {
			return true
		}
	}
	return false
}

func titlesSimilar(a, b string) bool {
	na, nb := normalizeTitle(a), normalizeTitle(b)
	if na == "" || nb == "" {
		return true
	}
	if na == nb || strings.Contains(na, nb) || strings.Contains(nb, na) {
		return true
	}
	ta := strings.Fields(na)
	tb := strings.Fields(nb)
	if len(ta) == 0 || len(tb) == 0 {
		return false
	}
	set := make(map[string]bool, len(ta))
	for _, t := range ta {
		set[t] = true
	}
	hits := 0
	for _, t := range tb {
		if set[t] {
			hits++
		}
	}
	denom := len(ta)
	if len(tb) < denom {
		denom = len(tb)
	}
	return denom > 0 && float64(hits)/float64(denom) >= 0.6
}

func normalizeTitle(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r > 127 {
			b.WriteRune(r)
			continue
		}
		b.WriteByte(' ')
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// selectReviewFiles ranks files by path keywords, language and size, and
// returns at most limit of them. Tests, docs and vendor trees are skipped.
func selectReviewFiles(files []*rules.File, limit int) []*rules.File {
	type candidate struct {
		file  *rules.File
		score int
	}
	var candidates []candidate
	for _, f := range files {
		if f == nil || len(f.Lines) == 0 {
			continue
		}
		rel, ok := cleanRelativePath(f.Path)
		if !ok {
			continue
		}
		if isSensitiveRepoFile(rel) || skipReviewPath(rel) {
			continue
		}
		candidates = append(candidates, candidate{file: f, score: reviewRiskScore(rel, f)})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].file.Path < candidates[j].file.Path
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]*rules.File, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.file)
	}
	return out
}

func skipReviewPath(rel string) bool {
	lower := strings.ToLower(rel)
	segments := strings.Split(lower, "/")
	for _, seg := range segments[:len(segments)-1] {
		switch seg {
		case "vendor", "node_modules", "test", "tests", "__tests__", "testdata",
			"fixtures", "docs", "doc", "documentation", "examples", "mocks",
			"third_party", "dist", "build", "coverage":
			return true
		}
	}
	base := segments[len(segments)-1]
	switch {
	case strings.HasSuffix(base, "_test.go"),
		strings.Contains(base, ".test."),
		strings.Contains(base, ".spec."),
		strings.HasPrefix(base, "test_"),
		strings.HasSuffix(base, ".md"),
		strings.HasSuffix(base, ".mdx"),
		strings.HasSuffix(base, ".rst"),
		base == "readme",
		strings.HasPrefix(base, "readme."):
		return true
	}
	return false
}

func reviewRiskScore(rel string, f *rules.File) int {
	lower := strings.ToLower(rel)
	score := 0

	lang := f.Language
	if lang == "" {
		lang = scanner.DetectLanguage(rel)
	}
	switch lang {
	case scanner.LanguageGo, scanner.LanguagePython, scanner.LanguageJavaScript,
		scanner.LanguageTypeScript, scanner.LanguageJava, scanner.LanguagePHP,
		scanner.LanguageRuby, scanner.LanguageCSharp, scanner.LanguageRust:
		score += 6
	case scanner.LanguageSQL, scanner.LanguageShell, scanner.LanguageTerraform,
		scanner.LanguageDockerfile:
		score += 4
	case scanner.LanguageYAML, scanner.LanguageJSON, scanner.LanguageXML, scanner.LanguageHTML:
		score += 2
	}

	hits := 0
	for _, kw := range []string{
		"auth", "login", "password", "token", "session", "admin",
		"upload", "payment", "api", "route", "controller", "handler",
	} {
		if strings.Contains(lower, kw) {
			hits++
		}
	}
	if hits > 4 {
		hits = 4
	}
	score += hits * 3

	size := f.Size
	if size <= 0 {
		for _, line := range f.Lines {
			size += len(line) + 1
		}
	}
	switch {
	case size >= 512 && size <= 64<<10:
		score += 2
	case size > 1<<20:
		score -= 6
	case size > 256<<10:
		score -= 3
	}
	return score
}

// chunkFile splits a file into windows of at most maxChars characters with
// overlap lines of overlap. Line-number prefixes are included in the budget.
func chunkFile(f *rules.File, maxChars, overlap int) []reviewChunk {
	if f == nil || len(f.Lines) == 0 {
		return nil
	}
	if maxChars < 200 {
		maxChars = 200
	}
	if overlap < 0 {
		overlap = 0
	}

	var chunks []reviewChunk
	start := 0
	for start < len(f.Lines) {
		line := f.Lines[start]
		prefix := len(fmt.Sprintf("%d| ", start+1))
		if len(line)+prefix > maxChars {
			// A single huge line (minified bundle, generated data) is split
			// into pieces so every window stays inside the budget.
			piece := maxChars - prefix
			if piece < 64 {
				piece = 64
			}
			for off := 0; off < len(line); off += piece {
				endOff := off + piece
				if endOff > len(line) {
					endOff = len(line)
				}
				chunks = append(chunks, reviewChunk{
					startLine: start + 1,
					endLine:   start + 1,
					text:      fmt.Sprintf("%d| %s", start+1, line[off:endOff]),
				})
			}
			start++
			continue
		}

		end := start
		size := 0
		for end < len(f.Lines) {
			l := f.Lines[end]
			p := len(fmt.Sprintf("%d| ", end+1))
			add := len(l) + p + 1
			if end > start && size+add > maxChars {
				break
			}
			size += add
			end++
			if size >= maxChars {
				break
			}
		}
		if end == start {
			end = start + 1
		}

		var b strings.Builder
		for i := start; i < end; i++ {
			fmt.Fprintf(&b, "%d| %s\n", i+1, f.Lines[i])
		}
		chunks = append(chunks, reviewChunk{startLine: start + 1, endLine: end, text: b.String()})

		if end >= len(f.Lines) {
			break
		}
		next := end - overlap
		if next <= start {
			next = end
		}
		start = next
	}
	return chunks
}
