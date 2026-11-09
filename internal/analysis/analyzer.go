// Package analysis implements the model-assisted half of Vigil: triage of
// deterministic findings, deep review of high-risk files, fix proposals,
// explanations and repository threat models.
//
// The deterministic rules are the source of truth. Everything in this package
// is advisory and must fail open: a missing, slow or broken model never blocks
// a scan and never deletes a deterministic finding.
//
// Scanned code is untrusted input. Every excerpt is wrapped in
// <untrusted_code> tags, control characters are stripped and the system
// prompts instruct the model to treat the contents as data, not instructions.
package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/llm"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
)

const (
	// triageBatchSize bounds how many findings one triage request may contain.
	triageBatchSize = 10

	// Deep review selection and chunking.
	maxDeepReviewFiles          = 8
	deepReviewWindowChars       = 12000
	deepReviewOverlapLines      = 20
	maxDeepReviewWindowsPerFile = 10
	maxDeepReviewWindows        = 40
	maxDeepReviewFindings       = 40

	// maxReasoningBytes caps each free-text model field copied into a finding.
	maxReasoningBytes = 2000

	// Fix and explanation bounds.
	maxFixFileBytes     = 200 << 10 // 200 KiB
	maxFixContextLines  = 40
	maxExplainBytes     = 8 << 10 // 8 KiB
	maxThreatModelBytes = 16 << 10

	// aiRuleID identifies findings that only the model produced.
	aiRuleID = "VGL-AI-001"
)

// ErrLLMNotConfigured is returned by the single-shot helpers when no model
// client was supplied. Triage and DeepReview never return it: they fail open
// and leave the deterministic findings untouched.
var ErrLLMNotConfigured = errors.New("LLM is not configured: set VIGIL_PROVIDER and credentials, or disable LLM features")

// Analyzer is the model-assisted analysis layer.
type Analyzer struct {
	cfg    config.Config
	client llm.Client
	logger *slog.Logger
}

// New builds an Analyzer. A nil client is valid and makes every method fail
// open. A nil logger discards diagnostics.
func New(cfg config.Config, client llm.Client, logger *slog.Logger) *Analyzer {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Analyzer{cfg: cfg, client: client, logger: logger}
}

// enabled reports whether a model is available.
func (a *Analyzer) enabled() bool { return a != nil && a.client != nil }

// modelName is the model identifier recorded on judgements.
func (a *Analyzer) modelName() string {
	if !a.enabled() {
		return ""
	}
	return a.client.Model()
}

// complete performs one request with the configured defaults. It never logs
// the prompt or response body.
func (a *Analyzer) complete(ctx context.Context, req llm.Request) (llm.Response, error) {
	if !a.enabled() {
		return llm.Response{}, ErrLLMNotConfigured
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = a.cfg.MaxTokens
	}
	if req.Temperature <= 0 {
		req.Temperature = a.cfg.Temperature
	}
	if strings.TrimSpace(req.System) == "" {
		req.System = systemAnalyst
	}
	resp, err := a.client.Complete(ctx, req)
	if err != nil {
		a.logger.Debug("llm request failed",
			"provider", a.client.Name(),
			"error", llm.TruncateText(err.Error(), 300))
		return llm.Response{}, err
	}
	return resp, nil
}

// verdict values accepted from the model.
const (
	verdictTruePositive  = "true_positive"
	verdictFalsePositive = "false_positive"
	verdictUncertain     = "uncertain"
)

// normalizeVerdict maps the model's spelling onto the three contract values.
func normalizeVerdict(v string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v, "-", "_"))) {
	case "true_positive", "truepositive", "tp", "true", "confirmed", "valid":
		return verdictTruePositive
	case "false_positive", "falsepositive", "fp", "false", "invalid", "not_exploitable", "notexploitable":
		return verdictFalsePositive
	default:
		return verdictUncertain
	}
}

// coerceFloat accepts numbers, numeric strings and a few qualitative labels.
func coerceFloat(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	case string:
		s := strings.TrimSpace(strings.ToLower(x))
		switch s {
		case "high", "certain", "very_high", "very high":
			return 0.9
		case "medium", "moderate", "likely":
			return 0.6
		case "low", "unlikely":
			return 0.3
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "%")
		var f float64
		if _, err := fmt.Sscanf(s, "%g", &f); err == nil {
			if strings.HasSuffix(strings.TrimSpace(x), "%") {
				f /= 100
			}
			return f
		}
	}
	return 0
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// confidenceFromScore maps a 0..1 model confidence onto the public label.
func confidenceFromScore(v float64) model.Confidence {
	switch {
	case v >= 0.8:
		return model.ConfidenceHigh
	case v >= 0.5:
		return model.ConfidenceMedium
	default:
		return model.ConfidenceLow
	}
}

var untrustedTagRE = regexp.MustCompile(`(?i)</?untrusted_code`)

// wrapUntrusted delimits code for the model. Any tag-looking text inside the
// excerpt is neutralised so the excerpt cannot close the delimiter and escape
// into instruction space.
func wrapUntrusted(pathAttr, body string) string {
	body = untrustedTagRE.ReplaceAllString(body, "&lt;untrusted_code")
	return `<untrusted_code path="` + attrEscape(pathAttr) + `">` + "\n" + body + "\n</untrusted_code>"
}

func attrEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		`"`, "&quot;",
		"<", "&lt;",
		">", "&gt;",
		"\n", " ",
		"\r", " ",
		"\t", " ",
	).Replace(s)
}

// stripControls normalises newlines and removes C0/C1 controls and Unicode
// format characters (bidi overrides, zero-width joiners). Newlines and tabs are
// preserved.
func stripControls(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// truncateBytes caps a string at max bytes without splitting a UTF-8 rune.
func truncateBytes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	const marker = "…"
	if max <= len(marker) {
		return s[:max]
	}
	cut := max - len(marker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker
}

// sanitizeCode strips control characters and caps the excerpt length.
func sanitizeCode(s string, max int) string {
	s = stripControls(s)
	if max <= 0 {
		return s
	}
	return truncateBytes(s, max)
}

// oneLine sanitises a metadata value so it cannot add prompt structure.
func oneLine(s string, max int) string {
	s = stripControls(s)
	s = strings.NewReplacer("\n", " ", "\t", " ").Replace(s)
	return truncateBytes(s, max)
}

// extractJSONArray returns the first balanced JSON array in s. It tolerates
// fences, leading prose, and models that wrap the array in an object such as
// {"findings": [...]}.
func extractJSONArray(s string) ([]byte, error) {
	t := strings.TrimSpace(strings.TrimPrefix(llm.StripFences(s), "\ufeff"))
	if t == "" {
		return nil, errors.New("empty model response")
	}
	if t[0] == '[' {
		if end := scanJSONArray(t, 0); end > 0 && json.Valid([]byte(t[:end])) {
			return []byte(t[:end]), nil
		}
		// Never fall back to a nested array: that would hide a malformed
		// outer response and could apply partial judgements.
		return nil, errors.New("response starts with an invalid JSON array")
	}

	if obj, err := llm.ExtractJSONObject(s); err == nil {
		var fields map[string]json.RawMessage
		if json.Unmarshal(obj, &fields) == nil {
			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			preferred := []string{"findings", "results", "items", "issues", "triage", "data"}
			for _, want := range preferred {
				if raw, ok := fields[want]; ok {
					var arr []json.RawMessage
					if json.Unmarshal(raw, &arr) == nil {
						return raw, nil
					}
				}
			}
			for _, k := range keys {
				var arr []json.RawMessage
				if json.Unmarshal(fields[k], &arr) == nil {
					return fields[k], nil
				}
			}
		}
	}

	for i := 0; i < len(t); i++ {
		if t[i] != '[' {
			continue
		}
		end := scanJSONArray(t, i)
		if end > 0 && json.Valid([]byte(t[i:end])) {
			return []byte(t[i:end]), nil
		}
	}
	return nil, errors.New("no JSON array found in model response")
}

// scanJSONArray returns the index just past the closing bracket, or -1.
func scanJSONArray(s string, start int) int {
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// isSensitiveRepoFile reports whether a path looks like a credential store
// that must never be sent to a model. Deterministic rules still scan these
// files locally and mask their evidence.
func isSensitiveRepoFile(rel string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(rel, "\\", "/")))
	switch base {
	case ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
		".npmrc", ".netrc", ".pypirc", ".git-credentials", ".htpasswd",
		"credentials", "secrets":
		return true
	}
	if strings.HasPrefix(base, ".env.") ||
		strings.HasPrefix(base, "secrets.") ||
		strings.HasPrefix(base, "credentials.") {
		return true
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore":
		return true
	}
	return false
}

// cleanRelativePath validates a repository-relative, slash-separated path. It
// rejects absolute paths, drive letters, UNC paths, traversal, NUL bytes and
// anything inside .git (case-insensitively, including Windows short forms).
func cleanRelativePath(p string) (string, bool) {
	clean, err := safepath.CleanRel(p)
	if err != nil {
		return "", false
	}
	return clean, true
}

// insideRoot joins rel onto root and verifies the result stays inside root,
// including through symlinks and junctions.
func insideRoot(root, rel string) (string, bool) {
	target, err := safepath.Resolve(root, rel)
	if err != nil {
		return "", false
	}
	return target, true
}

// pathWithin reports whether target is inside rootAbs.
func pathWithin(rootAbs, target string) bool {
	rel, err := filepath.Rel(rootAbs, target)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// readFileBounded reads at most max bytes of a file inside root. Symlinks are
// resolved and must stay inside the root. The returned bool reports truncation.
func readFileBounded(root, rel string, max int64) ([]byte, string, bool, error) {
	clean, ok := cleanRelativePath(rel)
	if !ok {
		return nil, "", false, fmt.Errorf("unsafe path %q", rel)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, "", false, err
	}
	if resolved, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = resolved
	}
	target, ok := insideRoot(rootAbs, clean)
	if !ok {
		return nil, "", false, fmt.Errorf("path %q escapes the scan root", rel)
	}
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil, "", false, err
	}
	if !pathWithin(rootAbs, real) {
		return nil, "", false, fmt.Errorf("path %q escapes the scan root through a symlink", rel)
	}
	info, err := os.Stat(real)
	if err != nil {
		return nil, "", false, err
	}
	if !info.Mode().IsRegular() {
		return nil, "", false, fmt.Errorf("%s is not a regular file", clean)
	}
	if multi, err := safepath.HasMultipleLinks(real); err != nil {
		return nil, "", false, fmt.Errorf("cannot verify %s: %w", clean, err)
	} else if multi {
		return nil, "", false, fmt.Errorf("%s is a hardlinked file", clean)
	}
	f, err := os.Open(real)
	if err != nil {
		return nil, "", false, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, "", false, err
	}
	truncated := int64(len(data)) > max
	if truncated {
		data = data[:max]
	}
	return data, clean, truncated, nil
}

// splitLines splits text into lines without a trailing empty line.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// numberedLines renders lines [from,to] (1-based, inclusive) with line-number
// prefixes so the model can return accurate line ranges.
func numberedLines(lines []string, from, to int) string {
	if from < 1 {
		from = 1
	}
	if to > len(lines) {
		to = len(lines)
	}
	if from > to {
		return ""
	}
	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "%d| %s\n", i, lines[i-1])
	}
	return strings.TrimRight(b.String(), "\n")
}

// normalizeCWE accepts a string, a comma-separated string or an array and
// returns canonical CWE-NNN entries.
func normalizeCWE(v any) []string {
	var raw []string
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		raw = strings.FieldsFunc(x, func(r rune) bool {
			return r == ',' || r == ';' || unicode.IsSpace(r)
		})
	case []string:
		raw = x
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "CWE-") {
			rest := strings.TrimSpace(s[4:])
			if i := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
				rest = rest[:i]
			}
			if !allDigits(rest) {
				continue
			}
			s = "CWE-" + rest
		} else if allDigits(s) {
			s = "CWE-" + s
		} else {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) == 10 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Explain returns a short model-written explanation, exploit scenario and fix
// direction for one finding. The file context is best-effort: if the file is
// missing or unsafe, the finding's own evidence is used instead.
func (a *Analyzer) Explain(ctx context.Context, f model.Finding, root string) (string, error) {
	if !a.enabled() {
		return "", ErrLLMNotConfigured
	}

	rel := ""
	contextText := ""
	if clean, ok := cleanRelativePath(f.Location.Path); ok {
		if content, cleanRel, _, err := readFileBounded(root, clean, maxFixFileBytes); err == nil {
			lines := splitLines(string(content))
			start := f.Location.StartLine
			if start < 1 {
				start = 1
			}
			// If the location is outside the readable part of the file, use
			// the finding's own evidence instead of a misleading window.
			if start <= len(lines) {
				end := f.Location.EndLine
				if end < start {
					end = start
				}
				if end > len(lines) {
					end = len(lines)
				}
				from := start - maxFixContextLines
				if from < 1 {
					from = 1
				}
				to := end + maxFixContextLines
				if to > len(lines) {
					to = len(lines)
				}
				contextText = numberedLines(lines, from, to)
				rel = cleanRel
			}
		}
	}
	if strings.TrimSpace(contextText) == "" {
		evidence := f.Evidence
		if strings.TrimSpace(evidence) == "" {
			evidence = f.Location.Snippet
		}
		contextText = sanitizeCode(evidence, 6000)
	}

	resp, err := a.complete(ctx, llm.Request{
		System:   systemExplain,
		Messages: []llm.Message{{Role: llm.RoleUser, Content: buildExplainPrompt(f, rel, contextText)}},
	})
	if err != nil {
		return "", fmt.Errorf("explain: %w", err)
	}
	text := strings.TrimSpace(strings.TrimPrefix(llm.StripFences(resp.Text), "\ufeff"))
	if text == "" {
		return "", errors.New("explain: model returned an empty response")
	}
	text = truncateBytes(stripControls(text), maxExplainBytes)
	if strings.TrimSpace(text) == "" {
		return "", errors.New("explain: model returned an empty response")
	}
	return text, nil
}
