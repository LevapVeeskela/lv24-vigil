package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// maxTextBytes bounds a tool's text response. Structured content is not
// bounded: clients that want the whole result read structuredContent.
const maxTextBytes = 40 << 10

// maxFindingsDefault and maxFindingsCap bound vigil_scan output.
const (
	maxFindingsDefault = 50
	maxFindingsCap     = 500
)

var severityOrder = []model.Severity{
	model.SeverityCritical,
	model.SeverityHigh,
	model.SeverityMedium,
	model.SeverityLow,
	model.SeverityInfo,
}

// decodeArgs unmarshals tool arguments into dst. A missing or null argument
// object is treated as an empty object.
func decodeArgs(raw json.RawMessage, dst any) *mcp.CallToolResult {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		raw = json.RawMessage(`{}`)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return mcp.TextError("invalid arguments: %v", err)
	}
	return nil
}

// result builds a text result with optional structured content. The text is
// redacted and truncated; the structured payload is passed through untouched.
func result(d Deps, text string, structured any) *mcp.CallToolResult {
	res := mcp.TextResult(boundText(redactKey(d, text)))
	res.StructuredContent = structured
	return res
}

// errorResult builds an isError result, redacting the configured key.
func errorResult(d Deps, format string, args ...any) *mcp.CallToolResult {
	return mcp.TextError("%s", redactKey(d, fmt.Sprintf(format, args...)))
}

// appReady guards every handler against an uninitialised runtime.
func appReady(d Deps) *mcp.CallToolResult {
	if d.App == nil {
		return mcp.TextError("vigil is not initialised: no app runtime is attached to this MCP server")
	}
	return nil
}

// boundText truncates s to about 40 KiB without splitting a UTF-8 rune.
func boundText(s string) string {
	if len(s) <= maxTextBytes {
		return s
	}
	cut := maxTextBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n\n… truncated: the response exceeded 40 KiB. Narrow the request " +
		"(lower maxFindings, a higher minSeverity, a smaller path) or write the full output " +
		"with vigil_report path=... .\n"
}

// fenced wraps code in a Markdown fence that cannot be terminated by the code
// itself.
func fenced(code, lang string) string {
	fence := "```"
	for strings.Contains(code, fence) {
		fence += "`"
	}
	return fence + lang + "\n" + strings.TrimRight(code, "\n") + "\n" + fence
}

// oneLine collapses whitespace so untrusted text cannot add structure to a
// report line.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// truncateRunes shortens s to n runes, appending an ellipsis.
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// humanBytes renders a byte count compactly.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// resolvePath resolves a user-supplied path against the app root. Relative
// paths are interpreted relative to the root, not the server process cwd.
func resolvePath(d Deps, p string) (string, error) {
	if d.App == nil {
		return "", errors.New("vigil is not initialised")
	}
	p = strings.TrimSpace(p)
	if p == "" {
		return d.App.Root, nil
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(d.App.Root, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", p, err)
	}
	return filepath.Clean(abs), nil
}

// cleanRelPath validates a repository-relative, slash-separated path used for
// report output. Absolute paths, traversal, control characters and .git are
// rejected.
func cleanRelPath(rel string) (string, error) {
	p := strings.TrimSpace(strings.ReplaceAll(rel, "\\", "/"))
	if p == "" {
		return "", errors.New("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains a NUL byte")
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return "", errors.New("path contains control characters")
		}
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", errors.New("absolute paths are not allowed")
	}
	if len(p) >= 2 && p[1] == ':' {
		return "", errors.New("absolute paths are not allowed")
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "..":
			return "", errors.New("path must not contain '..'")
		case ".git":
			return "", errors.New("refusing to write inside .git")
		}
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", errors.New("path is not a file inside the app root")
	}
	return c, nil
}

// resolveInsideRoot joins rel onto root and verifies the result cannot escape
// root, including through symlinked directories.
func resolveInsideRoot(root, rel string) (string, error) {
	clean, err := cleanRelPath(rel)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve app root: %w", err)
	}
	target := filepath.Join(rootAbs, filepath.FromSlash(clean))
	if !within(rootAbs, target) {
		return "", errors.New("path escapes the app root")
	}

	realRoot := rootAbs
	if resolved, err := filepath.EvalSymlinks(rootAbs); err == nil {
		realRoot = resolved
	}
	if realTarget, err := filepath.EvalSymlinks(target); err == nil {
		if !within(realRoot, realTarget) {
			return "", errors.New("path escapes the app root through a symlink")
		}
		return target, nil
	}
	// The file does not exist yet: check the deepest existing ancestor.
	dir := filepath.Dir(target)
	for {
		if realDir, err := filepath.EvalSymlinks(dir); err == nil {
			if !within(realRoot, realDir) {
				return "", errors.New("path escapes the app root through a symlink")
			}
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return target, nil
}

// within reports whether target is inside root.
func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// samePath compares two directories, tolerating case differences on Windows.
func samePath(a, b string) bool {
	ca, err := filepath.Abs(a)
	if err != nil {
		return false
	}
	cb, err := filepath.Abs(b)
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(ca); err == nil {
		ca = resolved
	}
	if resolved, err := filepath.EvalSymlinks(cb); err == nil {
		cb = resolved
	}
	ca, cb = filepath.Clean(ca), filepath.Clean(cb)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

// loadScan loads an explicit scan or the most recent one.
func loadScan(d Deps, scanID string) (*model.ScanResult, error) {
	if d.App == nil {
		return nil, errors.New("vigil is not initialised")
	}
	if id := strings.TrimSpace(scanID); id != "" {
		res, err := d.App.GetScan(id)
		if err != nil {
			return nil, fmt.Errorf("scan %q could not be loaded: %v (use vigil_history to list available scans)", id, err)
		}
		return res, nil
	}
	res, err := d.App.LastScan()
	if err != nil {
		return nil, fmt.Errorf("no stored scans yet: %v (run vigil_scan first)", err)
	}
	return res, nil
}

// lookupFinding resolves a finding by ID, fingerprint or a unique prefix in a
// scan (explicit or the latest). On a miss it returns a helpful error listing
// the findings that are available.
func lookupFinding(d Deps, scanID, findingID string) (*model.ScanResult, *model.Finding, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return nil, nil, errors.New("findingId is required")
	}
	res, err := loadScan(d, scanID)
	if err != nil {
		return nil, nil, err
	}

	all := make([]model.Finding, 0, len(res.Findings)+len(res.Suppressed))
	all = append(all, res.Findings...)
	all = append(all, res.Suppressed...)

	for i := range all {
		if strings.EqualFold(all[i].ID, id) {
			return res, &all[i], nil
		}
	}
	for i := range all {
		if strings.EqualFold(findingFingerprint(all[i]), id) {
			return res, &all[i], nil
		}
	}
	if len(id) >= 4 {
		lower := strings.ToLower(id)
		for i := range all {
			if strings.HasPrefix(strings.ToLower(findingFingerprint(all[i])), lower) {
				return res, &all[i], nil
			}
		}
		for i := range all {
			if strings.HasPrefix(strings.ToLower(all[i].ID), lower) {
				return res, &all[i], nil
			}
		}
	}
	return res, nil, fmt.Errorf("finding %q not found in scan %s. Available findings: %s. Use vigil_history to list scans or vigil_scan to create a new one.", id, res.ID, availableFindings(all))
}

// availableFindings renders a short list of finding IDs for error messages.
func availableFindings(fs []model.Finding) string {
	if len(fs) == 0 {
		return "none (the scan returned no findings)"
	}
	parts := make([]string, 0, 6)
	for i, f := range fs {
		if i == 10 {
			parts = append(parts, fmt.Sprintf("… and %d more", len(fs)-10))
			break
		}
		parts = append(parts, findingID(f)+" ("+locationString(f.Location)+")")
	}
	return strings.Join(parts, ", ")
}

func findingID(f model.Finding) string {
	if f.ID != "" {
		return f.ID
	}
	return f.ComputeID()
}

func findingFingerprint(f model.Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return f.ComputeFingerprint()
}

func locationString(l model.Location) string {
	p := strings.TrimSpace(l.Path)
	if p == "" {
		p = "(unknown)"
	}
	if l.StartLine > 0 {
		return fmt.Sprintf("%s:%d", p, l.StartLine)
	}
	return p
}

func displaySeverity(s model.Severity) string {
	v := strings.ToUpper(strings.TrimSpace(string(s)))
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

// findingSummary is the one-line form used in tables and top-N lists.
func findingSummary(f model.Finding) string {
	return fmt.Sprintf("%s [%s] %s — %s", findingID(f), displaySeverity(f.Severity), oneLine(f.Title), locationString(f.Location))
}

// severityLine renders non-zero severity counts, e.g. "critical 1, high 2".
func severityLine(fs []model.Finding) string {
	counts := make(map[model.Severity]int, len(severityOrder))
	for _, f := range fs {
		counts[f.Severity]++
	}
	parts := make([]string, 0, len(severityOrder))
	for _, s := range severityOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, counts[s]))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// countSeverity counts findings at exactly one severity.
func countSeverity(fs []model.Finding, s model.Severity) int {
	n := 0
	for _, f := range fs {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// warningLine renders scan errors and extra notes for a text summary.
func warningLine(errs []string, extra ...string) string {
	all := make([]string, 0, len(errs)+len(extra))
	all = append(all, extra...)
	all = append(all, errs...)
	if len(all) == 0 {
		return "none"
	}
	parts := make([]string, 0, 6)
	for i, e := range all {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("… and %d more", len(all)-5))
			break
		}
		parts = append(parts, oneLine(e))
	}
	return strings.Join(parts, "; ")
}

// modelLine describes the model used for a result. It never prints a key.
func modelLine(d Deps, m *model.ModelInfo) string {
	if m == nil && d.App != nil {
		m = d.App.Model
	}
	if d.App == nil || !d.App.LLM || m == nil {
		return "not used (deterministic rules only)"
	}
	name := strings.Trim(strings.Join([]string{
		strings.TrimSpace(m.Provider),
		strings.TrimSpace(m.Model),
	}, "/"), "/")
	if name == "" {
		name = "configured"
	}
	if base := redactURL(m.BaseURL); base != "" {
		name += " (" + base + ")"
	}
	return name
}

// redactURL removes userinfo and key-like query parameters from a base URL.
func redactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	q := u.Query()
	changed := false
	for k := range q {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "key") || strings.Contains(lk, "token") ||
			strings.Contains(lk, "secret") || strings.Contains(lk, "auth") {
			q.Set(k, "***")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// redactKey removes the configured API key from any text that may echo code or
// configuration. The key is never printed by any tool.
func redactKey(d Deps, s string) string {
	if d.App == nil || d.App.Config.APIKey == "" {
		return s
	}
	return strings.ReplaceAll(s, d.App.Config.APIKey, "***")
}

// jsonText renders v as indented JSON with a trailing newline.
func jsonText(v any) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func validMode(mode string) bool {
	switch mode {
	case "quick", "standard", "deep":
		return true
	default:
		return false
	}
}

// parseSeverityArg parses an optional severity argument. Empty means "use the
// configured default".
func parseSeverityArg(v string) (model.Severity, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	s, ok := model.ParseSeverity(v)
	if !ok {
		return "", fmt.Errorf("%q is not a severity (use critical, high, medium, low or info)", v)
	}
	return s, nil
}

// clampInt applies a default for non-positive values and caps large ones.
func clampInt(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if max > 0 && n > max {
		return max
	}
	return n
}
