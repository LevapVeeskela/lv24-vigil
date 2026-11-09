// Package model holds the shared domain types for Vigil.
//
// Everything in this package is plain data: it is safe to serialise, cache and
// pass between the scanner, the LLM layer, the reporters and the MCP server.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Severity is the impact of a finding if it is real.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank returns a sortable rank (higher is more severe). Unknown values rank 0.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ParseSeverity accepts the canonical names and a few common aliases.
func ParseSeverity(v string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical", "crit":
		return SeverityCritical, true
	case "high", "error":
		return SeverityHigh, true
	case "medium", "moderate", "warning", "warn":
		return SeverityMedium, true
	case "low", "note":
		return SeverityLow, true
	case "info", "informational", "none":
		return SeverityInfo, true
	default:
		return "", false
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// Confidence expresses how sure the engine is that a finding is real.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Rank returns a sortable rank (higher is more confident).
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// Category groups rules by the class of problem they look for.
type Category string

const (
	CategorySecrets    Category = "secrets"
	CategoryInjection  Category = "injection"
	CategoryAuth       Category = "auth"
	CategoryCrypto     Category = "crypto"
	CategoryConfig     Category = "config"
	CategoryCI         Category = "ci"
	CategoryDependency Category = "dependency"
	CategoryWeb        Category = "web"
	CategoryLogic      Category = "logic"
)

// Source says where a finding came from.
type Source string

const (
	SourceRule   Source = "rule"
	SourceLLM    Source = "llm"
	SourceHybrid Source = "hybrid"
)

// Location points at the code that triggered a finding. Lines are 1-based.
type Location struct {
	Path        string `json:"path"`
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
}

// Fix is a proposed remediation. Diff is a unified diff against the scanned
// tree and must apply with `git apply` / `patch -p1`.
type Fix struct {
	Description string   `json:"description"`
	Diff        string   `json:"diff"`
	Files       []string `json:"files,omitempty"`
	Applied     bool     `json:"applied,omitempty"`
}

// LLMJudgement is the model's opinion about a finding. It is advisory: the
// deterministic evidence stays in the Finding.
type LLMJudgement struct {
	Verdict     string   `json:"verdict"` // true_positive | false_positive | uncertain
	Severity    Severity `json:"severity,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"` // 0..1
	Reasoning   string   `json:"reasoning,omitempty"`
	Exploit     string   `json:"exploitScenario,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Model       string   `json:"model,omitempty"`
}

// Finding is one security issue.
type Finding struct {
	ID          string        `json:"id"`
	RuleID      string        `json:"ruleId"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    Severity      `json:"severity"`
	Confidence  Confidence    `json:"confidence"`
	Category    Category      `json:"category"`
	CWE         []string      `json:"cwe,omitempty"`
	OWASP       []string      `json:"owasp,omitempty"`
	Location    Location      `json:"location"`
	Evidence    string        `json:"evidence,omitempty"`
	Remediation string        `json:"remediation,omitempty"`
	References  []string      `json:"references,omitempty"`
	Tags        []string      `json:"tags,omitempty"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Source      Source        `json:"source"`
	LLM         *LLMJudgement `json:"llm,omitempty"`
	Fix         *Fix          `json:"fix,omitempty"`
	Suppressed  bool          `json:"suppressed,omitempty"`
	SuppressWhy string        `json:"suppressedReason,omitempty"`
}

// ComputeID derives a stable, content-addressed identifier. It is stable across
// runs as long as the rule, path, and normalised evidence stay the same, which
// is what baselines and suppression files rely on.
func (f *Finding) ComputeID() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00", f.RuleID, path.Clean(f.Location.Path), f.Location.StartLine)
	h.Write([]byte(normalizeForHash(f.Evidence)))
	sum := hex.EncodeToString(h.Sum(nil))
	return "VGL-" + strings.ToUpper(sum[:10])
}

// ComputeFingerprint is a looser identity used to match the same issue after a
// file moves a few lines. It intentionally ignores line numbers.
func (f *Finding) ComputeFingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", f.RuleID, path.Clean(f.Location.Path))
	h.Write([]byte(normalizeForHash(f.Evidence)))
	sum := hex.EncodeToString(h.Sum(nil))
	return "fp_" + sum[:16]
}

func normalizeForHash(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// Normalize fills derived fields and sorts slices deterministically.
func (f *Finding) Normalize() {
	if f.ID == "" {
		f.ID = f.ComputeID()
	}
	if f.Fingerprint == "" {
		f.Fingerprint = f.ComputeFingerprint()
	}
	if f.Location.EndLine == 0 {
		f.Location.EndLine = f.Location.StartLine
	}
	sort.Strings(f.CWE)
	sort.Strings(f.OWASP)
	sort.Strings(f.Tags)
	sort.Strings(f.References)
}

// RuleMeta describes a rule without executing it.
type RuleMeta struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Languages   []string `json:"languages,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	OWASP       []string `json:"owasp,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Stats summarises a scan.
type Stats struct {
	FilesScanned int              `json:"filesScanned"`
	FilesSkipped int              `json:"filesSkipped"`
	BytesScanned int64            `json:"bytesScanned"`
	DurationMS   int64            `json:"durationMs"`
	BySeverity   map[Severity]int `json:"bySeverity"`
	ByCategory   map[Category]int `json:"byCategory"`
	RulesRun     int              `json:"rulesRun"`
	LLMCalls     int              `json:"llmCalls"`
	LLMTokens    int              `json:"llmTokens,omitempty"`
}

// ModelInfo describes the model that produced LLM judgements.
type ModelInfo struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"baseUrl,omitempty"`
}

// ScanRequest is the input to a scan. Zero values mean "use defaults".
type ScanRequest struct {
	Root         string        `json:"root"`
	Mode         string        `json:"mode"` // quick | standard | deep
	ChangedOnly  bool          `json:"changedOnly,omitempty"`
	BaseRef      string        `json:"baseRef,omitempty"`
	Diff         string        `json:"diff,omitempty"` // unified diff; overrides ChangedOnly
	UseLLM       *bool         `json:"useLlm,omitempty"`
	DeepReview   bool          `json:"deepReview,omitempty"`
	ThreatModel  bool          `json:"threatModel,omitempty"`
	Include      []string      `json:"include,omitempty"`
	Exclude      []string      `json:"exclude,omitempty"`
	DisableRules []string      `json:"disableRules,omitempty"`
	OnlyRules    []string      `json:"onlyRules,omitempty"`
	MinSeverity  Severity      `json:"minSeverity,omitempty"`
	MaxFindings  int           `json:"maxFindings,omitempty"`
	Concurrency  int           `json:"concurrency,omitempty"`
	Timeout      time.Duration `json:"-"`
	BaselinePath string        `json:"baselinePath,omitempty"`
	NoBaseline   bool          `json:"noBaseline,omitempty"`
}

// ScanResult is the full output of one scan.
type ScanResult struct {
	ID          string     `json:"id"`
	StartedAt   time.Time  `json:"startedAt"`
	FinishedAt  time.Time  `json:"finishedAt"`
	Root        string     `json:"root"`
	Mode        string     `json:"mode"`
	Findings    []Finding  `json:"findings"`
	Suppressed  []Finding  `json:"suppressed,omitempty"`
	Stats       Stats      `json:"stats"`
	Model       *ModelInfo `json:"model,omitempty"`
	ThreatModel string     `json:"threatModel,omitempty"`
	Errors      []string   `json:"errors,omitempty"`
	Engine      string     `json:"engine"`
	Version     string     `json:"version"`
}

// SortFindings orders by severity, then confidence, then path/line.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Confidence.Rank() != b.Confidence.Rank() {
			return a.Confidence.Rank() > b.Confidence.Rank()
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		return a.Location.StartLine < b.Location.StartLine
	})
}

// Filter returns the findings at or above min and caps the result.
func Filter(fs []Finding, min Severity, max int) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if !f.Severity.AtLeast(min) {
			continue
		}
		out = append(out, f)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}
