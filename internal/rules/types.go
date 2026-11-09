// Package rules contains the deterministic detection rules and the engine that
// runs them over files. Rules are pure: they never touch the network, never
// write files and never execute scanned code.
package rules

import (
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// File is one text file handed to rules.
type File struct {
	// Path is the slash-separated path relative to the scan root.
	Path string
	// AbsPath is the absolute path on disk.
	AbsPath string
	// Content is the raw file content.
	Content []byte
	// Lines is Content split on newlines (without the newline bytes).
	Lines []string
	// Language is a coarse language label derived from the extension:
	// go, python, javascript, typescript, java, php, ruby, csharp, rust,
	// sql, yaml, json, dockerfile, terraform, shell, html, other.
	Language string
	// Size is len(Content).
	Size int
}

// Line returns the 1-based line, or "" when out of range.
func (f *File) Line(n int) string {
	if n < 1 || n > len(f.Lines) {
		return ""
	}
	return f.Lines[n-1]
}

// Window returns up to radius lines before and after line n joined by "\n".
func (f *File) Window(n, radius int) string {
	start := n - radius
	if start < 1 {
		start = 1
	}
	end := n + radius
	if end > len(f.Lines) {
		end = len(f.Lines)
	}
	return strings.Join(f.Lines[start-1:end], "\n")
}

// Rule is a deterministic check.
type Rule interface {
	Meta() model.RuleMeta
	// Check returns findings for f. Locations must be 1-based and the rule
	// must not mutate f.
	Check(f *File) []model.Finding
}

// FuncRule adapts a function to the Rule interface.
type FuncRule struct {
	M  model.RuleMeta
	Fn func(f *File) []model.Finding
}

func (r FuncRule) Meta() model.RuleMeta { return r.M }
func (r FuncRule) Check(f *File) []model.Finding {
	if r.Fn == nil {
		return nil
	}
	return r.Fn(f)
}

// New builds a FuncRule with the finding defaults applied. Rule authors set
// Title/Description/Severity/CWE on the meta and only fill location, evidence
// and an optional remediation in the returned findings.
func New(meta model.RuleMeta, fn func(f *File) []model.Finding) Rule {
	return FuncRule{M: meta, Fn: func(f *File) []model.Finding {
		out := fn(f)
		for i := range out {
			out[i].RuleID = meta.ID
			if out[i].Title == "" {
				out[i].Title = meta.Title
			}
			if out[i].Description == "" {
				out[i].Description = meta.Description
			}
			if out[i].Severity == "" {
				out[i].Severity = meta.Severity
			}
			if out[i].Category == "" {
				out[i].Category = meta.Category
			}
			if out[i].Source == "" {
				out[i].Source = model.SourceRule
			}
			if len(out[i].CWE) == 0 {
				out[i].CWE = append([]string(nil), meta.CWE...)
			}
			if len(out[i].OWASP) == 0 {
				out[i].OWASP = append([]string(nil), meta.OWASP...)
			}
			out[i].Normalize()
		}
		return out
	}}
}

// Registry is an ordered collection of rules.
type Registry struct {
	rules []Rule
	seen  map[string]bool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{seen: map[string]bool{}}
}

// Add appends rules, ignoring duplicate IDs.
func (r *Registry) Add(rs ...Rule) {
	for _, rule := range rs {
		id := rule.Meta().ID
		if id == "" || r.seen[id] {
			continue
		}
		r.seen[id] = true
		r.rules = append(r.rules, rule)
	}
}

// All returns every registered rule in registration order.
func (r *Registry) All() []Rule { return append([]Rule(nil), r.rules...) }

// Filter returns rules selected by only (if non-empty) minus disabled.
func (r *Registry) Filter(only, disabled []string) []Rule {
	onlySet := toSet(only)
	disabledSet := toSet(disabled)
	out := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		id := rule.Meta().ID
		if len(onlySet) > 0 && !onlySet[id] {
			continue
		}
		if disabledSet[id] {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// Metas returns metadata for every rule, sorted by ID.
func (r *Registry) Metas() []model.RuleMeta {
	out := make([]model.RuleMeta, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule.Meta())
	}
	sortMetas(out)
	return out
}

func toSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out[v] = true
		}
	}
	return out
}
