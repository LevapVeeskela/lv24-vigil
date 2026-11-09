package rules

import (
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func TestDefaultRegistryIsSound(t *testing.T) {
	reg := Default()
	metas := reg.Metas()
	if len(metas) < 100 {
		t.Fatalf("expected at least 100 rules, got %d", len(metas))
	}

	seen := map[string]bool{}
	byCategory := map[model.Category]int{}
	for _, m := range metas {
		if m.ID == "" {
			t.Errorf("rule with empty ID")
			continue
		}
		if seen[m.ID] {
			t.Errorf("duplicate rule ID %q", m.ID)
		}
		seen[m.ID] = true
		if !strings.HasPrefix(m.ID, "VGL-") {
			t.Errorf("rule %q does not use the VGL- prefix", m.ID)
		}
		if m.Title == "" {
			t.Errorf("rule %q has no title", m.ID)
		}
		if m.Description == "" {
			t.Errorf("rule %q has no description", m.ID)
		}
		if m.Severity.Rank() == 0 {
			t.Errorf("rule %q has an invalid severity %q", m.ID, m.Severity)
		}
		if m.Category == "" {
			t.Errorf("rule %q has no category", m.ID)
		}
		byCategory[m.Category]++
	}

	// Every pack must be represented: a silent import mistake would otherwise
	// look like a healthy registry with fewer rules.
	for _, c := range []model.Category{
		model.CategorySecrets, model.CategoryInjection, model.CategoryCrypto,
		model.CategoryAuth, model.CategoryWeb, model.CategoryConfig,
		model.CategoryCI, model.CategoryDependency,
	} {
		if byCategory[c] == 0 {
			t.Errorf("no rules in category %q", c)
		}
	}
}

func TestDefaultRegistryFilter(t *testing.T) {
	reg := Default()
	all := reg.All()
	if len(all) == 0 {
		t.Fatal("no rules")
	}
	first := all[0].Meta().ID
	got := reg.Filter([]string{first}, nil)
	if len(got) != 1 || got[0].Meta().ID != first {
		t.Fatalf("only-filter failed: %+v", got)
	}
	got = reg.Filter(nil, []string{first})
	for _, r := range got {
		if r.Meta().ID == first {
			t.Fatalf("disabled rule %q still selected", first)
		}
	}
	if len(got) != len(all)-1 {
		t.Fatalf("disabled filter returned %d rules, want %d", len(got), len(all)-1)
	}
}
