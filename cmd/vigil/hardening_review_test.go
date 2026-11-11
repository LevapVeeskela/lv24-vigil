package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression: user --rules was appended to the anti-RE list, so
// `vigil hardening --rules VGL-SEC-001` ran non-hardening rules.
func TestHardeningRejectsNonAntiRERules(t *testing.T) {
	dir := newTestRepo(t)

	_, _, err := runCLI(t, "hardening", dir, "--rules", "VGL-SEC-001", "--quiet", "--format", "json")

	if err == nil || !strings.Contains(err.Error(), "VGL-ARE") {
		t.Fatalf("want an anti-RE-only error, got %v", err)
	}
}

func TestHardeningRulesNarrowTheAntiRESet(t *testing.T) {
	dir := newTestRepo(t)

	out, _, err := runCLI(t, "hardening", dir, "--rules", "vgl-are-001", "--quiet", "--format", "json", "--no-baseline")

	if err != nil {
		t.Fatalf("hardening: %v", err)
	}
	var res struct {
		Stats struct {
			RulesRun int `json:"rulesRun"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if res.Stats.RulesRun != 1 {
		t.Fatalf("rulesRun = %d, want 1", res.Stats.RulesRun)
	}
}
