package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusJSONShape(t *testing.T) {
	dir := newTestRepo(t)
	const fakeKey = "sk-status-secret-must-never-print"
	t.Setenv("VIGIL_API_KEY", fakeKey)

	out, stderr, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("status: %v\nstderr:\n%s", err, stderr)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("status is not valid JSON: %v\n%s", err, out)
	}
	for _, key := range []string{
		"version", "commit", "date", "goVersion", "root", "provider", "model",
		"baseUrl", "apiKeySet", "llm", "llmStatus", "rules", "scanStore",
		"baseline", "lastScan", "configFiles", "userConfig", "userConfigExists",
		"sources", "warnings",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("status JSON missing key %q", key)
		}
	}

	var status struct {
		APIKeySet bool     `json:"apiKeySet"`
		LLM       bool     `json:"llm"`
		Rules     int      `json:"rules"`
		ScanStore string   `json:"scanStore"`
		Warnings  []string `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !status.APIKeySet {
		t.Error("apiKeySet = false, want true")
	}
	if status.LLM {
		t.Error("llm = true, want false when only a key is set")
	}
	if status.Rules == 0 {
		t.Error("rules = 0")
	}
	if status.ScanStore != filepath.Join(dir, ".vigil", "scans") {
		t.Errorf("scanStore = %q, want %q", status.ScanStore, filepath.Join(dir, ".vigil", "scans"))
	}
	if status.Warnings == nil {
		t.Error("warnings must be an array, not null")
	}
	if strings.Contains(out, fakeKey) {
		t.Error("status leaked the API key")
	}
}

func TestStatusHumanOutput(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{"provider", "not configured", "llm", "rules", "last scan", "run `vigil scan`"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q\n%s", want, out)
		}
	}
}
