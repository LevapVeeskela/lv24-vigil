package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/levapveeskela/lv24-vigil/internal/safepath"
)

const initTemplate = `# Vigil configuration — https://github.com/LevapVeeskela/lv24-vigil
#
# This file is safe to commit: it must never contain an API key.
# Keys belong in the environment (VIGIL_API_KEY, OPENAI_API_KEY, ...) or in the
# user config (~/.config/vigil/config.yaml). Project files may only tune scans.
#
# provider: openai        # openai | anthropic | gemini | openrouter | groq |
# model: gpt-4.1-mini     # deepseek | mistral | xai | ollama | lmstudio | custom
# base_url: ""            # user config only — never here
# api_key: ""             # user config only — never here

scan:
  # All modes run the same deterministic rules. quick/standard differ only in
  # the optional LLM passes; deep adds the LLM deep review.
  mode: standard
  min_severity: low
  max_findings: 200

  # Skip generated and vendored trees. Globs are matched against paths
  # relative to the project root.
  exclude:
    - .git/**
    - node_modules/**
    - vendor/**
    - dist/**
    - build/**
    - target/**
    - .venv/**
    - coverage/**
    - "*.min.js"
    - "*.map"

  # use_llm: true         # false forces deterministic-only scans
  # deep_review: false    # true adds the LLM deep review to every scan
  # baseline: .vigil-baseline.json

output:
  format: md              # md | json | sarif | html
  color: auto             # auto | always | never
  show_fix: true
`

func runInit(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("init")
	force := fs.Bool("force", false, "overwrite an existing .vigil.yaml")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, "Usage: vigil init [--force]\n\nWrites a commented .vigil.yaml starter in the current directory.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("init takes no arguments (got %q)", positional[0])
	}

	const path = ".vigil.yaml"
	// Refuse to follow a symlink or junction out of the current directory,
	// even with --force: a hostile repository must not turn `vigil init` into
	// an arbitrary-file overwrite.
	target, err := safepath.Resolve(".", path)
	if err != nil {
		return fmt.Errorf("refusing to write %s: %w", path, err)
	}
	if _, err := os.Stat(target); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass --force to overwrite it", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check %s: %w", path, err)
	}

	if err := writeFile(target, []byte(initTemplate)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, `Created %s

Next steps:
  1. Configure a model (optional — deterministic rules work without one):
       export OPENAI_API_KEY=...        # or ANTHROPIC_API_KEY, GEMINI_API_KEY, ...
       export OLLAMA_HOST=http://localhost:11434
  2. Run your first scan:
       vigil scan .
  3. Wire Vigil into your agent:
       vigil mcp
  4. Accept reviewed findings so they stop failing the build:
       vigil baseline add <FINDING_ID> --reason "why this is safe"
`, path)
	return nil
}
