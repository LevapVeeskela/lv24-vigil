// Command vigil is the CLI and MCP server entry point.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/levapveeskela/lv24-vigil/internal/version"
)

// ErrFindings is returned when a scan produced at least one finding at or above
// the --fail-on threshold. main turns it into exit code 2 without printing an
// error line: findings are a result, not a crash.
var ErrFindings = errors.New("findings at or above the fail-on threshold")

func main() {
	if err := runWithIO(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, ErrFindings) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "vigil:", err)
		os.Exit(1)
	}
}

// run keeps the historical entry point used by callers that only have args.
func run(args []string) error { return runWithIO(args, os.Stdout, os.Stderr) }

// runWithIO dispatches a command with explicit writers so tests never depend on
// the real process streams.
func runWithIO(args []string, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) == 0 {
		return runScan(nil, stdout, stderr)
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan", "audit":
		return runScan(rest, stdout, stderr)
	case "review":
		return runReview(rest, stdout, stderr)
	case "fix":
		return runFix(rest, stdout, stderr)
	case "mcp":
		return runMCP(rest, stdout, stderr)
	case "init":
		return runInit(rest, stdout, stderr)
	case "status", "doctor":
		return runStatus(rest, stdout, stderr)
	case "rules":
		return runRules(rest, stdout, stderr)
	case "baseline":
		return runBaseline(rest, stdout, stderr)
	case "report":
		return runReport(rest, stdout, stderr)
	case "precheck":
		return runPrecheck(rest, stdout, stderr)
	case "threat-model", "threatmodel":
		return runThreatModel(rest, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.String())
		return nil
	case "help", "--help", "-h":
		printHelp(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q (run `vigil help`)", cmd)
	}
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `vigil — security audit for your code, on your own model.

Usage:
  vigil scan [path] [flags]        scan a repository or directory
  vigil review [flags]             review only changed lines
  vigil fix FINDING_ID [flags]     propose (or apply) a fix
  vigil threat-model [path]        generate a threat model
  vigil mcp [--root DIR]           run as an MCP server (stdio)
  vigil init [--force]             write a starter .vigil.yaml
  vigil status [--json]            show provider, model and engine health
  vigil rules [flags]              list detection rules
  vigil baseline [list|add|remove|clear]
  vigil report [--scan ID]         render the last scan
  vigil precheck [flags]           upload a SARIF pre-check to LV24 security scans
  vigil version                    print the version
  vigil help                       show this help

Scan flags:
  --path DIR                     scan root (default .); a positional path also works
  --mode quick|standard|deep     scan depth (default from config: standard)
  --changed                      only files changed against --base
  --base REF                     git ref for --changed (default HEAD)
  --diff FILE                    scan added lines from a unified diff ("-" = stdin)
  --no-llm                       deterministic rules only
  --deep                         run the deep LLM review
  --threat-model                 generate a threat model as part of the scan
  --include GLOB                 only scan matching files (repeatable, comma-separated)
  --exclude GLOB                 skip matching files (repeatable, comma-separated)
  --rules ID[,ID]                run only these rules
  --disable ID[,ID]              skip these rules
  --min-severity LEVEL           low|medium|high|critical (default from config)
  --max-findings N               cap the number of findings
  --no-baseline                  ignore the suppression baseline
  --format md|json|sarif|html    report format (default from config: md)
  --output FILE                  write the report to FILE ("-" = stdout)
  --fail-on LEVEL                exit 2 when a finding at or above LEVEL exists
  --quiet                        skip the human summary
  --color auto|always|never      ANSI colour in the summary

Other flags:
  vigil fix ID --scan ID --apply --root DIR
  vigil report --format FMT --output FILE --scan ID
  vigil precheck --sarif FILE --target TARGET --api URL --token JWT
  vigil threat-model --output FILE
  vigil rules --category C --language L --severity S --query Q --json
  vigil baseline add ID --reason TEXT
  vigil baseline clear --yes

Environment:
  VIGIL_PROVIDER, VIGIL_MODEL, VIGIL_API_KEY, VIGIL_BASE_URL
  OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, ...
  OLLAMA_HOST (local models)
  VIGIL_NO_LLM=1 (force deterministic-only scans)
  VIGIL_CONFIG (override the user config path)
  VIGIL_SECURITY_API_TOKEN (staff JWT fallback for vigil precheck --token)
  VIGIL_BASE_URL and VIGIL_API_KEY belong in the user config or env, not in a project file.

Exit codes:
  0 success · 1 error · 2 findings at or above --fail-on

Docs: https://github.com/LevapVeeskela/lv24-vigil
`)
}
