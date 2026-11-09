# Contributing to Vigil

Thanks for helping. Vigil is a small Go project with a deliberately narrow
dependency set and a strong bias toward deterministic, reviewable behavior.

## Development setup

Requirements:

- Go 1.27 or newer.
- Git, for the changed-lines review and fix-apply paths.
- Optional: a model provider or a local Ollama/LM Studio instance for the LLM
  features.

```bash
git clone https://github.com/LevapVeeskela/lv24-vigil
cd lv24-vigil

go build ./cmd/vigil
go test ./...
go vet ./...
```

Run the binary from source:

```bash
go run ./cmd/vigil scan --no-llm
go run ./cmd/vigil status
go run ./cmd/vigil mcp
```

There is no CGO requirement and no code generator. Keep it that way unless a
change is discussed first.

## Project layout

| Path | Responsibility |
|---|---|
| `cmd/vigil/` | CLI entry point and command wiring |
| `internal/model/` | `Finding`, `ScanResult`, severity, fix and location types |
| `internal/config/` | defaults, user config, project config, environment |
| `internal/rules/` | deterministic rules and the registry |
| `internal/scanner/` | walker, ignore, language detection, diff, baseline |
| `internal/gitutil/` | read-only git operations and patch application |
| `internal/store/` | local scan history |
| `internal/llm/` | provider clients and retry/error handling |
| `internal/analysis/` | triage, deep review, fixes, explanations, threat model |
| `internal/report/` | Markdown, JSON, SARIF and HTML renderers |
| `internal/mcp/` | MCP transport and JSON-RPC types |
| `internal/tools/` | MCP tool, resource and prompt registration |
| `internal/safepath/` | repository-relative path validation and symlink-safe resolution |
| `internal/app/` | wiring of config, scanner, analyzer and store |

Dependencies flow inward. `rules` and `model` must not import the CLI, the MCP
server or a provider client.

## Adding a rule

1. Pick the right pack: `secrets.go`, `injection.go`, `crypto.go`, `auth.go`,
   `web.go`, `config.go`, `ci.go` or `dependencies.go`.
2. Give the rule a stable ID in the family namespace, for example
   `VGL-WEB-013`. Do not reuse or renumber an ID.
3. Fill the metadata: title, description, severity, category, languages, CWE,
   OWASP and tags where they apply.
4. Return 1-based locations. Include evidence and a concrete remediation.
5. Never execute or modify scanned code. Never make a network call from a rule.
6. Mask every credential with `rules.MaskSecret`; a finding must not contain the
   raw value.
7. Add table-driven tests with a positive case, a negative case and an obvious
   placeholder that must stay quiet.
8. Run `go test ./internal/rules/...` and the full suite.

Rules are intentionally shallow. A rule should have a clear sink or pattern and
a low false-positive rate. If a check needs data flow across files, propose it in
an issue first; a half-built flow engine is worse than a precise local rule.

## Adding a provider

1. Implement the `llm.Client` contract in `internal/llm/`.
2. Honour `context.Context` and the configured timeout.
3. Retry `429`, `5xx` and network errors at most twice with jitter.
4. Return typed `*llm.Error` values. Never log the API key or the prompt body.
5. Add the provider to `config` defaults, environment inference and `vigil
   status`.
6. Add tests with `httptest`; no live network calls in the test suite.
7. Update `docs/providers.md` and the provider table in both READMEs.

## Tests

```bash
go test ./...
go test ./internal/rules/... -run TestName -v
go vet ./...
```

Tests must be deterministic and offline. Use fixtures, `httptest` and temporary
directories. Do not require Docker, a model key or a live provider.

For changes that affect the CLI surface, also run the built binary against a
small fixture repository and check the exit code. For report changes, inspect the
rendered Markdown, JSON, SARIF and HTML.

## Documentation

- Every command, flag and provider in the docs must exist in the code.
- Do not claim benchmarks, "zero false positives" or full coverage.
- Keep the English and Russian READMEs structurally aligned.
- Prefer short, task-oriented pages with copy-pasteable commands.
- If you add a doc page, link it from the README documentation table and from at
  least one related page.

## Commit and pull request

Keep commits focused. A short imperative subject is enough; a body is useful for
the "why", not a restatement of the diff.

A pull request should include:

- the problem and the approach;
- the commands you ran (`go test ./...`, `go vet ./...`, a manual CLI check);
- a sample finding or report when the output changed;
- a note on compatibility, false-positive risk or new network behavior.

## Security-sensitive changes

Read [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md)
before changing any of these:

- secret masking or evidence rendering;
- prompt construction or untrusted-code delimiters;
- path validation for findings and fixes;
- `git apply` behavior;
- MCP tool permissions or the `apply=true` path;
- provider request logging or error formatting.

Do not include real credentials in a test, fixture, issue or pull request. Use a
synthetic value that matches the detector shape and is clearly fake.

## License

By contributing, you agree that your contribution is licensed under
Apache-2.0, the same license as the project.
