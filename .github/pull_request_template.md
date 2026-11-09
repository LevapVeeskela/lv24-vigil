## Summary

<!-- What changes, and why. Link the issue when one exists: "Closes #123". -->

## Type of change

- [ ] Bug fix (behavior change, no new surface)
- [ ] New rule or rule change
- [ ] New provider or provider change
- [ ] CLI, report or MCP surface change
- [ ] Docs only
- [ ] Build, CI or release plumbing

## Verification

<!-- Paste the commands you ran. Drop lines that do not apply. -->

```bash
go build ./cmd/vigil
go test ./...
go vet ./...
```

```bash
# Self-scan, same gate as .github/workflows/vigil.yml
go build -o vigil ./cmd/vigil
./vigil scan . --no-llm --fail-on high \
  --exclude 'internal/rules/**' --exclude 'scripts/**' \
  --exclude 'docs/**' --exclude 'examples/**'
```

Manual CLI check (for changes that touch the command surface or a renderer):

<!-- e.g. `./vigil scan ./testdata --format sarif` and the exit code you saw -->

## Checklist

- [ ] `go test ./...` passes.
- [ ] `go vet ./...` passes and `gofmt -l .` is empty.
- [ ] Tests are deterministic and offline — no live network, no model key, no Docker.
- [ ] New or changed behavior has tests, including the negative case for a rule.
- [ ] No real credentials, tokens or internal hostnames in code, tests, fixtures or this PR.
- [ ] Docs updated when a command, flag, provider or rule ID changed.
- [ ] English and Russian READMEs stay structurally aligned (if a README changed).
- [ ] No new dependency without a stated reason, and it is pinned exactly.
- [ ] Findings still mask secrets; no raw value reaches a report or a log.

## Compatibility and risk

<!--
Breaking change for an existing config or flag? New network call? Higher
false-positive risk in a rule? Say it here so reviewers can judge the blast
radius. Write "none" when there is nothing to flag.
-->
