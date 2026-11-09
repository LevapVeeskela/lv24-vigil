# CI and pull request scanning

Vigil is designed to fail a pull request on a real finding without uploading code
to a Vigil service. The job runs the CLI, writes SARIF, and lets GitHub code
scanning display the result.

## GitHub Actions

```yaml
name: vigil

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Vigil review
        run: |
          npx -y lv24-vigil review \
            --base origin/${{ github.event.pull_request.base.ref }} \
            --format sarif \
            --fail-on high > vigil.sarif
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vigil.sarif
```

The `if: always()` on the upload step is deliberate: `--fail-on high` exits `2`
and fails the job, but the SARIF file has already been written and should still
be uploaded.

`fetch-depth: 0` is required for `--base origin/<branch>` to resolve. Without it,
the checkout is shallow and git cannot find the merge base.

A complete example lives in
[../examples/github-workflow.yml](../examples/github-workflow.yml).

## Packaged action

`action.yml` is a composite action that downloads the release binary for the
runner, verifies it against `checksums.txt`, and runs a full `vigil scan`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- id: vigil
  uses: LevapVeeskela/lv24-vigil@v0.1.4
  with:
    path: .
    mode: standard
    fail-on: high
    format: sarif
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.vigil.outputs.sarif }}
```

Inputs: `path`, `mode`, `fail-on`, `format`, `version`. Outputs: `sarif`
(the report path), `exit-code` and `version`. The action defaults to the latest
release; set `version` and pin the `uses:` tag for reproducible runs. `v0.1.4` is
the initial release.

The action runs a full scan, not a diff review. Use the CLI `review --base` form
above when you want to gate only the lines a pull request changed.

## Full scan on a branch

For a scheduled or push scan, review the whole tree instead of a diff:

```bash
vigil scan --format sarif --fail-on high > vigil.sarif
```

Use this on a schedule, not on every pull request: a full scan is slower and will
report pre-existing findings that the pull request did not introduce.

## Fork pull requests

GitHub does not expose repository secrets to a `pull_request` workflow from a
fork. Without a provider key, Vigil still runs every deterministic rule and
produces SARIF; only triage, deep review, fixes and threat models are skipped.
That is a reasonable default for untrusted contributions.

If you need LLM analysis on fork PRs, use a `pull_request_target` workflow with a
strict checkout policy and no execution of contributor code, or run the scan in a
trusted environment after review. Do not expose a model key to a workflow that
checks out and runs untrusted code.

## Baselines

A repository with existing findings can adopt Vigil without blocking every pull
request:

1. Run `vigil scan --format json > baseline-scan.json` on the current main.
2. Record the accepted findings in `.vigil-baseline.json` with `vigil baseline`
   or by hand.
3. Commit the baseline.
4. Keep `--fail-on high` in CI.

New findings still fail; accepted debt does not. Review the baseline periodically
and remove entries when the underlying issue is fixed.

Baseline format and matching: [rules.md](rules.md).

## GitLab CI

The CLI is runner-agnostic. A minimal job:

```yaml
vigil:
  image: node:22
  script:
    - npx -y lv24-vigil review --base origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --format sarif --fail-on high > vigil.sarif
  artifacts:
    when: always
    paths:
      - vigil.sarif
  variables:
    OPENAI_API_KEY: $OPENAI_API_KEY
```

Make sure the clone is not shallow (`GIT_DEPTH: 0`) so the base branch exists.
GitLab can display SARIF through its security report ingestion if your plan
supports it; otherwise keep the file as an artifact.

## Other CI systems

Any runner with Node or the Vigil binary can run:

```bash
vigil review --base origin/main --format sarif --fail-on high > vigil.sarif
```

Exit codes:

- `0`: no finding at or above the threshold;
- `1`: runtime or configuration error;
- `2`: threshold met.

A `2` is a policy failure, not a crash. Keep the SARIF upload and any report
artifact on `always()` so reviewers can see why the job failed.

## What to scan in CI

- Review changed lines on pull requests.
- Full scan on a schedule or on the default branch.
- Do not run `vigil fix --apply` in CI. Fixes are a developer action.
- Do not pass secrets to a workflow that runs untrusted code.

## Cost control

LLM calls are the only variable cost. To keep CI cheap:

- use `--no-llm` on fork PRs and on large mechanical changes;
- use `--mode quick` (the default for `review`) and avoid `deep`;
- use a local model on a self-hosted runner if you have one;
- use `--fail-on high` for the gate and publish the full report as an artifact;
  `--fail-on` changes the exit code without hiding lower-severity findings.

The deterministic rules are free and fast; they run even with no model.
