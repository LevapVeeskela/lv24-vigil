# CI, hooks and pull request scanning

Vigil is designed to fail a commit, pull request or pipeline on a real finding
without uploading code to a Vigil service. The same deterministic gate works
locally and in CI:

```bash
vigil scan . --no-llm --format sarif --output vigil.sarif --fail-on high
```

`--no-llm` runs all 163 rules with no model, no key and no network. `--fail-on`
changes the exit code, not the report: the SARIF file is written before the
process exits `2`, so an upload step with `if: always()` still runs.

## Choose a path

| Where you work | Use | Template |
| --- | --- | --- |
| Local clone | `vigil hook install` | built in |
| GitHub | Actions on PR, `main` and manual dispatch | [`examples/github-workflow.yml`](../examples/github-workflow.yml) |
| GitLab | MR, default branch and manual web run | [`examples/gitlab-ci.yml`](../examples/gitlab-ci.yml) |
| Any runner | CLI + SARIF artifact | this document |
| GitHub with less YAML | composite action | [`action.yml`](../action.yml) |

## Local hooks (before commit / before push)

```bash
vigil hook install                  # pre-commit, --fail-on high
vigil hook install --mode pre-push  # before push instead
vigil hook status
vigil hook uninstall
```

What the generated hook does:

| Mode | Command |
| --- | --- |
| `pre-commit` | `vigil scan --changed --base HEAD --no-llm --fail-on high --quiet` |
| `pre-push` | `vigil scan --changed --base @{upstream} --no-llm --fail-on high --quiet`; falls back to `HEAD~1`, then `HEAD` on a single-commit branch |

The file starts with `#!/bin/sh`, is executable, and contains the exact marker
`# managed by lv24-vigil`. The hook:

- honours `VIGIL_BIN` (default `vigil`) and checks `command -v` before running;
  a missing binary fails the hook with installation instructions instead of
  silently skipping the check;
- never overwrites a hook it does not own. `vigil hook install` refuses a
  foreign hook and asks for `--force`; with `--force` the old file is saved as
  `<hook>.pre-vigil.bak` first;
- removes only marked hooks. `vigil hook uninstall` also restores a
  `.pre-vigil.bak` backup when one exists;
- runs deterministic rules only, so it is fast, offline and keyless.

`vigil hook status` prints every installed hook, its marker and the exact target
command. `--fail-on low|medium|high|critical` is available on install.

## GitHub Actions

Copy [`examples/github-workflow.yml`](../examples/github-workflow.yml) to
`.github/workflows/vigil.yml`. It runs on pull requests, pushes to `main`, and
manual dispatch; the manual input `fail-on` defaults to `high`.

```yaml
name: vigil
on:
  workflow_dispatch:
    inputs:
      fail-on:
        description: "Minimum severity that fails the scan"
        default: high
        type: choice
        options: [low, medium, high, critical]
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      FAIL_ON: ${{ inputs['fail-on'] || 'high' }}
      VIGIL_SECURITY_API_TOKEN: ${{ secrets.VIGIL_SECURITY_API_TOKEN }}
      VIGIL_SECURITY_API: ${{ vars.VIGIL_SECURITY_API }}
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with: { node-version: 22 }
      - run: npm i -g lv24-vigil@latest
      - run: vigil scan . --no-llm --format sarif --output vigil.sarif --fail-on "$FAIL_ON"
      - if: always() && hashFiles('vigil.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: vigil.sarif
          category: vigil
      - if: always() && env.VIGIL_SECURITY_API_TOKEN != ''
        run: |
          vigil precheck --sarif vigil.sarif \
            --api "${VIGIL_SECURITY_API:-https://lv24.by/api}" \
            --target "$GITHUB_REPOSITORY" --commit "$GITHUB_SHA"
```

The `if: always()` on the upload is deliberate: `--fail-on high` exits `2` and
fails the job, but the SARIF file already exists and code scanning should still
show it.

### Optional pre-check secret

The last step is optional and gated by a repository **secret**:

| Kind | Name | Meaning |
| --- | --- | --- |
| Secret | `VIGIL_SECURITY_API_TOKEN` | **Staff JWT with `ops:security-scans`** — not an npm token, not a registry token, not an API key |
| Variable (optional) | `VIGIL_SECURITY_API` | Control-plane base URL; defaults to `https://lv24.by/api` |

With the secret unset, the step is skipped and forks stay green. With it set, an
upload failure fails the job: a misconfigured control plane should be visible.
`vigil precheck` stores SARIF as evidence, does not start a scan and never
touches the Strix execution plane.

## GitLab CI

Copy [`examples/gitlab-ci.yml`](../examples/gitlab-ci.yml) to `.gitlab-ci.yml`.
It runs for merge requests, on the default branch, and manually from the web UI.

```yaml
vigil:
  image: node:22
  stage: test
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_PIPELINE_SOURCE == "web"'
      when: manual
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  variables:
    GIT_DEPTH: "0"
    VIGIL_FAIL_ON: "high"
  script:
    - npm i -g lv24-vigil@latest
    - |
      set +e
      vigil scan . --no-llm --format sarif --output vigil.sarif --fail-on "$VIGIL_FAIL_ON"
      code=$?
      set -e
      if [ -n "${VIGIL_SECURITY_API_TOKEN:-}" ] && [ -f vigil.sarif ]; then
        vigil precheck --sarif vigil.sarif \
          --api "${VIGIL_SECURITY_API:-https://lv24.by/api}" \
          --target "$CI_PROJECT_PATH" --commit "$CI_COMMIT_SHA"
      fi
      exit "$code"
  artifacts:
    when: always
    paths: [vigil.sarif]
    reports:
      sarif: vigil.sarif
```

- **Pre-check variable:** set `VIGIL_SECURITY_API_TOKEN` as a masked CI/CD
  variable (staff JWT, `ops:security-scans`). Set `VIGIL_SECURITY_API` only if
  the control plane is not `https://lv24.by/api`.
- **SARIF report:** `artifacts:reports:sarif` is native SARIF ingestion in
  GitLab 19.2+ Ultimate. On older instances keep the plain `paths` artifact and
  remove the `reports` block. GitLab's `reports:sast` expects its own
  `gl-sast-report.json` schema, not SARIF.
- **Exit code:** the shell captures the scan exit code, runs the optional
  pre-check, then exits with the original code, so a `2` still fails the job
  while artifacts and evidence are kept.

## Packaged composite action

`action.yml` installs the npm package and runs a full scan. It needs Node.js
18+ on the runner; GitHub-hosted runners already have it, and self-hosted
runners should call `actions/setup-node` first.

The action is listed on the [GitHub Marketplace](https://github.com/marketplace/actions/vigil-security-scan)
as **Vigil security scan** (Security + Code quality). Pin `version: 0.5.4` when
the CLI must match the action tag; the default `latest` follows the newest npm
release.

```yaml
- uses: actions/checkout@v7

- id: vigil
  uses: LevapVeeskela/lv24-vigil@v0.5.4
  with:
    path: .
    fail-on: high
    no-llm: true
    format: sarif
    version: 0.5.4

- if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ${{ steps.vigil.outputs.sarif }}
```

Inputs: `path`, `fail-on`, `no-llm`, `format`, `version`. Outputs: `sarif` /
`report` (the report path), `exit-code` and `version`. The action runs a full
scan, not a diff review. Use the CLI `review --base` form below when you want to
gate only changed lines.

## Review only changed lines

```bash
vigil review --base origin/main --format sarif --fail-on high > vigil.sarif
```

`fetch-depth: 0` is required for `--base origin/<branch>` to resolve; without it
the checkout is shallow and git cannot find the merge base. A full scan is the
right choice for `main`, a schedule or a manual run; a diff review is the right
choice for a large pull request.

## Other CI systems

Any runner with Node or the Vigil binary can run:

```bash
vigil scan . --no-llm --format sarif --output vigil.sarif --fail-on high
```

Keep the report as an artifact with `when: always` / `if: always()` so reviewers
can see why the job failed. Do not run `vigil fix --apply` in CI: fixes are a
developer action.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above the threshold |
| `1` | Runtime or configuration error |
| `2` | At least one finding at or above `--fail-on` |

A `2` is a policy failure, not a crash. `--fail-on` changes the exit code
without hiding lower-severity findings from the report.

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

1. Run `vigil scan --format json > baseline-scan.json` on the current `main`.
2. Record the accepted findings in `.vigil-baseline.json` with `vigil baseline`
   or by hand.
3. Commit the baseline.
4. Keep `--fail-on high` in CI.

New findings still fail; accepted debt does not. Review the baseline periodically
and remove entries when the underlying issue is fixed. Format and matching:
[rules.md](rules.md).

## Cost control

LLM calls are the only variable cost. To keep CI cheap:

- use `--no-llm` on every gate shown above;
- use `--mode quick` if you add an LLM pass to a review;
- use a local model on a self-hosted runner if you have one;
- use `--fail-on high` for the gate and publish the full report as an artifact.

The deterministic rules are free and fast; they run even with no model.
