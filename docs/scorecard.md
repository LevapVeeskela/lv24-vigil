# OpenSSF Scorecard

[OpenSSF Scorecard](https://github.com/ossf/scorecard) grades the *repository and
its release process* against supply-chain practices: reviews, branch
protection, pinned dependencies, token scope, signed releases. Vigil grades the
*code*. Run both: neither replaces the other, and a high Scorecard score is not
evidence that a project is free of vulnerabilities.

The workflow is [`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml).

## When it runs

| Trigger | Why |
| --- | --- |
| `branch_protection_rule` | Re-checks after a protection rule is created, edited or deleted |
| `schedule`, Mondays 01:30 UTC | Catches drift on settings that change without a commit |
| `push` to `main` | New commit, new score |

The job holds `security-events: write` (SARIF upload), `id-token: write`
(OIDC, required by `publish_results`), `contents: read` and `actions: read`;
everything else stays read-only because the workflow declares `permissions: read-all` at the top.

## What the checks mean

Each check scores 0-10; the overall score is the mean of the checks that could
be evaluated. "n/a" checks (for example `Packaging` for a project that ships no
packages) are dropped rather than counted as zero.

| Check | Question it answers | What moves it here |
| --- | --- | --- |
| `Binary-Artifacts` | Are binaries committed to the repo? | Keep generated binaries out of git; publish them as release assets |
| `Branch-Protection` | Are force-pushes and unreviewed merges blocked on `main`? | Required reviews, status checks, no force-push, admins included |
| `CI-Tests` | Do pull requests run tests? | `ci.yml` on `pull_request` (already present) |
| `CII-Best-Practices` | Is the OpenSSF Best Practices badge earned? | Register the project and answer the questionnaire |
| `Code-Review` | Are changes reviewed by someone other than the author? | Merged PRs with an approving review |
| `Contributors` | Is there more than one recent contributor? | Sustained outside contributions, or honest recognition that this is a single-maintainer project |
| `Dangerous-Workflow` | Can a PR inject code into a privileged workflow? | No `pull_request_target` with checkout of untrusted code, no untrusted `${{ }}` in `run:` |
| `Dependency-Update-Tool` | Is Dependabot or Renovate enabled? | `.github/dependabot.yml` |
| `Fuzzing` | Is there a fuzz target or an OSS-Fuzz integration? | `fuzz_test.go` is a start; the check looks for recognised fuzzing setups |
| `License` | Is there a recognised license file? | `LICENSE` at the repository root |
| `Maintained` | Is the project active? | Commits and issue activity within the last 90 days |
| `Packaging` | Are there published packages and a packaging workflow? | npm (`lv24-vigil`) and PyPI workflows (already present) |
| `Pinned-Dependencies` | Are Actions and container images pinned by hash? | Full commit SHAs with a version comment, as in the existing workflows |
| `SAST` | Does a static analysis tool run on the repo? | CodeQL or a SARIF upload (Vigil's own SARIF upload also counts) |
| `Security-Policy` | Is there a `SECURITY.md`? | A policy with a reporting channel and a response expectation |
| `Signed-Releases` | Are release assets signed or attested? | Sigstore/cosign signatures, SLSA provenance, or a GitHub attestation |
| `Token-Permissions` | Do workflows default to a read-only token? | Top-level `permissions:` blocks, no write-all |
| `Vulnerabilities` | Are there open, unfixed known vulnerabilities? | Keep dependency advisories closed; `vigil dependencies` lists OSV records |

## Where the results appear

1. **Security > Code scanning** in the repository, filter by tool
   `OpenSSF Scorecard` (category `scorecard`). Each check becomes an alert with
   its score, reason and remediation hint, and closes when the check passes.
2. **Actions > scorecard** for the raw run; the SARIF file is the job's
   `results.sarif`.
3. **OpenSSF public dataset**, because `publish_results: true`:
   - viewer: <https://securityscorecards.dev/viewer/?uri=github.com/LevapVeeskela/lv24-vigil>
   - JSON: <https://api.securityscorecards.dev/projects/github.com/LevapVeeskela/lv24-vigil>
   - badge: <https://api.securityscorecards.dev/projects/github.com/LevapVeeskela/lv24-vigil/badge>

Some checks (`Branch-Protection`, `Token-Permissions`) read settings that need
admin-level API access. Without it they return an inconclusive result with a
reason instead of a zero; the rest of the score is unaffected.

## Badge

The badge reflects the last published run, so a settings change shows up at the
next schedule or push, not immediately. Score 0-10; green is strong, red means
the process controls are missing. Clicking it opens the public result page.

README snippet (the README is not edited by the Scorecard change; paste this
line where badges belong):

```markdown
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/LevapVeeskela/lv24-vigil/badge)](https://securityscorecards.dev/viewer/?uri=github.com/LevapVeeskela/lv24-vigil)
```

## Publishing makes the score public

`publish_results: true` sends the check names, scores, reasons and repository
metadata to the OpenSSF public dataset, which is what the badge and the JSON
endpoint serve. The result is public and permanent for that commit; no source
code is uploaded, but the score, the failing checks and their reasons are
visible to anyone. To keep results private, set `publish_results: false` and
remove `id-token: write`; the Security tab and the Actions run keep working,
the public badge and viewer do not.

The upload needs a public repository and OIDC. On a fork or a private mirror the
analysis still runs locally in Actions, but `publish_results` fails unless the
fork is public and enrolled.

## Running it by hand

```bash
docker run --rm \
  -e GITHUB_AUTH_TOKEN="$(gh auth token)" \
  gcr.io/openssf/scorecard:stable \
  --repo=github.com/LevapVeeskela/lv24-vigil --show-details
```

This is read-only against the GitHub API. It is a posture report, not a gate:
nothing in Vigil fails a build on the Scorecard score.
