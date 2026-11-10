# PyPI publishing

`lv24-vigil` is published on PyPI as a small Python wrapper around the
canonical npm CLI. `pip install lv24-vigil` installs the `vigil` (and
`lv24-vigil`) console script, which delegates to the npm package through `npx`.
The rules engine, providers, MCP server and Go binary live in the npm package.
**npm remains the canonical distribution**: PyPI mirrors the same version and is
not a second source of features.

## Requirements

- Python 3.9+ (`requires-python` in `python/pyproject.toml`); the publish
  workflow uses Python 3.12.
- Node.js >= 18, including npm and npx.
- Network access on first run (or a warm npm cache), because `npx` may download
  the npm package. The wrapper does not bundle Node.js.

## One-time setup (Trusted Publishing)

No API token or repository secret is used: PyPI trusts GitHub's OIDC identity.

1. Create a PyPI account at <https://pypi.org/account/register/> and enable
   two-factor authentication; PyPI requires 2FA for publishing.
2. Open <https://pypi.org/manage/account/publishing/> and add a **pending
   trusted publisher**. The project does not exist yet, which is expected.

   | Field | Value |
   | --- | --- |
   | PyPI project name | `lv24-vigil` |
   | Owner | `LevapVeeskela` |
   | Repository name | `lv24-vigil` |
   | Workflow name | `pypi-publish.yml` |
   | Environment name | blank (or `pypi`, see below) |

3. Save. The first successful publish creates the project and converts the
   pending publisher into a normal trusted publisher. Do not create the project
   manually first, and do not add an API token.

The committed workflow has no `environment:`, so leave the PyPI environment
blank. For a GitHub environment named `pypi`, add `environment: pypi` to the
`publish` job and enter `pypi` on PyPI; both values must match exactly.

## Versioning

Vigil has no root `package.json`: npm package versions come from the release
tag, and GoReleaser injects the same version into the binary. The Python
launcher keeps its own version in two places, which must match the release tag:

- `python/pyproject.toml` (`[project].version`)
- `python/src/lv24_vigil/__init__.py` (`__version__`)

Bump both before tagging. The workflow resolves the version from the release
tag (or the manual input), strips a leading `v`, and fails fast if the tag and
either Python file differ. It also validates a root `package.json` when one is
present, so the same workflow works if npm metadata is added to the repository
later. `python/tests/test_cli.py` checks that `__version__` matches
`pyproject.toml` before any upload.

## Release flow

A GitHub release created **manually** (UI or a personal token) triggers
`pypi-publish.yml`. A release created by `release.yml` with the repository
`GITHUB_TOKEN` does **not**: GitHub suppresses workflows started by that token.
In that case dispatch the workflow explicitly (see the fallback below).

1. Bump the two Python version files and run the usual checks
   (`python -m unittest discover -s python/tests`, `python -m build` in
   `python/`).
2. Commit, tag (`git tag vX.Y.Z`), push, and publish a GitHub release.
3. Watch the `pypi-publish` run in Actions, or dispatch it manually when the
   release was created by `release.yml`.

Manual fallback, for example when a release tag predates the workflow:

```bash
gh workflow run pypi-publish.yml -f version=0.5.1
```

The input may include or omit the leading `v`. Existing versions are detected
through the public JSON API and skipped, so re-running is safe. PyPI never
allows re-uploading a filename; bump the version to replace a bad release.

The job uses `ubuntu-latest`, `id-token: write`, pinned action commits and no
secrets. It does not publish the npm packages; `npm-publish.yml` owns that step.

## Install and run

```bash
pip install lv24-vigil
vigil version
vigil scan --no-llm
vigil status
```

Set `VIGIL_NPM_VERSION` to pin the npm CLI version or tag the wrapper invokes
(default: the wrapper's own version):

```bash
VIGIL_NPM_VERSION=latest vigil scan --no-llm
VIGIL_NPM_VERSION=0.5.1 vigil scan --no-llm
```

On PowerShell: `$env:VIGIL_NPM_VERSION = "latest"`.

Upgrade with `pip install --upgrade lv24-vigil`. The PyPI version is kept in
lockstep with npm, so either installation route gives the same engine.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `invalid-publisher` or `Trusted publishing failed` | The owner, repository, workflow filename or environment does not match the pending publisher. Use `LevapVeeskela`, `lv24-vigil`, `pypi-publish.yml`; leave the environment blank unless the job declares it. |
| `id-token` or OIDC permission error | Keep `permissions: id-token: write` on the job. Do not replace Trusted Publishing with a token. |
| Version already exists | PyPI rejects duplicate filenames. Bump both Python version files and publish a new tag; the workflow skips existing versions automatically. |
| Upload rejected because 2FA is missing | Enable 2FA on the PyPI account. Publishing is blocked without it. |
| `npx was not found on PATH` | Install Node.js >= 18 (npm and npx included), or use the standalone binary / Go install from [install.md](install.md). |
| `platform package ... is not installed` | Reinstall the npm CLI with optional dependencies enabled: `npm i -g lv24-vigil@latest` without `--no-optional` or `--omit=optional`. |

### TestPyPI (optional)

TestPyPI is a separate service with separate accounts. Add a second pending
trusted publisher at <https://test.pypi.org/manage/account/publishing/> with the
same owner, repository and workflow values, then point the upload at
`https://test.pypi.org/legacy/` (a local twine upload uses TestPyPI
credentials):

```bash
python -m twine upload --repository-url https://test.pypi.org/legacy/ python/dist/*
```

The committed workflow publishes to PyPI only and never handles tokens. For a CI
dry run, add a separate job that passes
`repository-url: https://test.pypi.org/legacy/` to the publish action. Use a
throwaway version such as `0.5.1rc1` and never reuse it for a real release.

## Cost

Public GitHub Actions minutes and PyPI hosting are free for public projects.
The workflow uses a standard GitHub-hosted runner, OIDC and PyPI only; there
are no paid services, secrets or API tokens to maintain.
