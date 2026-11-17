# pre-commit

Vigil ships a [pre-commit](https://pre-commit.com) hook manifest, so a repository
that already uses the framework can add the deterministic gate without writing a
script. The hook runs every Vigil rule offline and fails the commit on findings
at or above `high`.

## Install the CLI first

`language: system` hooks run the binary that is already on `PATH`; pre-commit
does not build or download Vigil.

```bash
npm i -g lv24-vigil            # or pin: npm i -g lv24-vigil@0.10.2
vigil version
```

Or with Go 1.27+:

```bash
go install github.com/levapveeskela/lv24-vigil/cmd/vigil@latest
vigil version
```

Make sure `$(go env GOPATH)/bin` is on `PATH` after a Go install.

## Configure

Add the repository and the hook to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/LevapVeeskela/lv24-vigil
    rev: v0.10.2
    hooks:
      - id: vigil-scan
```

Then install the git hook and run once over the whole tree:

```bash
pre-commit install
pre-commit run --all-files
```

Hook ids in [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml):

| id | entry | When to enable |
| --- | --- | --- |
| `vigil-scan` | `vigil scan --no-llm --fail-on high` | Default gate: all 263 deterministic rules |
| `vigil-mcp-audit` | `vigil mcp-audit --fail-on high` | Opt-in: only for repositories that commit MCP server configuration |

Both hooks set `pass_filenames: false` and `always_run: true`, so they scan the
project rather than the staged file list and still run on a commit that changes
no files tracked by pre-commit.

The MCP audit is opt-in on purpose. It reads configuration files only and never
contacts a configured server, but most repositories do not keep MCP config, and
enabling a second full-tree pass on every commit buys nothing there:

```yaml
repos:
  - repo: https://github.com/LevapVeeskela/lv24-vigil
    rev: v0.10.2
    hooks:
      - id: vigil-scan
      - id: vigil-mcp-audit   # add only if the repo contains MCP config
```

## Change the threshold

`entry` already carries `--fail-on high`. To use a different severity, override
`entry` in your own config instead of appending `args` (which would pass the
flag twice):

```yaml
      - id: vigil-scan
        entry: vigil scan --no-llm --fail-on critical
```

Accepted values: `low`, `medium`, `high`, `critical`.

## Update the pin

`rev` is a tag, not a branch. Move it forward deliberately:

```bash
pre-commit autoupdate                 # rewrites rev to the newest tag
pre-commit autoupdate --repo https://github.com/LevapVeeskela/lv24-vigil
git diff .pre-commit-config.yaml
```

Review the diff and commit it; an autoupdate run that changes rules can surface
new findings on the next commit. `pre-commit autoupdate --freeze` pins the
resolved commit as well.

## Skip a hook

For one run, keep the rest of the hooks active:

```bash
SKIP=vigil-scan git commit -m "wip"
SKIP=vigil-scan,vigil-mcp-audit pre-commit run --all-files
```

For a single commit without re-running the hooks, `git commit --no-verify` works
as with any pre-commit hook, but it bypasses every hook in the framework, not
just Vigil. Neither form is a suppression: the finding still appears on the next
scan, in CI, and on `pre-commit run --all-files`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above `--fail-on` |
| `1` | Runtime or configuration error (missing CLI, unreadable path) |
| `2` | At least one finding at or above `--fail-on` |

Code `2` is a **policy failure, not a crash**: the scan completed and the
report is valid. pre-commit reports any non-zero exit as a failed hook, so read
the output to tell a finding (`2`) from a broken environment (`1`). `--fail-on`
changes the exit code only; lower-severity findings are still printed.

A repository with existing findings can adopt the hook without blocking every
commit by committing a baseline first — see [ci.md](ci.md#baselines).

## pre-commit.ci

[pre-commit.ci](https://pre-commit.ci) does not support `language: system`
hooks: it runs in its own environment and will not have the `vigil` binary. Keep
the `vigil-scan` hook for local commits, and use one of these for pull requests:

- the GitHub Actions workflow in [`examples/github-workflow.yml`](../examples/github-workflow.yml),
  which installs the CLI with `npm i -g lv24-vigil` and uploads SARIF;
- the composite action in [`action.yml`](../action.yml);
- a `repo: local` hook in CI that installs the CLI in a prior step.

If pre-commit.ci is enabled, disable the Vigil hook there rather than letting it
fail on a missing binary:

```yaml
ci:
  skip: [vigil-scan, vigil-mcp-audit]
```

`pre-commit.ci` still runs the other hooks, formatting and autoupdate; the
deterministic security gate runs in the workflow above.

## pre-commit or `vigil hook install`?

Both fail a commit on a finding; they differ in who owns the hook.

| | pre-commit hook | `vigil hook install` |
| --- | --- | --- |
| Requires | `pre-commit`, `.pre-commit-config.yaml` | nothing but the Vigil CLI |
| Hook file | managed by pre-commit | written by Vigil, marked `# managed by lv24-vigil` |
| Scope | full project scan (`pass_filenames: false`) | staged diff (`vigil scan --diff -`) |
| Other tools | shared with every framework hook | Vigil only |
| Pin | `rev` tag in the config, `pre-commit autoupdate` | the installed CLI version |
| Uninstall | remove the repo entry | `vigil hook uninstall` |

Use the framework hook when the repository already runs pre-commit, so the gate
travels with the config and updates through `autoupdate`. Use
`vigil hook install` for a zero-dependency, staged-diff check, or when you want
Vigil to own a `pre-commit`/`pre-push` hook without adding a Python toolchain.
Do not install both on the same hook type: the second install refuses to
overwrite a foreign hook, and running both just scans twice.

CI templates and the native hook details: [ci.md](ci.md).
