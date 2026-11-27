# Documentation index — Vigil

`docs/` has **25 top-level Markdown files**: 23 documents that existed before this index, the
new [ARCHITECTURE.md](ARCHITECTURE.md) front door, and this index. The separate
[plans/](plans/) folder is historical. Start with the architecture, then jump to the task you
need.

## Start here

| Doc | Audience | Why read it |
|---|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | engineers, agents | System context, pipeline, trust boundary, distribution, invariants |
| [architecture-deep-dive.md](architecture-deep-dive.md) | engineers | Deep dive: packages, design rationale, limits |
| [security-model.md](security-model.md) | security reviewers, agents | Egress, masking, prompt safety, boundaries |
| [rules.md](rules.md) | everyone | Rule families, inline suppressions, baseline semantics |

## Using Vigil

| Doc | Audience | Contents |
|---|---|---|
| [cli.md](cli.md) | users, CI engineers | Commands, flags, exit codes, formats |
| [mcp.md](mcp.md) | agent users | MCP clients, 14 tools, 4 resources, 5 prompts |
| [providers.md](providers.md) | users with a model | OpenAI/Anthropic/Gemini/local providers, keys, precedence |
| [pre-commit.md](pre-commit.md) | contributors | pre-commit framework hooks |
| [troubleshooting.md](troubleshooting.md) | users | Exact messages and fixes |

## Install and distribution

| Doc | Audience | Contents |
|---|---|---|
| [install.md](install.md) | users | npm, Go, installers, deb/rpm/apk, Scoop, Homebrew, AUR, container |
| [distribution.md](distribution.md) | maintainers | Per-channel live state, versions, pending gates |
| [release.md](release.md) | maintainers | Release pipeline, assets, verification, re-runs |
| [pypi.md](pypi.md) | maintainers | Python launcher and PyPI publishing |
| [mcp-registry.md](mcp-registry.md) | maintainers | Official MCP Registry entry |
| [mcp-directories.md](mcp-directories.md) | maintainers | Directory metadata and submission status |
| [aur.md](aur.md) | maintainers | Arch AUR package and publication |
| [container.md](container.md) | maintainers | GHCR image, provenance, SBOM |

## CI, compliance, positioning

| Doc | Audience | Contents |
|---|---|---|
| [ci.md](ci.md) | CI engineers | GitHub Actions, SARIF, fork PRs, prechecks, GitLab |
| [scorecard.md](scorecard.md) | maintainers | OpenSSF Scorecard workflow and badge |
| [cii-best-practices.md](cii-best-practices.md) | maintainers | CII Best Practices checklist |
| [anti-re-hardening.md](anti-re-hardening.md) | mobile/desktop engineers | ARE rules mapped to REA capabilities |
| [comparison.md](comparison.md) | evaluators | Vigil vs Strix vs hosted scanners |

## Historical (do not treat as current)

| File | Status |
|---|---|
| [history.md](history.md) | **Historical record** of the `dist-0.1.4` incident and repository history. |
| [lv24-security-analysis.md](lv24-security-analysis.md) | **Historical analysis** of the Strix upstream sync and the LV24 fork. |
| [plans/](plans/) | **Historical planning notes**; kept as evidence, not as current guidance. |

## Diagrams

| File | Purpose |
|---|---|
| [architecture/README.md](architecture/README.md) | Generated index: `.mmd` sources plus committed SVG/PNG |

## Outside `docs/`

| File | Purpose |
|---|---|
| [`../README.md`](../README.md) | Product front door, install, MCP setup |
| [`../README.ru.md`](../README.ru.md) | Russian overview (kept separately, not a translation of every edit) |
| [`../AGENTS.md`](../AGENTS.md) | Agent entry, commands, invariants |
| [`../llms.txt`](../llms.txt) | Plain-text index for LLM clients |
| [`../CONTRACTS.md`](../CONTRACTS.md) | CLI/MCP contract guarantees |
| [`../SECURITY.md`](../SECURITY.md) | Vulnerability reporting |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Release history |

## Conventions

- Diagrams: `.mmd` is the source; `.svg`/`.png` are generated with `lv24-diagram` and committed.
  Do not hand-edit generated files.
- One source of truth per fact: versions in `internal/version/version.go`; live channel state in
  `distribution.md`; commands in `cli.md`/`mcp.md`; agent rules in `AGENTS.md`.
- Anything unverified is marked as unverified; do not promote a planned channel to "available".
