# MCP directory listings

Ready-to-paste metadata for MCP directories and awesome lists. Every listing is
an account-gated web action: the text below is prepared, but the submission,
review and any claim flow must be done by the maintainer in a browser.

Status: the **official MCP Registry is live** (v0.9.3); the directories below
have not accepted Vigil yet. Vigil ships a stdio MCP server (`vigil mcp`),
14 tools, 4 resources and 5 prompts.

## Canonical metadata

Use these values everywhere so the listings stay consistent.

| Field | Value |
|---|---|
| Name | Vigil |
| npm package | `lv24-vigil` |
| Tagline | Local-first security auditor for AI coding agents |
| Short description | Local-first security auditor: 263 deterministic rules, fixes and an MCP server for coding agents. |
| Long description | See the 500-character block below |
| Categories | Security, Developer Tools, MCP |
| Transport | stdio (no HTTP port, no daemon) |
| Install | `npx -y lv24-vigil mcp` |
| Repository | https://github.com/LevapVeeskela/lv24-vigil |
| Documentation | https://github.com/LevapVeeskela/lv24-vigil/blob/main/docs/mcp.md |
| License | Apache-2.0 |
| Runtime | Go binary; Node.js 18+ when started through `npx` |

Description lengths: the short block is 97 characters, the long block is 482
(characters, including spaces). Do not append the install command to either
field; use the separate install field where the directory has one.

### 100-character description

```text
Local-first security auditor: 263 deterministic rules, fixes and an MCP server for coding agents.
```

### 500-character description

```text
Vigil is a local-first security auditor for source repositories. It runs 263 deterministic rules across secrets, injection, crypto, auth, web, config/IaC, CI, dependencies, MCP configuration and anti-RE hardening, then adds optional LLM triage using your model. The MCP server exposes 14 tools, 4 resources and 5 prompts over stdio, so an agent can scan, explain, fix, verify and threat-model in one session. Deterministic scans are offline and telemetry-free; no model is required.
```

### Client configuration

Generic `mcpServers` shape (Claude Desktop, Cursor and most clients):

```json
{
  "mcpServers": {
    "vigil": {
      "command": "npx",
      "args": ["-y", "lv24-vigil", "mcp"]
    }
  }
}
```

OpenCode uses its own `mcp` shape:

```json
{
  "mcp": {
    "vigil": {
      "type": "local",
      "command": ["npx", "-y", "lv24-vigil", "mcp"],
      "enabled": true
    }
  }
}
```

A global install (`npm i -g lv24-vigil`) can use `["vigil", "mcp"]` instead.

## Facts to reuse

- **263 deterministic rules** in ten families: secrets, injection, crypto,
  auth, web, config/IaC, CI, dependencies, MCP configuration and anti-RE
  hardening.
- **14 MCP tools**: `vigil_scan`, `vigil_review`, `vigil_explain`, `vigil_fix`,
  `vigil_threat_model`, `vigil_status`, `vigil_rules`, `vigil_baseline`,
  `vigil_report`, `vigil_verify`, `vigil_history`, `vigil_hardening`,
  `vigil_mcp_audit`, `vigil_dependencies`.
- **4 resources** (`vigil://status`, `vigil://rules`, `vigil://scan/last`,
  `vigil://scan/<id>`) and **5 prompts**.
- **Local-first:** deterministic scans make no network calls; there is no
  telemetry. A model is optional, and LLM calls go only to the endpoint the
  user configures. `vigil_dependencies` makes an explicit OSV request;
  `vigil precheck` is the only explicit upload and needs a staff JWT.
- **Read-only by default:** only `vigil_fix` with `apply=true` writes source
  files, and it never commits, stages or pushes.
- **Packaging:** npm, PyPI launcher, GitHub release binaries, deb/rpm/apk,
  Homebrew, Scoop, GHCR container and (pending) AUR.

## Submission targets

| Directory | Action | URL | Gate |
|---|---|---|---|
| Glama | Claim or refresh the listing for the GitHub repository | https://glama.ai/mcp/servers | GitHub account; Glama indexes repositories and exposes a claim flow |
| Smithery | Submit through the website | https://smithery.ai | Account required; this repository deliberately ships no Smithery config, so the listing is a web/account action |
| mcp.so | Use the site's submit form | https://mcp.so/submit | Account/review; if the automated request is rejected, open the form in a browser |
| PulseMCP | Use the submit form | https://www.pulsemcp.com/submit | Account/review |
| awesome-mcp-servers (punkpeye) | Pull request adding one line | https://github.com/punkpeye/awesome-mcp-servers | GitHub account; follow the list's format and alphabetical order |
| awesome-mcp-servers (wong2) | Pull request adding one line | https://github.com/wong2/awesome-mcp-servers | GitHub account; follow the list's format |

The URL layout of a directory can change. If a submit path returns an error,
start at the site root and follow its "Submit" or "Add server" link rather than
guessing a new path.

### Per-site notes

- **Glama** generates a server page from the public repository. After the first
  index, claim the page so the description, categories and install command can
  be corrected. Do not create a second entry for the npm package.
- **Smithery** is a web submission. Vigil is a local stdio server, not a hosted
  endpoint; do not describe it as a remote URL. No `smithery.yaml` or container
  config is provided here because the current form does not require one — if it
  asks for deployment details, stop and keep the listing source-only rather than
  inventing a config.
- **mcp.so** accepts community submissions; provide the repository, npm install
  command and the short description. The site may show a login wall before the
  form.
- **PulseMCP** reviews submissions manually. Point it at the repository and the
  MCP docs page, and mention that the server is stdio-only and needs no API key.
- **Awesome lists** take a one-line entry in their existing style, usually
  `- [Vigil](https://github.com/LevapVeeskela/lv24-vigil) - Local-first security
  auditor with 263 deterministic rules and an MCP server.` Keep the entry
  alphabetical and do not add badges or extra links if the list forbids them.

## Copy rules

- Say **local stdio server**, not hosted service or remote endpoint.
- Say **263 deterministic rules**, not "all vulnerabilities" or "zero-day
  detection". Dependency advisories are known public OSV records only.
- Say **optional LLM triage with your provider**, not "AI-powered scanning" as
  the primary description.
- Say **proposes fixes and never commits**, not "auto-fixes your repository".
- Do not claim language coverage beyond what `vigil rules` reports.
- Keep the license as **Apache-2.0** and link the repository, not a mirror.

## After submitting

1. Open each listing and check the name, install command, repository and license.
2. Confirm the 100/500-character fields were not truncated by the form.
3. Record the live URLs in the release notes or the project brain.
4. Re-check the listings after each minor release; directories cache README
   content and old version numbers.
