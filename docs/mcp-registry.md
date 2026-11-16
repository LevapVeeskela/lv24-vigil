# MCP Registry

The [official MCP Registry](https://registry.modelcontextprotocol.io) is the
metadata catalogue run by the Model Context Protocol project
([modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry)).
It stores `server.json` documents, not packages: a client that finds Vigil there
still downloads the npm package and runs the same stdio server.

**Status:** published on 2026-11-16 as version `0.10.1`; the registry reports it
`active` and latest. Verify:

```bash
curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=io.github.LevapVeeskela%2Fvigil' | jq .
```

Registry publishing is **account-gated and manual**. It needs a GitHub account
that owns the `io.github.LevapVeeskela` namespace, so it is not part of the
release workflow and no registry token is stored in CI.

## Registry entry

| Field | Value |
|---|---|
| Server name | `io.github.LevapVeeskela/vigil` |
| Package | npm `lv24-vigil`, version `0.10.1` |
| Transport | `stdio` |
| Runtime | `npx`, run argument `-y`, package argument `mcp` |
| Repository | https://github.com/LevapVeeskela/lv24-vigil |

The document is [`server.json`](../server.json) at the repository root and
follows the `2025-12-11` schema:

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "io.github.LevapVeeskela/vigil",
  "title": "Vigil",
  "description": "Local-first security auditor: 263 deterministic rules, LLM triage, fixes and MCP tools",
  "repository": {
    "url": "https://github.com/LevapVeeskela/lv24-vigil",
    "source": "github"
  },
  "version": "0.10.1",
  "packages": [
    {
      "registryType": "npm",
      "registryBaseUrl": "https://registry.npmjs.org",
      "identifier": "lv24-vigil",
      "version": "0.10.1",
      "runtimeHint": "npx",
      "runtimeArguments": [{ "type": "positional", "value": "-y" }],
      "packageArguments": [{ "type": "positional", "value": "mcp" }],
      "transport": { "type": "stdio" }
    }
  ]
}
```

`name`, `description` (100 characters maximum) and `version` are required.
`packages[].runtimeHint: "npx"` and the `-y`/`mcp` arguments reproduce the
command used everywhere else in the documentation:

```bash
npx -y lv24-vigil mcp
```

Pin a release with `npx -y lv24-vigil@0.10.1 mcp`. Client configuration, tools and
resources are described in [mcp.md](mcp.md).

Query the registry API to check what is published:

```bash
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.LevapVeeskela/vigil"
```

## Ownership proof: `mcpName`

The registry does not take the publisher's word for the package. For npm it
fetches `https://registry.npmjs.org/<identifier>/<version>` and requires a
top-level `mcpName` in that version's `package.json` that is **exactly** equal to
the `name` in `server.json`. An empty or different value fails the publish with
`NPM package 'lv24-vigil' is missing required 'mcpName' field` or
`NPM package ownership validation failed`.

`npm/build.mjs` writes the field into the launcher `lv24-vigil` package (the
platform packages `@lv24/vigil-<os>-<cpu>` stay without it), and
`npm/build.test.mjs` asserts it and its match with `server.json`. The generated
fields are, in part:

```json
{
  "name": "lv24-vigil",
  "version": "0.10.1",
  "mcpName": "io.github.LevapVeeskela/vigil"
}
```

Consequence: **the npm version must be published before the registry version.**
The registry validates the version named in `server.json`, so `0.10.1` on npm must
already carry `mcpName`. Confirm it before publishing:

```bash
npm view lv24-vigil@0.10.1 mcpName
# io.github.LevapVeeskela/vigil
```

The npm side is produced by the release pipeline:
[npm/build.mjs](../npm/build.mjs), [npm/publish.sh](../npm/publish.sh) and
[release.md](release.md).

## Publish (owner only)

1. Confirm `lv24-vigil@0.10.1` is on npm with the right `mcpName` (command above).
   If the version predates the `mcpName` field, cut a new version instead of
   editing a published one.
2. Set `version` and `packages[0].version` in `server.json` to that npm version.
3. Install `mcp-publisher`:

   ```bash
   brew install mcp-publisher
   ```

   ```powershell
   $arch = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq "Arm64") { "arm64" } else { "amd64" }
   Invoke-WebRequest -Uri "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_windows_$arch.tar.gz" -OutFile mcp-publisher.tar.gz
   tar xf mcp-publisher.tar.gz mcp-publisher.exe
   ```

4. Authenticate with the GitHub OAuth device flow:

   ```bash
   mcp-publisher login github
   # open https://github.com/login/device and enter the printed code
   ```

5. Check the document locally, then publish from the repository root:

   ```bash
   mcp-publisher validate server.json
   mcp-publisher publish server.json
   ```

   `publish` takes the registry URL from the saved login token; it has no
   `--registry` flag, so a second path argument is read as the `server.json`
   path.

6. Verify with the API query above. `mcp-publisher status` changes the lifecycle
   status of a published version (`mcp-publisher status --help`); it is how a
   bad release is deprecated or deleted.

The registry itself is in **preview**: the schema and API may change and data
resets are possible. Publishing is metadata only — no binary or source is
uploaded, and a registry listing is not a security review of Vigil.

## Version bumps

- The registry version is unique per publication and immutable. Re-publishing
  `0.10.1` is rejected; every release needs a new `server.json` version.
- Keep `version` and `packages[0].version` aligned with the npm release, as the
  [registry versioning guide](https://modelcontextprotocol.io/registry/versioning)
  recommends. A mismatch fails ownership validation for the npm package.
- Release order: bump the Vigil version → publish npm (with `mcpName`) → update
  `server.json` → `mcp-publisher publish`.
- For a metadata-only change (description, repository URL) when the npm package
  and code are unchanged, publish a prerelease version such as `0.10.1-1` and keep
  `packages[0].version` at `0.10.1`. Prereleases sort before the release, so they
  do not become the entry's latest version.
- Version ranges (`^0.10.1`, `~0.10.1`, `>=0.10.1`, `0.9.x`) are rejected; use an
  exact version.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `NPM package 'lv24-vigil' is missing required 'mcpName' field` | The npm version in `server.json` was published before this field existed. Publish a new npm version that includes it. |
| `NPM package ownership validation failed` | `mcpName` on npm and `name` in `server.json` differ; they must be identical. |
| `You do not have permission to publish this server` | With GitHub auth the name must start with `io.github.<your-login>/`; the login is compared literally, so match the account's capitalization. Organization namespaces need the Owner role and a credential that can read it (`mcp-publisher login github --token <classic PAT with read:org>`, or GitHub Actions OIDC). |
| `Invalid or expired Registry JWT token` | Run `mcp-publisher login github` again; tokens are short-lived. |

More: [mcp.md](mcp.md) · [install.md](install.md) · [release.md](release.md).
