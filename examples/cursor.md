# Cursor

Register Vigil as a local stdio MCP server in `~/.cursor/mcp.json` (global) or
`.cursor/mcp.json` in the project:

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

If Vigil is installed globally, use the binary directly:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "vigil",
      "args": ["mcp"]
    }
  }
}
```

Restart Cursor after adding the server. Start it from the repository you want to
scan; the server uses its working directory as the project root. To pin a
different root, add `"args": ["mcp", "--root", "/path/to/repo"]`.

Ask Cursor:

```text
Scan this repository with Vigil. Summarise the critical and high findings, then
explain the most serious one.
```

Keep `vigil_fix` behind Cursor's approval prompt. Vigil never commits;
`apply=true` only writes the working tree. Tool list and protocol details:
[../docs/mcp.md](../docs/mcp.md).
