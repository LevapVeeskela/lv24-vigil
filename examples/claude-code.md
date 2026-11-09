# Claude Code

Register Vigil as a local stdio MCP server:

```bash
claude mcp add vigil -- npx -y lv24-vigil mcp
```

If Vigil is installed globally, use the binary directly:

```bash
claude mcp add vigil -- vigil mcp
```

Run the command from the repository you want Vigil to scan, then restart Claude
Code. The server uses its working directory as the project root.

Ask Claude Code to use it:

```text
Scan this repository with Vigil. Summarise the critical and high findings, then
explain the most serious one.
```

To require confirmation before a fix is written, keep `vigil_fix` behind the
client's approval prompt. Vigil never commits; `apply=true` only writes the
working tree.
