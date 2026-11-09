# Codex

Add Vigil to `~/.codex/config.toml`:

```toml
[mcp_servers.vigil]
command = "npx"
args = ["-y", "lv24-vigil", "mcp"]
```

If Vigil is installed globally:

```toml
[mcp_servers.vigil]
command = "vigil"
args = ["mcp"]
```

Start Codex from the repository you want to scan. The server uses its working
directory as the project root.

Example request:

```text
Use Vigil to review the current diff. Show the findings in severity order and
propose a fix for the highest one, but do not apply it yet.
```
