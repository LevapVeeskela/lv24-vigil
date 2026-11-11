# Vigil rule expansion — research brief (2026-11-11)

Goal: expand the 163 deterministic rules with **useful, high-signal, non-controversial**
rules for the Vigil CLI/MCP. Research the internet and open-source rule packs,
then propose only rules that fit the current engine.

## Hard constraints

- **Deterministic only.** No LLM, no network, no taint/dataflow engine, no whole-program analysis.
  The engine works on files with line-oriented checks, regex/AST-ish helpers and path globs.
- **High signal.** A finding must be actionable and specific. Prefer provider-specific
  secrets, concrete dangerous sinks, explicit insecure flags, and IaC fields that are
  unambiguously unsafe.
- **No controversial rules.** Reject generic `password` variable names, missing security
  headers, broad `innerHTML` without a dangerous context, “latest tag” on every image,
  root user in every Dockerfile, dependency age, style/lint issues, and anything that
  requires runtime/deployment assumptions.
- **No duplicates** of the current 163 (see `current-rules.md`).
- **Every candidate needs a vulnerable and a safe fixture** (short snippets) and a
  false-positive guard.
- **Cite sources** (URLs) for the rule/pattern and the CWE/OWASP mapping.
- Prefer rules that cover multiple languages or one high-value ecosystem.

## Output

Write one markdown file per topic in this folder:

- `secrets-deps.md`
- `injection-languages.md`
- `crypto-auth-web.md`
- `config-iac-ci.md`

Each candidate:

```
### VGL-XXX-NNN — title
- Severity: critical|high|medium|low
- Languages/files: ...
- Detection: regex / line pattern / helper logic
- Why high-signal: ...
- False-positive guard: ...
- Vulnerable fixture: ...
- Safe fixture: ...
- CWE/OWASP: ...
- Sources: ...
- Priority: P0|P1|P2
```

Also include a **Rejected** section: rules considered but rejected as noisy,
controversial, or impossible without dataflow, with a one-line reason.

Do not edit code, do not commit, do not run `mem_save`.
