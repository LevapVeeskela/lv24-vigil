# How Vigil compares

Vigil is not trying to be every security tool. It is a fast, local, repeatable
auditor that a developer or a coding agent can run on every change. This page
compares it with the tools it is most often confused with.

No benchmarks are claimed here. The differences are about workflow, not scores.

## Short version

- **Vigil** is a static + LLM auditor. It reads code, runs deterministic rules,
  optionally asks your model for context, and returns findings, diffs and a threat
  model. No Docker, no sandbox, no exploit execution, no SaaS.
- **Strix** (`usestrix/strix`) is an autonomous pentesting agent. It runs a
  sandbox, uses offensive tooling and actively validates vulnerabilities with
  proofs of concept. It needs Docker and is built for deeper, authorized
  assessments.
- **A hosted scanner** is a managed service. It is convenient for a team without
  local setup, but code leaves your environment and the vendor controls the
  engine and the data.

They solve different problems. Use Vigil while you write code; use Strix when you
need to prove an issue is exploitable; use a hosted scanner when you need a
managed program and accept the trade-offs.

## Comparison

| | Vigil | Strix | Hosted scanner | Classic SAST |
|---|---|---|---|---|
| Primary job | find and explain issues in source | autonomously pentest a target | managed scanning | pattern/flow analysis |
| Runs locally | yes | yes | no | often |
| Needs Docker | no | yes | no | no |
| Executes the target | no | yes, in a sandbox | varies | no |
| Produces exploit PoCs | no | yes | varies | no |
| Uses an LLM | optional, your model | yes, your model | vendor-managed | usually no |
| MCP server for coding agents | yes | separate integration | usually no | rarely |
| Code leaves the machine | only to your model, if enabled | to your model and sandbox | yes | usually no |
| Output | md, json, sarif, html | report, SARIF, PoCs | dashboard, report | SARIF, IDE |
| Best cadence | every change | scheduled / pre-release | continuous | every build |

## What Vigil is good at

- Catching hardcoded secrets, dangerous sinks and misconfiguration before a
  commit leaves the laptop.
- Giving a coding agent a security tool it can call without a sandbox or a
  separate service.
- Producing SARIF for code scanning with a predictable exit code.
- Running on a local model when code cannot leave the machine.
- Keeping the deterministic evidence when the model is unavailable.

## What Vigil is not good at

- Proving that a vulnerability is exploitable.
- Testing a running application, an API or an infrastructure.
- Multi-file semantic data flow.
- Replacing a pentest, a threat-model workshop or a dependency advisory feed.
- Giving a team a shared dashboard; the store is local.

## What Strix is good at

- Validating a suspected issue with a real proof of concept in a sandbox.
- Chaining vulnerabilities and testing business logic.
- Exploring a live target with browser, proxy and offensive tooling.
- Producing a deeper assessment than a static scan.

Strix is heavier by design: it needs Docker, a capable model and time. It is the
right tool when the question is "is this actually exploitable?" rather than "is
there a risky pattern here?".

## Where they overlap

Both can use your own model key, both can produce SARIF, and both can be driven
from an agent. The overlap is at the edges: Vigil can propose a fix and a threat
model; Strix can review source before it starts testing. Neither replaces the
other's core job.

## Choosing

| Situation | Start with |
|---|---|
| Pre-commit or pull-request check | Vigil |
| Coding agent needs a security tool | Vigil |
| Code cannot leave the machine | Vigil with Ollama or LM Studio |
| "Is this SQL injection actually exploitable?" | Strix, with authorization |
| Pre-release pentest of a staging app | Strix |
| Team without local setup | Hosted scanner |
| Compliance evidence from a managed vendor | Hosted scanner |

## The LV24 context

LV24 uses both layers:

- **`security-engine`** is a thin fork of Strix, embedded as a Python library and
  driven by the **`security-scans-api`** control plane for staff-authorized
  autonomous pentests. It runs in per-run sandboxes and is deliberately separate
  from the product request path.
- **Vigil** is the developer-facing MCP layer. It is a separate Go project with
  no shared code, no sandbox and no control plane. It catches deterministic
  issues early and gives coding agents a safe, read-only-by-default tool.

The fork analysis, including the upstream sync from `6b7ae2eb` to `215482eb`, is
in [lv24-security-analysis.md](lv24-security-analysis.md).

## A note on claims

Vigil does not claim "zero false positives", "finds all vulnerabilities" or a
benchmark result. Heuristic rules miss things, LLM findings can be wrong, and a
clean report is not proof of safety. The honest workflow is: run Vigil, review the
evidence, fix what is real, and use a deeper tool when the risk justifies it.
