# Security policy

Vigil is a security tool, so reports about Vigil itself are taken seriously. This
page explains what to report and what to expect.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| older | no |

The project is at 0.1.0. Fixes land on the current minor line; there is no
long-term support branch yet.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

https://github.com/LevapVeeskela/lv24-vigil/security/advisories/new

Please include:

- the Vigil version (`vigil version`) and install method;
- the operating system and architecture;
- a minimal reproduction, ideally a small fixture repository or a diff;
- the impact you believe the issue has;
- whether the issue requires a model, a specific provider, MCP, or CI.

Do not open a public issue for an unfixed vulnerability. Do not include real
credentials, customer data or private source code in the report; use synthetic
values and a minimal reproduction.

## What is in scope

- The Vigil CLI, MCP server, scanner, rule engine and report renderers.
- Path handling, ignore rules, baseline matching and fix application.
- Secret masking and evidence rendering.
- Prompt construction and the handling of untrusted repository content.
- Provider request handling, retry behavior and error redaction.
- Packaging and install paths that could execute unexpected code.
- The GitHub Action and example CI configuration in this repository.

## What is out of scope

- Vulnerabilities in code that Vigil scans. Report those to the owner of that
  code.
- Vulnerabilities in a third-party model provider, API or local model server.
- Findings that require the attacker to already control the user's machine,
  shell, model endpoint or MCP client.
- Missing detections ("Vigil did not find this bug") without a concrete rule or
  validation defect. Those are coverage requests, not security reports.
- Social engineering, physical access and denial of service against a provider.

## Response

This is a small project. Reports are handled on a best-effort basis; there is no
paid SLA. You can expect an acknowledgement when the report is reviewed, a
decision on severity, and a coordinated disclosure date for a confirmed issue.

Please give the maintainers a reasonable window to ship a fix before publishing
details. Credit is given in the advisory unless you ask to stay anonymous.

## Security design

The design assumptions are documented in
[docs/security-model.md](docs/security-model.md). In short:

- deterministic scans are local and make no network calls;
- LLM features send context only to the endpoint the user configures;
- scans are read-only by default;
- only `vigil_fix` with `apply=true` writes source files, and it never commits;
  the baseline, report and init commands write only their own artifacts;
- detected secrets are masked in output;
- scanned code is treated as untrusted input in every prompt;
- model-proposed paths, lines and diffs are validated before use.

## Safe harbour

The maintainers will not pursue legal action against researchers who make a good
faith effort to follow this policy, avoid privacy violations and data
destruction, and give reasonable time to fix the issue before disclosure. This
statement does not override any law or third-party rights.
