# Detection rules

Vigil ships 100+ deterministic rules. They are pure: they read a file, never
write, never execute scanned code and never make a network call. The CLI is the
authoritative catalog:

```bash
vigil rules
```

The tables below describe the families and a representative subset. They are not
a complete list and will lag behind the code.

## Families

| Family | Prefix | Rules | Focus |
|---|---|---:|---|
| Secrets | `VGL-SEC` | 24 | Credentials committed to the repository |
| Injection | `VGL-INJ` | 37 | Sinks that turn untrusted input into code, SQL, shell or markup |
| Crypto | `VGL-CRY` | 12 | Broken algorithms, weak parameters and disabled verification |
| Auth | `VGL-AUTH` | 9 | JWT, cookies, CORS, CSRF and default credentials |
| Web | `VGL-WEB` | 12 | SSRF, traversal, redirects, headers, debug surfaces |
| Config / IaC | `VGL-CFG` | 17 | Docker, Compose, Kubernetes, Terraform, nginx, env files |
| CI | `VGL-CI` | 11 | Workflow permissions, untrusted checkouts and shell injection |
| Dependencies | `VGL-DEP` | 7 | Lockfiles, version ranges, install sources and TLS |

The table counts the 129 deterministic rules in 0.1.4; `vigil rules` is always
current. `VGL-AI-001` is synthesized by the LLM deep review and is not part of
the deterministic catalog, so it does not appear in `vigil rules`.

## Representative rules

| ID | Severity | Title |
|---|---|---|
| `VGL-SEC-002` | Critical | AWS secret access key hardcoded in source |
| `VGL-SEC-003` | Critical | GitHub token hardcoded in source |
| `VGL-SEC-011` | Critical | Private key block committed to the repository |
| `VGL-SEC-014` | High | Generic hardcoded password or secret assignment |
| `VGL-INJ-001` | High | Dynamic code execution in JavaScript or TypeScript |
| `VGL-INJ-004` | High | SQL query built from dynamic input in JavaScript or TypeScript |
| `VGL-INJ-010` | High | Unsafe deserialization in Python |
| `VGL-INJ-019` | Critical | Unsafe Java deserialization |
| `VGL-INJ-022` | Critical | OS command built from PHP superglobals |
| `VGL-CRY-003` | High | AES ECB mode used |
| `VGL-CRY-005` | High | Insecure randomness used for security values |
| `VGL-CRY-011` | Critical | JWT `none` algorithm accepted |
| `VGL-AUTH-002` | Critical | JWT signature verification explicitly disabled |
| `VGL-AUTH-004` | High | CORS wildcard combined with credentials |
| `VGL-WEB-001` | High | Server-side request forgery through a user-controlled URL |
| `VGL-WEB-002` | High | Path traversal through user-controlled file path |
| `VGL-CFG-001` | Medium | Container runs as root |
| `VGL-CFG-009` | High | Docker socket mounted into a container |
| `VGL-CFG-013` | High | Terraform security group opens a sensitive port to the internet |
| `VGL-CI-002` | Critical | `pull_request_target` checks out untrusted PR code |
| `VGL-CI-003` | High | Untrusted event data interpolated into a shell command |
| `VGL-DEP-006` | High | npm TLS verification disabled |

Each finding carries a description, evidence, a location, CWE/OWASP references
where applicable, a remediation and a confidence.

## Severity

| Severity | Meaning |
|---|---|
| `critical` | Direct compromise path with high impact, or a live credential |
| `high` | Serious issue that is usually exploitable with modest effort |
| `medium` | Real weakness with preconditions, limited impact or partial mitigation |
| `low` | Hygiene or defense-in-depth issue |
| `info` | Informational observation, not a vulnerability by itself |

Severity is the rule author's assessment for the general case. Context can make a
`medium` urgent or a `high` unreachable. Triage is where the model adds context;
the deterministic severity stays visible.

## Confidence

| Confidence | Meaning |
|---|---|
| `high` | The pattern is specific and the evidence is direct |
| `medium` | The pattern is real but context can change the conclusion |
| `low` | A heuristic lead that needs review |

Confidence is separate from severity. A low-confidence critical finding is a lead,
not a confirmed compromise.

## Secrets

Secret rules look for provider-specific shapes and generic assignments. They:

- check entropy and obvious placeholder values to avoid documentation noise;
- skip values that look like examples, test fixtures or template variables;
- mask the detected value in evidence, snippets and reports;
- never print the raw credential.

Masking is not a license to commit secrets. Rotate anything that was committed;
removing it from the working tree does not remove it from git history.

## Model findings

The LLM deep review can add findings with rule ID `VGL-AI-001`. They are marked
with source `llm` and category `logic`. The model must point at a real path and
line range inside the reviewed file; invalid items are dropped, duplicates are
suppressed and the result is capped.

A model-only critical finding is downgraded to `high` when the model's confidence
is below `0.5`. LLM findings are advisory. They are not proof of exploitability.

## Disabling rules

In `.vigil.yaml`:

```yaml
scan:
  disable_rules:
    - VGL-DEP-001
    - VGL-CFG-003
```

Disable a rule when it does not fit the project, not to make a report green. Add a
reason in the pull request or the baseline entry.

## Baseline and suppression

The baseline records accepted findings so a scan can focus on what is new. The
default file is `.vigil-baseline.json`:

```json
{
  "version": 1,
  "fingerprints": ["fp_0123456789abcdef"],
  "findings": [
    { "id": "VGL-XXXXXXXXXX", "reason": "accepted risk in legacy importer" }
  ]
}
```

Matching is intentionally loose:

- an exact finding ID is a match;
- a fingerprint is a match and survives small line moves;
- the reason is carried into the suppressed finding.

Suppressed findings are not deleted. They are recorded separately in the scan
result, so a reviewer can still see what was accepted.

Manage the file with:

```bash
vigil baseline list
vigil baseline add VGL-XXXXXXXXXX --reason "accepted risk in legacy importer"
vigil baseline remove VGL-XXXXXXXXXX
vigil baseline clear --yes
```

`add` records the finding fingerprint as well, so the entry survives small line
moves. `clear` requires `--yes`. You can also edit the file by hand. See
[cli.md](cli.md).

## What the rules do not do

- They do not execute the scanned code.
- They do not run a full data-flow or points-to analysis.
- They do not prove exploitability.
- They do not replace dependency advisory data, dynamic testing or a pentest.
- They can miss multi-line semantic bugs; the optional LLM deep review covers
  some of that gap, not all of it.

Rule authoring guide: [../CONTRIBUTING.md](../CONTRIBUTING.md).
