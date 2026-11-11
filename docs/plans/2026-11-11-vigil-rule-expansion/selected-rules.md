# Selected rule expansion (35 rules)

Source proposals: `secrets-deps.md`, `injection-languages.md`,
`crypto-auth-web.md`, `config-iac-ci.md` in this folder. Implement **only**
these IDs; do not implement P2/unselected candidates.

## Secrets / dependencies (8)

- `VGL-SEC-025` Telegram bot token hardcoded — P0
- `VGL-SEC-026` HashiCorp Vault service/batch token — P1
- `VGL-SEC-028` npm access token outside .npmrc — P1
- `VGL-SEC-029` GitLab deploy/runner/CI/OAuth token — P1
- `VGL-SEC-030` Azure Service Bus / Event Hubs SharedAccessKey — P1
- `VGL-DEP-013` Composer secure-http/TLS disabled — P1
- `VGL-DEP-014` Yarn strict SSL disabled — P1
- `VGL-DEP-015` Go module checksum verification disabled — P1

## Injection / language sinks (10)

- `VGL-INJ-038` Go SQL built from dynamic input — P0
- `VGL-INJ-039` Java XML parser without XXE hardening — P0 (file-level: only if no hardening token)
- `VGL-INJ-040` Java JNDI lookup from dynamic input — P0
- `VGL-INJ-041` Ruby unsafe deserialization (Marshal/JSON.load/unsafe YAML/Oj) — P0
- `VGL-INJ-042` .NET legacy formatters / type-resolving JavaScriptSerializer — P0
- `VGL-INJ-043` Newtonsoft.Json TypeNameHandling enabled — P1
- `VGL-INJ-044` Python os.popen/getoutput — P1
- `VGL-INJ-045` Python pickle-based model/array loaders — P1
- `VGL-INJ-046` PHP extract/parse_str imports request data — P1
- `VGL-INJ-048` EF Core raw SQL interpolation/concatenation — P1

## Crypto / auth / web (6)

- `VGL-CRY-013` Java trust-all TrustManager/HostnameVerifier — P0
- `VGL-CRY-014` .NET certificate validation callback always true — P1
- `VGL-CRY-015` PHP/Ruby TLS verification disabled — P1
- `VGL-CRY-017` Legacy SSLv3/TLS 1.0/1.1 pinned — P1
- `VGL-AUTH-017` OAuth redirect_uri taken from request data — P1
- `VGL-WEB-020` Spring Boot actuator exposure `*` — P1

## Config / IaC / CI (11)

- `VGL-CFG-036` Docker CLI runs a container privileged — P0
- `VGL-CFG-040` IAM policy grants full administrative access — P0
- `VGL-CFG-041` Security group allows all traffic from the internet — P0
- `VGL-CFG-042` S3 public access block explicitly disabled — P0
- `VGL-CFG-044` EC2 metadata allows IMDSv1 — P0
- `VGL-CI-018` Privileged workflow checks out untrusted PR code (`workflow_run`) — P0
- `VGL-CFG-030` Docker CLI shares host network/PID/IPC/UTS — P1
- `VGL-CFG-032` Container disables seccomp/AppArmor — P1
- `VGL-CFG-033` Container grants dangerous Linux capabilities (not SYS_ADMIN; CFG-010 owns it) — P1
- `VGL-CFG-045` nginx disables upstream TLS verification — P1
- `VGL-CI-019` Untrusted event data in actions/github-script — P1

## Implementation rules

- Use the existing rule engine; no taint/dataflow, no new dependencies.
- Keep new helpers local to the family file (do not edit `helpers.go`) to avoid conflicts.
- Add a new test file per family; include vulnerable and safe fixtures.
- Do not edit docs, README, CHANGELOG, version, action.yml, or default.go.
- Do not commit; the parent reviews and commits.
- If a rule cannot be implemented without unacceptable false positives, skip it and report why.
