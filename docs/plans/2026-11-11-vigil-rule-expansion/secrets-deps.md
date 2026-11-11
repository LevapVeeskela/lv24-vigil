# Vigil rule expansion — secrets and dependencies

Research date: 2026-11-11. Scope: deterministic, line/path/AST-ish rules only.
This file proposes **18 new rules** (10 secrets, 8 dependency) and records rejected
candidates. It does **not** duplicate the opt-in OSV scanner: no CVE/version lookups here.

Sources compared against the current 163 rules:

- gitleaks default config — https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- trufflehog detectors — https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors
- detect-secrets plugins — https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins
- secretlint presets — https://github.com/secretlint/secretlint/tree/master/packages/%40secretlint
- Semgrep secrets rules — https://github.com/semgrep/semgrep-rules/tree/develop/generic/secrets
- GitHub secret-scanning patterns — https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns

Conventions used below: `LooksLikePlaceholder` and `MaskSecret` are the existing helpers in
`internal/rules/helpers.go`; every secret finding must mask Evidence and Snippet per
`CONTRACTS.md`. `pbSev` applies the existing docs/tests severity cap.

## Summary

| ID | Title | Severity | Priority |
|---|---|---|---|
| VGL-SEC-025 | Telegram bot token hardcoded in source | critical | P0 |
| VGL-SEC-026 | HashiCorp Vault service or batch token hardcoded | critical | P1 |
| VGL-SEC-027 | 1Password service-account token or secret key hardcoded | critical | P1 |
| VGL-SEC-028 | npm access token hardcoded outside .npmrc | high | P1 |
| VGL-SEC-029 | GitLab deploy, runner, CI or OAuth token hardcoded | high | P1 |
| VGL-SEC-030 | Azure Service Bus or Event Hubs connection string with SharedAccessKey | critical | P1 |
| VGL-SEC-031 | age secret key hardcoded | critical | P2 |
| VGL-SEC-032 | Composer auth.json credentials committed | high | P2 |
| VGL-SEC-033 | Kubernetes Secret manifest contains literal data | high | P2 |
| VGL-SEC-034 | .pgpass or .netrc password file committed | high | P2 |
| VGL-DEP-013 | Composer secure-http or TLS requirement disabled | high | P1 |
| VGL-DEP-014 | Yarn strict SSL disabled | high | P1 |
| VGL-DEP-015 | Go module checksum verification disabled | high | P1 |
| VGL-DEP-016 | Gradle wrapper distribution downloaded over HTTP | high | P1 |
| VGL-DEP-017 | Maven dependency uses system scope or systemPath | high | P2 |
| VGL-DEP-018 | uv index isolation or TLS verification weakened | high | P2 |
| VGL-DEP-019 | Gradle dependency uses a dynamic version | medium | P2 |
| VGL-DEP-020 | NuGet package source uses plain HTTP | high | P2 |

Priority mix: **1 P0 + 9 P1 + 8 P2**.

Coverage note: existing VGL-DEP-001/002/003/006/010/011 already cover npm/pnpm manifests,
TLS and lockfile HTTP; VGL-DEP-008/009 cover Bundler/Cargo git refs; VGL-DEP-004/007 cover
pip URL/trusted-host. The new rules fill Composer, Yarn Classic/Berry TLS, Go checksum
settings, Gradle wrapper/dynamic versions, Maven system scope, uv index/TLS and NuGet sources.

---

## Secrets

### VGL-SEC-025 — Telegram bot token hardcoded in source
- Severity: critical
- Languages/files: all text files; common in JS/TS, Python, Go, PHP, YAML, `.env`
- Detection: line regex `\b\d{8,10}:[A-Za-z0-9_-]{35}\b`; report the match; skip comment lines; reject `LooksLikePlaceholder(match)`.
- Why high-signal: the `<bot_id>:<35-char secret>` shape is unique to BotFather tokens. A leaked token gives full control of the bot (send messages, read updates, change webhook).
- False-positive guard: exact digit/length structure; comments, docs and fixtures are skipped or capped; no generic keyword/entropy rule.
- Vulnerable fixture:
  ```ts
  const bot = new Telegraf('1234567890:<redacted>');
  ```
- Safe fixture:
  ```ts
  const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN!);
  ```
- CWE/OWASP: CWE-798; OWASP A07:2021
- Sources: gitleaks `telegram-bot-api-token`; trufflehog `telegrambottoken`; detect-secrets `telegram_token.py`; https://core.telegram.org/bots/api#authorizing-your-bot
- Priority: P0

### VGL-SEC-026 — HashiCorp Vault service or batch token hardcoded
- Severity: critical
- Languages/files: all text files (shell, YAML, Dockerfile, `.env`, source)
- Detection: `\b(?:hvs\.[A-Za-z0-9_-]{90,120}|hvb\.[A-Za-z0-9_-]{138,300})\b`; skip comments; `LooksLikePlaceholder` on the token body.
- Why high-signal: `hvs.` service tokens and `hvb.` batch tokens authenticate directly to Vault and inherit the token's policies, often including secret reads and writes. The prefixes are fixed by Vault; the length ranges follow the gitleaks detectors.
- False-positive guard: only the two modern prefixed formats; the short legacy `s.` format is intentionally excluded because it is too generic.
- Vulnerable fixture:
  ```sh
  export VAULT_TOKEN=hvs.<redacted>
  ```
- Safe fixture:
  ```sh
  export VAULT_TOKEN="$(vault write -field=token auth/approle/login role_id="$ROLE" secret_id="$SECRET")"
  ```
- CWE/OWASP: CWE-798; OWASP A07:2021
- Sources: gitleaks `vault-service-token`, `vault-batch-token`; https://developer.hashicorp.com/vault/docs/concepts/tokens
- Priority: P1

### VGL-SEC-027 — 1Password service-account token or secret key hardcoded
- Severity: critical
- Languages/files: all text files
- Detection: two alternatives, one rule:
  - `\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}` (service-account token)
  - `\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b` (secret key)
  Skip comments; `LooksLikePlaceholder` on the value.
- Why high-signal: an `ops_` token grants programmatic access to every vault the service account can read; the `A3-…` secret key is the second factor of the account unlock chain. Both formats are provider-specific.
- False-positive guard: fixed prefixes and group lengths; the secret-key pattern requires the exact 6/11/5/5/5 grouping.
- Vulnerable fixture:
  ```sh
  OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ<redacted>
  ```
- Safe fixture:
  ```sh
  op run --env-file=.env -- ./deploy.sh   # token injected by the 1Password CLI
  ```
- CWE/OWASP: CWE-798; OWASP A07:2021
- Sources: gitleaks `1password-service-account-token`, `1password-secret-key`; https://developer.1password.com/docs/service-accounts/
- Priority: P1

### VGL-SEC-028 — npm access token hardcoded outside .npmrc
- Severity: high
- Languages/files: all text files except `.npmrc`
- Detection: `\bnpm_[A-Za-z0-9]{36}\b`; return nil for `.npmrc` (VGL-SEC-016 already owns registry auth lines); skip comments; `LooksLikePlaceholder`.
- Why high-signal: npm tokens can publish packages, change dist-tags and read private packages. The `npm_` prefix plus fixed length is provider-specific.
- False-positive guard: exact prefix/length; the `.npmrc` gate prevents a double report with VGL-SEC-016; docs/tests are capped.
- Vulnerable fixture:
  ```yaml
  env:
    NPM_TOKEN: npm_<redacted>
  ```
- Safe fixture:
  ```yaml
  env:
    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
  ```
- CWE/OWASP: CWE-798; OWASP A07:2021, A08:2021
- Sources: gitleaks `npm-access-token`; GitHub supported patterns (`npm Access Token`); https://docs.npmjs.com/about-access-tokens
- Priority: P1

### VGL-SEC-029 — GitLab deploy, runner, CI or OAuth token hardcoded
- Severity: high
- Languages/files: all text files (CI YAML, shell, source, `.env`)
- Detection: `\b(?:glrtr?|gldt|glptt|gloas|glcbt|glft|glimt|glsoat|glagent|glwt)-[A-Za-z0-9_-]{20,}\b`; do not include `glpat-` (VGL-SEC-004); skip comments; `LooksLikePlaceholder`.
- Why high-signal: these prefixes are fixed by GitLab and cover deploy tokens, runner authentication, pipeline triggers, OAuth application secrets, job tokens, feed tokens, SCIM tokens and Kubernetes agent tokens. Several grant repository or CI write access.
- False-positive guard: prefix allow-list from GitLab's token-prefix table; `glpat-` excluded to avoid overlap; the 20-character minimum filters prose.
- Vulnerable fixture:
  ```yaml
  variables:
    CI_DEPLOY_TOKEN: glrt-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5
  ```
- Safe fixture:
  ```yaml
  variables:
    CI_DEPLOY_TOKEN: $CI_DEPLOY_TOKEN   # masked project variable
  ```
- CWE/OWASP: CWE-798; OWASP A07:2021
- Sources: gitleaks `gitlab-runner-authentication-token`, `gitlab-deploy-token`, `gitlab-ptt`, `gitlab-oauth-app-secret`, `gitlab-cicd-job-token`; https://docs.gitlab.com/security/tokens (Token prefixes)
- Priority: P1

### VGL-SEC-030 — Azure Service Bus or Event Hubs connection string with SharedAccessKey
- Severity: critical
- Languages/files: all text files; common in `appsettings.json`, `.env`, YAML, C#
- Detection: line regex `(?i)\bSharedAccessKey\s*=\s*([A-Za-z0-9+/=]{30,})`; require `Endpoint=sb://` or `SharedAccessKeyName=` on the same line or within ±2 lines (connection strings are sometimes YAML-folded); report the value; `LooksLikePlaceholder`.
- Why high-signal: a Service Bus/Event Hubs connection string with `SharedAccessKey` is a complete bearer credential for the namespace. `SharedAccessKeyName` alone is not a secret and is not reported.
- False-positive guard: require the `SharedAccessKey=` key name and a 30+ character base64 value plus connection-string context; skip `SharedAccessKeyName`; docs/tests capped.
- Vulnerable fixture:
  ```json
  { "ServiceBus": "Endpoint=sb://lv24.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=<redacted>" }
  ```
- Safe fixture:
  ```json
  { "ServiceBus": "Endpoint=sb://lv24.servicebus.windows.net/;SharedAccessKeyName=app;SharedAccessKey=${SERVICEBUS_KEY}" }
  ```
- CWE/OWASP: CWE-798; OWASP A07:2021
- Sources: https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization ; trufflehog Azure detector family (connection-string handling)
- Priority: P1

### VGL-SEC-031 — age secret key hardcoded
- Severity: critical
- Languages/files: all text files
- Detection: `\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b`; case-sensitive; skip comments; `LooksLikePlaceholder`.
- Why high-signal: an age identity decrypts every file encrypted to its public key. The `AGE-SECRET-KEY-1` prefix and bech32 charset are unambiguous.
- False-positive guard: exact prefix and bech32 alphabet/length; public `age1…` recipients are not matched; docs/tests capped.
- Vulnerable fixture:
  ```sh
  AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE
  ```
- Safe fixture:
  ```sh
  age -d -i "$HOME/.config/age/keys.txt" secrets.age > secrets.txt
  ```
- CWE/OWASP: CWE-321, CWE-798; OWASP A02:2021
- Sources: gitleaks `age-secret-key`; https://github.com/FiloSottile/age
- Priority: P2

### VGL-SEC-032 — Composer auth.json credentials committed
- Severity: high
- Languages/files: `auth.json` (case-insensitive basename)
- Detection: require the file to contain `"http-basic"`, `"bearer"` or `"bitbucket-oauth"`; then match `"(?:password|token|consumer-secret)"\s*:\s*"([^"]{8,})"`; skip values containing `${`, `{{` or `LooksLikePlaceholder`. Do not match `"github-oauth"`/`"gitlab-token"` values (VGL-SEC-003/004 already cover those tokens).
- Why high-signal: Composer's `auth.json` stores registry and VCS credentials in plaintext. Committing it leaks package-publish and private-repository access.
- False-positive guard: dedicated filename plus a Composer-specific section key; a generic `auth.json` without those sections is ignored; duplicate provider-token reports are avoided by the section scope.
- Vulnerable fixture:
  ```json
  { "http-basic": { "repo.lv24.by": { "username": "ci", "password": "P9k2Lm4Qr7St1Vx6" } } }
  ```
- Safe fixture:
  ```json
  { "github-oauth": { "github.com": "${GITHUB_TOKEN}" } }
  ```
  (real credentials live in `COMPOSER_HOME/auth.json`, outside the repository)
- CWE/OWASP: CWE-798; OWASP A07:2021
- Sources: https://getcomposer.org/doc/articles/authentication-for-private-packages.md ; gitleaks `nuget-config-password` (same dedicated-credential-file pattern)
- Priority: P2

### VGL-SEC-033 — Kubernetes Secret manifest contains literal data
- Severity: high
- Languages/files: `*.yaml`, `*.yml`
- Detection: helper, not a single regex:
  1. Gate on `pbIsKubernetes(f)`; skip the whole file if it contains `sops:` or `kind: SealedSecret`.
  2. Track YAML documents (`---`). When a document has `kind: Secret`, find `data:` or `stringData:` and parse its child mapping until indentation drops.
  3. For `data:` values matching `[A-Za-z0-9+/]{10,}={0,2}`, base64-decode; require decoded length ≥ 8; skip decoded `LooksLikePlaceholder`; skip public-certificate keys (`*.crt`, `*.pub`, `ca.crt`).
  4. For `stringData:` values, strip quotes; skip empty, `${…}`, `{{…}}` and placeholders.
  5. Emit one finding per document (first non-placeholder value) at the value line.
- Why high-signal: base64 in a Secret is encoding, not encryption. A committed `kind: Secret` with real `data`/`stringData` leaks the credential into Git, the API server and etcd backups.
- False-positive guard: `SealedSecret` and SOPS-encrypted manifests are skipped; public certificate keys are skipped; empty/placeholder values are skipped; tests/docs capped.
- Vulnerable fixture:
  ```yaml
  apiVersion: v1
  kind: Secret
  metadata: { name: db }
  data:
    password: cGctUzNjcjN0LTlmMmE3Yw==
  ```
- Safe fixture:
  ```yaml
  apiVersion: bitnami.com/v1alpha1
  kind: SealedSecret
  metadata: { name: db }
  spec:
    encryptedData:
      password: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEq...
  ```
- CWE/OWASP: CWE-798; OWASP A02:2021
- Sources: gitleaks `kubernetes-secret-yaml`; Semgrep `yaml/kubernetes/security/secrets-in-config-file`; https://kubernetes.io/docs/concepts/configuration/secret/
- Priority: P2

### VGL-SEC-034 — .pgpass or .netrc password file committed
- Severity: high
- Languages/files: `.pgpass`, `.netrc`, `_netrc` (case-insensitive basename)
- Detection: path-gated helper:
  - `.pgpass`: split each non-comment line on unescaped `:`; require exactly 5 fields; take field 5; skip empty, `*`, and `LooksLikePlaceholder`.
  - `.netrc`/`_netrc`: match `^\s*password\s+(\S+)\s*$`; skip `LooksLikePlaceholder`.
  Report at the credential line; never echo the password.
- Why high-signal: these files exist only to store plaintext credentials for automated clients. A committed `.pgpass` exposes a database account; a `.netrc` exposes HTTP/FTP credentials.
- False-positive guard: exact filenames and file formats; `*` wildcard and placeholders are skipped; docs/tests capped.
- Vulnerable fixture:
  ```text
  db.lv24.by:5432:app:app:S3cr3t-9f2a7c
  ```
- Safe fixture:
  ```text
  # .pgpass is not committed; CI mounts it at runtime
  export PGPASSFILE=/run/secrets/pgpass
  ```
- CWE/OWASP: CWE-798, CWE-256; OWASP A07:2021
- Sources: https://www.postgresql.org/docs/current/libpq-pgpass.html ; https://curl.se/docs/manpage.html#-n
- Priority: P2

---

## Dependencies

### VGL-DEP-013 — Composer secure-http or TLS requirement disabled
- Severity: high
- Languages/files: `composer.json`
- Detection: `(?i)"(?:secure-http|disable-tls)"\s*:\s*(true|false)`; report when `secure-http` is `false` or `disable-tls` is `true`; skip comments.
- Why high-signal: Composer defaults `secure-http` to `true`. Disabling it allows `http://` package metadata and dist downloads, so a network attacker can serve a malicious package or a tampered `composer.lock` source.
- False-positive guard: only the two explicit Composer config keys and boolean literals; `${…}` values are ignored; docs/tests capped.
- Vulnerable fixture:
  ```json
  { "config": { "secure-http": false } }
  ```
- Safe fixture:
  ```json
  { "config": { "secure-http": true } }
  ```
- CWE/OWASP: CWE-319, CWE-494; OWASP A02:2021, A08:2021
- Sources: https://getcomposer.org/doc/06-config.md#secure-http ; https://getcomposer.org/doc/06-config.md#disable-tls
- Priority: P1

### VGL-DEP-014 — Yarn strict SSL disabled
- Severity: high
- Languages/files: `.yarnrc.yml` (Yarn Berry), `.yarnrc` (Yarn Classic)
- Detection:
  - `.yarnrc.yml`: `^\s*enableStrictSsl\s*:\s*false\s*(?:#.*)?$`
  - `.yarnrc`: `^\s*strict-ssl\s*(?:=|\s)\s*false\s*$`
  Skip comments; report at the setting line.
- Why high-signal: both settings disable certificate validation for package downloads. A MITM or a compromised registry can then serve a tampered tarball that Yarn installs.
- False-positive guard: exact key names and boolean `false`; `strict-ssl=true` and comments are ignored; only Yarn config files are checked.
- Vulnerable fixture:
  ```yaml
  enableStrictSsl: false
  ```
- Safe fixture:
  ```yaml
  enableStrictSsl: true
  ```
- CWE/OWASP: CWE-295; OWASP A02:2021, A08:2021
- Sources: https://yarnpkg.com/configuration/yarnrc#enableStrictSsl ; https://classic.yarnpkg.com/lang/en/docs/cli/config/
- Priority: P1

### VGL-DEP-015 — Go module checksum verification disabled
- Severity: high
- Languages/files: Dockerfile, CI YAML, shell, `Makefile`, `.env*`, `go.env`, any text file (docs excluded)
- Detection: line regexes
  - `(?i)\bGOINSECURE\s*=\s*["']?([^\s"'#]+)` — report when the value is non-empty and not `${…}`/`{{…}}`.
  - `(?i)\bGOSUMDB\s*=\s*["']?off\b`
  Do **not** flag `GOPRIVATE` or `GONOSUMDB`: they are the supported way to keep private modules out of the public proxy/checksum database.
- Why high-signal: `GOINSECURE` permits HTTP/insecure VCS for matching module paths, and `GOSUMDB=off` disables the checksum database entirely. Either lets a tampered module be accepted without the normal integrity check.
- False-positive guard: assignment syntax only; comments and docs are skipped; placeholders are ignored; legitimate `GOPRIVATE` usage stays quiet.
- Vulnerable fixture:
  ```dockerfile
  ENV GOINSECURE=modules.lv24.by
  RUN GOSUMDB=off go build ./...
  ```
- Safe fixture:
  ```dockerfile
  ENV GOPRIVATE=git.lv24.by
  RUN go build ./...
  ```
- CWE/OWASP: CWE-494, CWE-345; OWASP A08:2021
- Sources: https://go.dev/ref/mod#checksum-database ; https://pkg.go.dev/cmd/go#hdr-Environment_variables
- Priority: P1

### VGL-DEP-016 — Gradle wrapper distribution downloaded over HTTP
- Severity: high
- Languages/files: `gradle-wrapper.properties` (`gradle/wrapper/gradle-wrapper.properties`)
- Detection: `(?i)^\s*distributionUrl\s*=\s*http\\?://`; skip comments; ignore `https://`, `file:` and `${…}` URLs.
- Why high-signal: the wrapper downloads and executes the Gradle distribution at build time. An HTTP URL lets a network attacker replace the distribution with arbitrary code that runs with the build's credentials.
- False-positive guard: only the `distributionUrl` property in a wrapper properties file; HTTPS and local file URLs are safe.
- Vulnerable fixture:
  ```properties
  distributionUrl=http\://services.gradle.org/distributions/gradle-8.10-bin.zip
  ```
- Safe fixture:
  ```properties
  distributionUrl=https\://services.gradle.org/distributions/gradle-8.10-bin.zip
  ```
- CWE/OWASP: CWE-494, CWE-319; OWASP A08:2021
- Sources: https://docs.gradle.org/current/userguide/gradle_wrapper.html ; https://docs.gradle.org/current/userguide/dependency_verification.html
- Priority: P1

### VGL-DEP-017 — Maven dependency uses system scope or systemPath
- Severity: high
- Languages/files: `pom.xml`
- Detection: helper over `<dependency>` blocks (skip XML comments). Report when a block contains `<systemPath>` (preferred location) or `<scope>system</scope>` without a path. One finding per dependency block.
- Why high-signal: system-scoped dependencies are not resolved from a repository, so Maven skips checksum verification, dependency mediation and repository policy. The build depends on a local jar path that can be missing or replaced.
- False-positive guard: only `pom.xml` and only inside a `<dependency>` block; property placeholders are still reported because the hazard is the system scope itself; docs/tests capped.
- Vulnerable fixture:
  ```xml
  <dependency>
    <groupId>com.lv24</groupId>
    <artifactId>legacy</artifactId>
    <version>1.0.0</version>
    <scope>system</scope>
    <systemPath>${project.basedir}/lib/legacy.jar</systemPath>
  </dependency>
  ```
- Safe fixture:
  ```xml
  <dependency>
    <groupId>com.lv24</groupId>
    <artifactId>legacy</artifactId>
    <version>1.0.0</version>
  </dependency>
  ```
- CWE/OWASP: CWE-829; OWASP A08:2021
- Sources: https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#system-dependencies ; https://maven.apache.org/pom.html#Dependencies
- Priority: P2

### VGL-DEP-018 — uv index isolation or TLS verification weakened
- Severity: high
- Languages/files: `pyproject.toml`, `uv.toml`
- Detection: helper over both files:
  - `^\s*index-strategy\s*=\s*"(unsafe-best-match|unsafe-first-match)"` → finding.
  - `^\s*allow-insecure-host\s*=\s*\[` → collect quoted hosts until `]`; report when at least one host is not loopback (`localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`).
  Skip `#` comments; one finding per setting.
- Why high-signal: both `unsafe-*` strategies search every configured index; `unsafe-best-match` then picks the best version across them, which is the classic dependency-confusion setup. `allow-insecure-host` explicitly disables certificate verification for the listed hosts (uv's own warning says it "could expose you to MITM attacks").
- False-positive guard: exact setting names; `allow-insecure-host = []` and loopback-only lists are safe; `index-strategy = "first-index"` (default) is not reported.
- Vulnerable fixture:
  ```toml
  [tool.uv]
  index-strategy = "unsafe-best-match"
  allow-insecure-host = ["pypi.lv24.by"]
  ```
- Safe fixture:
  ```toml
  [tool.uv]
  index-strategy = "first-index"
  allow-insecure-host = []
  ```
- CWE/OWASP: CWE-829, CWE-494; OWASP A08:2021
- Sources: https://docs.astral.sh/uv/concepts/indexes/#index-strategy ; https://docs.astral.sh/uv/reference/settings/#allow-insecure-host
- Priority: P2

### VGL-DEP-019 — Gradle dependency uses a dynamic version
- Severity: medium
- Languages/files: `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`
- Detection: `["'][A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:(?:[0-9][A-Za-z0-9_.-]*\+|\+|latest\.(?:release|integration))["']`; skip comments; report at the coordinate line.
- Why high-signal: a `+` version or `latest.release` resolves to a different artifact as soon as a new release appears. Builds stop being reproducible, and a compromised release is picked up without a code change.
- False-positive guard: only literal dependency coordinates with a dynamic version segment; version ranges such as `[1.0,2.0)` are deliberate and are not matched; `project(...)`, `files(...)` and variable coordinates are not matched.
- Vulnerable fixture:
  ```kotlin
  dependencies {
      implementation("org.springframework:spring-core:5.3.+")
  }
  ```
- Safe fixture:
  ```kotlin
  dependencies {
      implementation("org.springframework:spring-core:5.3.8")
  }
  ```
- CWE/OWASP: CWE-1104, CWE-829; OWASP A08:2021
- Sources: https://docs.gradle.org/current/userguide/dependency_versions.html#dynamic-versions ; https://docs.gradle.org/current/userguide/dependency_verification.html
- Priority: P2

### VGL-DEP-020 — NuGet package source uses plain HTTP
- Severity: high
- Languages/files: `nuget.config`, `NuGet.Config` (case-insensitive)
- Detection: helper tracks the `<packageSources>` block (case-insensitive); line regex `<add\b[^>]*\bvalue\s*=\s*"(http://[^"]+)"[^>]*>`; report unless the host is loopback (`localhost`, `127.0.0.1`, `[::1]`) or the value contains a `%…%` environment placeholder.
- Why high-signal: NuGet restores package metadata and `.nupkg` files from the configured source. An HTTP source lets a network attacker serve a tampered package that restore accepts.
- False-positive guard: block-scoped to `<packageSources>`; HTTPS sources, local feeds and environment placeholders are ignored; docs/tests capped.
- Vulnerable fixture:
  ```xml
  <packageSources>
    <add key="lv24" value="http://nuget.lv24.by/v3/index.json" />
  </packageSources>
  ```
- Safe fixture:
  ```xml
  <packageSources>
    <add key="lv24" value="https://nuget.lv24.by/v3/index.json" />
  </packageSources>
  ```
- CWE/OWASP: CWE-319, CWE-494; OWASP A02:2021, A08:2021
- Sources: https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file#packagesources ; https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping
- Priority: P2

---

## Rejected

These were considered and deliberately left out. Reasons are one line each.

| Candidate | Why rejected |
|---|---|
| Generic high-entropy string | High false-positive rate in minified code, hashes, UUIDs and test data; VGL-SEC-014 already covers quoted assignments. |
| Generic `password`/`secret`/`token` variable name | Explicitly forbidden by the brief; names are not evidence and the existing generic rule is already broad. |
| AWS session token | No stable prefix; would need a keyword gate and still matches temporary STS blobs in fixtures. |
| Azure AD client secret | The `…Q~…` shape is short and keyword-dependent; high false positives in GUIDs and generated IDs. |
| Cloudflare API key / global key | 37–40 alphanumeric characters only; indistinguishable from hashes without a `cloudflare` keyword. |
| Atlassian, Okta, New Relic, Datadog tokens | Short, prefix-less formats; keyword-gated detection is noisy and overlaps generic API-key rules. |
| Discord bot token / client secret | 64-hex or 32-char values with a `discord` keyword; lower precision than the accepted prefix rules; can be added later. |
| Mailgun / Mailchimp keys | `key-…` / hex-plus-`-usN` shapes are distinctive but still keyword-dependent; P2 reserve. |
| Stripe test keys (`sk_test_`) | Not a production credential; the existing Stripe rule intentionally covers live keys only. |
| SSH host/public keys | Public by design; only private key blocks are secrets (already VGL-SEC-011). |
| `.env.example` placeholder values | Already suppressed by `LooksLikePlaceholder` and VGL-SEC-017. |
| `terraform.tfstate` committed | Belongs to the config/IaC topic; overlaps VGL-CFG-025 and state files are often large/binary. |
| `*.p12`, `*.pfx`, `*.jks` keystores | Binary files are skipped by the scanner before rules run; a path-only rule would never fire. |
| "Dependency is old" / outdated version | No deterministic threshold; OSV scanner owns vulnerability/version advice. |
| CVE/OSV lookups | Explicitly out of scope; the opt-in OSV scanner already does this. |
| Missing lockfile for every ecosystem | Libraries legitimately omit lockfiles; VGL-DEP-001 already covers npm. A Python/Cargo variant would need a product decision. |
| `postinstall` script present | Many legitimate uses; VGL-CI-013 already catches remote download-and-execute. |
| `--extra-index-url` in pip | Widely used with private indexes; deciding whether the extra index is trusted requires configuration context. |
| `GOPRIVATE` / `GONOSUMDB` | Supported, legitimate settings for private modules; flagging them would punish correct usage. |
| Maven `LATEST` / `RELEASE` | Maven 3 rejects these metaversions, so the rule would only fire on Maven 2 projects and often on a build error. |
| Maven open-ended version range `[1.0,)` | Deliberate compatibility policy; ranges are supported and not inherently insecure. |
| `composer.json` `minimum-stability: dev` | Often paired with `prefer-stable`; project policy rather than a concrete vulnerability. |
| Gradle `flatDir` repository | Local jars are a real hazard, but the signal is lower than `systemPath` and some builds use it intentionally. |
| npm lockfile missing `integrity` | Old lockfiles and git/file dependencies legitimately lack it; noisy without per-entry context. |
| Yarn PnP / global cache settings | Not security controls. |
| Docker `:latest` / root user | Already covered by VGL-CFG-002/011/019 and VGL-CFG-001. |
| `npm audit` / `yarn audit` not configured | Process advice, not a code finding; OSV scanner is the intended path. |
| Missing `SECURITY.md` | Not a secret or dependency hazard. |

### Deferred strong candidates (not counted above)

Provider tokens with excellent prefixes but lower current priority:
PyPI upload token (`pypi-AgEIcHlwaS5vcmc…`), RubyGems (`rubygems_…`),
Sentry (`sntryu_…`/`sntrys_…`), Hugging Face (`hf_…`), Grafana service account
(`glsa_…`), Databricks (`dapi…`), Postman (`PMAK-…`), Doppler (`dp.pt.…`),
Shopify (`shpat_…`/`shpca_…`/`shppa_…`/`shpss_…`), Square (`sq0atp-…`),
Discord and Microsoft Teams webhook URLs, and Terraform Cloud (`atlasv1.…`).
They can be added as VGL-SEC-035+ once the first batch is implemented and tuned.

## Integration notes

- Every new secret rule should reuse `secPattern`/`secScan` where possible and must
  mask Evidence and Snippet through `MaskSecret`; the raw token must never appear in JSON,
  SARIF or console output.
- Dedupe deliberately: npm rule skips `.npmrc` (VGL-SEC-016), GitLab rule excludes `glpat-`
  (VGL-SEC-004), Composer rule ignores `github-oauth`/`gitlab-token` values
  (VGL-SEC-003/004), and Azure rule ignores `SharedAccessKeyName`.
- Path severity caps: all rules use `pbSev`/`SeverityForLanguage`, so a real token in
  `docs/` is LOW and one in `fixtures/` is at most MEDIUM.
- Lockfile/config rules must not parse the whole file when a line pattern is enough; the
  scanner's 2 MiB cap means very large lockfiles may be skipped, which is acceptable for
  the config files selected here.
- No rule performs network verification (no Telegram `getMe`, no registry calls). That keeps
  scans deterministic and offline.
- OSV is untouched: VGL-DEP-019 flags a dynamic version because it is non-reproducible, not
  because a particular version is vulnerable.

## CWE / OWASP references

- CWE-256 (plaintext storage of a password) — https://cwe.mitre.org/data/definitions/256.html
- CWE-295 (improper certificate validation) — https://cwe.mitre.org/data/definitions/295.html
- CWE-319 (cleartext transmission of sensitive information) — https://cwe.mitre.org/data/definitions/319.html
- CWE-321 (hard-coded cryptographic key) — https://cwe.mitre.org/data/definitions/321.html
- CWE-345 (insufficient verification of data authenticity) — https://cwe.mitre.org/data/definitions/345.html
- CWE-494 (download of code without integrity check) — https://cwe.mitre.org/data/definitions/494.html
- CWE-798 (hard-coded credentials) — https://cwe.mitre.org/data/definitions/798.html
- CWE-829 (inclusion of functionality from untrusted control sphere) — https://cwe.mitre.org/data/definitions/829.html
- CWE-1104 (use of unmaintained third-party components) — https://cwe.mitre.org/data/definitions/1104.html
- OWASP A02:2021 (cryptographic failures) — https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- OWASP A07:2021 (identification and authentication failures) — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- OWASP A08:2021 (software and data integrity failures) — https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
