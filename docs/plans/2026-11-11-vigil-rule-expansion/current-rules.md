# Current Vigil rules (163)

Source: `vigil rules --json` on 0.5.4. Do not propose duplicates.

## auth (16)

| ID | Severity | Title |
|---|---|---|
| VGL-AUTH-001 | high | JWT decoded without signature verification |
| VGL-AUTH-002 | critical | JWT signature verification explicitly disabled |
| VGL-AUTH-003 | medium | Session cookie missing Secure, HttpOnly or SameSite |
| VGL-AUTH-004 | high | CORS wildcard combined with credentials |
| VGL-AUTH-005 | medium | CSRF protection disabled |
| VGL-AUTH-006 | critical | Default or well-known administrative password |
| VGL-AUTH-007 | medium | Timing-unsafe comparison of a secret |
| VGL-AUTH-008 | medium | OAuth authorization request without state parameter |
| VGL-AUTH-009 | high | Authorization decision trusts a client-controlled role header |
| VGL-AUTH-010 | high | JWT signing secret is too short |
| VGL-AUTH-011 | high | OAuth redirect URI accepts a wildcard |
| VGL-AUTH-012 | high | OIDC issuer or audience validation disabled |
| VGL-AUTH-013 | high | JWT expiration validation disabled |
| VGL-AUTH-014 | medium | OAuth implicit grant is used |
| VGL-AUTH-015 | medium | JWT verified without an algorithm allow-list |
| VGL-AUTH-016 | high | JWT secret falls back to a hardcoded default |

## ci (17)

| ID | Severity | Title |
|---|---|---|
| VGL-CI-001 | high | GitHub Action is not pinned to a commit SHA |
| VGL-CI-002 | critical | pull_request_target checks out untrusted PR code |
| VGL-CI-003 | high | Untrusted event data interpolated into a shell command |
| VGL-CI-004 | medium | Workflow grants write-all permissions |
| VGL-CI-005 | low | Reusable workflow inherits all secrets |
| VGL-CI-006 | medium | Remote script piped into a shell in CI |
| VGL-CI-007 | high | Secret printed to CI logs |
| VGL-CI-008 | high | Self-hosted runner used |
| VGL-CI-009 | low | Artifact upload may include hidden files |
| VGL-CI-010 | info | GitLab security job is allowed to fail |
| VGL-CI-011 | high | Jenkins shell step interpolates build parameters |
| VGL-CI-012 | low | CircleCI image uses a mutable tag |
| VGL-CI-013 | high | npm lifecycle script downloads and executes remote code |
| VGL-CI-014 | medium | GitHub Actions docker:// image uses a mutable tag |
| VGL-CI-015 | high | GitLab CI enables CI_DEBUG_TRACE |
| VGL-CI-016 | medium | CI pipeline pipes a remote script into a shell |
| VGL-CI-017 | high | GitLab CI includes remote configuration over plain HTTP |

## config (28)

| ID | Severity | Title |
|---|---|---|
| VGL-CFG-001 | medium | Container runs as root |
| VGL-CFG-002 | low | Docker base image is mutable or untagged |
| VGL-CFG-003 | low | apt-get install pulls recommended packages |
| VGL-CFG-004 | medium | ADD fetches a remote URL without verification |
| VGL-CFG-005 | high | Secret stored in a Docker ARG or ENV |
| VGL-CFG-006 | medium | Remote script piped into a shell in Dockerfile |
| VGL-CFG-007 | high | Docker Compose container runs privileged |
| VGL-CFG-008 | medium | Docker Compose uses host networking |
| VGL-CFG-009 | high | Docker socket mounted into a container |
| VGL-CFG-010 | high | SYS_ADMIN capability granted |
| VGL-CFG-011 | low | Docker Compose image uses a mutable tag |
| VGL-CFG-012 | high | Kubernetes workload has elevated privileges or host access |
| VGL-CFG-013 | high | Terraform security group opens a sensitive port to the internet |
| VGL-CFG-014 | high | Object storage bucket allows public ACL |
| VGL-CFG-015 | medium | EBS volume encryption disabled |
| VGL-CFG-016 | medium | nginx directory listing enabled |
| VGL-CFG-017 | medium | Environment file present in the repository |
| VGL-CFG-018 | high | Kubernetes container explicitly allows running as root |
| VGL-CFG-019 | medium | Kubernetes image uses a mutable or missing tag |
| VGL-CFG-020 | high | Kubernetes environment variable contains a literal secret |
| VGL-CFG-021 | low | Kubernetes container has no resource limits |
| VGL-CFG-023 | critical | Terraform database is publicly accessible |
| VGL-CFG-024 | high | Terraform storage encryption disabled |
| VGL-CFG-025 | high | Terraform file contains a hardcoded secret |
| VGL-CFG-026 | medium | Terraform stateful resource can be force-destroyed |
| VGL-CFG-027 | critical | Terraform security group exposes a datastore or admin port |
| VGL-CFG-028 | high | nginx enables deprecated TLS 1.0 or 1.1 |
| VGL-CFG-029 | high | Kubernetes binding grants cluster-admin |

## crypto (12)

| ID | Severity | Title |
|---|---|---|
| VGL-CRY-001 | high | Weak hash algorithm used for passwords or signatures |
| VGL-CRY-002 | high | Broken or legacy cipher (DES, RC4 or 3DES) |
| VGL-CRY-003 | high | AES ECB mode used |
| VGL-CRY-004 | high | Hardcoded initialization vector or nonce |
| VGL-CRY-005 | high | Insecure randomness used for security values |
| VGL-CRY-006 | medium | Weak bcrypt work factor |
| VGL-CRY-007 | high | TLS certificate verification disabled (Go) |
| VGL-CRY-008 | high | TLS certificate verification disabled (Python) |
| VGL-CRY-009 | high | TLS certificate verification disabled (Node.js) |
| VGL-CRY-010 | medium | TLS verification disabled in curl or wget |
| VGL-CRY-011 | critical | JWT 'none' algorithm accepted |
| VGL-CRY-012 | medium | RSA key shorter than 2048 bits |

## dependency (12)

| ID | Severity | Title |
|---|---|---|
| VGL-DEP-001 | low | package.json has no lockfile |
| VGL-DEP-002 | low | Dependency uses a wildcard or latest version |
| VGL-DEP-003 | medium | Dependency installed from a git or HTTP source |
| VGL-DEP-004 | medium | pip installs an artifact URL without a hash |
| VGL-DEP-005 | info | go.mod replace points to a local path |
| VGL-DEP-006 | high | npm TLS verification disabled |
| VGL-DEP-007 | medium | pip trusted-host bypasses TLS verification |
| VGL-DEP-008 | medium | Bundler dependency from git without a ref |
| VGL-DEP-009 | medium | Cargo dependency from git without rev or tag |
| VGL-DEP-010 | high | Package index is configured over plain HTTP |
| VGL-DEP-011 | medium | Lockfile resolves a package over plain HTTP |
| VGL-DEP-012 | medium | Maven repository is configured over plain HTTP |

## injection (37)

| ID | Severity | Title |
|---|---|---|
| VGL-INJ-001 | high | Dynamic code execution in JavaScript or TypeScript |
| VGL-INJ-002 | high | Shell command built from dynamic input in Node.js |
| VGL-INJ-003 | high | Unescaped HTML sink in JavaScript or TypeScript |
| VGL-INJ-004 | high | SQL query built from dynamic input in JavaScript or TypeScript |
| VGL-INJ-005 | medium | Module loaded from a dynamic path |
| VGL-INJ-006 | medium | Prototype pollution through object merge |
| VGL-INJ-007 | medium | javascript: URL or user-controlled link target in React |
| VGL-INJ-008 | high | Dynamic code execution in Python |
| VGL-INJ-009 | high | Shell command built from dynamic input in Python |
| VGL-INJ-010 | high | Unsafe deserialization in Python |
| VGL-INJ-011 | high | Server-side template injection in Python |
| VGL-INJ-012 | high | Unescaped HTML in Python templates |
| VGL-INJ-013 | high | Flask debug mode enabled |
| VGL-INJ-014 | high | SQL query built with Python string formatting |
| VGL-INJ-015 | high | Shell command built from dynamic input in Go |
| VGL-INJ-016 | high | HTML rendered with text/template or template.HTML |
| VGL-INJ-017 | info | Unsafe pointer conversion in Go |
| VGL-INJ-018 | high | Command execution with user input in Java |
| VGL-INJ-019 | critical | Unsafe Java deserialization |
| VGL-INJ-020 | high | SQL query built by concatenation in Java |
| VGL-INJ-021 | high | Dynamic code execution in PHP |
| VGL-INJ-022 | critical | OS command built from PHP superglobals |
| VGL-INJ-023 | high | PHP file inclusion from a variable |
| VGL-INJ-024 | high | Unsafe PHP deserialization |
| VGL-INJ-025 | high | SQL query built by concatenation in PHP |
| VGL-INJ-026 | high | Dynamic code or command execution in Ruby |
| VGL-INJ-027 | high | Ruby dynamic dispatch from user input |
| VGL-INJ-028 | high | Unsafe YAML deserialization in Ruby |
| VGL-INJ-029 | critical | C# BinaryFormatter deserialization |
| VGL-INJ-030 | high | Process.Start with user-controlled input in C# |
| VGL-INJ-031 | high | SQL query built by concatenation in C# |
| VGL-INJ-032 | medium | Command execution with user input in Rust |
| VGL-INJ-033 | info | Unsafe transmute in Rust |
| VGL-INJ-034 | medium | Dynamic SQL executed with EXEC/EXECUTE |
| VGL-INJ-035 | high | Remote script piped into a shell |
| VGL-INJ-036 | high | Shell eval of a variable |
| VGL-INJ-037 | high | HTML response built from dynamic input |

## secrets (24)

| ID | Severity | Title |
|---|---|---|
| VGL-SEC-001 | high | AWS access key ID hardcoded in source |
| VGL-SEC-002 | critical | AWS secret access key hardcoded in source |
| VGL-SEC-003 | critical | GitHub token hardcoded in source |
| VGL-SEC-004 | critical | GitLab personal access token hardcoded in source |
| VGL-SEC-005 | high | Slack token hardcoded in source |
| VGL-SEC-006 | high | Slack incoming webhook URL hardcoded in source |
| VGL-SEC-007 | critical | Stripe live secret key hardcoded in source |
| VGL-SEC-008 | high | Google API key hardcoded in source |
| VGL-SEC-009 | critical | OpenAI API key hardcoded in source |
| VGL-SEC-010 | critical | Anthropic API key hardcoded in source |
| VGL-SEC-011 | critical | Private key block committed to the repository |
| VGL-SEC-012 | high | JWT literal hardcoded in source |
| VGL-SEC-013 | high | Credentials embedded in a URL |
| VGL-SEC-014 | high | Generic hardcoded password or secret assignment |
| VGL-SEC-015 | critical | Database or message-broker connection string with credentials |
| VGL-SEC-016 | high | npm registry auth token hardcoded in .npmrc |
| VGL-SEC-017 | high | Real secret value committed in an environment file |
| VGL-SEC-018 | high | Heroku API key hardcoded in source |
| VGL-SEC-019 | critical | DigitalOcean personal access token hardcoded in source |
| VGL-SEC-020 | high | Twilio credential hardcoded in source |
| VGL-SEC-021 | critical | SendGrid API key hardcoded in source |
| VGL-SEC-022 | critical | Azure Storage account key hardcoded in source |
| VGL-SEC-023 | high | Terraform variable contains a hardcoded secret |
| VGL-SEC-024 | high | Registry credentials stored in a Docker config file |

## web (17)

| ID | Severity | Title |
|---|---|---|
| VGL-WEB-001 | high | Server-side request forgery through a user-controlled URL |
| VGL-WEB-002 | high | Path traversal through user-controlled file path |
| VGL-WEB-003 | medium | Open redirect through user-controlled destination |
| VGL-WEB-004 | medium | Permissive CORS policy |
| VGL-WEB-005 | info | Server framework configured without security headers |
| VGL-WEB-006 | medium | GraphQL introspection or playground enabled |
| VGL-WEB-007 | medium | Debug or actuator endpoint exposed |
| VGL-WEB-008 | medium | Directory listing enabled |
| VGL-WEB-009 | medium | Authentication endpoint uses plain HTTP |
| VGL-WEB-010 | info | Localhost address hardcoded in production configuration |
| VGL-WEB-011 | medium | Host header used to build a URL |
| VGL-WEB-012 | high | Debug mode enabled |
| VGL-WEB-013 | info | GraphQL server has no query depth or complexity limit |
| VGL-WEB-014 | medium | Content-Security-Policy allows unsafe-inline or unsafe-eval |
| VGL-WEB-015 | medium | API documentation UI exposed in production |
| VGL-WEB-016 | medium | API credential passed in the query string |
| VGL-WEB-017 | medium | CORS origin is reflected from the request |

