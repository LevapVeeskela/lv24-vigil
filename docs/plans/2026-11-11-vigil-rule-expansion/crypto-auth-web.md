# Crypto, auth and web — new deterministic Vigil rules (2026-11-11)

Scope: 17 new rules that extend the current 163 without duplicating them.
IDs continue after the current maxima: `VGL-CRY-012`, `VGL-AUTH-016`,
`VGL-WEB-017`.

Priority split: **1 × P0, 8 × P1, 8 × P2** (9 P0/P1, 8 P2).

All regexes below are RE2-compatible (the engine uses `regexp.MustCompile`);
no look-around, no back-references. Rules should use the existing
`pbFinding`, `pbSev`, `pbComment`, `pbDocsPath`, `isTestPath` and
`codeContextAt` helpers so snippets, severity caps and comment handling stay
consistent with packs A–C.

## Summary

| ID | Rule | Severity | Priority | Languages/files |
|---|---|---|---|---|
| VGL-CRY-013 | TLS verification disabled (Java trust-all TrustManager) | critical | P0 | Java |
| VGL-CRY-014 | TLS verification disabled (.NET validation callback) | high | P1 | C# |
| VGL-CRY-015 | TLS verification disabled (PHP/Ruby) | high | P1 | PHP, Ruby |
| VGL-CRY-016 | TLS verification disabled (Rust `reqwest`) | high | P2 | Rust |
| VGL-CRY-017 | Legacy SSLv3/TLS 1.0/TLS 1.1 pinned in code | high | P1 | Go, Python, Java, C#, JS/TS, Ruby, PHP |
| VGL-CRY-018 | DSA key shorter than 2048 bits | medium | P2 | Go, Python, Java, shell |
| VGL-CRY-019 | PBKDF2 iteration count below 10,000 | medium | P2 | Python, JS/TS, Java, Go, PHP, Ruby, C# |
| VGL-AUTH-017 | OAuth `redirect_uri` taken from request data | high | P1 | JS/TS, Python, Java, PHP, C#, Ruby, Go |
| VGL-AUTH-018 | Client-supplied session identifier adopted | high | P1 | JS/TS, Python, PHP, Ruby, Go, Java, C# |
| VGL-AUTH-019 | Basic auth sent over plain HTTP | medium | P2 | JS/TS, Python, Java, PHP, Ruby, C#, Go, shell |
| VGL-AUTH-020 | JWT key material taken from token header (`jku`/`x5u`/`jwk`) | high | P1 | JS/TS, Python, Java, Go, PHP, Ruby, C# |
| VGL-WEB-018 | Static file server rooted at the project root | high | P1 | JS/TS, Python, Go, Ruby |
| VGL-WEB-019 | Static file server explicitly allows dotfiles | medium | P2 | JS/TS |
| VGL-WEB-020 | Spring Boot actuator endpoints exposed without auth | high | P1 | `.properties`, `.yml`, `.yaml` |
| VGL-WEB-021 | Directory listing enabled (Apache `Options Indexes`, IIS, Caddy) | medium | P2 | web-server configs |
| VGL-WEB-022 | Backup or database dump committed | medium | P2 | any file path |
| VGL-WEB-023 | `phpinfo()` exposed | medium | P2 | PHP |

OWASP mappings use the 2021 Top 10:
[A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/),
[A02 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/),
[A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/),
[A07 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/).

Already covered — **not** proposed again: JWT `alg:none` (`VGL-CRY-011`),
JWT without an algorithm allow-list (`VGL-AUTH-015`), JWT decode/verify off
(`VGL-AUTH-001` / `VGL-AUTH-002`), `SameSite=None` without `Secure` and
`httpOnly:false`/`secure:false` (`VGL-AUTH-003`), API key/token in the query
string (`VGL-WEB-016`), generic open redirect (`VGL-WEB-003`), GraphQL
introspection (`VGL-WEB-006`), nginx `autoindex` (`VGL-CFG-016`), Apache
`Options +Indexes` (`VGL-WEB-008`) and committed `.env` (`VGL-CFG-017`).
The Rejected section explains each one.

## Rule packs and standards reviewed

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet Series — TLS, Password Storage, Session Management, JWT,
  Unvalidated Redirects, Secrets Management:
  https://cheatsheetseries.owasp.org/
- CWE Top 25 (2025): https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- JWT Best Current Practices, RFC 8725: https://www.rfc-editor.org/rfc/rfc8725.html
- OAuth 2.0, RFC 6749 §3.1.2.3: https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.3
- Deprecating TLS 1.0/1.1, RFC 8996: https://www.rfc-editor.org/rfc/rfc8996.html
- Semgrep registry (PHP `curl-ssl-verifypeer-off`, Python
  `unverified-ssl-context`, Rust `reqwest-accept-invalid`, Spring
  `spring-actuator-fully-enabled-yaml`, Java trust-manager rules):
  https://semgrep.dev/r
- gosec G401–G404: https://github.com/securego/gosec#available-rules
- Bandit B311, B324, B501, B502:
  https://bandit.readthedocs.io/en/latest/plugins/index.html and
  https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html
- FindSecBugs `WEAK_TRUST_MANAGER`, `WEAK_HOSTNAME_VERIFIER`,
  `WEAK_MESSAGE_DIGEST_MD5`, `STATIC_IV`, `UNVALIDATED_REDIRECT`:
  https://find-sec-bugs.github.io/bugs.htm
- nodejsscan: https://github.com/ajinabraham/nodejsscan
- Brakeman `SSLVerificationBypass`, `SessionSetting`, `Redirect`:
  https://brakemanscanner.org/docs/warning_types/
- Psalm security analysis: https://psalm.dev/docs/security_analysis/
- PHPStan (type analysis; no core taint rules):
  https://phpstan.org/

Real-world anchors used in the rationale: jsonwebtoken `alg:none`
(CVE-2015-9235, https://nvd.nist.gov/vuln/detail/CVE-2015-9235) and PyJWT key
confusion (CVE-2022-29217, https://nvd.nist.gov/vuln/detail/CVE-2022-29217).
The trust-all Java pattern and the `VERIFY_NONE` Ruby pattern are the exact
examples documented by FindSecBugs and Brakeman, respectively.

## Shared helpers to add

Two small helpers remove most of the duplicated logic in AUTH-017/018/019/020.
They are file-local and do not need a new package.

```go
// pbRequestReadsKey reports whether line reads key from a request object.
// key is the bare field name, e.g. "redirect_uri" or "session_id".
func pbRequestReadsKey(line, key string) bool

// pbSplitArgs splits a call's argument list at top-level commas, ignoring
// commas inside quotes, brackets, braces and parentheses. It is used by
// VGL-CRY-019 to pick the iteration argument without an AST.
func pbSplitArgs(args string) []string
```

`pbRequestReadsKey` should cover these accessors (case-insensitive):

```text
JS/TS   req|request|ctx|event . query|body|params|headers  .key or ["key"]
Python  request.(args|GET|POST|form|json|values).get("key")
        request.(args|GET|POST|form)["key"]
Java    request.getParameter("key")
PHP     $_GET["key"] | $_POST["key"] | $_REQUEST["key"]
C#      Request.QueryString["key"] | Request.Form["key"] | Request.Query["key"]
Ruby    params[:key] | params["key"]
Go      r.URL.Query().Get("key") | c.Query("key")
```

It must return false for a constant assignment
(`redirect_uri: "https://app.example/callback"`) and for a value read from
configuration (`config.redirectUri`, `process.env.REDIRECT_URI`).

---

## Crypto

### VGL-CRY-013 — TLS certificate verification disabled (Java trust-all TrustManager)

- Severity: critical
- Languages/files: `java`
- Detection: gate on `f.Language == "java"` and `!pbDocsPath(f.Path)`. Run three checks:
  1. **Named trust-all class**: line matches
     `(?i)\b(?:TrustAllCerts|TrustAllManager|TrustAllTrustManager|AllTrustingTrustManager|AcceptAllTrustManager)\b`.
     Report the line with high confidence.
  2. **Empty `X509TrustManager`**: find a line matching
     `(?i)\b(?:implements\s+X509TrustManager|new\s+X509TrustManager\s*\()`.
     Scan forward at most 40 lines for `checkServerTrusted`. Inspect the body:
     if it is `{}`, `{ }`, or the first non-blank/non-comment line after the
     signature is `}`, report the `checkServerTrusted` line. A body that throws
     `CertificateException` or delegates to a `TrustManagerFactory` is safe.
  3. **Trust-all `HostnameVerifier`**: line matches
     `(?i)\bverify\s*\(\s*(?:final\s+)?String\s+\w+\s*,\s*(?:final\s+)?SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;`
     or a `new HostnameVerifier()` block whose `verify` body is only
     `return true;`. Report the `verify` line.
- Why high-signal: an empty `checkServerTrusted` accepts every certificate and a
  `HostnameVerifier` returning `true` accepts every host, so the TLS handshake
  provides no authentication. This is the canonical Java/Android trust-all
  implementation, not a heuristic. The current pack has Go, Python, Node and
  curl TLS rules but no Java rule.
- False-positive guard: skip comments and documentation paths; cap test/fixture
  paths with `pbSev` (critical → medium). Do not flag an `X509TrustManager`
  whose `checkServerTrusted` performs any validation or throws; do not flag a
  bare `getAcceptedIssuers() { return new X509Certificate[0]; }` on its own.
  A class merely named `TrustAllCerts` in test code is still reported but
  capped.
- Vulnerable fixture:
  ```java
  SSLContext ctx = SSLContext.getInstance("TLS");
  ctx.init(null, new TrustManager[]{
      new X509TrustManager() {
          public void checkClientTrusted(X509Certificate[] c, String a) {}
          public void checkServerTrusted(X509Certificate[] c, String a) {}
          public X509Certificate[] getAcceptedIssuers() { return null; }
      }
  }, new SecureRandom());
  ```
- Safe fixture:
  ```java
  TrustManagerFactory tmf = TrustManagerFactory.getInstance(
      TrustManagerFactory.getDefaultAlgorithm());
  tmf.init((KeyStore) null);
  SSLContext ctx = SSLContext.getInstance("TLS");
  ctx.init(null, tmf.getTrustManagers(), null);
  ```
- CWE/OWASP: CWE-295; OWASP A02:2021, A07:2021
- Sources:
  - https://find-sec-bugs.github.io/bugs.htm#WEAK_TRUST_MANAGER
  - https://find-sec-bugs.github.io/bugs.htm#WEAK_HOSTNAME_VERIFIER
  - https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/X509TrustManager.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/295.html
- Priority: P0

### VGL-CRY-014 — TLS certificate verification disabled (.NET validation callback)

- Severity: high
- Languages/files: `csharp`
- Detection: gate on `f.Language == "csharp"` and `!pbDocsPath(f.Path)`.
  Report a line matching any of:
  - `(?i)\b(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|RemoteCertificateValidationCallback)\s*=\s*(?:delegate\s*)?(?:\([^)]*\)|\w+)\s*=>\s*true\b`
  - `(?i)\bDangerousAcceptAnyServerCertificateValidator\b`
  - block form: assignment line ends with `=>` or `=> {`, and the next
    1–5 lines contain `return true;` with no `SslPolicyErrors`, `errors ==`,
    `ValidateCertificate`, `CustomValidator` or other predicate in that window.
    Report the assignment line with medium confidence.
- Why high-signal: these callbacks are the only certificate check .NET performs
  for `HttpClient`/`ServicePointManager`; returning `true` unconditionally
  disables chain and hostname validation. `DangerousAcceptAnyServerCertificateValidator`
  is a framework-provided trust-all callback. No current rule covers C# TLS.
- False-positive guard: require an unconditional `true` (or the named dangerous
  validator). A callback that checks `errors == SslPolicyErrors.None`, calls
  `X509Chain.Build`, or delegates to a custom validator is safe. Skip comments,
  docs, and cap test/fixture paths with `pbSev`.
- Vulnerable fixture:
  ```csharp
  var handler = new HttpClientHandler();
  handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
  var client = new HttpClient(handler);
  ```
- Safe fixture:
  ```csharp
  handler.ServerCertificateCustomValidationCallback =
      (_, _, _, errors) => errors == SslPolicyErrors.None;
  ```
- CWE/OWASP: CWE-295; OWASP A02:2021, A07:2021
- Sources:
  - https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.servercertificatecustomvalidationcallback
  - https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager.servercertificatevalidationcallback
  - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/295.html
- Priority: P1

### VGL-CRY-015 — TLS certificate verification disabled (PHP/Ruby)

- Severity: high
- Languages/files: `php`, `ruby`
- Detection: gate on `f.Language` being `php` or `ruby`, and
  `!pbDocsPath(f.Path)`.
  - PHP patterns (both the array/`stream_context` form and the
    `curl_setopt` function form):
    - `(?i)CURLOPT_SSL_VERIFYPEER\s*=>\s*(?:false|0)\b`
    - `(?i)CURLOPT_SSL_VERIFYHOST\s*=>\s*(?:0|false)\b`
    - `(?i)curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b`
    - `(?i)curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYHOST\s*,\s*(?:0|false)\b`
    - `(?i)["']verify_peer(?:name)?["']\s*=>\s*false\b`
    - `(?i)["']allow_self_signed["']\s*=>\s*true\b` only when the same
      `stream_context_create` window also disables `verify_peer` (otherwise it
      is a weaker policy, not disabled verification).
  - Ruby patterns:
    - `(?i)\bOpenSSL::SSL::VERIFY_NONE\b`
    - `(?i)\bverify_mode\s*[:=]\s*(?:OpenSSL::SSL::)?VERIFY_NONE\b`
    - `(?i)\bssl_verify_mode\s*[:=]\s*(?:0|:none)\b`
    - `(?i)\bverify\s*:\s*false\b` only when the same line or previous two
      lines contain `ssl`, `tls`, `faraday`, `httparty`, `net::http` or
      `rest-client` (otherwise `verify: false` is an unrelated option).
- Why high-signal: `CURLOPT_SSL_VERIFYPEER=false`, `VERIFYHOST=0` and
  `VERIFY_NONE` are explicit "do not validate" switches; they make every
  HTTPS call interceptable. The current pack covers Go, Python, Node and
  curl/wget but not PHP or Ruby.
- False-positive guard: language gate; skip comments/docs; cap tests with
  `pbSev`. Do not flag `CURLOPT_SSL_VERIFYPEER => true`,
  `CURLOPT_SSL_VERIFYHOST => 2`, or `VERIFY_PEER`. Do not flag a generic
  `verify: false` outside an SSL client context.
- Vulnerable fixture:
  ```php
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
  ```
  ```ruby
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  ```
- Safe fixture:
  ```php
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
  ```
  ```ruby
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  ```
- CWE/OWASP: CWE-295; OWASP A02:2021, A07:2021
- Sources:
  - https://www.php.net/manual/en/function.curl-setopt.php
  - https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html
  - https://docs.ruby-lang.org/en/master/OpenSSL/SSL/SSLContext.html
  - https://semgrep.dev/r/php.lang.security.curl-ssl-verifypeer-off.curl-ssl-verifypeer-off
  - https://brakemanscanner.org/docs/warning_types/ssl_verification_bypass/
  - https://cwe.mitre.org/data/definitions/295.html
- Priority: P1

### VGL-CRY-016 — TLS certificate verification disabled (Rust reqwest)

- Severity: high
- Languages/files: `rust`
- Detection: gate on `f.Language == "rust"` and `!pbDocsPath(f.Path)`.
  Report a line matching:
  - `(?i)\bdanger_accept_invalid_certs\s*\(\s*true\s*\)`
  - `(?i)\bdanger_accept_invalid_hostnames\s*\(\s*true\s*\)`
- Why high-signal: both are explicit `reqwest::ClientBuilder` opt-outs from
  certificate and hostname verification. They are the Rust equivalent of
  `InsecureSkipVerify` and are almost always left over from local debugging.
- False-positive guard: require the literal `true` argument; `false` is the
  secure default and must not be reported. Skip comments/docs; cap tests with
  `pbSev`. Do not flag `dangerous()` alone or a custom `rustls`
  `ServerCertVerifier` that actually validates.
- Vulnerable fixture:
  ```rust
  let client = reqwest::Client::builder()
      .danger_accept_invalid_certs(true)
      .danger_accept_invalid_hostnames(true)
      .build()?;
  ```
- Safe fixture:
  ```rust
  let client = reqwest::Client::builder()
      .add_root_certificate(reqwest::Certificate::from_pem(ca)?)
      .build()?;
  ```
- CWE/OWASP: CWE-295; OWASP A02:2021
- Sources:
  - https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html#method.danger_accept_invalid_certs
  - https://semgrep.dev/r/rust.lang.security.reqwest-accept-invalid.reqwest-accept-invalid
  - https://cwe.mitre.org/data/definitions/295.html
- Priority: P2

### VGL-CRY-017 — Legacy SSLv3, TLS 1.0 or TLS 1.1 pinned in application code

- Severity: high
- Languages/files: `go`, `python`, `java`, `csharp`, `javascript`,
  `typescript`, `ruby`, `php`
- Detection: gate on a code language and `!pbDocsPath(f.Path)`. Report a line
  matching the language-specific table below. Do not inspect nginx/Apache
  configs here; `VGL-CFG-028` already owns the nginx form.
  - Go: `(?i)\b(?:MinVersion|MaxVersion)\s*:\s*tls\.Version(?:SSL30|TLS10|TLS11)\b`
    or a bare `tls.Version(?:SSL30|TLS10|TLS11)\b` inside a `tls.Config` literal.
  - Python: `(?i)\bssl\.PROTOCOL_(?:SSLv3|TLSv1|TLSv1_1)\b`
    (`PROTOCOL_TLSv1_2` does not match because `_` is a word character and
    there is no `\b` between `1` and `_`).
  - Java: `(?i)SSLContext\.getInstance\(\s*"(?:SSLv3|TLSv1|TLSv1\.1)"\s*\)`
    or `setEnabledProtocols\s*\([^)]*"(?:SSLv3|TLSv1|TLSv1\.1)"`.
  - C#: `(?i)\bSslProtocols\.(?:Ssl3|Tls|Tls11)\b` or
    `SecurityProtocolType\.(?:Ssl3|Tls|Tls11)\b`.
  - Node: `(?i)\bminVersion\s*:\s*["'](?:SSLv3|TLSv1|TLSv1\.1)["']` or
    `secureProtocol\s*:\s*["'](?:SSLv3|TLSv1|TLSv1_1)_method["']`.
  - Ruby: `(?i)\bssl_version\s*[:=]\s*["']?:?(?:SSLv3|TLSv1_1|TLSv1)\b`
    (the optional `:` covers `ssl_version: :TLSv1`).
  - PHP: `(?i)CURLOPT_SSLVERSION\s*=>\s*CURL_SSLVERSION_(?:SSLv3|TLSv1(?:_0|_1)?)\b`
    or `STREAM_CRYPTO_METHOD_(?:SSLv3|TLSv1_0|TLSv1_1)_CLIENT`.
- Why high-signal: RFC 8996 deprecates TLS 1.0 and TLS 1.1; SSLv3 is broken
  (POODLE). Allowing these versions in code permits a downgrade to a deprecated
  protocol regardless of the server's preference. No current code rule covers
  this (CFG-028 is nginx-only).
- False-positive guard: exact version constants only. Do not flag
  `TLSv1_2`, `TLSv1_3`, `TLSv1_2_method`, `SslProtocols.Tls12`,
  `SslProtocols.Tls13`, or `SslProtocols.None` (system default). Skip
  comments/docs; cap tests with `pbSev`.
- Vulnerable fixture:
  ```go
  cfg := &tls.Config{MinVersion: tls.VersionTLS10}
  ```
  ```python
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
  ```
- Safe fixture:
  ```go
  cfg := &tls.Config{MinVersion: tls.VersionTLS12}
  ```
  ```python
  ctx = ssl.create_default_context()  # TLS 1.2+ by default
  ```
- CWE/OWASP: CWE-326, CWE-327; OWASP A02:2021
- Sources:
  - https://www.rfc-editor.org/rfc/rfc8996.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
  - https://bandit.readthedocs.io/en/latest/plugins/b502_ssl_with_bad_version.html
  - https://cwe.mitre.org/data/definitions/326.html
- Priority: P1

### VGL-CRY-018 — DSA key shorter than 2048 bits

- Severity: medium
- Languages/files: `go`, `python`, `java`, `shell`
- Detection: report a line matching one of:
  - Go: `(?i)\bdsa\.(?:GenerateKey|GenerateParameters)\s*\([^)]*\bL1024N160\b`
    (Go's `crypto/dsa` selects the group with `ParameterSizes`, not a bit count).
  - Python: `(?i)\bDSA\.generate\s*\(\s*(?:bits\s*=\s*)?(512|1024|1536)\b`
    or `dsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(512|1024|1536)`
  - Java: a line matching `(?i)KeyPairGenerator\.getInstance\(\s*"DSA"\s*\)`
    followed within 8 lines by `initialize\s*\(\s*(512|1024|1536)\s*\)`;
    or `AlgorithmParameterGenerator` + `"DSA"` followed by
    `init\s*\(\s*(512|1024|1536)\s*\)`.
  - Shell: `(?i)\bopenssl\s+dsaparam\s+(512|1024|1536)\b`
- Why high-signal: DSA with a 1024-bit group is deprecated and no longer
  approved for new use; FIPS 186-5 removed DSA entirely. The current
  `VGL-CRY-012` covers RSA only, so DSA is an uncovered weak-key path.
- False-positive guard: require a DSA context; do not flag RSA
  (`VGL-CRY-012` owns it) or ECDSA/Ed25519. Only the weak `L1024N160` group or
  literal 512/1024/1536 sizes; `L2048N224`, `L2048N256`, `L3072N256` and
  2048/3072-bit keys are safe. Skip comments/docs; cap tests with `pbSev`.
- Vulnerable fixture:
  ```go
  var params dsa.Parameters
  dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
  ```
- Safe fixture:
  ```go
  key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  ```
- CWE/OWASP: CWE-326; OWASP A02:2021
- Sources:
  - https://github.com/securego/gosec#available-rules (G403 covers weak RSA/DSA)
  - https://github.com/securego/gosec/blob/master/rules/rsa.go
  - https://csrc.nist.gov/pubs/fips/186-5/final
  - https://cwe.mitre.org/data/definitions/326.html
- Priority: P2

### VGL-CRY-019 — PBKDF2 iteration count below 10,000

- Severity: medium
- Languages/files: `python`, `javascript`, `typescript`, `java`, `go`, `php`,
  `ruby`, `csharp`
- Detection: find a PBKDF2 call, extract the iteration argument, and report the
  call line when the literal value is `< 10000`.
  - Python: `hashlib.pbkdf2_hmac(` — iteration index 3, or
    `iterations\s*=\s*(\d+)`.
  - Node: `crypto.pbkdf2(` / `crypto.pbkdf2Sync(` — iteration index 2.
  - Java: `new PBEKeySpec(` — iteration index 2.
  - Go: `pbkdf2.Key(` — iteration index 2.
  - PHP: `hash_pbkdf2(` — iteration index 3.
  - Ruby: `OpenSSL::KDF.pbkdf2_hmac(` / `PBKDF2.new(` — keyword
    `iterations:`.
  - C#: `new Rfc2898DeriveBytes(` — iteration index 2.
  Use `pbSplitArgs` for positional calls. Strip `_` numeric separators before
  parsing (`600_000` → `600000`). If the argument is a variable or a constant,
  skip it (the value is unknown without dataflow).
- Why high-signal: PBKDF2's only cost parameter is the iteration count.
  NIST SP 800-132 sets a floor of 1,000 iterations, and OWASP recommends
  600,000 for PBKDF2-HMAC-SHA256; anything below 10,000 is unambiguously
  brute-forceable. `VGL-CRY-006` covers bcrypt cost and `VGL-CRY-001` covers
  MD5/SHA-1, but no rule checks PBKDF2 parameters.
- False-positive guard: only literal numeric arguments; skip variables. Do not
  flag `>= 10000`. Test vectors that intentionally use 1 iteration are capped
  to low/medium by `pbSev`; docs are skipped. The call itself is
  password-oriented, so no separate "is this a password" check is needed.
- Vulnerable fixture:
  ```python
  dk = hashlib.pbkdf2_hmac("sha256", password, salt, 1000)
  ```
  ```js
  const dk = crypto.pbkdf2Sync(password, salt, 1000, 32, "sha256");
  ```
- Safe fixture:
  ```python
  dk = hashlib.pbkdf2_hmac("sha256", password, salt, 600_000)
  ```
  ```js
  const dk = crypto.pbkdf2Sync(password, salt, 600_000, 32, "sha256");
  ```
- CWE/OWASP: CWE-916; OWASP A02:2021
- Sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  - https://csrc.nist.gov/pubs/sp/800/132/final
  - https://cwe.mitre.org/data/definitions/916.html
- Priority: P2

---

## Auth

### VGL-AUTH-017 — OAuth redirect_uri taken from request data

- Severity: high
- Languages/files: `javascript`, `typescript`, `python`, `java`, `php`,
  `csharp`, `ruby`, `go`
- Detection: two shapes.
  1. **Direct assignment**: a line contains an OAuth redirect key
     (`redirect_uri|redirectUri|callback_url|callbackUrl|return_uri|returnUri`)
     and `pbRequestReadsKey(line, key)` is true.
  2. **Variable indirection**: a line contains the key and a variable RHS
     (`redirect_uri: target`), and one of the previous five lines assigns
     `target` from a request source (`pbRequestReadsKey`).
  Also apply the same check to a line that builds an authorize URL
  (`authorize`, `/oauth`, `/authorize?`) and contains `redirect_uri=`.
- Why high-signal: RFC 6749 §3.1.2.3 requires the authorization server to
  compare `redirect_uri` against a pre-registered exact value. Taking it from
  the request lets an attacker receive the authorization code or token at a
  host they control. `VGL-AUTH-011` covers wildcard registration and
  `VGL-WEB-003` covers generic redirect sinks, but neither covers a
  request-controlled OAuth parameter.
- False-positive guard: skip when the same line or the previous three lines
  contain an allow-list check (`allowlist`, `allowedRedirect`, `allowed`,
  `whitelist`, `isValidRedirect`, `startsWith`, `equals`, `in_array`,
  `contains`, `includes`). A static value
  (`redirect_uri: "https://app.example/callback"`) is safe. Skip
  comments/docs/tests. Confidence medium because validation may live in a
  helper; severity stays high.
- Vulnerable fixture:
  ```js
  const redirectUri = req.query.redirect_uri;
  const url = `${authorizeUrl}?client_id=${id}&redirect_uri=${redirectUri}`;
  ```
  ```java
  String redirectUri = request.getParameter("redirect_uri");
  response.sendRedirect(redirectUri);
  ```
- Safe fixture:
  ```js
  const requested = req.query.redirect_uri;
  const redirectUri = ALLOWED_REDIRECTS.has(requested)
    ? requested
    : DEFAULT_REDIRECT;
  ```
- CWE/OWASP: CWE-601, CWE-522; OWASP A01:2021, A07:2021
- Sources:
  - https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.3
  - https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/601.html
  - https://cwe.mitre.org/data/definitions/522.html
- Priority: P1

### VGL-AUTH-018 — Client-supplied session identifier adopted (session fixation)

- Severity: high
- Languages/files: `javascript`, `typescript`, `python`, `php`, `ruby`, `go`,
  `java`, `csharp`
- Detection: report a line where a session-identifier target is assigned from
  request data, or where the request read is within the previous three lines.
  Targets:
  - JS/TS: `req.sessionID =`, `req.session.id =`,
    `res.cookie("session|sessionid|sid|connect.sid", ...)`
  - Python: `session["id"|"session_id"|"sid"] =`,
    `request.session.session_key =`
  - PHP: `session_id($_GET|$_POST|$_REQUEST|$_COOKIE[...])`
  - Ruby: `session[:id|:session_id|:sid] =`,
    `cookies[:session|:session_id|:sid] =`
  - Go: `session.Values["id"|"session_id"|"sid"] =`
  - Java: `session.setAttribute("sessionid"|"session_id", ...)`
  - C#: `Session["sessionid"|"session_id"] =`
  The RHS must match `pbRequestReadsKey` for the same key.
- Why high-signal: adopting an attacker-chosen session ID lets the attacker
  pre-create a session, send the victim a link, and then use the same ID after
  the victim logs in. This is the classic session-fixation pattern and is not
  covered by `VGL-AUTH-003` (cookie flags) or `VGL-AUTH-005` (CSRF).
- False-positive guard: require both an assignment target and a request source.
  Do not flag reads (`req.sessionID`, `session.id`) used for logging or
  comparison. Skip lines containing `regenerate`, `rotate`, `destroy`,
  `invalidate`, `newSession` or `createSession` (these are the safe fixes).
  Skip comments/docs/tests. Use high confidence for PHP `session_id()` and
  JS `req.sessionID =`/`res.cookie(...)`, medium for the Java/C# attribute
  forms where the name may be an application-level value rather than the
  container session ID.
- Vulnerable fixture:
  ```php
  session_id($_GET['PHPSESSID']);
  session_start();
  ```
  ```js
  req.sessionID = req.query.sid;
  ```
- Safe fixture:
  ```js
  req.session.regenerate((err) => {
    if (err) return next(err);
    req.session.user = user;
  });
  ```
- CWE/OWASP: CWE-384; OWASP A07:2021
- Sources:
  - https://owasp.org/www-community/attacks/Session_fixation
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - https://brakemanscanner.org/docs/warning_types/session_setting/
  - https://cwe.mitre.org/data/definitions/384.html
- Priority: P1

### VGL-AUTH-019 — Basic auth sent over plain HTTP

- Severity: medium
- Languages/files: `javascript`, `typescript`, `python`, `java`, `php`,
  `ruby`, `csharp`, `go`, `shell`
- Detection: report a line (or a 4-line window) that contains both:
  1. a Basic-auth construction:
     - `(?i)\bAuthorization\s*[:=]\s*["']?Basic\b`
     - `(?i)\bBasic\s+["']?\s*\+\s*(?:btoa|base64|Base64)`
     - `(?i)\bcurl\b[^\n]*\s(?:-u|--user)\s`
     - `(?i)\brequests\.(?:get|post|put|delete|request)\s*\([^)]*\bauth\s*=`
     - `(?i)\baxios\.(?:get|post|put|delete|request)\s*\([^)]*\bauth\s*:`
     - `(?i)\bSetBasicAuth\s*\(` or `(?i)\bbasic_auth\s*\(`
  2. an `http://` URL on the same line, or a variable assigned `http://`
     within the previous three lines.
- Why high-signal: Basic auth sends the username and password as reversible
  Base64; over plain HTTP any network observer can read them. `VGL-WEB-009`
  flags authentication *endpoint URLs* over HTTP and `VGL-SEC-013` flags
  `user:pass@host` URLs, but neither catches a Basic `Authorization` header
  sent to an `http://` API.
- False-positive guard: require both the auth construction and the `http://`
  URL. Skip `https://`. Reuse `pbReservedHTTPHost` to ignore localhost,
  `127.0.0.1`, `.test`, `.example` and `.invalid` hosts. Skip comments,
  docs and tests.
- Vulnerable fixture:
  ```bash
  curl -u admin:secret http://api.acme-corp.com/admin
  ```
  ```python
  requests.get("http://internal.acme-corp.com", auth=("user", "pass"))
  ```
- Safe fixture:
  ```bash
  curl -u "$TOKEN" https://api.acme-corp.com/admin
  ```
  ```python
  requests.get("https://internal.acme-corp.com", auth=("user", "pass"))
  ```
- CWE/OWASP: CWE-319, CWE-522; OWASP A02:2021, A07:2021
- Sources:
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
  - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/319.html
  - https://cwe.mitre.org/data/definitions/522.html
- Priority: P2

### VGL-AUTH-020 — JWT key material taken from the token header (jku/x5u/jwk)

- Severity: high
- Languages/files: `javascript`, `typescript`, `python`, `java`, `go`, `php`,
  `ruby`, `csharp`
- Detection: report a line where a JWT header field is used to fetch or select
  the verification key:
  - a line contains `jku`, `x5u` or `jwk` and one of
    `header|headers|decoded|payload|claims` (dot or bracket access), and
  - the same line or the next five lines contain a network/key-fetch sink:
    `fetch(`, `axios.`, `requests.`, `http.Get`, `urlopen`, `httpx.`, `got(`,
    `superagent`, `Net::HTTP`, `curl`, or a `jwt.verify(..., <field>)` call.
  Also report `jwt.verify(token, header.jwk)` / `jwt.verify(token, decoded.jwk)`
  directly.
- Why high-signal: `jku`/`x5u`/`jwk` are attacker-controlled header fields. If
  the verifier fetches the key from them instead of a pinned JWKS/secret, an
  attacker signs a token with their own key and the signature validates.
  `VGL-AUTH-015` covers a missing algorithm allow-list and `VGL-AUTH-012`
  covers issuer/audience validation, but neither covers key-source confusion.
- False-positive guard: only when the field is read from a decoded token header
  and used to fetch/select a key. Do not flag setting `jku`/`x5u` on an
  outgoing token (`jku: issuerUrl` in a sign call), a static JWKS URL
  (`jwksUri` from configuration), or documentation. Skip comments/docs/tests;
  confidence medium.
- Vulnerable fixture:
  ```js
  const { header } = jwt.decode(token, { complete: true });
  const res = await fetch(header.jku);
  const key = await res.text();
  jwt.verify(token, key);
  ```
- Safe fixture:
  ```js
  const key = await jwksClient.getSigningKey(header.kid);
  jwt.verify(token, key.getPublicKey(), {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
  });
  ```
- CWE/OWASP: CWE-347; OWASP A02:2021, A07:2021
- Sources:
  - https://www.rfc-editor.org/rfc/rfc8725.html
  - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/347.html
  - https://nvd.nist.gov/vuln/detail/CVE-2022-29217
- Priority: P1

---

## Web

### VGL-WEB-018 — Static file server rooted at the project root

- Severity: high
- Languages/files: `javascript`, `typescript`, `python`, `go`, `ruby`
- Detection: report a line where a static-file API is given the project root:
  - JS/TS: `express.static(` / `serveStatic(` / `serve-static(` with an
    argument that is exactly `"."`, `"./"`, `__dirname`, `process.cwd()`,
    `path.join(__dirname)`, `path.resolve(__dirname)`, `path.join(".")`,
    `path.resolve(".")`, `path.join(__dirname, ".")`,
    `path.resolve(__dirname, ".")`, or the same with `process.cwd()`.
  - Go: `http.FileServer(http.Dir("."))`, `http.Dir("./")`, or
    `http.Dir(os.Getwd())`.
  - Python: `StaticFiles(directory=".")`, `StaticFiles(".")`,
    `send_from_directory(".", ...)`.
  - Ruby: `Rack::Static` with `root: "."` / `root: "./"`.
- Why high-signal: a static server rooted at the repository or working
  directory serves `.env`, `.git/`, `node_modules`, backups, source maps and
  configuration files. This is a direct path to secret disclosure and is a
  common Express/FastAPI/Go mistake. No current rule checks the static root.
- False-positive guard: require the static-serving API and a root that is the
  project root. Safe when the path contains a subdirectory
  (`public`, `static`, `dist`, `build`, `assets`, `www`, `client`, `web`,
  `media`, `uploads`) or a configured absolute path outside the repo. Skip
  comments/docs/tests; cap tests with `pbSev`.
- Vulnerable fixture:
  ```js
  app.use(express.static(__dirname));
  ```
  ```python
  app.mount("/", StaticFiles(directory="."), name="static")
  ```
- Safe fixture:
  ```js
  app.use(express.static(path.join(__dirname, "public")));
  ```
  ```python
  app.mount("/static", StaticFiles(directory="public"), name="static")
  ```
- CWE/OWASP: CWE-538, CWE-548; OWASP A01:2021, A05:2021
- Sources:
  - https://expressjs.com/en/4x/api.html#express.static
  - https://expressjs.com/en/resources/middleware/serve-static.html
  - https://pkg.go.dev/net/http#FileServer
  - https://fastapi.tiangolo.com/tutorial/static-files/
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
  - https://cwe.mitre.org/data/definitions/538.html
- Priority: P1

### VGL-WEB-019 — Static file server explicitly allows dotfiles

- Severity: medium
- Languages/files: `javascript`, `typescript`
- Detection: report a line matching:
  - `(?i)\bdotfiles\s*:\s*["']allow["']`
  - `(?i)\bhidden\s*:\s*true\b` only when the same line or previous three
    lines contain `serveIndex(`, `serve-index`, `serveStatic(` or
    `express.static(`.
- Why high-signal: `dotfiles: "allow"` overrides the safe default and serves
  `.env`, `.git/`, `.htaccess` and editor backups from a directory that may
  otherwise be public. `hidden: true` does the same for `serve-index`
  directory listings. No current rule covers static-server dotfile policy.
- False-positive guard: only in a static-server option context. `dotfiles:
  "deny"` and `"ignore"` are safe. Skip comments/docs/tests; cap tests with
  `pbSev`.
- Vulnerable fixture:
  ```js
  app.use(express.static("public", { dotfiles: "allow" }));
  ```
- Safe fixture:
  ```js
  app.use(express.static("public", { dotfiles: "ignore" }));
  ```
- CWE/OWASP: CWE-538, CWE-548; OWASP A05:2021
- Sources:
  - https://expressjs.com/en/resources/middleware/serve-static.html
  - https://expressjs.com/en/resources/middleware/serve-index.html
  - https://cwe.mitre.org/data/definitions/538.html
- Priority: P2

### VGL-WEB-020 — Spring Boot actuator endpoints exposed without auth

- Severity: high
- Languages/files: `application*.properties`, `application*.yml`,
  `application*.yaml`, `bootstrap*.yml`, `src/main/resources/`
- Detection: gate on a Spring config path and report:
  - Properties: `management.endpoints.web.exposure.include` whose value is
    `*` or contains any of `env`, `heapdump`, `jolokia`, `threaddump`,
    `configprops`, `beans`, `logfile`, `shutdown`, `mappings`, `sessions`,
    `httptrace`, `auditevents`, `quartz`. Strip surrounding quotes and
    whitespace from the value first.
  - YAML: a line `include:` under a file that contains both `management:` and
    `exposure:`, with the same dangerous value (`*` or the endpoint list);
    strip quotes before comparing.
  - `management.security.enabled=false` (Spring Boot 1.x).
  - `management.endpoint.shutdown.enabled=true` (shutdown endpoint on).
- Why high-signal: `include=*` exposes `/actuator/env`, `/actuator/heapdump`
  (heap dumps contain credentials and tokens), `/actuator/configprops` and
  `/actuator/shutdown` unless Spring Security separately protects them.
  `VGL-WEB-007` only matches literal `/actuator/env` route strings; it does
  not see the `exposure.include` switch that creates the exposure.
- False-positive guard: only Spring application config paths; skip
  `src/test/`, `application-test`, `application-local`, `application-dev`
  (cap to medium). `include=health,info` is safe; `exposure.exclude=*` is
  safe. `include=*` is still reported when Spring Security is present, but
  the message must say "unless Spring Security restricts these endpoints".
- Vulnerable fixture:
  ```yaml
  management:
    endpoints:
      web:
        exposure:
          include: "*"
  ```
- Safe fixture:
  ```yaml
  management:
    endpoints:
      web:
        exposure:
          include: health,info
  ```
- CWE/OWASP: CWE-489, CWE-306, CWE-200; OWASP A01:2021, A05:2021
- Sources:
  - https://docs.spring.io/spring-boot/reference/actuator/endpoints.html
  - https://semgrep.dev/r/java.spring.security.audit.spring-actuator-fully-enabled-yaml.spring-actuator-fully-enabled-yaml
  - https://cwe.mitre.org/data/definitions/489.html
  - https://cwe.mitre.org/data/definitions/306.html
- Priority: P1

### VGL-WEB-021 — Directory listing enabled (Apache `Options Indexes`, IIS, Caddy)

- Severity: medium
- Languages/files: `*.conf`, `.htaccess`, `httpd.conf`, `apache2.conf`,
  `web.config`, `Caddyfile`
- Detection: gate on a web-server config path.
  - Apache: parse a line starting with `Options ` (case-insensitive). If any
    token is `+Indexes`, skip it — `VGL-WEB-008` already owns that form.
    Otherwise track the last occurrence of bare `Indexes` (on) versus
    `-Indexes` (off) and report when the final state is on. This catches
    `Options Indexes FollowSymLinks`, ignores `Options -Indexes`, and does not
    double-report `Options +Indexes`.
  - IIS: `(?i)<directoryBrowse\s+[^>]*enabled\s*=\s*["']true["']`.
  - Caddy: `(?i)^\s*file_server\b[^\n]*\bbrowse\b`, or a `browse` line inside
    a `file_server { ... }` block (scan up to five lines for `file_server`).
- Why high-signal: directory indexes disclose file names, backups, uploads and
  sometimes credentials. `VGL-WEB-008` only matches `Options +Indexes` (with
  the plus), `serveIndex`, `directoryListing:true`; `VGL-CFG-016` only matches
  nginx `autoindex on`. `Options Indexes`, IIS and Caddy are currently missed.
- False-positive guard: web-server config paths only; skip comments/docs/tests.
  `Options -Indexes` is safe; `file_server` without `browse` is safe;
  `<directoryBrowse enabled="false">` is safe.
- Vulnerable fixture:
  ```apache
  <Directory /var/www>
      Options Indexes FollowSymLinks
  </Directory>
  ```
  ```xml
  <directoryBrowse enabled="true" />
  ```
- Safe fixture:
  ```apache
  Options -Indexes
  ```
  ```xml
  <directoryBrowse enabled="false" />
  ```
- CWE/OWASP: CWE-548; OWASP A05:2021
- Sources:
  - https://httpd.apache.org/docs/2.4/mod/core.html#options
  - https://learn.microsoft.com/en-us/iis/configuration/system.webserver/directorybrowse/
  - https://caddyserver.com/docs/caddyfile/directives/file_server
  - https://cwe.mitre.org/data/definitions/548.html
- Priority: P2

### VGL-WEB-022 — Backup or database dump committed

- Severity: medium
- Languages/files: any file path
- Detection: path-only rule. Normalize the path, then report when:
  - the base name ends with `.bak`, `.old`, `.orig`, `.save`, `.swp` or `~`
    (editor/merge backup), or
  - the base name has a data/archive extension (`.sql`, `.dump`, `.tar`,
    `.gz`, `.tgz`, `.zip`, `.7z`, `.rar`) **and** contains a name hint
    `backup`, `bkp`, `dump`, `prod`, `production` or `live` as a
    dot/underscore/dash-separated token.
- Why high-signal: committed dumps routinely contain PII, password hashes and
  session data; `settings.php.bak` bypasses `.gitignore` patterns that only
  list `settings.php`. `VGL-CFG-017` covers `.env` itself, but not
  `db/prod_backup.sql` or `config/settings.php.bak`.
- False-positive guard: skip `docs/`, `test/`, `tests/`, `fixtures/`,
  `examples/`, `migrations/`, `seeds/` and `schema/`. Exclude `.env*` names
  (owned by `VGL-CFG-017`). Exclude source-code extensions, so `src/backup.ts`
  and `backup.go` are not reported. Only flag `.sql`/archives when the name
  hint is present, so `db/migrations/001_init.sql` is safe.
- Vulnerable fixture:
  ```text
  db/prod_backup.sql
  config/settings.php.bak
  backup-2026-01-01.tar.gz
  ```
- Safe fixture:
  ```text
  db/migrations/001_init.sql
  docs/backup-policy.md
  src/backup.ts
  ```
- CWE/OWASP: CWE-538; OWASP A02:2021, A05:2021
- Sources:
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
  - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/538.html
- Priority: P2

### VGL-WEB-023 — phpinfo() exposed

- Severity: medium
- Languages/files: `php`
- Detection: gate on `f.Language == "php"` and report a line matching
  `(?i)\bphpinfo\s*\(`. This includes `phpinfo()` and `phpinfo(INFO_ALL)`.
- Why high-signal: `phpinfo()` prints the PHP version, loaded extensions,
  `DOCUMENT_ROOT`, environment variables and sometimes database credentials.
  It is a debug page, never a production endpoint. No current rule covers it
  (`VGL-WEB-007` matches URL strings, not the function call).
- False-positive guard: skip comments and documentation paths. Cap
  `tests/`, `fixtures/` and `examples/` with `pbSev`. Do not flag a string
  literal containing `phpinfo()` in a non-PHP file (language gate).
- Vulnerable fixture:
  ```php
  <?php phpinfo(); ?>
  ```
- Safe fixture:
  ```php
  <?php
  header('Content-Type: application/json');
  echo json_encode(['status' => 'ok']);
  ```
- CWE/OWASP: CWE-200, CWE-489; OWASP A05:2021
- Sources:
  - https://www.php.net/manual/en/function.phpinfo.php
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration
  - https://cwe.mitre.org/data/definitions/200.html
  - https://cwe.mitre.org/data/definitions/489.html
- Priority: P2

---

## Rejected

Rules considered but **not** proposed, because they duplicate the current 163,
need dataflow, or are too noisy/controversial for a deterministic engine.

| Candidate | Reason |
|---|---|
| JWT `alg: none` accepted | Already `VGL-CRY-011`. |
| JWT verified without an algorithm allow-list | Already `VGL-AUTH-015`. |
| JWT decoded without signature verification | Already `VGL-AUTH-001`. |
| JWT `verify=False` / `verify_signature:false` | Already `VGL-AUTH-002`. |
| JWT expiration validation disabled | Already `VGL-AUTH-013`. |
| OIDC issuer/audience validation disabled | Already `VGL-AUTH-012`. |
| JWT signing secret too short / hardcoded fallback | Already `VGL-AUTH-010` and `VGL-AUTH-016`. |
| Session cookie missing `Secure`/`HttpOnly`/`SameSite` | Already `VGL-AUTH-003`; it also covers `SameSite=None` without `Secure`, `httpOnly:false` and `secure:false`. |
| CORS wildcard / reflected origin | Already `VGL-AUTH-004`, `VGL-WEB-004` and `VGL-WEB-017`. |
| Generic open redirect through a user-controlled destination | Already `VGL-WEB-003`. The Java/PHP/C# accessors (`getParameter`, `$_GET`, `Request.QueryString`) are a real gap, but the right fix is to extend `pbUserSourceRe` in `VGL-WEB-003`, not to add a near-duplicate rule. |
| API key or token in the query string | Already `VGL-WEB-016`. |
| Password in a URL query string | Covered by `VGL-WEB-016` for `?password=`/`?token=` URL expressions. A route-path rule (`/:password`, `<password>`) would also flag documentation and form routes; not worth the noise. |
| GraphQL introspection or playground enabled | Already `VGL-WEB-006`. |
| Debug/actuator route strings (`/actuator/env`, `/debug`) | Already `VGL-WEB-007`. `VGL-WEB-020` is the config-switch gap, not a duplicate. |
| nginx `autoindex on` | Already `VGL-CFG-016`. |
| Apache `Options +Indexes`, `serveIndex`, `directoryListing:true` | Already `VGL-WEB-008`. `VGL-WEB-021` covers the forms it misses. |
| `.env` committed | Already `VGL-CFG-017`; `VGL-WEB-022` excludes `.env*`. |
| Missing security headers | Already `VGL-WEB-005`, and explicitly excluded by the brief. |
| Generic `Math.random`/`random` outside a security context | Already `VGL-CRY-005`; broadening it would flag UI jitter, sampling and test data. |
| Weak RSA key size | Already `VGL-CRY-012`; `VGL-CRY-018` adds DSA only. |
| Weak bcrypt work factor | Already `VGL-CRY-006`. |
| Hardcoded symmetric encryption key | Overlaps `VGL-SEC-014` (generic secret assignment) and `VGL-CRY-004` (static IV); key-vs-password classification needs entropy and context that the current line engine does not have. |
| Static password salt | Related to `VGL-CRY-004`, but salt names are heavily overloaded (test vectors, KDF demos); lower signal than the PBKDF2 iteration rule. |
| Weak scrypt/Argon2 parameters | Thresholds depend on library units and hardware; more controversial than the PBKDF2 `< 10,000` floor. |
| JWT stored in `localStorage` | Many SPAs do this deliberately; the root cause is XSS, and the rule would be controversial without a storage-access dataflow. |
| Cookie `Domain=.example.com` | Multi-subdomain apps legitimately need a parent-domain cookie; not high-signal without knowing which subdomains are untrusted. |
| Missing `HttpOnly` on non-session cookies | Often intentional (theme/locale cookies); `VGL-AUTH-003` already covers session cookies. |
| Exposed `.git/` path rule | The scanner normally excludes `.git`; a path rule would almost never fire. Runtime exposure is covered by `VGL-WEB-018` (root static server) and `VGL-WEB-022` (backups). |
| Spring Boot `management.endpoint.health.show-details=always` | Leaks component names/versions but not credentials; lower signal than `include=*`. |
| Django `ALLOWED_HOSTS = ["*"]` | Host-header validation is disabled, but this is common in local/dev settings and overlaps `VGL-WEB-011`; needs a production-path heuristic to be useful. |
| Laravel `APP_DEBUG=true` / Rails `consider_all_requests_local` | Debug-mode variants; `VGL-WEB-012` already owns the generic debug switch and a framework-by-framework expansion is low value. |
| PHP `display_errors=On` | Debug/config leak, but overlaps `VGL-WEB-012` and is often set in a php.ini outside the repository. |
| Directory listing on lighttpd | Low usage, and the upstream documentation URL is no longer stable; not worth a dedicated detector. |
| `X-Powered-By` / version disclosure | Low severity and frequently stripped at the edge; not actionable enough. |
| Source maps served in production | Often intentional for error reporting; controversial without a deployment-context check. |
| Missing `Content-Type`/`X-Content-Type-Options` on downloads | Header-policy rule, excluded by the brief and noisy without response context. |
| Generic `Authorization: Basic` anywhere | Only the HTTP variant is high-signal; Basic over HTTPS is normal. `VGL-AUTH-019` requires the `http://` URL. |
| `TrustAllCerts` as a bare class name in tests | Still reported by `VGL-CRY-013` but capped by `pbSev`; not a separate rule. |

## Suggested implementation order

1. **P0/P1 first** — `VGL-CRY-013`, `VGL-CRY-014`, `VGL-CRY-015`,
   `VGL-CRY-017`, `VGL-AUTH-017`, `VGL-AUTH-018`, `VGL-AUTH-020`,
   `VGL-WEB-018`, `VGL-WEB-020`.
2. **P2 next** — `VGL-CRY-016`, `VGL-CRY-018`, `VGL-CRY-019`,
   `VGL-AUTH-019`, `VGL-WEB-019`, `VGL-WEB-021`, `VGL-WEB-022`,
   `VGL-WEB-023`.
3. Register `VGL-CRY-013`–`019` in `CryptoRules()`, `VGL-AUTH-017`–`020`
   in `AuthRules()` and `VGL-WEB-018`–`023` in `WebRules()`. Add one positive
   and one negative fixture per rule in a new `pack_d_test.go` (or the
   matching pack test file), plus a precision test for the two riskiest
   detectors: `VGL-AUTH-017` (validation-keyword guard) and `VGL-WEB-020`
   (YAML block detection).
4. Keep every rule file-local and line-oriented. Do not add a YAML parser or
   a dataflow pass for this batch; the structural scans above are bounded
   windows (≤ 40 lines) and must stop at the first non-comment line.
