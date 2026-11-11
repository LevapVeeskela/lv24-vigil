# Injection and language sinks — proposed Vigil rules

Research date: 2026-11-11. Target: `vigil` 0.5.4, 163 existing rules.
Scope: deterministic, file-local patterns only. No taint/dataflow, no network, no
whole-program analysis. Every rule below is implementable with the existing
`injSpec` / `injFindSink` / `injFindings` helpers plus small line-window helpers.

**Next free ID: `VGL-INJ-038`.** This document proposes 22 rules: 5 × P0,
7 × P1, 10 × P2. All are non-duplicates of `current-rules.md`; where a rule
extends an existing sink family, the relationship is stated explicitly.

## Summary

| ID | Title | Languages | Severity | Priority | CWE |
|---|---|---|---|---|---|
| VGL-INJ-038 | SQL query built from dynamic input in Go | Go | high | P0 | CWE-89 |
| VGL-INJ-039 | Java XML parser created without XXE hardening | Java | high | P0 | CWE-611 |
| VGL-INJ-040 | JNDI lookup receives dynamic or request-controlled name | Java | critical | P0 | CWE-502 |
| VGL-INJ-041 | Ruby unsafe deserialization (Marshal, JSON.load, unsafe YAML, Oj object mode) | Ruby | critical | P0 | CWE-502 |
| VGL-INJ-042 | Legacy .NET formatters and type-resolving JavaScriptSerializer | C# | critical | P0 | CWE-502 |
| VGL-INJ-043 | Newtonsoft.Json TypeNameHandling enabled | C# | high | P1 | CWE-502 |
| VGL-INJ-044 | Python shell execution through os.popen or getoutput | Python | high | P1 | CWE-78 |
| VGL-INJ-045 | Python pickle-based model/array loaders | Python | high | P1 | CWE-502 |
| VGL-INJ-046 | PHP extract/parse_str imports request data into scope | PHP | high | P1 | CWE-621 |
| VGL-INJ-047 | Ruby command injection through system/exec/Open3/%x | Ruby | high | P1 | CWE-78 |
| VGL-INJ-048 | EF Core raw SQL built with interpolation or concatenation | C# | high | P1 | CWE-89 |
| VGL-INJ-049 | SnakeYAML constructed without SafeConstructor | Java | high | P1 | CWE-502 |
| VGL-INJ-050 | Django raw SQL APIs receive formatted SQL | Python | high | P2 | CWE-89 |
| VGL-INJ-051 | PHP XML parsing enables entity substitution or external DTDs | PHP | high | P2 | CWE-611 |
| VGL-INJ-052 | .NET XML reader enables DTD parsing or an external resolver | C# | high | P2 | CWE-611 |
| VGL-INJ-053 | Ruby raw/html_safe renders request data | Ruby | high | P2 | CWE-79 |
| VGL-INJ-054 | Java script or expression engine evaluates dynamic input | Java | high | P2 | CWE-95 |
| VGL-INJ-055 | SQL Server xp_cmdshell used or enabled | SQL | high | P2 | CWE-78 |
| VGL-INJ-056 | PHP dynamic callable selected by a superglobal | PHP | high | P2 | CWE-470 |
| VGL-INJ-057 | lxml XMLParser enables DTD loading without disabling entities | Python | high | P2 | CWE-611 |
| VGL-INJ-058 | Ruby ERB template compiled from request data | Ruby | high | P2 | CWE-1336 |
| VGL-INJ-059 | JavaScript string passed to setTimeout/setInterval | JS/TS | medium | P2 | CWE-95 |

## Detection conventions

- `R(...)` means a Go `regexp.MustCompile` pattern. All patterns are RE2-safe:
  no look-around, no back-references. `(?i)` is allowed.
- `W(n)` means `f.Window(line, n)` — the existing bounded window helper.
- `D(line)` means the existing `injDynamic(line)` helper: `${…}`, `#{…}`, or a
  quote on either side of `+`.
- `C(line)` means `IsCommentLine(line, f.Language)`.
- `Q(s)` means the argument is a quoted string literal with no interpolation.
- A "one-hop assignment check" means: find the identifier argument, scan at most
  10 lines upwards for its nearest assignment, and inspect that assignment line.
  This is the same deterministic technique already used by `injFindJSSQL`; it is
  not a taint engine.
- Findings are reported at the sink line unless the rule says otherwise. For
  file-level configuration rules (XXE, TypeNameHandling) the config line is the
  finding.
- Reuse `SeverityForLanguage` so tests/fixtures/docs are capped exactly like the
  existing rules.
- Confidence: explicit dangerous call = high; absence-of-hardening in a window =
  medium; name-based fallback = low. State the confidence in the rule text.

---

## P0 — implement first

### VGL-INJ-038 — SQL query built from dynamic input in Go

- Severity: high
- Languages/files: `go` (`.go`)
- Detection:
  - Sink: `R(\b(?:db|tx|conn|stmt|database)\.(?:Query|QueryRow|QueryContext|Exec|ExecContext|Prepare|PrepareContext|Raw)\s*\()`.
  - High confidence when the sink line itself contains:
    - string concatenation with a quote on either side (`injConcatRe`), or
    - `fmt.Sprintf(` and an SQL keyword (`(?i)\b(?:select|insert|update|delete|where|values|from)\b`).
  - Medium confidence when the first sink argument is a bare identifier and a
    one-hop assignment check finds `fmt.Sprintf(` or concatenation plus an SQL
    keyword in the assignment line.
  - Skip if the query argument is a pure quoted literal and contains no `%s`/`%d`
    formatting verb.
  - Helper sketch:
    ```
    if !sinkRe.MatchString(line) { continue }
    if Q(firstArg(line)) && !strings.Contains(firstArg(line), "%") { continue }
    if injConcatRe.MatchString(line) && sqlKeywordRe.MatchString(line) { report }
    if strings.Contains(line, "fmt.Sprintf") && sqlKeywordRe.MatchString(line) { report }
    if id := bareIdentifier(firstArg(line)); id != "" {
        if assignmentWithin(f, i, 10, id, func(a string) bool {
            return (strings.Contains(a, "fmt.Sprintf") || injConcatRe.MatchString(a)) &&
                sqlKeywordRe.MatchString(a)
        }) { report }
    }
    ```
- Why high-signal: `database/sql` never parameterizes a string that was already
  assembled; `fmt.Sprintf` and `+` are the canonical Go SQLi pattern. gosec ships
  G201/G202 specifically for this and the existing pack has no Go SQL rule at all
  (VGL-INJ-015 is shell only, VGL-INJ-016 is templates, VGL-INJ-017 is unsafe).
- False-positive guard: skip literal-only queries; skip `db.Query("… WHERE id = ?", id)`;
  skip `fmt.Sprintf` whose format string has no verb (for example
  `fmt.Sprintf("SELECT 1")`); the one-hop check avoids flagging a variable that is
  assigned a constant SQL string. If a table/column name comes from a fixed
  package-level allowlist, suppress with a justification.
- Vulnerable fixture:
  ```go
  name := r.URL.Query().Get("name")
  q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
  rows, err := db.Query(q)
  ```
- Safe fixture:
  ```go
  rows, err := db.Query("SELECT * FROM users WHERE name = $1", name)
  // or a fixed allowlist for identifiers:
  q := "SELECT * FROM users WHERE name = $1"
  ```
- CWE/OWASP: CWE-89; A03:2021 – Injection.
- Sources:
  - https://securego.io/docs/rules/g201-g202.html
  - https://github.com/securego/gosec/blob/master/RULES.md
  - https://cwe.mitre.org/data/definitions/89.html
- Priority: P0

### VGL-INJ-039 — Java XML parser created without XXE hardening

- Severity: high
- Languages/files: `java` (`.java`)
- Detection:
  - Factory tokens:
    `R(\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReaderFactory)\.(?:newInstance|newDefaultInstance|createXMLReader)\s*\(|new\s+(?:SAXBuilder|SAXReader|SAXParser)\s*\()`.
  - Hardening tokens (any of):
    - `disallow-doctype-decl`
    - `SUPPORT_DTD` set to `false`
    - `IS_SUPPORTING_EXTERNAL_ENTITIES` set to `false`
    - `ACCESS_EXTERNAL_DTD` / `ACCESS_EXTERNAL_SCHEMA` set to `""`
    - `http://xml.org/sax/features/external-general-entities` set to `false`
    - `http://xml.org/sax/features/external-parameter-entities` set to `false`
    - `FEATURE_SECURE_PROCESSING` set to `true`
    - `setEntityResolver` installed
  - Algorithm:
    1. Collect factory lines and hardening lines.
    2. If the file has no hardening line at all, report every factory line
       (confidence high: the file never hardens any parser).
    3. If the file has hardening lines, report a factory only when no hardening
       line exists within `W(25)` of it (confidence medium; message:
       "hardening exists in this file but not near this factory — verify it
       applies to this instance").
    4. Skip comments and string literals.
  - Do **not** count `setExpandEntityReferences(false)` alone as hardening;
    OWASP explicitly says it is not a substitute for blocking external resources.
- Why high-signal: Java's JAXP parsers are unsafe by default: a stock
  `DocumentBuilderFactory` resolves external general entities and expands DTDs.
  The rule maps to the exact Semgrep/FindSecBugs XXE family and the existing pack
  has no XXE rule in any language. A file that creates a parser and never calls
  `setFeature("…disallow-doctype-decl", true)` (or the equivalent) is the
  textbook CWE-611 pattern.
- False-positive guard: skip if `SafeConstructor`-style hardening is present
  within 25 lines; skip `SAXBuilder`/`SAXReader` when the file sets
  `disallow-doctype-decl`; skip comments; if the parser only parses a hardcoded
  local resource with no request path, suppress with a justification (the rule is
  still correctly reporting the unsafe configuration).
- Vulnerable fixture:
  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  DocumentBuilder builder = dbf.newDocumentBuilder();
  Document doc = builder.parse(request.getInputStream());
  ```
- Safe fixture:
  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
  DocumentBuilder builder = dbf.newDocumentBuilder();
  ```
- CWE/OWASP: CWE-611; A05:2021 – Security Misconfiguration (XXE was A04:2017).
- Sources:
  - https://github.com/semgrep/semgrep-rules/blob/develop/java/lang/security/audit/xxe/documentbuilderfactory-disallow-doctype-decl-missing.yaml
  - https://github.com/semgrep/semgrep-rules/blob/develop/java/lang/security/audit/xxe/saxparserfactory-disallow-doctype-decl-missing.yaml
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
  - https://find-sec-bugs.github.io/bugs.htm (XXE_DOCUMENT, XXE_SAXPARSER, XXE_XMLREADER, XXE_XMLSTREAMREADER)
- Priority: P0

### VGL-INJ-040 — JNDI lookup receives dynamic or request-controlled name

- Severity: critical
- Languages/files: `java` (`.java`)
- Detection:
  - Gate: file contains `InitialContext`, `InitialDirContext`, or `javax.naming`.
  - Sink: `R(\.lookup\s*\()`.
  - Extract the first argument. Skip `Q(arg)`.
  - Report high confidence when the argument contains any of:
    `+`, `String.format(`, `StringBuilder`, `System.getenv(`, `String.valueOf(`.
  - Report high confidence when the argument itself contains a request source:
    `getParameter|getHeader|getQueryString|@RequestParam|request\.|params\.|getCookies`.
  - Report high confidence when the argument is a bare identifier and a one-hop
    assignment check (10 lines) finds one of those request sources.
  - Skip comments.
- Why high-signal: `InitialContext.lookup` with an attacker-controlled name can
  point the server at an RMI/LDAP endpoint and load a remote factory, which is
  the JNDI-injection class behind Log4Shell. The existing Java rules cover
  `Runtime.exec`, `ObjectInputStream`, `XMLDecoder` and SQL, but not JNDI. A
  dynamic or request-derived `lookup` argument is a direct RCE path.
- False-positive guard: skip literal names such as
  `lookup("java:comp/env/jdbc/app")`; skip files with no JNDI context; the
  one-hop check avoids flagging a local constant. A lookup of a value from a
  fixed allowlist is safe — the finding asks for that allowlist to be made
  explicit.
- Vulnerable fixture:
  ```java
  @GetMapping("/lookup")
  public Object lookup(@RequestParam String name) throws Exception {
      return new InitialContext().lookup(name);
  }
  ```
- Safe fixture:
  ```java
  private static final Set<String> ALLOWED = Set.of("java:comp/env/jdbc/app");
  public Object lookup(String name) throws Exception {
      if (!ALLOWED.contains(name)) throw new IllegalArgumentException();
      return new InitialContext().lookup(name);
  }
  ```
- CWE/OWASP: CWE-502, CWE-74; A08:2021 – Software and Data Integrity Failures.
- Sources:
  - https://www.veracode.com/blog/research/exploiting-jndi-injections-java
  - https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf
  - https://cwe.mitre.org/data/definitions/502.html
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Priority: P0

### VGL-INJ-041 — Ruby unsafe deserialization (Marshal, JSON.load, unsafe YAML, Oj object mode)

- Severity: critical
- Languages/files: `ruby` (`.rb`, `.rake`, `Rakefile`, `Gemfile` is not Ruby code)
- Detection:
  - Sinks:
    - `R(\bMarshal\.(?:load|restore)\s*\()` — always report.
    - `R(\b(?:YAML|Psych)\.unsafe_load\s*\()` — always report.
    - `R(\bJSON\.load\s*\()` — report unless `create_additions: false` appears in
      the same call or `W(3)`.
    - `R(\bOj\.(?:load|object_load)\s*\()` — report `object_load` always; report
      `load` when the call contains `mode: :object` or `object_mode: true`, or
      when the file has no safe `Oj.default_options` (`mode: :compat` / `:strict`).
  - Skip `Q(arg)` (a hardcoded serialized string is not untrusted input).
  - Skip comments.
- Why high-signal: Ruby's own security guide says never pass untrusted data to
  `Marshal.load`; `JSON.load` enables `create_additions` by default; `Oj` object
  mode instantiates arbitrary classes. These are explicit sinks that the existing
  pack does not cover — VGL-INJ-028 only covers `YAML.load`, and VGL-INJ-026 only
  covers `eval`/backticks.
- False-positive guard: skip `JSON.parse` (safe), `YAML.safe_load` (safe),
  `Marshal.dump` (serialization, not deserialization), literal arguments, and
  `Oj.load` when the file sets `Oj.default_options` to `:compat`/`:strict`.
  A `Marshal.load` of a literal test fixture is skipped by the literal guard.
- Vulnerable fixture:
  ```ruby
  user = Marshal.load(Base64.decode64(params[:user]))
  prefs = JSON.load(params[:prefs])
  obj = YAML.unsafe_load(request.body.read)
  ```
- Safe fixture:
  ```ruby
  user = JSON.parse(Base64.decode64(params[:user]))
  prefs = JSON.parse(params[:prefs])
  obj = YAML.safe_load(request.body.read, permitted_classes: [Date])
  ```
- CWE/OWASP: CWE-502; A08:2021 – Software and Data Integrity Failures.
- Sources:
  - https://docs.ruby-lang.org/en/master/security/security_rdoc.html
  - https://brakemanscanner.org/docs/warning_types/unsafe_deserialization/
  - https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/checks/check_deserialize.rb
  - https://blog.trailofbits.com/2025/08/20/marshal-madness-a-brief-history-of-ruby-deserialization-exploits/
  - https://github.com/semgrep/semgrep-rules/blob/develop/ruby/lang/security/bad-deserialization.yaml
- Priority: P0

### VGL-INJ-042 — Legacy .NET formatters and type-resolving JavaScriptSerializer

- Severity: critical
- Languages/files: `csharp` (`.cs`)
- Detection:
  - Types: `LosFormatter`, `ObjectStateFormatter`, `SoapFormatter`,
    `NetDataContractSerializer`.
  - Report a line that contains `new <Type>(` (instantiation).
  - Report a line with `.Deserialize(` or `.ReadObject(` when one of those type
    names appears in `W(5)` (field/property injection or a formatter variable).
  - Also report `new JavaScriptSerializer(` when `new SimpleTypeResolver(` is in
    the same line or `W(3)` — this is the type-resolving JavaScriptSerializer
    form flagged by Security Code Scan SCS0028.
  - Skip comments and `using`/`typeof`/`nameof` references that do not
    instantiate or deserialize.
- Why high-signal: Microsoft's own analyzers mark the four legacy formatters as
  insecure deserializers that cannot be made safe; they perform unrestricted
  polymorphic deserialization and have framework gadget chains.
  `JavaScriptSerializer` with `SimpleTypeResolver` is the same
  arbitrary-type-selection problem. VGL-INJ-029 covers only `BinaryFormatter`,
  so these are a real gap in the C# pack.
- False-positive guard: skip type names in comments, `using` directives,
  `typeof(...)`, and `nameof(...)`; skip `BinaryFormatter` (already VGL-INJ-029);
  skip `new JavaScriptSerializer()` without a `SimpleTypeResolver` (the default
  resolver does not instantiate arbitrary types). A reference that only mentions
  the type in a doc comment is ignored by `IsCommentLine`.
- Vulnerable fixture:
  ```csharp
  var formatter = new LosFormatter();
  var state = formatter.Deserialize(Request.Form["viewState"]);

  var js = new JavaScriptSerializer(new SimpleTypeResolver());
  var obj = js.Deserialize<object>(Request.Form["payload"]);
  ```
- Safe fixture:
  ```csharp
  var order = JsonSerializer.Deserialize<Order>(json, JsonOptions);
  // or DataContractSerializer with a known-types allowlist
  ```
- CWE/OWASP: CWE-502; A08:2021 – Software and Data Integrity Failures.
- Sources:
  - https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide
  - https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2305
  - https://security-code-scan.github.io/ (SCS0028 – Insecure Deserialization)
  - https://www.ndepend.com/default-rules/nd3110-dont-use-insecure-deserializers
- Priority: P0

---

## P1 — next

### VGL-INJ-043 — Newtonsoft.Json TypeNameHandling enabled

- Severity: high
- Languages/files: `csharp` (`.cs`)
- Detection:
  - Gate: file contains `Newtonsoft` or `JsonSerializerSettings` or `JsonConvert`.
  - Pattern: `R(\bTypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b|\bTypeNameHandling\.(?:All|Auto|Objects|Arrays)\b)`.
  - Report at the assignment/reference line.
  - If `SerializationBinder` appears in `W(5)`, report with medium confidence and
    a message to verify the binder is a strict allowlist (a binder can restrict
    types but is easy to get wrong; Microsoft still flags non-None values).
- Why high-signal: `TypeNameHandling.All/Auto/Objects/Arrays` lets the JSON
  payload choose the .NET type, which is the standard Json.NET deserialization
  RCE. Microsoft ships CA2326 specifically for it, and the existing pack has no
  Newtonsoft rule.
- False-positive guard: ignore `TypeNameHandling.None` (the safe default); skip
  comments and strings; require the Newtonsoft/JsonSerializerSettings gate so an
  unrelated enum named `TypeNameHandling` is not flagged.
- Vulnerable fixture:
  ```csharp
  var settings = new JsonSerializerSettings {
      TypeNameHandling = TypeNameHandling.All
  };
  var obj = JsonConvert.DeserializeObject<object>(json, settings);
  ```
- Safe fixture:
  ```csharp
  var settings = new JsonSerializerSettings(); // TypeNameHandling.None
  var obj = JsonConvert.DeserializeObject<Order>(json, settings);
  ```
- CWE/OWASP: CWE-502; A08:2021 – Software and Data Integrity Failures.
- Sources:
  - https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2326
  - https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2327
  - https://semgrep.dev/r?q=csharp.lang.security.insecure-deserialization.newtonsoft.insecure-newtonsoft-deserialization
  - https://cwe.mitre.org/data/definitions/502.html
- Priority: P1

### VGL-INJ-044 — Python shell execution through os.popen or getoutput

- Severity: high
- Languages/files: `python` (`.py`, `.pyi`)
- Detection:
  - Sink: `R(\b(?:os\.popen[234]?|subprocess\.getoutput|subprocess\.getstatusoutput|commands\.getoutput|commands\.getstatusoutput)\s*\()`.
  - Report when the first argument is not `Q(arg)`.
  - If the argument is a bare identifier and its nearest assignment within 10
    lines is a quoted literal, skip (constant command).
  - Skip comments.
- Why high-signal: these APIs always run through a shell (`/bin/sh -c` or
  `cmd.exe /c`), unlike `subprocess.run([...])`. VGL-INJ-009 covers
  `os.system` and `subprocess(..., shell=True)` but not `os.popen`,
  `subprocess.getoutput` or the Python-2 `commands` helpers. Bandit B605 lists
  exactly these names as the shell family.
- False-positive guard: skip literal-only commands; skip a variable whose
  nearest assignment is a literal; skip comments. If the command is assembled
  from a fixed allowlist, suppress with a justification.
- Vulnerable fixture:
  ```python
  host = request.args["host"]
  out = os.popen("ping -c 1 " + host).read()
  ```
- Safe fixture:
  ```python
  out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
  ```
- CWE/OWASP: CWE-78; A03:2021 – Injection.
- Sources:
  - https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
  - https://docs.python.org/3/library/os.html#os.popen
  - https://cwe.mitre.org/data/definitions/78.html
- Priority: P1

### VGL-INJ-045 — Python pickle-based model/array loaders

- Severity: high
- Languages/files: `python` (`.py`, `.pyi`)
- Detection:
  - `R(\btorch\.(?:load|serialization\.load)\s*\()`:
    report unless `weights_only=True` appears in the same call or `W(3)`.
    If `weights_only=False` is present, report.
  - `R(\b(?:numpy|np)\.load\s*\()`:
    report only when `allow_pickle=True` appears in the same call or `W(3)`.
  - `R(\b(?:pandas|pd)\.read_pickle\s*\()`: report always.
  - `R(\bjoblib\.load\s*\()`: report always.
  - `R(\bdill\.load\s*\()`: report always.
  - Skip `torch.jit.load` (not pickle-based).
- Why high-signal: `torch.load`, `numpy.load(allow_pickle=True)`,
  `pandas.read_pickle`, `joblib.load` and `dill.load` all reconstruct Python
  objects through pickle. Loading a model or array from an upload, a shared
  cache, or a downloaded artifact is a code-execution path. Bandit added B614
  for `torch.load`; the existing VGL-INJ-010 only covers
  `pickle`/`marshal`/`yaml.load`, not the ML/data-science wrappers.
- False-positive guard: `torch.load(..., weights_only=True)` is safe;
  `numpy.load` without `allow_pickle=True` is safe; `safetensors` is safe and is
  not matched. Note that PyTorch 2.6 changed the default to `weights_only=True`;
  the rule still asks for the explicit safe argument so the result does not
  depend on the installed version.
- Vulnerable fixture:
  ```python
  model = torch.load(request.files["model"].stream)
  arr = numpy.load(upload_path, allow_pickle=True)
  frame = pandas.read_pickle(cache_path)
  ```
- Safe fixture:
  ```python
  model = torch.load(path, weights_only=True)
  arr = numpy.load(path)  # allow_pickle defaults to False
  model = safetensors.torch.load_file(path)
  ```
- CWE/OWASP: CWE-502; A08:2021 – Software and Data Integrity Failures.
- Sources:
  - https://bandit.readthedocs.io/en/latest/plugins/b614_pytorch_load.html
  - https://pytorch.org/docs/stable/generated/torch.load.html
  - https://numpy.org/doc/stable/reference/generated/numpy.load.html
  - https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html
  - https://joblib.readthedocs.io/en/stable/generated/joblib.load.html
- Priority: P1

### VGL-INJ-046 — PHP extract/parse_str imports request data into scope

- Severity: high
- Languages/files: `php` (`.php`, `.phtml`, `.inc`)
- Detection:
  - `R(\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER))`.
  - `R(\bextract\s*\(\s*\$request\s*->\s*(?:all|input|query)\s*\()`.
  - `R(\bparse_str\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)(?:\[[^\]]*\])?\s*\))`
    — the closing `)` directly after the superglobal ensures the one-argument
    form; `parse_str($str, $out)` does not match.
  - Skip when the `extract` call contains a non-overwriting flag:
    `EXTR_SKIP`, `EXTR_PREFIX_ALL`, `EXTR_PREFIX_SAME`, `EXTR_PREFIX_STRING`,
    `EXTR_PREFIX_INVALID`.
  - Skip comments.
- Why high-signal: `extract($_REQUEST)` with the default `EXTR_OVERWRITE` lets
  an attacker create or replace any local variable, including variables used in
  authorization or SQL. The one-argument `parse_str` is the same primitive
  (deprecated in PHP 7.2, removed in PHP 8, but still common in legacy code).
  The existing PHP rules cover command execution, include, unserialize and SQL,
  but not variable extraction.
- False-positive guard: skip `extract($data)` where the source is a database row
  or a function result (no superglobal/request token); skip `extract` with a
  non-overwriting flag; skip `parse_str` with a result array; skip comments.
- Vulnerable fixture:
  ```php
  extract($_REQUEST);
  if ($is_admin) { /* ... */ }

  parse_str($_SERVER['QUERY_STRING']);
  ```
- Safe fixture:
  ```php
  $input = $_REQUEST;
  $name = $input['name'] ?? '';
  parse_str($_SERVER['QUERY_STRING'], $query);
  ```
- CWE/OWASP: CWE-621 (Variable Extraction Error); A03:2021 – Injection.
- Sources:
  - https://www.php.net/manual/en/function.extract.php
  - https://www.php.net/manual/en/function.parse-str.php
  - https://exakat.readthedocs.io/en/latest/Reference/Rules/Security/ConfigureExtract.html
  - https://bugs.php.net/bug.php?id=71686
- Priority: P1

### VGL-INJ-047 — Ruby command injection through system/exec/Open3/%x

- Severity: high
- Languages/files: `ruby` (`.rb`, `.rake`, `Rakefile`)
- Detection:
  - Sink: `R(\b(?:system|exec|spawn|IO\.popen|Open3\.(?:capture2|capture2e|capture3|capture3e|popen2|popen3)|%x[({])`.
  - Report when the sink argument contains `#{` interpolation.
  - Report when the call has a single argument that is a request-ish token:
    `params`, `request`, `cookies`, `session`, `user`, `input`.
  - Report when the call has `"sh"` or `"bash"` plus `"-c"` and a request-ish
    token in the remaining arguments (the `sh -c` form is a shell even in argv
    style).
  - Skip when `Shellwords.escape`, `shellescape`, or `shelljoin` appears in the
    same line or `W(2)`.
  - Skip argv form with multiple comma-separated arguments and no interpolation
    (`system("ls", params[:dir])` is safe).
  - Skip comments.
- Why high-signal: Ruby's `system`/`exec`/`spawn`/`IO.popen`/`Open3`/`%x` all
  reach a shell when given a single string or when interpolation is used. The
  existing VGL-INJ-026 only covers `eval` and backticks with `#{}`; it misses
  `system("ls #{params[:dir]}")`, `Open3.capture3("sh", "-c", params[:cmd])`
  and `%x{...}`. Brakeman's command-injection check covers exactly this family.
- False-positive guard: skip `Shellwords.escape`/`shellescape`; skip argv form
  with no interpolation and no `sh -c`; skip literal-only commands; skip
  comments.
- Vulnerable fixture:
  ```ruby
  system("ls #{params[:dir]}")
  exec("md5sum #{params[:input]}")
  Open3.capture3("sh", "-c", params[:cmd])
  %x{tar -tf #{params[:archive]}}
  ```
- Safe fixture:
  ```ruby
  system("ls", params[:dir])
  Open3.capture3("grep", params[:pattern], "file.txt")
  system("ls #{Shellwords.escape(params[:dir])}")
  ```
- CWE/OWASP: CWE-78; A03:2021 – Injection.
- Sources:
  - https://brakemanscanner.org/docs/warning_types/command_injection/
  - https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/checks/check_execute.rb
  - https://cwe.mitre.org/data/definitions/78.html
- Priority: P1

### VGL-INJ-048 — EF Core raw SQL built with interpolation or concatenation

- Severity: high
- Languages/files: `csharp` (`.cs`)
- Detection:
  - Sink: `R(\b(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync)\s*\()`.
  - Extract the first argument (up to the first top-level comma; if the call
    spans lines, use `W(5)`).
  - Report when the first argument contains `$"`, `$@"`, `string.Format(` or
    quote-adjacent concatenation (`injConcatRe`), not an arithmetic `+` inside
    a SQL literal.
  - Skip `FromSqlInterpolated`, `ExecuteSqlInterpolated`,
    `ExecuteSqlInterpolatedAsync` (safe siblings).
  - Skip when the first argument is a plain literal with `{0}` placeholders and
    the values are passed as separate parameters.
- Why high-signal: EF Core's `FromSqlRaw` receives an already-built string;
  interpolating `$"… {user}"` puts the value into SQL text. Microsoft's docs
  explicitly warn that `FromSqlRaw` can be vulnerable and that
  `FromSql`/`FromSqlInterpolated` are the parameterized alternatives. The
  existing C# SQL rule covers `new SqlCommand`/`CommandText`, not EF Core.
- False-positive guard: skip `FromSqlRaw("… {0}", value)` with a separate
  parameter; skip the interpolated safe siblings; skip a literal-only raw query.
- Vulnerable fixture:
  ```csharp
  var email = Request.Query["email"];
  var users = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'").ToList();
  ```
- Safe fixture:
  ```csharp
  var users = db.Users.FromSql($"SELECT * FROM Users WHERE Email = {email}").ToList();
  // or:
  var users = db.Users.FromSqlRaw("SELECT * FROM Users WHERE Email = {0}", email).ToList();
  ```
- CWE/OWASP: CWE-89; A03:2021 – Injection.
- Sources:
  - https://learn.microsoft.com/en-us/ef/core/querying/sql-queries
  - https://learn.microsoft.com/en-us/dotnet/api/microsoft.entityframeworkcore.relationalqueryableextensions.fromsqlraw
  - https://cwe.mitre.org/data/definitions/89.html
- Priority: P1

### VGL-INJ-049 — SnakeYAML constructed without SafeConstructor

- Severity: high
- Languages/files: `java` (`.java`)
- Detection:
  - `R(\bnew\s+Yaml\s*\()`.
  - If the constructor arguments contain `SafeConstructor`, skip.
  - If the arguments contain `new Constructor(` (not `SafeConstructor`), report
    high confidence.
  - Otherwise, if a `.load(`, `.loadAs(`, `.loadAll(` or `.loadFromReader(`
    call appears in `W(20)` and its argument is not `Q(arg)`, report medium
    confidence.
  - Skip comments.
- Why high-signal: SnakeYAML's `Constructor` does not restrict the types it can
  instantiate (CVE-2022-1471); a crafted YAML document can reach
  `ScriptEngineManager`/`URLClassLoader` gadget chains. `SafeConstructor` is the
  documented mitigation. The existing Java deserialization rule covers
  `ObjectInputStream`/`XMLDecoder`, not YAML.
- False-positive guard: skip `SafeConstructor`; skip `new Yaml()` with no nearby
  `load`; skip a literal YAML argument. **Version caveat:** SnakeYAML 2.0+
  changed the default to be safe; if the project pins `org.yaml:snakeyaml` at
  2.0 or later, suppress the medium-confidence finding with a justification.
  The high-confidence `new Constructor(` form remains valid on all versions.
- Vulnerable fixture:
  ```java
  Yaml yaml = new Yaml();
  Object value = yaml.load(request.getInputStream());
  ```
- Safe fixture:
  ```java
  Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
  Object value = yaml.load(request.getInputStream());
  ```
- CWE/OWASP: CWE-502; A08:2021 – Software and Data Integrity Failures.
- Sources:
  - https://www.cve.org/CVERecord?id=CVE-2022-1471
  - https://github.com/google/security-research/security/advisories/GHSA-mjmj-j48q-9wg2
  - https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471
  - https://cwe.mitre.org/data/definitions/502.html
- Priority: P1

---

## P2 — backlog

### VGL-INJ-050 — Django raw SQL APIs receive formatted SQL

- Severity: high
- Languages/files: `python` (`.py`, `.pyi`)
- Detection:
  - Sink: `R(\bRawSQL\s*\(|\.extra\s*\(|\.raw\s*\()`.
  - `RawSQL(`: report when the first argument is not `Q(arg)` and contains
    `f"`, `f'`, `.format(`, `%`, `+`, or a bare identifier whose nearest
    assignment within 10 lines is dynamic.
  - `.extra(`: report when `where=`, `select=`, `tables=` or `order_by=` is
    present and its value is not a literal; skip when only `params=` is present.
  - `.raw(`: report when the SQL argument is not a literal and is dynamic.
  - Skip comments.
- Why high-signal: Django's `RawSQL`, `extra()` and `raw()` accept SQL fragments;
  f-strings/`.format`/`%`/concatenation put request values into SQL text. Bandit
  ships B610/B611 for exactly these APIs. The existing VGL-INJ-014 covers
  `cursor.execute` with formatting, not the ORM raw-SQL helpers.
- False-positive guard: skip literal SQL; skip `.extra(params=...)`; skip a
  variable whose nearest assignment is a literal; skip comments.
- Vulnerable fixture:
  ```python
  User.objects.annotate(val=RawSQL(f"SELECT {request.GET['col']} FROM auth_user", []))
  User.objects.extra(where=[f"name = '{request.GET['name']}'"])
  ```
- Safe fixture:
  ```python
  User.objects.annotate(val=RawSQL("SELECT id FROM auth_user WHERE id = %s", [user_id]))
  User.objects.extra(where=["name = %s"], params=[name])
  ```
- CWE/OWASP: CWE-89; A03:2021 – Injection.
- Sources:
  - https://bandit.readthedocs.io/en/latest/plugins/b610_django_extra_used.html
  - https://bandit.readthedocs.io/en/latest/plugins/b611_django_rawsql_used.html
  - https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection
  - https://cwe.mitre.org/data/definitions/89.html
- Priority: P2

### VGL-INJ-051 — PHP XML parsing enables entity substitution or external DTDs

- Severity: high
- Languages/files: `php` (`.php`, `.phtml`, `.inc`)
- Detection:
  - `R(\blibxml_disable_entity_loader\s*\(\s*false\s*\))` — always report.
  - `R(\bLIBXML_(?:NOENT|DTDLOAD|DTDVALID)\b)` — report when the same line or
    `W(3)` contains an XML parse call (`DOMDocument`, `loadXML`, `load(`,
    `simplexml_load_string`, `simplexml_load_file`, `XMLReader`, `xml_parse`).
  - Skip when `LIBXML_NO_XXE` appears in the same call (PHP 8.4+ mitigation).
  - Skip comments.
- Why high-signal: `LIBXML_NOENT` substitutes entities (the PHP manual marks it
  as an XXE risk); `LIBXML_DTDLOAD`/`LIBXML_DTDVALID` load external DTDs; and
  `libxml_disable_entity_loader(false)` explicitly re-enables external entity
  loading. The existing pack has no PHP XXE rule.
- False-positive guard: skip `LIBXML_NO_XXE`; skip comments; a trusted local DTD
  with `LIBXML_DTDVALID` can be a false positive — suppress with a justification
  and keep `LIBXML_NOENT` findings.
- Vulnerable fixture:
  ```php
  libxml_disable_entity_loader(false);
  $doc = new DOMDocument();
  $doc->loadXML($_POST['xml'], LIBXML_NOENT | LIBXML_DTDLOAD);
  ```
- Safe fixture:
  ```php
  $doc = new DOMDocument();
  $doc->loadXML($xml, LIBXML_NOENT | LIBXML_NO_XXE); // PHP 8.4+
  // or: libxml_set_external_entity_loader(static fn () => null);
  ```
- CWE/OWASP: CWE-611; A05:2021 – Security Misconfiguration.
- Sources:
  - https://www.php.net/manual/en/libxml.constants.php
  - https://www.php.net/manual/en/function.libxml-disable-entity-loader.php
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#php
  - https://cwe.mitre.org/data/definitions/611.html
- Priority: P2

### VGL-INJ-052 — .NET XML reader enables DTD parsing or an external resolver

- Severity: high
- Languages/files: `csharp` (`.cs`)
- Detection:
  - `R(\bDtdProcessing\s*=\s*DtdProcessing\.Parse\b)`.
  - `R(\bXmlResolver\s*=\s*new\s+XmlUrlResolver\s*\()`.
  - Gate: file contains `System.Xml` or `XmlReader`/`XmlDocument`/`XDocument`.
  - Confidence high when both `DtdProcessing.Parse` and
    `XmlResolver = new XmlUrlResolver()` appear in `W(10)`; medium when only one
    is present.
  - Skip comments.
- Why high-signal: in .NET 4.5.2+ the safe defaults are
  `DtdProcessing.Prohibit` and `XmlResolver = null`; explicitly setting
  `Parse` plus a non-null `XmlUrlResolver` restores external entity resolution.
  Microsoft's CA3075 and Security Code Scan SCS0007 describe exactly this pair.
- False-positive guard: skip `DtdProcessing.Prohibit`/`Ignore`; skip
  `XmlResolver = null`; skip `XmlSecureResolver` (a mitigation, though not
  perfect); skip comments.
- Vulnerable fixture:
  ```csharp
  var settings = new XmlReaderSettings {
      DtdProcessing = DtdProcessing.Parse,
      XmlResolver = new XmlUrlResolver()
  };
  var reader = XmlReader.Create(Request.Body, settings);
  ```
- Safe fixture:
  ```csharp
  var settings = new XmlReaderSettings {
      DtdProcessing = DtdProcessing.Prohibit,
      XmlResolver = null
  };
  var reader = XmlReader.Create(Request.Body, settings);
  ```
- CWE/OWASP: CWE-611; A05:2021 – Security Misconfiguration.
- Sources:
  - https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075
  - https://security-code-scan.github.io/ (SCS0007)
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#net
  - https://www.ndepend.com/default-rules/nd3111-dont-enable-external-xml-entity-resolution-xxe
- Priority: P2

### VGL-INJ-053 — Ruby raw/html_safe renders request data

- Severity: high
- Languages/files: `ruby` (`.rb`, `.erb`, `.rake`)
- Detection:
  - `R(\braw\s*\(\s*(?:params|request|cookies|session|@))` — direct request or
    instance-variable source.
  - `R(\.html_safe\b)` — report when the same line contains a request-ish token
    (`params`, `request`, `cookies`, `session`, `user`, `input`, `@`) or a
    one-hop assignment check finds one within 5 lines.
  - Skip `raw("literal")` and `.html_safe` on a literal string.
  - Skip `sanitize(...)` (the Rails sanitizer is a mitigation).
  - Skip comments.
- Why high-signal: Rails auto-escapes ERB output; `raw` and `.html_safe` turn
  that off. Applying either to `params` is the canonical Rails XSS sink. The
  existing pack has JS/TS, Python and Go XSS rules, but no Ruby one.
- False-positive guard: skip literals; skip `sanitize`; skip `.html_safe` on a
  value with no request source; skip comments.
- Vulnerable fixture:
  ```erb
  <%= raw(params[:message]) %>
  <%= @user.bio.html_safe %>
  ```
- Safe fixture:
  ```erb
  <%= sanitize(params[:message]) %>
  <%= h(@user.bio) %>
  ```
- CWE/OWASP: CWE-79; A03:2021 – Injection.
- Sources:
  - https://brakemanscanner.org/docs/warning_types/cross_site_scripting/
  - https://guides.rubyonrails.org/security.html#cross-site-scripting-xss
  - https://cwe.mitre.org/data/definitions/79.html
- Priority: P2

### VGL-INJ-054 — Java script or expression engine evaluates dynamic input

- Severity: high
- Languages/files: `java` (`.java`)
- Detection:
  - Gate: file contains one of `ScriptEngineManager`, `GroovyShell`,
    `SpelExpressionParser`, `ExpressionParser`, `MVEL`, `Ognl`.
  - Sinks:
    - `R(\.eval\s*\()` when `ScriptEngineManager`/`getEngineByName` is in the
      file.
    - `R(\.evaluate\s*\()` when `GroovyShell` is in the file.
    - `R(\.parseExpression\s*\()` when `SpelExpressionParser`/`ExpressionParser`
      is in the file; also require `getValue(` in `W(5)`.
    - `R(\bMVEL\.eval\s*\(|\bOgnl\.getValue\s*\()`.
  - Skip when the script/expression argument is `Q(arg)`.
  - Skip comments.
- Why high-signal: `ScriptEngine.eval`, `GroovyShell.evaluate`, SpEL
  `parseExpression(...).getValue()` and OGNL/MVEL evaluation all execute a
  string as code. If the string is request-controlled, this is direct RCE.
  FindSecBugs ships `SCRIPT_ENGINE_INJECTION` and `SPEL_INJECTION` for these
  sinks; the existing Java rules cover commands, deserialization and SQL, not
  expression engines.
- False-positive guard: skip literal scripts/expressions; skip comments; a
  fixed internal script can be suppressed with a justification.
- Vulnerable fixture:
  ```java
  ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
  engine.eval(request.getParameter("script"));
  ```
- Safe fixture:
  ```java
  // Do not evaluate user input. If a fixed script is required:
  engine.eval("1 + 1");
  ```
- CWE/OWASP: CWE-95, CWE-94; A03:2021 – Injection.
- Sources:
  - https://find-sec-bugs.github.io/bugs.htm#SCRIPT_ENGINE_INJECTION
  - https://find-sec-bugs.github.io/bugs.htm#SPEL_INJECTION
  - https://cwe.mitre.org/data/definitions/95.html
- Priority: P2

### VGL-INJ-055 — SQL Server xp_cmdshell used or enabled

- Severity: high
- Languages/files: `sql` (`.sql`)
- Detection:
  - `R((?i)\bxp_cmdshell\b)` — report unless the line starts with `DENY` or
    `REVOKE` (a mitigation), or the line is a comment.
  - `R((?i)\bsp_configure\s*\(\s*['"]xp_cmdshell['"]\s*,\s*1\s*\))` — report
    (enabling the feature).
  - Skip `sp_configure 'xp_cmdshell', 0` (disabling).
  - Skip SQL comments (`--`, `/*`).
- Why high-signal: `xp_cmdshell` runs an operating-system command with the SQL
  Server service account's rights; Microsoft says new code should not use it and
  it should stay disabled. A reference in application SQL is either a command
  execution sink or a privilege-escalation enabler. VGL-INJ-034 covers dynamic
  `EXEC`/`EXECUTE` SQL, not this specific OS-command procedure.
- False-positive guard: skip `DENY`/`REVOKE`; skip `sp_configure ..., 0`; skip
  comments.
- Vulnerable fixture:
  ```sql
  EXEC master..xp_cmdshell 'whoami';
  EXEC sp_configure 'xp_cmdshell', 1;
  ```
- Safe fixture:
  ```sql
  DENY EXECUTE ON master..xp_cmdshell TO app_user;
  EXEC sp_configure 'xp_cmdshell', 0;
  ```
- CWE/OWASP: CWE-78; A03:2021 – Injection.
- Sources:
  - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql
  - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option
  - https://cwe.mitre.org/data/definitions/78.html
- Priority: P2

### VGL-INJ-056 — PHP dynamic callable selected by a superglobal

- Severity: high
- Languages/files: `php` (`.php`, `.phtml`, `.inc`)
- Detection:
  - `R(\bcall_user_func(?:_array)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER))`.
  - `R(\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER))` — variable function
    called with a superglobal argument.
  - `R(\$\w+\s*->\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER))` — variable method.
  - Two-step form: a variable call `$fn(...)` or `$obj->$method(...)` whose
    one-hop assignment check (10 lines) finds `$fn = $_GET…` / `$method = $_POST…`.
  - Skip `call_user_func('literal', ...)`.
  - Skip comments.
- Why high-signal: a superglobal in the callable position lets the request pick
  the function or method, which can bypass authorization and reach dangerous
  helpers. VGL-INJ-027 covers Ruby `send`/`constantize`, but the PHP pack has no
  equivalent.
- False-positive guard: skip literal callables; skip comments. A dynamic
  callable from a fixed allowlist should be written as an explicit `match` and
  will not match this rule.
- Vulnerable fixture:
  ```php
  call_user_func($_GET['action']);
  $fn = $_POST['fn'];
  $fn();
  ```
- Safe fixture:
  ```php
  $actions = ['list' => 'listItems', 'show' => 'showItem'];
  $fn = $actions[$_GET['action']] ?? 'listItems';
  $fn();
  ```
- CWE/OWASP: CWE-470; A03:2021 – Injection.
- Sources:
  - https://www.php.net/manual/en/function.call-user-func.php
  - https://cwe.mitre.org/data/definitions/470.html
  - https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
- Priority: P2

### VGL-INJ-057 — lxml XMLParser enables DTD loading without disabling entities

- Severity: high
- Languages/files: `python` (`.py`, `.pyi`)
- Detection:
  - Sink: `R(\b(?:etree\.)?XMLParser\s*\()`.
  - Report when the call contains `load_dtd=True`, `dtd_validation=True` or
    `attribute_defaults=True`, and does not contain `resolve_entities=False` in
    the same call or `W(3)`.
  - Also report when `no_network=False` and `load_dtd=True` are both present.
  - Skip `etree.HTMLParser` (HTML parser, not XML).
  - Skip comments.
- Why high-signal: lxml's `load_dtd=True` makes the parser load the document's
  DTD; with entity resolution left on (the default), external entities can be
  resolved. The lxml docs call out `load_dtd`, `dtd_validation` and
  `attribute_defaults` as DTD-loading options; the safe pattern is
  `resolve_entities=False` (and `no_network=True`). The existing pack has no
  Python XXE rule.
- False-positive guard: skip when `resolve_entities=False` is present; skip
  `HTMLParser`; skip comments. A parser that only handles a trusted local schema
  can be suppressed with a justification.
- Vulnerable fixture:
  ```python
  parser = etree.XMLParser(load_dtd=True)
  root = etree.fromstring(request.data, parser)
  ```
- Safe fixture:
  ```python
  parser = etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
  root = etree.fromstring(request.data, parser)
  ```
- CWE/OWASP: CWE-611; A05:2021 – Security Misconfiguration.
- Sources:
  - https://lxml.de/parsing.html
  - https://lxml.de/3.8/api/lxml.etree.XMLParser-class.html
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#python
  - https://cwe.mitre.org/data/definitions/611.html
- Priority: P2

### VGL-INJ-058 — Ruby ERB template compiled from request data

- Severity: high
- Languages/files: `ruby` (`.rb`, `.rake`, `Rakefile`)
- Detection:
  - `R(\bERB\.new\s*\()`: report when the argument contains `params`, `request`,
    `cookies`, `session`, `user`, `input`, `@`, `+`, or `#{`.
  - `R(\brender\s+inline\s*:)`: report when the value contains a request-ish
    token (`params`, `request`, `user`, `input`).
  - Skip `ERB.new("<%= fixed %>")` and `ERB.new(File.read("fixed.erb"))`.
  - Skip comments.
- Why high-signal: ERB has no sandbox; `<%= ... %>` is arbitrary Ruby. Compiling
  a template from `params` is direct RCE (PortSwigger's ERB SSTI example).
  VGL-INJ-026 covers `eval`/backticks, but not `ERB.new` or Rails
  `render inline:`.
- False-positive guard: skip literal templates; skip a fixed template file read;
  skip comments. A user-authored template feature is still dangerous by design —
  the finding should be reviewed, not auto-suppressed.
- Vulnerable fixture:
  ```ruby
  template = ERB.new(params[:template])
  render html: template.result(binding).html_safe
  ```
- Safe fixture:
  ```ruby
  template = ERB.new(File.read(Rails.root.join("app/views/mailer/welcome.erb")))
  ```
- CWE/OWASP: CWE-1336, CWE-94; A03:2021 – Injection.
- Sources:
  - https://portswigger.net/web-security/server-side-template-injection
  - https://docs.ruby-lang.org/en/master/ERB.html
  - https://cwe.mitre.org/data/definitions/1336.html
- Priority: P2

### VGL-INJ-059 — JavaScript string passed to setTimeout/setInterval

- Severity: medium
- Languages/files: `javascript`, `typescript` (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`)
- Detection:
  - ``R(\b(?:setTimeout|setInterval)\s*\(\s*(?:["']|`[^`]*\$\{))``.
  - `R(\bexecScript\s*\(\s*["'])` (legacy IE).
  - Skip when the first argument is a function expression, arrow function, or a
    bare identifier that is not a string literal/template.
  - Skip comments.
- Why high-signal: a string first argument to `setTimeout`/`setInterval` is
  compiled and executed like `eval`; ESLint's `no-implied-eval` exists for this
  exact pattern. VGL-INJ-001 covers `eval`, `new Function` and `vm.*`, but not
  the timer string form.
- False-positive guard: skip `setTimeout(fn, 100)`,
  `setTimeout(() => doWork(), 100)`, and a bare identifier; skip comments. If a
  project intentionally uses string timers, suppress with a justification.
- Vulnerable fixture:
  ```javascript
  setTimeout("refresh()", 1000);
  setInterval(`poll('${userId}')`, 5000);
  ```
- Safe fixture:
  ```javascript
  setTimeout(refresh, 1000);
  setInterval(() => poll(userId), 5000);
  ```
- CWE/OWASP: CWE-95; A03:2021 – Injection.
- Sources:
  - https://eslint.org/docs/latest/rules/no-implied-eval
  - https://developer.mozilla.org/en-US/docs/Web/API/setTimeout
  - https://cwe.mitre.org/data/definitions/95.html
- Priority: P2

---

## Rejected

These were considered and rejected. The reason is either duplication, noise,
or the need for dataflow/whole-program analysis that the engine does not have.

### Already covered by existing rules

| Candidate | Existing rule | Reason |
|---|---|---|
| `include $_GET['page']` / `require $var` | VGL-INJ-023 | PHP file inclusion from a variable already covers the superglobal and variable forms. |
| `unserialize($_GET['x'])` | VGL-INJ-024 | Unsafe PHP deserialization already covers every `unserialize()` call. |
| `pickle.loads`, `marshal.loads`, `yaml.load` | VGL-INJ-010 | Python unsafe deserialization already covers these sinks, including the `SafeLoader` guard. |
| `ObjectInputStream.readObject`, `XMLDecoder` | VGL-INJ-019 | Java unsafe deserialization already covers both. |
| `BinaryFormatter` | VGL-INJ-029 | C# BinaryFormatter is already critical; VGL-INJ-042 adds the sibling legacy formatters and type-resolving JavaScriptSerializer. |
| `Runtime.getRuntime().exec`, `new ProcessBuilder` | VGL-INJ-018 | Java command execution already covers both. |
| `eval` / `new Function` / `vm.runInNewContext` / `document.write` | VGL-INJ-001, VGL-INJ-003 | JS dynamic code execution and HTML sinks already cover them. |
| `child_process.exec` / `execSync` | VGL-INJ-002 | Node shell command rule already covers them. |
| `require(variable)` / `import(variable)` | VGL-INJ-005 | Dynamic module load is already covered. |
| `YAML.load` in Ruby | VGL-INJ-028 | Existing Ruby YAML rule; VGL-INJ-041 adds `unsafe_load`, `Marshal.load`, `JSON.load`, `Oj`. |
| `dangerouslySetInnerHTML` | VGL-INJ-003 | Explicitly excluded by the brief and already covered. |
| `innerHTML` / `outerHTML` | VGL-INJ-003 | Generic HTML sink; context-dependent and already covered. |
| `document.location = userInput` / `window.open(userInput)` | VGL-WEB-003 | Open redirect already covered. |
| `requests.get(userUrl)` / `http.Get(userUrl)` / `URL.openConnection()` | VGL-WEB-001 | SSRF (CWE-918) already covered; without taint a new rule would duplicate or be noisy. |
| `open(userPath)` / `filepath.Join(root, userPath)` / `Paths.get(userPath)` | VGL-WEB-002 | Path traversal (CWE-22) already covered; needs taint to be useful. |
| `EXEC(@sql)` where the same line contains `+` and `@` | VGL-INJ-034 | The existing dynamic-SQL rule covers the single-line form. The two-step `SET @sql = … + …; EXEC(@sql)` form is a real gap but needs a file-level variable check; deferred as a future P2. |

### Rejected as noisy, version-dependent, or requiring dataflow

| Candidate | Reason |
|---|---|
| Generic `eval` in test/tooling code | Already covered by VGL-INJ-001/008/021/026; a new broad rule would add noise, especially in test fixtures. |
| `js-yaml.load()` | Behavior depends on the installed js-yaml major (v4 safe by default, v3 unsafe); the rule cannot know the version from a line. |
| `yaml.load` in Python | Already covered by VGL-INJ-010; `safe_load` is the documented safe form. |
| `XStream.fromXML` | Real deserialization risk, but niche and overlaps the Java unsafe-deserialization family; can be a later P2 if demand appears. |
| `Java Class.forName(userInput)` + `newInstance()` | Needs local dataflow to separate fixed JDBC driver names from request data; high false-positive rate. |
| `C# Activator.CreateInstance(Type.GetType(userInput))` | Valid dynamic type load, but rare and overlaps VGL-INJ-043/VGL-INJ-042; a later P2 candidate. |
| `Go gob.NewDecoder(...).Decode(...)` | Unsafe for untrusted data but primarily type confusion/DoS, not the RCE class this pack targets; lower signal. |
| `COPY ... FROM PROGRAM` (PostgreSQL) | Valid OS-command sink, but PostgreSQL-specific and much less common than `xp_cmdshell`; deferred to a later SQL pack. |
| `PHP assert($_GET['x'])`, `create_function`, `preg_replace` `/e` | Removed or deprecated in PHP 8; legacy-only and low value for current codebases. |
| `session_decode($_GET['x'])` | Niche session deserialization vector; too rare for a high-signal default rule. |
| `phar://` stream deserialization | Requires knowing the stream wrapper and file operation; not a line-deterministic sink. |
| Log4j JNDI lookup patterns | Dependency/version-specific; the dependency scanner should flag the vulnerable Log4j version, and VGL-INJ-040 covers application-level JNDI lookups. |
| `node-serialize.unserialize()` | Valid RCE sink but very rare; a later P2 candidate for the JS pack. |
| `child_process.fork(variable)` | Dynamic module load, but overlaps VGL-INJ-005 and is noisy in test runners and worker pools. |
| `RegExp(userInput)` | ReDoS, not injection; needs regex complexity analysis rather than a sink match. |
| `document.domain = ...` | Not an injection sink; it is a legacy same-origin relaxation. |
| `process.env` / secret logging | Not injection; belongs to the secrets/logging pack. |
| `setAttribute('href', userInput)` | XSS-adjacent but context-dependent; the existing VGL-INJ-007 covers the React URL case, and a generic attribute rule would be noisy. |
| `insertAdjacentHTML` with dynamic content | A real DOM XSS sink, but the brief asks to avoid generic HTML sinks; VGL-INJ-003 already covers the main `innerHTML` family. Could be a later P2 with a sanitizer guard. |
| `new XmlTextReader(...)` | In .NET 4.5.2+ the internal resolver defaults to null; without a `DtdProcessing.Parse`/`XmlUrlResolver` pair it is not reliably vulnerable. |
| `XmlSerializer.Deserialize(stream)` | Needs CA5369-style analysis of the overload and the reader; the simple line pattern would flag safe known-type usage. |

## Implementation notes

1. **IDs and registration.** Add the rules in `internal/rules/injection.go`
   (or a new `injection_languages.go` in the same package) and append them to
   `InjectionRules()`. Keep the existing `injMeta` helper so CWE references and
   OWASP defaults are generated consistently. The next free ID is
   `VGL-INJ-038`.
2. **Language gates.** Use `injLangAllowed(f.Language, meta.Languages)`. The
   scanner already labels `go`, `python`, `javascript`, `typescript`, `java`,
   `php`, `ruby`, `csharp`, `sql`, so no new language detection is needed.
3. **RE2 discipline.** Do not use look-around or back-references. The patterns
   above are written for Go's `regexp` package. Where a pattern needs "no second
   argument" (`parse_str`), the regex closes the parenthesis directly rather than
   using a negative look-ahead.
4. **Comment handling.** Every rule must call `IsCommentLine` or check
   `codeContextAt` before reporting. This is especially important for the
   config-token rules (XXE, TypeNameHandling) where documentation often contains
   the dangerous token.
5. **Window size.** Use `W(3)` for call-local keywords (`weights_only`,
   `create_additions`, `resolve_entities`), `W(10)` for one-hop assignment
   checks and .NET settings blocks, and `W(20–25)` for factory hardening and
   SnakeYAML load pairing. Do not scan the whole file for call-local keywords;
   that causes cross-function false negatives/positives.
6. **Severity caps.** Pass every finding through `SeverityForLanguage`; the
   helper already lowers test/docs findings. Do not hardcode a lower severity in
   the rule.
7. **Confidence.** `injFindings` takes a single confidence for the whole rule.
   For rules with high/medium paths (VGL-INJ-039, 040, 043, 049, 052), use a
   custom `New(...)` function that sets `Confidence` per finding instead of
   `injSpec`, or extend `injFindings` with a `confidenceFor(line)` callback.
   Do not register two rules with the same ID: the registry silently ignores the
   duplicate. The simplest change is a small per-rule closure that calls
   `injFindings` twice with different confidence values and merges the slices.
8. **Test layout.** Add one fixture directory per language under
   `internal/rules/testdata/injection-languages/` with `vulnerable.*` and
   `safe.*` files, plus a table-driven test that asserts exact rule IDs and line
   numbers. The existing `injection_test.go` and `precision_test.go` show the
   pattern. At minimum, add the vulnerable/safe snippets from this document as
   unit cases and one "safe project" regression fixture per language.
9. **Suggested order.** P0: 038, 044, 045, 046, 047 (line-local, quick wins),
   then 048, 043, 049, then 039, 040, 041, 042 (window/file-level). P2 after the
   P0/P1 suite is green.
10. **Do not co-commit** these rules with unrelated crypto/auth or config/IaC
    changes; keep the injection pack reviewable as one change set.

## Source index

Primary rule packs and guidance used above:

- Semgrep registry / rules repository: https://github.com/semgrep/semgrep-rules
  (Java XXE, Ruby deserialization, C# insecure Newtonsoft, PHP/C#/Go injection).
- Bandit: https://bandit.readthedocs.io/en/latest/plugins/index.html
  (B605 shell, B610/B611 Django raw SQL, B614 PyTorch load).
- gosec: https://github.com/securego/gosec/blob/master/RULES.md and
  https://securego.io/docs/rules/g201-g202.html (G201/G202 SQL).
- FindSecBugs: https://find-sec-bugs.github.io/bugs.htm
  (XXE_*, SCRIPT_ENGINE_INJECTION, SPEL_INJECTION, JNDI/LDAP family).
- Brakeman: https://brakemanscanner.org/docs/warning_types/
  (command injection, unsafe deserialization, XSS).
- Security Code Scan: https://security-code-scan.github.io/
  (SCS0007 XXE, SCS0028 insecure deserialization).
- ESLint `no-implied-eval`: https://eslint.org/docs/latest/rules/no-implied-eval
  (string timers).
- nodejsscan rules: https://github.com/ajinabraham/nodejsscan/tree/master/nodejsscan/rules/semantic_grep
  (JS dangerous sinks; used as a cross-check, no rule copied verbatim).
- eslint-plugin-security: https://github.com/eslint-community/eslint-plugin-security
  (detect-child-process, detect-eval-with-expression, detect-non-literal-require).
- Psalm security analysis: https://psalm.dev/docs/security_analysis/
  (taint-based; reviewed for PHP sink vocabulary, not used as a deterministic
  pattern source). PHPStan has no built-in security rule set; third-party taint
  rules exist.
- OWASP Top 10 2021: https://owasp.org/Top10/
  A03 Injection, A05 Security Misconfiguration, A08 Software and Data Integrity Failures.
- OWASP XXE Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- CWE definitions: https://cwe.mitre.org/data/definitions/22.html,
  /78.html, /89.html, /94.html, /95.html, /470.html, /502.html, /611.html,
  /621.html, /918.html, /1336.html.
- Microsoft .NET guidance:
  https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide,
  https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2326,
  https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075,
  https://learn.microsoft.com/en-us/ef/core/querying/sql-queries.
- PHP manual:
  https://www.php.net/manual/en/function.extract.php,
  https://www.php.net/manual/en/function.parse-str.php,
  https://www.php.net/manual/en/function.libxml-disable-entity-loader.php,
  https://www.php.net/manual/en/libxml.constants.php.
- Ruby security:
  https://docs.ruby-lang.org/en/master/security/security_rdoc.html,
  https://brakemanscanner.org/docs/warning_types/unsafe_deserialization/,
  https://brakemanscanner.org/docs/warning_types/command_injection/.
- lxml parsing: https://lxml.de/parsing.html.
- SnakeYAML CVE: https://www.cve.org/CVERecord?id=CVE-2022-1471 and
  https://github.com/google/security-research/security/advisories/GHSA-mjmj-j48q-9wg2.
- JNDI injection: https://www.veracode.com/blog/research/exploiting-jndi-injections-java
  and https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf.
- SQL Server xp_cmdshell:
  https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql
  and
  https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option.
