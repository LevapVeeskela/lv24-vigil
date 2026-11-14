package rules

import (
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ---------------------------------------------------------------------------
// Wave-2 fixtures (VGL-AUTH-023, VGL-WEB-026, VGL-INJ-063/064/065). The
// cawFile/cawCheck/cawRule helpers from crypto_auth_web_expansion_test.go are
// reused so the assertions and the severity-cap behaviour stay identical.
// ---------------------------------------------------------------------------

func wave2Rule(t *testing.T, rs []Rule, id string) Rule {
	t.Helper()
	return cawRule(t, rs, id)
}

func TestWave2RulesRegistered(t *testing.T) {
	rules := []Rule{
		wave2Rule(t, AuthRules(), "VGL-AUTH-023"),
		wave2Rule(t, WebRules(), "VGL-WEB-026"),
		wave2Rule(t, InjectionRules(), "VGL-INJ-063"),
		wave2Rule(t, InjectionRules(), "VGL-INJ-064"),
		wave2Rule(t, InjectionRules(), "VGL-INJ-065"),
	}
	for _, rule := range rules {
		m := rule.Meta()
		if m.Title == "" || m.Description == "" || m.Severity.Rank() == 0 || m.Category == "" {
			t.Errorf("%s metadata incomplete: %+v", m.ID, m)
		}
		if len(m.Languages) == 0 {
			t.Errorf("%s has no language list", m.ID)
		}
		if len(m.CWE) == 0 || len(m.OWASP) == 0 {
			t.Errorf("%s is missing CWE/OWASP metadata", m.ID)
		}
		if len(m.Tags) == 0 {
			t.Errorf("%s has no tags", m.ID)
		}
		if len(m.References) == 0 {
			t.Errorf("%s has no references", m.ID)
		}
	}
}

func TestWave2RulesHandleNilFile(t *testing.T) {
	for _, rule := range []Rule{
		wave2Rule(t, AuthRules(), "VGL-AUTH-023"),
		wave2Rule(t, WebRules(), "VGL-WEB-026"),
		wave2Rule(t, InjectionRules(), "VGL-INJ-063"),
		wave2Rule(t, InjectionRules(), "VGL-INJ-064"),
		wave2Rule(t, InjectionRules(), "VGL-INJ-065"),
	} {
		if got := rule.Check(nil); len(got) != 0 {
			t.Errorf("%s: nil file produced %d findings", rule.Meta().ID, len(got))
		}
	}
}

// ---------------------------------------------------------------------------
// VGL-AUTH-023 — JWT key material taken from the token header
// ---------------------------------------------------------------------------

func TestWave2AuthJWTHeaderKey(t *testing.T) {
	rule := wave2Rule(t, AuthRules(), "VGL-AUTH-023")
	js := "src/auth/verify.ts"

	cawCheck(t, rule, js, "typescript", `const { header } = jwt.decode(token, { complete: true });
const res = await fetch(header.jku);
const key = await res.text();
jwt.verify(token, key);`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, js, "typescript", `jwt.verify(token, decoded.jwk);`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, js, "typescript", `const header = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
const jwks = await axios.get(header.x5u);`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, "app/jwt_auth.py", "python", `header = jwt.get_unverified_header(token)
jku = header["jku"]
resp = requests.get(jku)`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, "internal/auth/jwt.go", "go", `header := token.Header
jku := header["jku"].(string)
resp, err := http.Get(jku)`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, "app/services/jwt_check.rb", "ruby", `header = JWT.decode(token, nil, false)[0]
jku = header["jku"]
key = Net::HTTP.get(URI(jku))`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, "src/main/java/app/JwtVerifier.java", "java", `String jku = headers.get("jku");
HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(jku)).build(), HttpResponse.BodyHandlers.ofString());`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, "src/Auth/JwtVerifier.cs", "csharp", `var jku = header["jku"].ToString();
var key = await httpClient.GetAsync(jku);`,
		cawWant{line: 1, sev: model.SeverityHigh})

	// Safe: the header field is only read for logging.
	cawCheck(t, rule, js, "typescript", `logger.info("token key id", header.jku);`)

	// Safe: an HttpClient call against a configured URL selects no header key.
	cawCheck(t, rule, "src/main/java/app/JwtVerifier.java", "java",
		`HttpClient.newHttpClient().send(cachedRequest, HttpResponse.BodyHandlers.ofString());`)

	// Safe: a Python docstring only documents the verifier.
	cawCheck(t, rule, "app/jwt_auth.py", "python", `"""
header = jwt.get_unverified_header(token)
jku = header["jku"]
resp = requests.get(jku)
"""`)
	cawCheck(t, rule, "app/jwt_auth.py", "python", `jku = header["jku"]
example = """
resp = requests.get(jku)
"""`)

	// Safe: signing advertises a key, it does not select the verification key.
	cawCheck(t, rule, js, "typescript",
		`const out = jwt.sign(payload, secret, { header: { jku: decoded.jku } });`)

	// Safe: pinned JWKS client and a configured URL.
	cawCheck(t, rule, js, "typescript", `const key = await jwksClient.getSigningKey(header.kid);
jwt.verify(token, key.getPublicKey(), { algorithms: ["RS256"] });`)
	cawCheck(t, rule, js, "typescript", `const jwksUri = config.jwksUri;
const res = await fetch(jwksUri);`)

	// Safe: a literal or configured verification key.
	cawCheck(t, rule, js, "typescript", `jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });`)
	cawCheck(t, rule, "app/auth.py", "python", `payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])`)

	// Tests and documentation are not production verifiers.
	cawCheck(t, rule, "src/auth/jwt.test.ts", "typescript",
		`const res = await fetch(header.jku);`)
	cawCheck(t, rule, "docs/jwt.md", "markdown",
		`const res = await fetch(header.jku);`)
}

// ---------------------------------------------------------------------------
// VGL-WEB-026 — static file server rooted at the project root
// ---------------------------------------------------------------------------

func TestWave2WebStaticRoot(t *testing.T) {
	rule := wave2Rule(t, WebRules(), "VGL-WEB-026")

	cawCheck(t, rule, "src/app.ts", "typescript", `app.use(express.static(__dirname));`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "src/app.js", "javascript", `app.use(express.static("."));`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "src/app.js", "javascript",
		`app.use(express.static(path.join(process.cwd(), ".")));`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "internal/server/files.go", "go",
		`fs := http.FileServer(http.Dir("."))`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "internal/server/files.go", "go",
		`fs := http.FileServer(http.Dir(os.Getwd()))`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/main.py", "python",
		`app.mount("/", StaticFiles(directory="."), name="static")`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/upload.py", "python",
		`return send_from_directory(".", filename)`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "config.ru", "ruby",
		`use Rack::Static, urls: ["/"], root: "."`,
		cawWant{line: 1, sev: model.SeverityHigh})
	// `..` walks back to the project root even though "web" is a bounded name.
	cawCheck(t, rule, "src/app.js", "javascript",
		`app.use(express.static("./web/.."));`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "src/app.js", "javascript",
		`app.use(express.static(path.join(__dirname, "..")));`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/main.py", "python",
		`app.mount("/", StaticFiles(directory="./assets/../.."), name="static")`,
		cawWant{line: 1, sev: model.SeverityHigh})

	// Safe: a bounded subdirectory or a configured path.
	cawCheck(t, rule, "src/app.ts", "typescript",
		`app.use(express.static(path.join(__dirname, "public")));`)
	cawCheck(t, rule, "src/app.js", "javascript", `app.use(express.static("dist"));`)
	cawCheck(t, rule, "internal/server/files.go", "go",
		`fs := http.FileServer(http.Dir("./public"))`)
	cawCheck(t, rule, "app/main.py", "python",
		`app.mount("/static", StaticFiles(directory="public"), name="static")`)
	cawCheck(t, rule, "app/main.py", "python",
		`app.mount("/s", StaticFiles(directory=settings.STATIC_ROOT), name="static")`)
	cawCheck(t, rule, "config.ru", "ruby", `use Rack::Static, urls: ["/"], root: "./public"`)

	// Safe: a docstring does not mount a static server.
	cawCheck(t, rule, "app/main.py", "python", `"""Example mount:
app.mount("/", StaticFiles(directory="."), name="static")
"""`)

	// A commented-out mount is not served.
	cawCheck(t, rule, "app/main.py", "python",
		`# app.mount("/", StaticFiles(directory="."), name="static")`)
	// A string that merely shows the call is not a mount.
	cawCheck(t, rule, "src/docs.ts", "typescript",
		"const sample = \"app.use(express.static(__dirname));\";")

	// Test fixtures are still reported, but capped at medium.
	cawCheck(t, rule, "src/app.test.ts", "typescript",
		`app.use(express.static(__dirname));`,
		cawWant{line: 1, sev: model.SeverityMedium})

	// Documentation is skipped.
	cawCheck(t, rule, "docs/static.md", "markdown",
		`app.use(express.static(__dirname));`)
}

// ---------------------------------------------------------------------------
// VGL-INJ-063 — Django raw SQL APIs receive formatted SQL
// ---------------------------------------------------------------------------

func TestWave2InjectionDjangoRawSQL(t *testing.T) {
	rule := wave2Rule(t, InjectionRules(), "VGL-INJ-063")

	cawCheck(t, rule, "app/views/reports.py", "python",
		`User.objects.annotate(val=RawSQL(f"SELECT {request.GET['col']} FROM auth_user", []))`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/views/reports.py", "python",
		`User.objects.extra(where=[f"name = '{request.GET['name']}'"])`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/views/reports.py", "python",
		`User.objects.raw("SELECT * FROM auth_user WHERE id = " + user_id)`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/views/reports.py", "python",
		`RawSQL("SELECT {} FROM auth_user".format(column), [])`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/views/reports.py", "python", `sql = f"SELECT * FROM auth_user WHERE username = '{name}'"
User.objects.raw(sql)`,
		cawWant{line: 2, sev: model.SeverityHigh})

	// Safe: constants with placeholders and bound parameters.
	cawCheck(t, rule, "app/views/reports.py", "python",
		`User.objects.annotate(val=RawSQL("SELECT id FROM auth_user WHERE id = %s", [user_id]))`)
	cawCheck(t, rule, "app/views/reports.py", "python",
		`User.objects.extra(where=["name = %s"], params=[name])`)
	cawCheck(t, rule, "app/views/reports.py", "python",
		`User.objects.raw("SELECT * FROM auth_user WHERE active = True")`)
	cawCheck(t, rule, "app/views/reports.py", "python", `sql = "SELECT * FROM auth_user WHERE id = %s"
User.objects.raw(sql)`)
	cawCheck(t, rule, "app/views/reports.py", "python",
		`# User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")`)
	cawCheck(t, rule, "app/views/reports.py", "python", `"""Example: User.objects.raw(f"SELECT {column} FROM auth_user")"""`)

	// Test fixtures are capped at medium.
	cawCheck(t, rule, "tests/test_reports.py", "python",
		`User.objects.raw("SELECT * FROM auth_user WHERE id = " + user_id)`,
		cawWant{line: 1, sev: model.SeverityMedium})
}

func TestWave2InjectionDjangoRawSQLConfidence(t *testing.T) {
	rule := wave2Rule(t, InjectionRules(), "VGL-INJ-063")
	got := rule.Check(cawFile("app/views/reports.py", "python",
		`User.objects.raw("SELECT * FROM auth_user WHERE id = " + user_id)`))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1\n%s", len(got), cawDescribe(got))
	}
	// The formatted string is syntactic evidence, not a proven taint path.
	if got[0].Confidence != model.ConfidenceMedium {
		t.Errorf("confidence = %q, want %q", got[0].Confidence, model.ConfidenceMedium)
	}
}

// ---------------------------------------------------------------------------
// VGL-INJ-064 — PHP XML parsing enables entity substitution or external DTDs
// ---------------------------------------------------------------------------

func TestWave2InjectionPHPXXE(t *testing.T) {
	rule := wave2Rule(t, InjectionRules(), "VGL-INJ-064")

	cawCheck(t, rule, "app/import.php", "php", `libxml_disable_entity_loader(false);`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/import.php", "php", `$doc = new DOMDocument();
$doc->loadXML($_POST['xml'], LIBXML_NOENT | LIBXML_DTDLOAD);`,
		cawWant{line: 2, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/import.php", "php",
		`$xml = simplexml_load_string($data, "SimpleXMLElement", LIBXML_NOENT);`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/import.inc", "other",
		`$r = new XMLReader();
$r->open($path, null, LIBXML_DTDLOAD);`,
		cawWant{line: 2, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/import.php", "php", `$doc->loadXML(
    $_POST['xml'],
    LIBXML_NOENT
);`,
		cawWant{line: 3, sev: model.SeverityHigh})

	// Safe: the mitigation flag and the default loader.
	cawCheck(t, rule, "app/import.php", "php",
		`$doc->loadXML($xml, LIBXML_NOENT | LIBXML_NO_XXE);`)
	cawCheck(t, rule, "app/import.php", "php", `libxml_disable_entity_loader(true);`)
	cawCheck(t, rule, "app/config.php", "php", `$flags = LIBXML_NOENT;`)
	cawCheck(t, rule, "app/config.php", "php",
		`// $doc->loadXML($xml, LIBXML_NOENT);`)

	// Safe: a flag assigned on another statement never reaches the parse call.
	cawCheck(t, rule, "app/import.php", "php", `$flags = LIBXML_NOENT;
$doc->loadXML($xml);`)
	cawCheck(t, rule, "app/import.php", "php", `$doc = new DOMDocument();
$flags = LIBXML_NOENT | LIBXML_DTDLOAD;
$doc->load($xml);`)
	cawCheck(t, rule, "app/import.php", "php", `$options = array(LIBXML_DTDLOAD);
$reader->open($path);`)

	// Test fixtures are capped at medium.
	cawCheck(t, rule, "tests/ImportTest.php", "php",
		`libxml_disable_entity_loader(false);`,
		cawWant{line: 1, sev: model.SeverityMedium})
}

// ---------------------------------------------------------------------------
// VGL-INJ-065 — Ruby raw/html_safe renders request data
// ---------------------------------------------------------------------------

func TestWave2InjectionRubyRawHTML(t *testing.T) {
	rule := wave2Rule(t, InjectionRules(), "VGL-INJ-065")
	erb := "app/views/messages/show.html.erb"
	rb := "app/helpers/messages_helper.rb"

	cawCheck(t, rule, erb, "other", `<%= raw(params[:message]) %>`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, erb, "ruby", `<%= @user.bio.html_safe %>`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, erb, "ruby", `<%= request.headers["X-Title"].html_safe %>`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, rb, "ruby", `bio = params[:bio]
content = bio.html_safe`,
		cawWant{line: 2, sev: model.SeverityHigh})

	// Safe: literals, the sanitizer and values without a request source.
	cawCheck(t, rule, erb, "ruby", `<%= raw("<b>static</b>") %>`)
	cawCheck(t, rule, erb, "ruby", `<%= "<b>static</b>".html_safe %>`)
	cawCheck(t, rule, erb, "ruby", `<%= sanitize(params[:message]) %>`)
	cawCheck(t, rule, erb, "ruby", `<%= sanitize(params[:message]).html_safe %>`)
	cawCheck(t, rule, rb, "ruby", `html = "<b>static</b>"
out = html.html_safe`)
	cawCheck(t, rule, rb, "ruby", `# <%= raw(params[:message]) %>`)

	// Safe: ERB comment tags render nothing.
	cawCheck(t, rule, erb, "other", `<%# raw(params[:x]) %>`)
	cawCheck(t, rule, erb, "ruby", `<%#= @x.html_safe %>`)
	cawCheck(t, rule, erb, "other", `  <%# raw(params[:x]) %>`)

	// Test fixtures are capped at medium.
	cawCheck(t, rule, "test/helpers/messages_helper_test.rb", "ruby",
		`assert_equal raw(params[:message]), value`,
		cawWant{line: 1, sev: model.SeverityMedium})
}
