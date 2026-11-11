package rules

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ---------------------------------------------------------------------------
// Fixtures for the crypto/auth/web expansion (VGL-CRY-013/014/015/017,
// VGL-AUTH-017, VGL-WEB-020). Helper names are prefixed with "caw" so parallel
// rule packs can add their own without collisions.
// ---------------------------------------------------------------------------

func cawFile(path, language, content string) *File {
	content = strings.TrimSuffix(content, "\n")
	lines := strings.Split(content, "\n")
	return &File{
		Path:     path,
		AbsPath:  path,
		Content:  []byte(content),
		Lines:    lines,
		Language: language,
		Size:     len(content),
	}
}

type cawWant struct {
	line int
	sev  model.Severity
}

func cawDescribe(fs []model.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  ")
		b.WriteString(f.RuleID)
		b.WriteString(" line ")
		b.WriteString(strconv.Itoa(f.Location.StartLine))
		b.WriteString(" ")
		b.WriteString(string(f.Severity))
		b.WriteString(" ")
		b.WriteString(string(f.Confidence))
		b.WriteString(": ")
		b.WriteString(f.Evidence)
		b.WriteString("\n")
	}
	return b.String()
}

func cawCheck(t *testing.T, rule Rule, path, language, content string, wants ...cawWant) {
	t.Helper()
	got := rule.Check(cawFile(path, language, content))
	sort.SliceStable(got, func(i, j int) bool {
		return got[i].Location.StartLine < got[j].Location.StartLine
	})
	if len(got) != len(wants) {
		t.Fatalf("got %d findings, want %d\n%s", len(got), len(wants), cawDescribe(got))
	}
	for i, want := range wants {
		g := got[i]
		if g.RuleID != rule.Meta().ID {
			t.Errorf("finding %d: rule = %q, want %q", i, g.RuleID, rule.Meta().ID)
		}
		if g.Location.StartLine != want.line {
			t.Errorf("finding %d: line = %d, want %d", i, g.Location.StartLine, want.line)
		}
		if want.sev != "" && g.Severity != want.sev {
			t.Errorf("finding %d: severity = %q, want %q", i, g.Severity, want.sev)
		}
		if g.ID == "" || g.Fingerprint == "" {
			t.Errorf("finding %d: ID/fingerprint not normalised", i)
		}
	}
}

func cawRule(t *testing.T, rs []Rule, id string) Rule {
	t.Helper()
	for _, r := range rs {
		if r.Meta().ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not registered", id)
	return nil
}

func TestExpansionRulesRegistered(t *testing.T) {
	ids := []struct {
		pack []Rule
		id   string
	}{
		{CryptoRules(), "VGL-CRY-013"},
		{CryptoRules(), "VGL-CRY-014"},
		{CryptoRules(), "VGL-CRY-015"},
		{CryptoRules(), "VGL-CRY-017"},
		{AuthRules(), "VGL-AUTH-017"},
		{WebRules(), "VGL-WEB-020"},
	}
	for _, tc := range ids {
		rule := cawRule(t, tc.pack, tc.id)
		m := rule.Meta()
		if m.Title == "" || m.Description == "" || m.Severity.Rank() == 0 || m.Category == "" {
			t.Errorf("%s metadata incomplete: %+v", tc.id, m)
		}
		if len(m.CWE) == 0 || len(m.OWASP) == 0 {
			t.Errorf("%s missing CWE/OWASP mapping", tc.id)
		}
	}
}

// ---------------------------------------------------------------------------
// VGL-CRY-013 — Java trust-all TrustManager / HostnameVerifier
// ---------------------------------------------------------------------------

func TestExpansionJavaTrustAll(t *testing.T) {
	rule := cawRule(t, CryptoRules(), "VGL-CRY-013")
	path := "src/main/java/com/acme/net/TlsClient.java"

	cawCheck(t, rule, path, "java", `SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
}, new SecureRandom());`,
		cawWant{line: 5, sev: model.SeverityCritical})

	cawCheck(t, rule, path, "java", `public class TrustAllCerts implements X509TrustManager {
    public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
        throw new CertificateException("not trusted");
    }
}`,
		cawWant{line: 1, sev: model.SeverityCritical})

	cawCheck(t, rule, path, "java", `HostnameVerifier verifier = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) { return true; }
};`,
		cawWant{line: 2, sev: model.SeverityCritical})

	cawCheck(t, rule, path, "java", `HostnameVerifier verifier = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};`,
		cawWant{line: 2, sev: model.SeverityCritical})

	// Safe: platform trust store and a validating HostnameVerifier.
	cawCheck(t, rule, path, "java", `TrustManagerFactory tmf = TrustManagerFactory.getInstance(
    TrustManagerFactory.getDefaultAlgorithm());
tmf.init((KeyStore) null);
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, tmf.getTrustManagers(), null);`)

	cawCheck(t, rule, path, "java", `public boolean verify(String hostname, SSLSession session) {
    return hostname.equals(session.getPeerHost());
}`)

	// Safe: an abstract declaration has no body, and an import is not a usage.
	cawCheck(t, rule, path, "java", `public abstract class DelegatingTrustManager implements X509TrustManager {
    public abstract void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException;
}`)
	cawCheck(t, rule, path, "java", `import com.acme.net.TrustAllCerts;`)

	// Test paths are still reported, but capped at medium.
	cawCheck(t, rule, "src/test/java/com/acme/TlsClientTest.java", "java",
		`TrustAllCerts trustAll = new TrustAllCerts();`,
		cawWant{line: 1, sev: model.SeverityMedium})
}

// ---------------------------------------------------------------------------
// VGL-CRY-014 — .NET certificate validation callback
// ---------------------------------------------------------------------------

func TestExpansionDotNetTrustAll(t *testing.T) {
	rule := cawRule(t, CryptoRules(), "VGL-CRY-014")
	path := "src/Api/HttpClientFactory.cs"

	cawCheck(t, rule, path, "csharp", `var handler = new HttpClientHandler();
handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
var client = new HttpClient(handler);`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, path, "csharp", `var handler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
};`,
		cawWant{line: 3, sev: model.SeverityHigh})

	cawCheck(t, rule, path, "csharp", `handler.ServerCertificateCustomValidationCallback = (_, _, _, _) =>
{
    return true;
};`,
		cawWant{line: 1, sev: model.SeverityHigh})

	// Safe: the callback inspects SslPolicyErrors.
	cawCheck(t, rule, path, "csharp", `handler.ServerCertificateCustomValidationCallback =
    (_, _, _, errors) => errors == SslPolicyErrors.None;`)

	cawCheck(t, rule, path, "csharp",
		`handler.ServerCertificateCustomValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None;`)
}

// ---------------------------------------------------------------------------
// VGL-CRY-015 — PHP / Ruby TLS verification disabled
// ---------------------------------------------------------------------------

func TestExpansionPHPRubyTLS(t *testing.T) {
	rule := cawRule(t, CryptoRules(), "VGL-CRY-015")
	php := "src/Http/Client.php"

	cawCheck(t, rule, php, "php", `<?php
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);`,
		cawWant{line: 3, sev: model.SeverityHigh},
		cawWant{line: 4, sev: model.SeverityHigh})

	cawCheck(t, rule, php, "php", `$options = [
    CURLOPT_SSL_VERIFYPEER => false,
];`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, php, "php", `$ctx = stream_context_create([
    'ssl' => [
        'verify_peer' => false,
        'allow_self_signed' => true,
    ],
]);`,
		cawWant{line: 3, sev: model.SeverityHigh},
		cawWant{line: 4, sev: model.SeverityHigh})

	// Safe: verification stays enabled.
	cawCheck(t, rule, php, "php", `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);`)

	cawCheck(t, rule, php, "php", `$ctx = stream_context_create([
    'ssl' => [
        'verify_peer' => true,
        'allow_self_signed' => true,
    ],
]);`)

	ruby := "app/lib/http_client.rb"

	cawCheck(t, rule, ruby, "ruby", `http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE`,
		cawWant{line: 3, sev: model.SeverityHigh})

	cawCheck(t, rule, ruby, "ruby", `Faraday.new(url: url, ssl: { verify: false })`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, ruby, "ruby", `http.ssl_verify_mode = 0`,
		cawWant{line: 1, sev: model.SeverityHigh})

	// Safe: peer verification, and `verify: false` outside an SSL client.
	cawCheck(t, rule, ruby, "ruby", `http.verify_mode = OpenSSL::SSL::VERIFY_PEER`)
	cawCheck(t, rule, ruby, "ruby", `opts = { verify: false }`)
}

// ---------------------------------------------------------------------------
// VGL-CRY-017 — legacy SSLv3 / TLS 1.0 / TLS 1.1 pinned
// ---------------------------------------------------------------------------

func TestExpansionLegacyTLSVersion(t *testing.T) {
	rule := cawRule(t, CryptoRules(), "VGL-CRY-017")

	cawCheck(t, rule, "internal/tls/client.go", "go",
		`cfg := &tls.Config{MinVersion: tls.VersionTLS10}`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "internal/tls/client.go", "go",
		`cfg := &tls.Config{MinVersion: tls.VersionTLS12}`)

	cawCheck(t, rule, "internal/tls/client.go", "go", `cfg := &tls.Config{}
cfg.MinVersion = tls.VersionTLS11`,
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, "app/tls.py", "python",
		`ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "app/tls.py", "python", `ctx = ssl.create_default_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_2`)

	cawCheck(t, rule, "src/main/java/com/acme/Tls.java", "java",
		`SSLContext ctx = SSLContext.getInstance("TLSv1.1");`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "src/main/java/com/acme/Tls.java", "java",
		`SSLContext ctx = SSLContext.getInstance("TLSv1.2");`)
	cawCheck(t, rule, "src/main/java/com/acme/Tls.java", "java",
		`sslSocket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.2"});`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, "src/Net/Client.cs", "csharp",
		`ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "src/Net/Client.cs", "csharp",
		`ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;`)
	cawCheck(t, rule, "src/Net/Client.cs", "csharp",
		`var protocols = SslProtocols.None;`)

	cawCheck(t, rule, "src/server.ts", "typescript",
		`const server = https.createServer({ minVersion: "TLSv1" }, app);`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "src/server.ts", "typescript",
		`const server = https.createServer({ minVersion: "TLSv1.2" }, app);`)

	cawCheck(t, rule, "lib/tls.rb", "ruby",
		`ctx.ssl_version = :TLSv1`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "lib/tls.rb", "ruby", `ctx.ssl_version = :TLSv1_2`)

	cawCheck(t, rule, "src/Curl.php", "php",
		`$opts = [CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1];`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, "src/Curl.php", "php",
		`$opts = [CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2];`)
}

// ---------------------------------------------------------------------------
// VGL-AUTH-017 — OAuth redirect_uri taken from request data
// ---------------------------------------------------------------------------

func TestExpansionOAuthRedirectFromRequest(t *testing.T) {
	rule := cawRule(t, AuthRules(), "VGL-AUTH-017")
	js := "src/auth/oauth.ts"

	cawCheck(t, rule, js, "typescript",
		"const redirectUri = req.query.redirect_uri;\nconst url = `${authorizeUrl}?client_id=${id}&redirect_uri=${redirectUri}`;",
		cawWant{line: 1, sev: model.SeverityHigh},
		cawWant{line: 2, sev: model.SeverityHigh})

	cawCheck(t, rule, "src/main/java/com/acme/OAuthController.java", "java", `String redirectUri = request.getParameter("redirect_uri");
response.sendRedirect(redirectUri);`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, "app/oauth.py", "python",
		`redirect_uri = request.args.get("redirect_uri")`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, "public/oauth.php", "php", `$redirect = $_GET['redirect_uri'];
header('Location: ' . $redirect);`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, "internal/oauth/handler.go", "go",
		`redirectURI := r.URL.Query().Get("redirect_uri")`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, "src/OAuth/Callback.cs", "csharp",
		`string redirectUri = Request.QueryString["redirect_uri"];`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, "app/controllers/oauth_controller.rb", "ruby",
		`redirect_uri = params[:redirect_uri]`,
		cawWant{line: 1, sev: model.SeverityHigh})

	// Safe: the requested value is resolved through an allow-list.
	cawCheck(t, rule, js, "typescript", `const requested = req.query.redirect_uri;
const redirectUri = ALLOWED_REDIRECTS.has(requested)
  ? requested
  : DEFAULT_REDIRECT;`)

	// Safe: static callback URL and a configured value.
	cawCheck(t, rule, js, "typescript",
		"const url = `${authorizeUrl}?client_id=${id}&redirect_uri=${encodeURIComponent(CALLBACK_URL)}`;")
	cawCheck(t, rule, js, "typescript", `const redirectUri = config.redirectUri;`)
	cawCheck(t, rule, js, "typescript", `const redirect_uri = "https://app.example/callback";`)
	cawCheck(t, rule, js, "typescript",
		`if (redirect_uri === req.query.redirect_uri) { return; }`)

	// Tests are out of scope for this rule.
	cawCheck(t, rule, "src/auth/oauth.test.ts", "typescript",
		`const redirectUri = req.query.redirect_uri;`)
}

// ---------------------------------------------------------------------------
// VGL-WEB-020 — Spring Boot actuator exposure
// ---------------------------------------------------------------------------

func TestExpansionSpringActuatorExposure(t *testing.T) {
	rule := cawRule(t, WebRules(), "VGL-WEB-020")
	yml := "src/main/resources/application.yml"
	props := "src/main/resources/application.properties"

	cawCheck(t, rule, yml, "yaml", `management:
  endpoints:
    web:
      exposure:
        include: "*"`,
		cawWant{line: 5, sev: model.SeverityHigh})

	cawCheck(t, rule, yml, "yaml", `management:
  endpoints:
    web:
      exposure:
        include: health,info`)

	cawCheck(t, rule, yml, "yaml", `management:
  endpoints:
    web:
      exposure:
        include: [env, heapdump]`,
		cawWant{line: 5, sev: model.SeverityHigh})

	cawCheck(t, rule, props, "other", `management.endpoints.web.exposure.include=*`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, props, "other", `management.endpoints.web.exposure.include="*"`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, props, "other", `management.endpoints.web.exposure.include=health,env,heapdump`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, props, "other", `management.endpoints.web.exposure.include=health,info`)
	cawCheck(t, rule, props, "other", `management.endpoints.web.exposure.exclude=*`)

	cawCheck(t, rule, props, "other", `management.security.enabled=false`,
		cawWant{line: 1, sev: model.SeverityHigh})
	cawCheck(t, rule, props, "other", `management.endpoint.shutdown.enabled=true`,
		cawWant{line: 1, sev: model.SeverityHigh})

	cawCheck(t, rule, yml, "yaml", `management:
  endpoint:
    shutdown:
      enabled: true`,
		cawWant{line: 4, sev: model.SeverityHigh})
	cawCheck(t, rule, yml, "yaml", `management:
  endpoint:
    shutdown:
      enabled: false`)
	cawCheck(t, rule, yml, "yaml", `management:
  security:
    enabled: false`,
		cawWant{line: 3, sev: model.SeverityHigh})

	// Only Spring configuration files are in scope.
	cawCheck(t, rule, "config/app.yml", "yaml", `include: "*"`)

	// Safe: an unrelated include and a health-details security switch that is
	// not `management.security.enabled`.
	cawCheck(t, rule, yml, "yaml", `other:
  exposure:
    include: "*"
management:
  endpoints:
    web:
      exposure:
        exclude: "*"`)
	cawCheck(t, rule, yml, "yaml", `management:
  endpoint:
    health:
      security:
        enabled: false`)

	// Dev/test profiles are capped instead of silently ignored.
	cawCheck(t, rule, "src/main/resources/application-dev.yml", "yaml", `management:
  endpoints:
    web:
      exposure:
        include: "*"`,
		cawWant{line: 5, sev: model.SeverityMedium})
}
