package rules

import (
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// These tests pin the precision fixes that came out of the backend scan:
// every case is a real shape from that scan or the canonical true positive the
// rule must keep.

func precisionRule(t *testing.T, rs []Rule, id string) Rule {
	t.Helper()
	for _, r := range rs {
		if r.Meta().ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not registered", id)
	return nil
}

func precisionCheck(t *testing.T, rule Rule, path, language, content string) []model.Finding {
	t.Helper()
	return rule.Check(packBFile(path, language, content))
}

func TestPrecisionAuth006SkipsEnumsAndTypes(t *testing.T) {
	rule := precisionRule(t, AuthRules(), "VGL-AUTH-006")
	cases := []struct {
		name    string
		path    string
		lang    string
		content string
		want    int
	}{
		{
			name: "enum member",
			path: "src/users/entities/user.entity.ts",
			lang: "typescript",
			content: `export enum UserAuthProvider {
  PASSWORD = 'password',
  GOOGLE = 'google',
}`,
			want: 0,
		},
		{
			name: "const enum member",
			path: "src/users/mode.ts",
			lang: "typescript",
			content: `const enum Mode {
  PASSWORD = 'password',
}`,
			want: 0,
		},
		{
			name: "interface property",
			path: "src/users/creds.ts",
			lang: "typescript",
			content: `interface Creds {
  password: 'admin';
}`,
			want: 0,
		},
		{
			name: "type alias property",
			path: "src/users/creds.ts",
			lang: "typescript",
			content: `type Creds = {
  password: 'admin';
};`,
			want: 0,
		},
		{
			name:    "default constant",
			path:    "config/settings.py",
			lang:    "python",
			content: `DEFAULT_PASSWORD = 'admin'`,
			want:    1,
		},
		{
			name:    "camel case default",
			path:    "src/users/config.ts",
			lang:    "typescript",
			content: `adminPassword: 'admin'`,
			want:    1,
		},
		{
			name:    "plain assignment",
			path:    "config/settings.py",
			lang:    "python",
			content: `password = 'admin'`,
			want:    1,
		},
		{
			name:    "non default value",
			path:    "config/settings.py",
			lang:    "python",
			content: `password = 'Xk9!mQ2p'`,
			want:    0,
		},
		{
			name:    "unquoted variable in code",
			path:    "src/users/account-close.service.test.ts",
			lang:    "typescript",
			content: `currentPassword: password,`,
			want:    0,
		},
		{
			name:    "default word with suffix",
			path:    "src/users/account-close.service.test.ts",
			lang:    "typescript",
			content: `currentPassword: 'password1',`,
			want:    0,
		},
		{
			name:    "quoted default in test fixture",
			path:    "src/users/account-close.service.test.ts",
			lang:    "typescript",
			content: `currentPassword: 'admin',`,
			want:    1,
		},
		{
			name:    "translation catalog label",
			path:    "i18n/locales/en.json",
			lang:    "json",
			content: `"auth.login.password": "Password",`,
			want:    0,
		},
		{
			name:    "translation shard label",
			path:    "i18n/shards/en.public.json",
			lang:    "json",
			content: `"admin.users.create.password": "Password",`,
			want:    0,
		},
		{
			name:    "real json default is still reported",
			path:    "config/app.json",
			lang:    "json",
			content: `"admin.password": "admin",`,
			want:    1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, tc.path, tc.lang, tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionCry001AllowsTOTPAndHMAC(t *testing.T) {
	rule := precisionRule(t, CryptoRules(), "VGL-CRY-001")
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{
			name:    "hmac sha1 for totp",
			content: `const hmac = createHmac('sha1', secret).update(buf).digest();`,
			want:    0,
		},
		{
			name:    "otpauth uri",
			content: "return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;",
			want:    0,
		},
		{
			name:    "hmac sha1 helper",
			content: `return HmacSHA1(secret, message);`,
			want:    0,
		},
		{
			name:    "md5 password",
			content: `const sum = md5(password);`,
			want:    1,
		},
		{
			name:    "sha1 password",
			content: `hash = sha1(password)`,
			want:    1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, "src/auth/hash.ts", "typescript", tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionSec014RejectsNamesAndLabels(t *testing.T) {
	rule := precisionRule(t, SecretsRules(), "VGL-SEC-014")
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "env var mapping",
			content: `const env = {
  brand_token: 'TELEGRAM_BOT_TOKEN',
};`,
			want: 0,
		},
		{
			name:    "human label with whitespace",
			content: `webhook_secret: 'Webhook / forward secret',`,
			want:    0,
		},
		{
			name:    "second env var mapping",
			content: `chat_id_key: 'TELEGRAM_CHAT_ID_ENCRYPTION_KEY',`,
			want:    0,
		},
		{
			name:    "lowercase identifier",
			content: `signing_secret: 'signing_secret',`,
			want:    0,
		},
		{
			name:    "kebab case label",
			content: `token: 'raw-token-value',`,
			want:    0,
		},
		{
			name:    "real mixed secret",
			content: `apiKey: 'Qz7mK2pL9vN4sT8x',`,
			want:    1,
		},
		{
			name:    "real secret with symbol",
			content: `token: 'SuperSecretPassword123!',`,
			want:    1,
		},
		{
			name:    "long passphrase without digits",
			content: `password: 'QwErTyUiOpAsDfGhJkLzXcVbNm',`,
			want:    1,
		},
		{
			name:    "long high entropy mixed case",
			content: `secret: 'PlOkIjUhYgTfRdEsWaQzXcVbNm',`,
			want:    1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, "src/config.ts", "typescript", tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionAuth007SkipsTypeGuardsAndOverloadedTokens(t *testing.T) {
	rule := precisionRule(t, AuthRules(), "VGL-AUTH-007")
	cases := []struct {
		name    string
		path    string
		lang    string
		content string
		want    int
	}{
		{
			name:    "typeof guard",
			path:    "src/common/guards/api-key.guard.ts",
			lang:    "typescript",
			content: `if (typeof apiKey !== 'string' || apiKey.length === 0) {`,
			want:    0,
		},
		{
			name:    "length check",
			path:    "src/editorial/digest.ts",
			lang:    "typescript",
			content: `if (currentCollections.length !== digest.collections.length) {`,
			want:    0,
		},
		{
			name:    "dedupe token comparison",
			path:    "src/agent/lib/alert-dedupe.ts",
			lang:    "typescript",
			content: `if (!existing || existing.token !== token) {`,
			want:    0,
		},
		{
			name:    "single letter callback token",
			path:    "src/business/promo-card.ts",
			lang:    "typescript",
			content: `if (token !== 'c' && token !== 'x' && token !== 'v') return null;`,
			want:    0,
		},
		{
			name:    "sentinel hash",
			path:    "src/city-tools/city-tools.service.ts",
			lang:    "typescript",
			content: `return principal.hash === '-';`,
			want:    0,
		},
		{
			name:    "digest object identity",
			path:    "src/share-cards/share-cards.service.ts",
			lang:    "typescript",
			content: `return slug === digest.slug ? digest : null;`,
			want:    0,
		},
		{
			name:    "cache hash comparison",
			path:    "src/fx/fx-retail.service.ts",
			lang:    "typescript",
			content: `if (this.lastPublishedRetailHash === hash) {`,
			want:    0,
		},
		{
			name:    "cyrillic word token",
			path:    "src/news/facts.ts",
			lang:    "typescript",
			content: `if (token === 'Администрация') return true;`,
			want:    0,
		},
		{
			name:    "bytewise signature sniff",
			path:    "src/ai-attachments/sniff.ts",
			lang:    "typescript",
			content: `if (bytes[i] !== signature[i]) return false;`,
			want:    0,
		},
		{
			name:    "trim only",
			path:    "src/ai-proxy/secrets.service.ts",
			lang:    "typescript",
			content: `if (typeof patch.apiKey === 'string' && patch.apiKey.trim()) {`,
			want:    0,
		},
		{
			name:    "weak token outside auth path",
			path:    "src/fx/rates.ts",
			lang:    "typescript",
			content: `if (token !== expectedToken) {`,
			want:    0,
		},
		{
			name:    "api key comparison",
			path:    "src/auth/internal-auth.service.ts",
			lang:    "typescript",
			content: `if (apiKey !== validApiKey) {`,
			want:    1,
		},
		{
			name:    "password compare",
			path:    "src/auth/login.py",
			lang:    "python",
			content: "def check(password, stored):\n    return password == stored",
			want:    1,
		},
		{
			name:    "weak token in auth path",
			path:    "src/auth/session.ts",
			lang:    "typescript",
			content: `if (token !== expectedToken) {`,
			want:    1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, tc.path, tc.lang, tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionInj005DynamicImportOnly(t *testing.T) {
	rule := precisionRule(t, InjectionRules(), "VGL-INJ-005")
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{
			name:    "prose with spaced import",
			content: `summary: 'Retail phase outcome from worker scrape+import (skips Nest adapter HTTP)',`,
			want:    0,
		},
		{
			name:    "import inside a string",
			content: `const code = 'return import(specifier)';`,
			want:    0,
		},
		{
			name:    "import in a comment",
			content: `// import(specifier)`,
			want:    0,
		},
		{
			name:    "literal require",
			content: `const cfg = require("./config");`,
			want:    0,
		},
		{
			name:    "static template literal",
			content: "const m = await import(`./plugin`);",
			want:    0,
		},
		{
			name:    "dynamic import",
			content: `await import(specifier);`,
			want:    1,
		},
		{
			name:    "dynamic require",
			content: `const pw = require(pwPath) as { chromium: unknown };`,
			want:    1,
		},
		{
			name:    "dynamic template literal",
			content: "const m = await import(`./plugins/${name}`);",
			want:    1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, "src/loader.ts", "typescript", tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionCfg009OnlyRealSocketMounts(t *testing.T) {
	rule := precisionRule(t, ConfigRules(), "VGL-CFG-009")
	cases := []struct {
		name    string
		path    string
		lang    string
		content string
		want    int
	}{
		{
			name:    "string constant",
			path:    "src/cleaner/host-disk-env.ts",
			lang:    "typescript",
			content: `const DEFAULT_SOCKET = '/var/run/docker.sock';`,
			want:    0,
		},
		{
			name:    "client option",
			path:    "src/cleaner/actions.test.ts",
			lang:    "typescript",
			content: `socketPath: '/var/run/docker.sock',`,
			want:    0,
		},
		{
			name: "compose short syntax",
			path: "docker-compose.yml",
			lang: "yaml",
			content: `services:
  app:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock`,
			want: 1,
		},
		{
			name: "compose quoted short syntax",
			path: "docker-compose.yml",
			lang: "yaml",
			content: `services:
  app:
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"`,
			want: 1,
		},
		{
			name: "compose long syntax",
			path: "docker-compose.yml",
			lang: "yaml",
			content: `services:
  app:
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock`,
			want: 1,
		},
		{
			name:    "docker cli flag",
			path:    "scripts/run.sh",
			lang:    "shell",
			content: `docker run -v /var/run/docker.sock:/var/run/docker.sock app`,
			want:    1,
		},
		{
			name: "kubernetes hostPath",
			path: "k8s/deployment.yaml",
			lang: "yaml",
			content: `apiVersion: v1
kind: Pod
spec:
  volumes:
    - name: sock
      hostPath:
        path: /var/run/docker.sock`,
			want: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, tc.path, tc.lang, tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionWeb006RequiresGraphQLContext(t *testing.T) {
	rule := precisionRule(t, WebRules(), "VGL-WEB-006")
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "assistant dto without graphql",
			content: `return {
  channel,
  playground: true,
  actorUserId,
};`,
			want: 0,
		},
		{
			name:    "prose mention",
			content: `'playground:true and actorUserId. No SSE. Scope: ops:assistant (ADMIN only). ' +`,
			want:    0,
		},
		{
			name: "apollo server context",
			content: `const server = new ApolloServer({
  typeDefs,
  resolvers,
  playground: true,
});`,
			want: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, "src/assistant/admin.service.ts", "typescript", tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionWeb012OnlyServerDebugFlags(t *testing.T) {
	rule := precisionRule(t, WebRules(), "VGL-WEB-012")
	cases := []struct {
		name    string
		path    string
		lang    string
		content string
		want    int
	}{
		{
			name:    "dto object literal",
			path:    "src/fx/summary.test.ts",
			lang:    "typescript",
			content: `rawSource: { debug: true },`,
			want:    0,
		},
		{
			name:    "typescript dto",
			path:    "src/fx/dto/summary.ts",
			lang:    "typescript",
			content: `rawSource: { debug: true },`,
			want:    0,
		},
		{
			name: "flask app run",
			path: "src/web/main.py",
			lang: "python",
			content: `from flask import Flask
app = Flask(__name__)
if __name__ == '__main__':
    app.run(debug=True)`,
			want: 1,
		},
		{
			name:    "django settings debug",
			path:    "src/settings.py",
			lang:    "python",
			content: `DEBUG = True`,
			want:    1,
		},
		{
			name: "yaml config debug",
			path: "config/application.yaml",
			lang: "yaml",
			content: `server:
  debug: true`,
			want: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, tc.path, tc.lang, tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestPrecisionWeb007SkipsURLHosts(t *testing.T) {
	rule := precisionRule(t, WebRules(), "VGL-WEB-007")
	got := precisionCheck(t, rule, "src/ai-proxy/secrets.service.ts", "typescript",
		`'xAI key looks invalid. Create a key at https://console.x.ai (official Grok API).',`)
	if len(got) != 0 {
		t.Fatalf("URL host matched as a debug endpoint: %+v", got)
	}
	got = precisionCheck(t, rule, "src/web/routes.py", "python", `@app.route('/debug')`)
	if len(got) != 1 {
		t.Fatalf("real debug route lost: got %d findings, want 1", len(got))
	}
}

func TestPrecisionWeb009SkipsReservedHostsAndTests(t *testing.T) {
	rule := precisionRule(t, WebRules(), "VGL-WEB-009")
	cases := []struct {
		name    string
		path    string
		lang    string
		content string
		want    int
	}{
		{
			name:    "dot test host",
			path:    "src/cinema/client.ts",
			lang:    "typescript",
			content: `const url = 'http://cinema.test/cinema/internal/sessions';`,
			want:    0,
		},
		{
			name:    "dot example host",
			path:    "config/prod.yaml",
			lang:    "yaml",
			content: `auth_url: http://auth.example/login`,
			want:    0,
		},
		{
			name:    "localhost",
			path:    "config/prod.yaml",
			lang:    "yaml",
			content: `auth_url: http://localhost:3000/login`,
			want:    0,
		},
		{
			name:    "test file with real host",
			path:    "src/auth/client.test.ts",
			lang:    "typescript",
			content: `const url = 'http://auth.internal.corp/login';`,
			want:    0,
		},
		{
			name:    "real non local endpoint",
			path:    "config/prod.yaml",
			lang:    "yaml",
			content: `auth_url: http://auth.internal.corp/login`,
			want:    1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := precisionCheck(t, rule, tc.path, tc.lang, tc.content)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestSeverityForLanguageCapsAreIdempotent(t *testing.T) {
	levels := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}
	paths := []struct {
		path string
		max  model.Severity
	}{
		{"pkg/tests/test_app.py", model.SeverityMedium},
		{"internal/rules/secrets_test.go", model.SeverityMedium},
		{"src/fixtures/user.json", model.SeverityMedium},
		{"examples/demo.py", model.SeverityMedium},
		{"docs/security.md", model.SeverityLow},
		{"docs/setup.MD", model.SeverityLow},
		{"README.md", model.SeverityLow},
	}
	for _, p := range paths {
		for _, base := range levels {
			got := SeverityForLanguage(base, p.path)
			want := base
			if base.Rank() > p.max.Rank() {
				want = p.max
			}
			if got != want {
				t.Errorf("SeverityForLanguage(%q, %q) = %q, want %q", base, p.path, got, want)
			}
			if twice := SeverityForLanguage(got, p.path); twice != got {
				t.Errorf("SeverityForLanguage not idempotent for %q/%q: %q then %q", base, p.path, got, twice)
			}
		}
	}
}
