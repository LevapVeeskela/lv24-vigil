package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ---------------------------------------------------------------------------
// Helpers for the pack-B tests. Names are prefixed so parallel rule packs can
// add their own test helpers without collisions.
// ---------------------------------------------------------------------------

type packBWant struct {
	ruleID   string
	line     int
	severity model.Severity
}

type packBCase struct {
	name string
	file *File
	want []packBWant
}

func packBFile(path, language, content string) *File {
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

func packBFileAt(abs, path, language, content string) *File {
	f := packBFile(path, language, content)
	f.AbsPath = abs
	return f
}

func packBRun(rs []Rule, f *File) []model.Finding {
	var out []model.Finding
	for _, r := range rs {
		out = append(out, r.Check(f)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Location.StartLine < out[j].Location.StartLine
	})
	return out
}

func packBRunCases(t *testing.T, rs []Rule, cases []packBCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := packBRun(rs, tc.file)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d\n%s", len(got), len(tc.want), packBDescribe(got))
			}
			for i, want := range tc.want {
				g := got[i]
				if g.RuleID != want.ruleID {
					t.Errorf("finding %d: rule = %q, want %q", i, g.RuleID, want.ruleID)
				}
				if g.Location.StartLine != want.line {
					t.Errorf("finding %d (%s): line = %d, want %d", i, g.RuleID, g.Location.StartLine, want.line)
				}
				if g.Severity != want.severity {
					t.Errorf("finding %d (%s): severity = %q, want %q", i, g.RuleID, g.Severity, want.severity)
				}
				if g.ID == "" || g.Fingerprint == "" {
					t.Errorf("finding %d (%s): ID/fingerprint not normalised", i, g.RuleID)
				}
				if g.Location.Path != tc.file.Path {
					t.Errorf("finding %d (%s): path = %q, want %q", i, g.RuleID, g.Location.Path, tc.file.Path)
				}
			}
		})
	}
}

func packBDescribe(fs []model.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  ")
		b.WriteString(f.RuleID)
		b.WriteString(" line ")
		b.WriteString(strconv.Itoa(f.Location.StartLine))
		b.WriteString(" ")
		b.WriteString(string(f.Severity))
		b.WriteString(": ")
		b.WriteString(f.Evidence)
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

func TestPackBCryptoRules(t *testing.T) {
	cases := []packBCase{
		{
			name: "md5 used for password",
			file: packBFile("src/auth/hash.go", "go", `package auth

import "crypto/md5"

func hashPassword(password string) []byte {
	sum := md5.Sum([]byte(password))
	return sum[:]
}`),
			want: []packBWant{{"VGL-CRY-001", 6, model.SeverityHigh}},
		},
		{
			name: "go tls skip verify",
			file: packBFile("src/client/client.go", "go", `package client

import "crypto/tls"

func config() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}`),
			want: []packBWant{{"VGL-CRY-007", 6, model.SeverityHigh}},
		},
		{
			name: "python verify false",
			file: packBFile("src/api/client.py", "python", `import requests

def get(url):
    return requests.get(url, verify=False)`),
			want: []packBWant{{"VGL-CRY-008", 4, model.SeverityHigh}},
		},
		{
			name: "math random token",
			file: packBFile("src/session.js", "javascript", `function newToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}`),
			want: []packBWant{{"VGL-CRY-005", 2, model.SeverityHigh}},
		},
		{
			name: "static iv",
			file: packBFile("src/crypto/aes.py", "python", `from Crypto.Cipher import AES
iv = b"0123456789abcdef"
cipher = AES.new(key, AES.MODE_CBC, iv)`),
			want: []packBWant{{"VGL-CRY-004", 2, model.SeverityHigh}},
		},
		{
			name: "bcrypt cost four",
			file: packBFile("src/auth/password.go", "go", `package auth

import "golang.org/x/crypto/bcrypt"

func hash(pw []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(pw, 4)
}`),
			want: []packBWant{{"VGL-CRY-006", 6, model.SeverityMedium}},
		},
		{
			name: "jwt none algorithm",
			file: packBFile("src/auth/jwt.go", "go", `package auth

var config = map[string]string{"alg": "none"}`),
			want: []packBWant{{"VGL-CRY-011", 3, model.SeverityCritical}},
		},
		{
			name: "negative strong hashing and csprng",
			file: packBFile("src/auth/hash.py", "python", `import hashlib
import secrets

def hash_password(password):
    salt = secrets.token_bytes(16)
    return hashlib.sha256(salt + password.encode()).hexdigest()

def new_token():
    return secrets.token_urlsafe(32)`),
		},
	}
	packBRunCases(t, CryptoRules(), cases)
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

func TestPackBAuthRules(t *testing.T) {
	cases := []packBCase{
		{
			name: "jwt decode without verification in node",
			file: packBFile("src/auth/session.js", "javascript", `const jwt = require('jsonwebtoken');

function who(token) {
  return jwt.decode(token);
}`),
			want: []packBWant{{"VGL-AUTH-001", 4, model.SeverityHigh}},
		},
		{
			name: "jwt verification disabled in python",
			file: packBFile("src/auth/tokens.py", "python", `import jwt

def claims(token):
    return jwt.decode(token, options={"verify_signature": False})`),
			want: []packBWant{{"VGL-AUTH-002", 4, model.SeverityCritical}},
		},
		{
			name: "cookie without httponly",
			file: packBFile("src/web/session.js", "javascript", `function login(res, sid) {
  res.cookie('sid', sid, { httpOnly: false, secure: true });
}`),
			want: []packBWant{{"VGL-AUTH-003", 2, model.SeverityMedium}},
		},
		{
			name: "cors wildcard with credentials",
			file: packBFile("src/web/cors.js", "javascript", `app.use(cors({
  origin: '*',
  credentials: true
}));`),
			want: []packBWant{{"VGL-AUTH-004", 2, model.SeverityHigh}},
		},
		{
			name: "django csrf exempt",
			file: packBFile("src/web/views.py", "python", `from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def update(request):
    return None`),
			want: []packBWant{{"VGL-AUTH-005", 3, model.SeverityMedium}},
		},
		{
			name: "default admin password",
			file: packBFile("config/settings.py", "python", `ADMIN_PASSWORD = "admin"`),
			want: []packBWant{{"VGL-AUTH-006", 1, model.SeverityCritical}},
		},
		{
			name: "timing unsafe password compare",
			file: packBFile("src/auth/login.py", "python", `def check(password, stored):
    return password == stored`),
			want: []packBWant{{"VGL-AUTH-007", 2, model.SeverityMedium}},
		},
		{
			name: "oauth authorize without state",
			file: packBFile("src/auth/oauth.py", "python", `def login_url(client_id):
    return f"https://id.example.com/oauth/authorize?response_type=code&client_id={client_id}"`),
			want: []packBWant{{"VGL-AUTH-008", 2, model.SeverityMedium}},
		},
		{
			name: "role taken from request header",
			file: packBFile("src/auth/admin.js", "javascript", `function isAdmin(req) {
  return req.headers['x-user-role'] === 'admin';
}`),
			want: []packBWant{{"VGL-AUTH-009", 2, model.SeverityHigh}},
		},
		{
			name: "negative verified jwt and secure cookie",
			file: packBFile("src/auth/session.js", "javascript", `const jwt = require('jsonwebtoken');

function who(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}

function login(res, sid) {
  res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'lax' });
}`),
		},
	}
	packBRunCases(t, AuthRules(), cases)
}

// ---------------------------------------------------------------------------
// Web
// ---------------------------------------------------------------------------

func TestPackBWebRules(t *testing.T) {
	cases := []packBCase{
		{
			name: "ssrf through fetch",
			file: packBFile("src/api/proxy.js", "javascript", `app.get('/fetch', async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});`),
			want: []packBWant{{"VGL-WEB-001", 2, model.SeverityHigh}},
		},
		{
			name: "path traversal through filepath join",
			file: packBFile("src/files/download.go", "go", `package files

import (
	"net/http"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	p := filepath.Join("/srv/files", name)
	http.ServeFile(w, r, p)
}`),
			want: []packBWant{{"VGL-WEB-002", 10, model.SeverityHigh}},
		},
		{
			name: "open redirect",
			file: packBFile("src/web/login.js", "javascript", `function afterLogin(req, res) {
  res.redirect(req.query.next);
}`),
			want: []packBWant{{"VGL-WEB-003", 2, model.SeverityMedium}},
		},
		{
			name: "debug endpoint with security headers configured",
			file: packBFile("src/server/routes.py", "python", `from flask import Flask
app = Flask(__name__)
app.config['CONTENT_SECURITY_POLICY'] = "default-src 'self'"
@app.route('/debug')
def debug():
    return 'ok'`),
			want: []packBWant{{"VGL-WEB-007", 4, model.SeverityMedium}},
		},
		{
			name: "permissive cors",
			file: packBFile("src/web/server.js", "javascript", `const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const app = express();
app.use(helmet());
app.use(cors());
app.get('/health', (req, res) => res.send('ok'));`),
			want: []packBWant{{"VGL-WEB-004", 6, model.SeverityMedium}},
		},
		{
			name: "server without security headers",
			file: packBFile("src/web/app.js", "javascript", `const express = require('express');
const app = express();
app.get('/ping', (req, res) => res.send('pong'));`),
			want: []packBWant{{"VGL-WEB-005", 2, model.SeverityInfo}},
		},
		{
			name: "graphql introspection enabled",
			file: packBFile("src/graphql/schema.js", "javascript", `const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true
});`),
			want: []packBWant{{"VGL-WEB-006", 4, model.SeverityMedium}},
		},
		{
			name: "directory listing enabled",
			file: packBFile("src/web/static.js", "javascript", `app.use(serveIndex('public'));`),
			want: []packBWant{{"VGL-WEB-008", 1, model.SeverityMedium}},
		},
		{
			name: "plain http auth endpoint",
			file: packBFile("config/prod.yaml", "yaml", `auth_url: http://auth.internal.corp/login`),
			want: []packBWant{{"VGL-WEB-009", 1, model.SeverityMedium}},
		},
		{
			name: "localhost in production config",
			file: packBFile("config/production.yaml", "yaml", `database:
  host: localhost`),
			want: []packBWant{{"VGL-WEB-010", 2, model.SeverityInfo}},
		},
		{
			name: "host header in reset link",
			file: packBFile("src/auth/reset.py", "python", `def reset_link(request):
    return "https://" + request.get_host() + "/reset"`),
			want: []packBWant{{"VGL-WEB-011", 2, model.SeverityMedium}},
		},
		{
			name: "flask debug mode",
			file: packBFile("src/web/main.py", "python", `from flask import Flask
app = Flask(__name__)
if __name__ == '__main__':
    app.run(debug=True)`),
			want: []packBWant{{"VGL-WEB-012", 4, model.SeverityHigh}},
		},
		{
			name: "negative constant api url",
			file: packBFile("src/api/client.js", "javascript", `const API = 'https://api.example.com/v1';

async function load() {
  const r = await fetch(API + '/status');
  return r.json();
}`),
		},
	}
	packBRunCases(t, WebRules(), cases)
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

func TestPackBConfigRules(t *testing.T) {
	cases := []packBCase{
		{
			name: "dockerfile without user",
			file: packBFile("Dockerfile", "dockerfile", `FROM golang:1.22
WORKDIR /app
COPY . .
CMD ["./app"]`),
			want: []packBWant{{"VGL-CFG-001", 1, model.SeverityMedium}},
		},
		{
			name: "dockerfile latest apt secret curl pipe",
			file: packBFile("Dockerfile", "dockerfile", `FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ENV API_KEY=super-secret-value-123
RUN curl -fsSL https://example.com/install.sh | sh
USER app`),
			want: []packBWant{
				{"VGL-CFG-002", 1, model.SeverityLow},
				{"VGL-CFG-003", 2, model.SeverityLow},
				{"VGL-CFG-005", 3, model.SeverityHigh},
				{"VGL-CFG-006", 4, model.SeverityMedium},
			},
		},
		{
			name: "dockerfile add remote url",
			file: packBFile("Dockerfile", "dockerfile", `FROM alpine:3.19
ADD https://example.com/tool.tar.gz /opt/tool.tar.gz
USER app`),
			want: []packBWant{{"VGL-CFG-004", 2, model.SeverityMedium}},
		},
		{
			name: "compose privileged host network socket and sysadmin",
			file: packBFile("docker-compose.yml", "yaml", `services:
  app:
    image: myapp:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    cap_add:
      - SYS_ADMIN`),
			want: []packBWant{
				{"VGL-CFG-007", 4, model.SeverityHigh},
				{"VGL-CFG-008", 5, model.SeverityMedium},
				{"VGL-CFG-009", 7, model.SeverityHigh},
				{"VGL-CFG-010", 9, model.SeverityHigh},
				{"VGL-CFG-011", 3, model.SeverityLow},
			},
		},
		{
			name: "kubernetes host access and privileged",
			file: packBFile("k8s/deployment.yaml", "yaml", `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          securityContext:
            privileged: true
            runAsUser: 0
          volumeMounts:
            - name: host
              mountPath: /host
      volumes:
        - name: host
          hostPath:
            path: /`),
			want: []packBWant{
				{"VGL-CFG-012", 6, model.SeverityMedium},
				{"VGL-CFG-012", 10, model.SeverityHigh},
				{"VGL-CFG-012", 11, model.SeverityMedium},
				{"VGL-CFG-012", 17, model.SeverityHigh},
			},
		},
		{
			name: "terraform public ssh public bucket unencrypted volume",
			file: packBFile("infra/main.tf", "terraform", `resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "public" {
  bucket = "example"
  acl    = "public-read"
}
resource "aws_ebs_volume" "data" {
  encrypted = false
}`),
			want: []packBWant{
				{"VGL-CFG-013", 5, model.SeverityHigh},
				{"VGL-CFG-014", 10, model.SeverityHigh},
				{"VGL-CFG-015", 13, model.SeverityMedium},
			},
		},
		{
			name: "nginx autoindex",
			file: packBFile("infra/nginx/site.conf", "other", `server {
    location /files/ {
        autoindex on;
    }
}`),
			want: []packBWant{{"VGL-CFG-016", 3, model.SeverityMedium}},
		},
		{
			name: "committed env file",
			file: packBFile(".env", "other", `DATABASE_URL=postgres://user:pass@db:5432/app`),
			want: []packBWant{{"VGL-CFG-017", 1, model.SeverityMedium}},
		},
		{
			name: "negative pinned dockerfile",
			file: packBFile("Dockerfile", "dockerfile", `FROM golang:1.22@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
COPY . /app
USER nonroot
CMD ["/app"]`),
		},
	}
	packBRunCases(t, ConfigRules(), cases)
}

// ---------------------------------------------------------------------------
// CI
// ---------------------------------------------------------------------------

func TestPackBCIRules(t *testing.T) {
	cases := []packBCase{
		{
			name: "actions pinned to tags",
			file: packBFile(".github/workflows/ci.yml", "yaml", `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5`),
			want: []packBWant{
				{"VGL-CI-001", 7, model.SeverityHigh},
				{"VGL-CI-001", 8, model.SeverityHigh},
			},
		},
		{
			name: "pull request target checks out pr head",
			file: packBFile(".github/workflows/pr.yml", "yaml", `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          ref: ${{ github.event.pull_request.head.sha }}`),
			want: []packBWant{{"VGL-CI-002", 8, model.SeverityCritical}},
		},
		{
			name: "run step interpolates pr title",
			file: packBFile(".github/workflows/title.yml", "yaml", `on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"`),
			want: []packBWant{{"VGL-CI-003", 6, model.SeverityHigh}},
		},
		{
			name: "write all self hosted secrets inherit echo and pipe",
			file: packBFile(".github/workflows/risky.yml", "yaml", `on: push
permissions: write-all
jobs:
  test:
    runs-on: self-hosted
    secrets: inherit
    steps:
      - run: echo "${{ secrets.TOKEN }}"
      - run: curl -fsSL https://example.com/i.sh | bash`),
			want: []packBWant{
				{"VGL-CI-004", 2, model.SeverityMedium},
				{"VGL-CI-005", 6, model.SeverityLow},
				{"VGL-CI-006", 9, model.SeverityMedium},
				{"VGL-CI-007", 8, model.SeverityHigh},
				{"VGL-CI-008", 5, model.SeverityHigh},
			},
		},
		{
			name: "artifact upload includes hidden files",
			file: packBFile(".github/workflows/artifact.yml", "yaml", `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567
        with:
          name: build
          path: .*`),
			want: []packBWant{{"VGL-CI-009", 9, model.SeverityLow}},
		},
		{
			name: "gitlab security job allowed to fail",
			file: packBFile(".gitlab-ci.yml", "yaml", `stages:
  - test
security-scan:
  stage: test
  script:
    - semgrep --config auto .
  allow_failure: true`),
			want: []packBWant{{"VGL-CI-010", 7, model.SeverityInfo}},
		},
		{
			name: "jenkins sh interpolates params",
			file: packBFile("Jenkinsfile", "groovy", `pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        sh "echo ${params.VERSION}"
      }
    }
  }
}`),
			want: []packBWant{{"VGL-CI-011", 6, model.SeverityHigh}},
		},
		{
			name: "negative pinned workflow",
			file: packBFile(".github/workflows/safe.yml", "yaml", `on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - run: go test ./...`),
		},
	}
	packBRunCases(t, CIRules(), cases)
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

func TestPackBDependencyRules(t *testing.T) {
	lockDir := t.TempDir()
	lockAbs := filepath.Join(lockDir, "package.json")
	if err := os.WriteFile(lockAbs, []byte(`{"dependencies":{"express":"4.19.2"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	lockedDir := t.TempDir()
	lockedAbs := filepath.Join(lockedDir, "package.json")
	if err := os.WriteFile(lockedAbs, []byte(`{"dependencies":{"express":"4.19.2"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lockedDir, "yarn.lock"), []byte("# lockfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []packBCase{
		{
			name: "wildcard and latest versions",
			file: packBFile("package.json", "json", `{
  "name": "demo",
  "dependencies": {
    "left-pad": "*",
    "express": "latest",
    "lodash": "^4.17.21"
  }
}`),
			want: []packBWant{
				{"VGL-DEP-002", 4, model.SeverityLow},
				{"VGL-DEP-002", 5, model.SeverityLow},
			},
		},
		{
			name: "package json without lockfile",
			file: packBFileAt(lockAbs, "package.json", "json", `{"dependencies":{"express":"4.19.2"}}`),
			want: []packBWant{{"VGL-DEP-001", 1, model.SeverityLow}},
		},
		{
			name: "package json with lockfile is negative",
			file: packBFileAt(lockedAbs, "package.json", "json", `{"dependencies":{"express":"4.19.2"}}`),
		},
		{
			name: "git dependency in package json",
			file: packBFile("package.json", "json", `{
  "dependencies": {
    "demo": "git+https://github.com/example/demo.git"
  }
}`),
			want: []packBWant{{"VGL-DEP-003", 3, model.SeverityMedium}},
		},
		{
			name: "pip artifact url without hash",
			file: packBFile("requirements.txt", "other", `https://example.com/pkg-1.0.0-py3-none-any.whl`),
			want: []packBWant{{"VGL-DEP-004", 1, model.SeverityMedium}},
		},
		{
			name: "go mod local replace",
			file: packBFile("go.mod", "go", `module example.com/demo

go 1.22

replace example.com/lib => ../lib`),
			want: []packBWant{{"VGL-DEP-005", 5, model.SeverityInfo}},
		},
		{
			name: "npm strict ssl disabled",
			file: packBFile(".npmrc", "other", `strict-ssl=false`),
			want: []packBWant{{"VGL-DEP-006", 1, model.SeverityHigh}},
		},
		{
			name: "pip trusted host",
			file: packBFile("requirements.txt", "other", `--trusted-host internal.example.com
requests==2.32.0`),
			want: []packBWant{{"VGL-DEP-007", 1, model.SeverityMedium}},
		},
		{
			name: "negative pinned package json",
			file: packBFile("package.json", "json", `{
  "dependencies": {
    "express": "4.19.2"
  }
}`),
		},
	}
	packBRunCases(t, DependencyRules(), cases)
}

// ---------------------------------------------------------------------------
// Metadata and ID hygiene
// ---------------------------------------------------------------------------

func TestPackBRuleMetadata(t *testing.T) {
	groups := []struct {
		name   string
		prefix string
		min    int
		rules  []Rule
	}{
		{"crypto", "VGL-CRY-", 12, CryptoRules()},
		{"auth", "VGL-AUTH-", 9, AuthRules()},
		{"web", "VGL-WEB-", 12, WebRules()},
		{"config", "VGL-CFG-", 17, ConfigRules()},
		{"ci", "VGL-CI-", 11, CIRules()},
		{"dependencies", "VGL-DEP-", 7, DependencyRules()},
	}
	seen := map[string]bool{}
	for _, g := range groups {
		if len(g.rules) < g.min {
			t.Errorf("%s: got %d rules, want at least %d", g.name, len(g.rules), g.min)
		}
		for _, r := range g.rules {
			m := r.Meta()
			if !strings.HasPrefix(m.ID, g.prefix) {
				t.Errorf("%s: rule ID %q does not start with %q", g.name, m.ID, g.prefix)
			}
			if seen[m.ID] {
				t.Errorf("duplicate rule ID %q", m.ID)
			}
			seen[m.ID] = true
			if m.Title == "" || m.Description == "" {
				t.Errorf("%s: rule %s has empty title or description", g.name, m.ID)
			}
			if m.Severity.Rank() == 0 {
				t.Errorf("%s: rule %s has invalid severity %q", g.name, m.ID, m.Severity)
			}
			if m.Category == "" {
				t.Errorf("%s: rule %s has no category", g.name, m.ID)
			}
		}
	}
}
