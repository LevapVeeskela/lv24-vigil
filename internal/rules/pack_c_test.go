package rules

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ---------------------------------------------------------------------------
// Helpers for the pack-C tests. Names are prefixed so parallel rule packs can
// add their own test helpers without collisions.
// ---------------------------------------------------------------------------

type packCWant struct {
	ruleID   string
	line     int
	severity model.Severity
}

type packCCase struct {
	name string
	file *File
	want []packCWant
}

func packCFile(path, language, content string) *File {
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

func packCRun(f *File) []model.Finding {
	var out []model.Finding
	for _, r := range PackCRules() {
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

func packCRunCases(t *testing.T, cases []packCCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := packCRun(tc.file)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d\n%s", len(got), len(tc.want), packCDescribe(got))
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
				if g.Remediation == "" {
					t.Errorf("finding %d (%s): missing remediation", i, g.RuleID)
				}
				if len(g.CWE) == 0 || len(g.OWASP) == 0 {
					t.Errorf("finding %d (%s): missing CWE/OWASP", i, g.RuleID)
				}
			}
		})
	}
}

func packCDescribe(fs []model.Finding) string {
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
// Config: Kubernetes / Terraform / nginx
// ---------------------------------------------------------------------------

func TestPackCConfigRules(t *testing.T) {
	cases := []packCCase{
		{
			name: "kubernetes runAsNonRoot false",
			file: packCFile("k8s/deployment.yaml", "yaml", `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3
          securityContext:
            runAsNonRoot: false
          resources:
            limits:
              cpu: 100m`),
			want: []packCWant{{"VGL-CFG-018", 10, model.SeverityHigh}},
		},
		{
			name: "kubernetes runAsNonRoot true is negative",
			file: packCFile("k8s/deployment.yaml", "yaml", `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: 100m`),
		},
		{
			name: "kubernetes latest image tag",
			file: packCFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: api
      image: myorg/api:latest
      resources:
        limits:
          memory: 128Mi`),
			want: []packCWant{{"VGL-CFG-019", 6, model.SeverityMedium}},
		},
		{
			name: "kubernetes untagged image",
			file: packCFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: api
      image: myorg/api
      resources:
        limits:
          memory: 128Mi`),
			want: []packCWant{{"VGL-CFG-019", 6, model.SeverityMedium}},
		},
		{
			name: "kubernetes literal secret in env",
			file: packCFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: api
      image: myorg/api:1.4.0
      resources:
        limits:
          memory: 128Mi
      env:
        - name: DATABASE_PASSWORD
          value: "s3cr3t-hunter2-pass"`),
			want: []packCWant{{"VGL-CFG-020", 12, model.SeverityHigh}},
		},
		{
			name: "kubernetes secret reference is negative",
			file: packCFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: api
      image: myorg/api:1.4.0
      resources:
        limits:
          memory: 128Mi
      env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db
              key: password`),
		},
		{
			name: "kubernetes missing resource limits",
			file: packCFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: worker
      image: myorg/worker:1.4.0
      ports:
        - containerPort: 8080`),
			want: []packCWant{{"VGL-CFG-021", 6, model.SeverityLow}},
		},
		{
			name: "kubernetes with limits is negative",
			file: packCFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: worker
      image: myorg/worker:1.4.0
      resources:
        limits:
          memory: 256Mi`),
		},
		{
			name: "kubernetes cluster admin binding",
			file: packCFile("k8s/rbac.yaml", "yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: app`),
			want: []packCWant{{"VGL-CFG-029", 8, model.SeverityHigh}},
		},
		{
			name: "terraform publicly accessible database",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_db_instance" "db" {
  engine              = "postgres"
  publicly_accessible = true
}`),
			want: []packCWant{{"VGL-CFG-023", 3, model.SeverityCritical}},
		},
		{
			name: "terraform private database is negative",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_db_instance" "db" {
  engine              = "postgres"
  publicly_accessible = false
}`),
		},
		{
			name: "terraform unencrypted database storage",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_db_instance" "db" {
  engine            = "postgres"
  storage_encrypted = false
}`),
			want: []packCWant{{"VGL-CFG-024", 3, model.SeverityHigh}},
		},
		{
			name: "terraform hardcoded password",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_db_instance" "db" {
  master_password = "S3cr3tPr0dPassw0rd!"
}`),
			want: []packCWant{{"VGL-CFG-025", 2, model.SeverityHigh}},
		},
		{
			name: "terraform secret from variable is negative",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_db_instance" "db" {
  master_password = var.db_password
}`),
		},
		{
			name: "terraform force destroy bucket",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_s3_bucket" "logs" {
  bucket        = "logs"
  force_destroy = true
}`),
			want: []packCWant{{"VGL-CFG-026", 3, model.SeverityMedium}},
		},
		{
			name: "terraform public elasticsearch port",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_security_group" "es" {
  ingress {
    from_port   = 9200
    to_port     = 9200
    cidr_blocks = ["0.0.0.0/0"]
  }
}`),
			want: []packCWant{{"VGL-CFG-027", 5, model.SeverityCritical}},
		},
		{
			name: "terraform public https is allowed",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}`),
		},
		{
			name: "nginx tls 1.0 and 1.1 enabled",
			file: packCFile("infra/nginx/site.conf", "other", `server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
}`),
			want: []packCWant{{"VGL-CFG-028", 3, model.SeverityHigh}},
		},
		{
			name: "nginx modern tls is negative",
			file: packCFile("infra/nginx/site.conf", "other", `server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
}`),
		},
	}
	packCRunCases(t, cases)
}

// ---------------------------------------------------------------------------
// CI
// ---------------------------------------------------------------------------

func TestPackCCIRules(t *testing.T) {
	cases := []packCCase{
		{
			name: "circleci latest image",
			file: packCFile(".circleci/config.yml", "yaml", `version: 2.1
jobs:
  build:
    docker:
      - image: cimg/node:latest
    steps:
      - checkout`),
			want: []packCWant{{"VGL-CI-012", 5, model.SeverityLow}},
		},
		{
			name: "circleci pinned image is negative",
			file: packCFile(".circleci/config.yml", "yaml", `version: 2.1
jobs:
  build:
    docker:
      - image: cimg/node:20.11
    steps:
      - checkout`),
		},
		{
			name: "npm postinstall pipes remote script",
			file: packCFile("package.json", "json", `{
  "name": "demo",
  "scripts": {
    "postinstall": "curl -fsSL https://example.com/i.sh | bash"
  }
}`),
			want: []packCWant{{"VGL-CI-013", 4, model.SeverityHigh}},
		},
		{
			name: "npm postinstall local build is negative",
			file: packCFile("package.json", "json", `{
  "name": "demo",
  "scripts": {
    "postinstall": "node ./scripts/build.js"
  }
}`),
		},
		{
			name: "plain npm install is negative",
			file: packCFile("scripts/install.sh", "shell", `#!/bin/sh
set -eu
npm install --no-audit --no-fund`),
		},
		{
			name: "github docker action latest",
			file: packCFile(".github/workflows/ci.yml", "yaml", `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:latest`),
			want: []packCWant{{"VGL-CI-014", 6, model.SeverityMedium}},
		},
		{
			name: "github docker action pinned is negative",
			file: packCFile(".github/workflows/ci.yml", "yaml", `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.19`),
		},
		{
			name: "gitlab ci debug trace",
			file: packCFile(".gitlab-ci.yml", "yaml", `stages:
  - test
variables:
  CI_DEBUG_TRACE: "true"`),
			want: []packCWant{{"VGL-CI-015", 4, model.SeverityHigh}},
		},
		{
			name: "gitlab ci debug trace disabled is negative",
			file: packCFile(".gitlab-ci.yml", "yaml", `stages:
  - test
variables:
  CI_DEBUG_TRACE: "false"`),
		},
		{
			name: "jenkins pipes remote script",
			file: packCFile("Jenkinsfile", "groovy", `pipeline {
  agent any
  stages {
    stage('deploy') {
      steps {
        sh "curl -fsSL https://example.com/i.sh | bash"
      }
    }
  }
}`),
			want: []packCWant{{"VGL-CI-016", 6, model.SeverityMedium}},
		},
		{
			name: "jenkins local script is negative",
			file: packCFile("Jenkinsfile", "groovy", `pipeline {
  agent any
  stages {
    stage('deploy') {
      steps {
        sh "./ci/deploy.sh"
      }
    }
  }
}`),
		},
		{
			name: "gitlab remote include over http",
			file: packCFile(".gitlab-ci.yml", "yaml", `include:
  - remote: 'http://ci.example.com/templates/security.yml'
stages:
  - test`),
			want: []packCWant{{"VGL-CI-017", 2, model.SeverityHigh}},
		},
		{
			name: "gitlab remote include over https is negative",
			file: packCFile(".gitlab-ci.yml", "yaml", `include:
  - remote: 'https://ci.example.com/templates/security.yml'
stages:
  - test`),
		},
	}
	packCRunCases(t, cases)
}

// ---------------------------------------------------------------------------
// Auth: OAuth / OIDC / JWT
// ---------------------------------------------------------------------------

func TestPackCAuthRules(t *testing.T) {
	cases := []packCCase{
		{
			name: "short jwt secret in env file",
			file: packCFile(".env", "other", `JWT_SECRET=s3cr3t-value-here12`),
			want: []packCWant{{"VGL-AUTH-010", 1, model.SeverityHigh}},
		},
		{
			name: "long jwt secret is negative",
			file: packCFile(".env", "other", `JWT_SECRET=Qm9vR2F0ZXN4c2VjcmV0S2V5Rm9yUHJvZHVjdGlvbg`),
		},
		{
			name: "oauth redirect uri wildcard",
			file: packCFile("src/auth/oauth.js", "javascript", `const redirectUri = 'https://app.example.com/*';`),
			want: []packCWant{{"VGL-AUTH-011", 1, model.SeverityHigh}},
		},
		{
			name: "oauth exact redirect uri is negative",
			file: packCFile("src/auth/oauth.js", "javascript", `const redirectUri = 'https://app.example.com/callback';`),
		},
		{
			name: "oidc issuer check skipped",
			file: packCFile("src/auth/oidc.go", "go", `package auth

var cfg = oidc.Config{
	SkipIssuerCheck: true,
}`),
			want: []packCWant{{"VGL-AUTH-012", 4, model.SeverityHigh}},
		},
		{
			name: "oidc issuer check enabled is negative",
			file: packCFile("src/auth/oidc.go", "go", `package auth

var cfg = oidc.Config{
	SkipIssuerCheck: false,
}`),
		},
		{
			name: "jwt ignore expiration",
			file: packCFile("src/auth/jwt.js", "javascript", `const claims = jwt.verify(token, secret, { ignoreExpiration: true });`),
			want: []packCWant{{"VGL-AUTH-013", 1, model.SeverityHigh}},
		},
		{
			name: "jwt expiration enforced is negative",
			file: packCFile("src/auth/jwt.js", "javascript", `const claims = jwt.verify(token, secret, { ignoreExpiration: false, algorithms: ['HS256'] });`),
		},
		{
			name: "oauth implicit grant",
			file: packCFile("src/auth/login.js", "javascript", `const url = 'https://id.example.com/oauth/authorize?response_type=token&client_id=' + id;`),
			want: []packCWant{{"VGL-AUTH-014", 1, model.SeverityMedium}},
		},
		{
			name: "oauth code grant is negative",
			file: packCFile("src/auth/login.js", "javascript", `const url = 'https://id.example.com/oauth/authorize?response_type=code&client_id=' + id + '&state=' + state;`),
		},
		{
			name: "jwt verify without algorithms",
			file: packCFile("src/auth/session.js", "javascript", `const claims = jwt.verify(token, secret);`),
			want: []packCWant{{"VGL-AUTH-015", 1, model.SeverityMedium}},
		},
		{
			name: "jwt verify with algorithms is negative",
			file: packCFile("src/auth/session.js", "javascript", `const claims = jwt.verify(token, secret, { algorithms: ['HS256'] });`),
		},
		{
			name: "jwt secret fallback default",
			file: packCFile("src/auth/config.js", "javascript", `const secret = process.env.JWT_SECRET || 'dev-secret-value';`),
			want: []packCWant{{"VGL-AUTH-016", 1, model.SeverityHigh}},
		},
		{
			name: "jwt secret from env only is negative",
			file: packCFile("src/auth/config.js", "javascript", `const secret = process.env.JWT_SECRET;`),
		},
	}
	packCRunCases(t, cases)
}

// ---------------------------------------------------------------------------
// Web: GraphQL / API / headers
// ---------------------------------------------------------------------------

func TestPackCWebRules(t *testing.T) {
	cases := []packCCase{
		{
			name: "graphql without depth limit",
			file: packCFile("src/graphql/server.js", "javascript", `const { ApolloServer } = require('apollo-server');

const server = new ApolloServer({
  typeDefs,
  resolvers,
});`),
			want: []packCWant{{"VGL-WEB-013", 3, model.SeverityInfo}},
		},
		{
			name: "graphql with depth limit is negative",
			file: packCFile("src/graphql/server.js", "javascript", `const { ApolloServer } = require('apollo-server');
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(10)],
});`),
		},
		{
			name: "csp allows unsafe inline",
			file: packCFile("infra/nginx/site.conf", "other", `server {
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'";
}`),
			want: []packCWant{{"VGL-WEB-014", 2, model.SeverityMedium}},
		},
		{
			name: "csp with nonce is negative",
			file: packCFile("infra/nginx/site.conf", "other", `server {
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-r4nd0m'";
}`),
		},
		{
			name: "swagger ui in production",
			file: packCFile("src/config/production.ts", "typescript", `import { SwaggerModule } from '@nestjs/swagger';

SwaggerModule.setup('api', app, document);`),
			want: []packCWant{{"VGL-WEB-015", 3, model.SeverityMedium}},
		},
		{
			name: "production file without swagger is negative",
			file: packCFile("src/config/production.ts", "typescript", `export const config = {
  port: 3000,
  logLevel: 'warn',
};`),
		},
		{
			name: "api key in query string",
			file: packCFile("src/api/client.ts", "typescript", `const url = 'https://api.example.com/items?api_key=' + key;`),
			want: []packCWant{{"VGL-WEB-016", 1, model.SeverityMedium}},
		},
		{
			name: "bearer header is negative",
			file: packCFile("src/api/client.ts", "typescript", `const headers = { Authorization: 'Bearer ' + key };
const url = 'https://api.example.com/items';`),
		},
		{
			name: "cors origin reflected from request",
			file: packCFile("src/web/cors.js", "javascript", `res.setHeader('Access-Control-Allow-Origin', req.headers.origin);`),
			want: []packCWant{{"VGL-WEB-017", 1, model.SeverityMedium}},
		},
		{
			name: "cors fixed origin is negative",
			file: packCFile("src/web/cors.js", "javascript", `res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');`),
		},
	}
	packCRunCases(t, cases)
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

func TestPackCDependencyRules(t *testing.T) {
	cases := []packCCase{
		{
			name: "gemfile git dependency without ref",
			file: packCFile("Gemfile", "other", `source "https://rubygems.org"

gem "rails", git: "https://github.com/rails/rails.git"`),
			want: []packCWant{{"VGL-DEP-008", 3, model.SeverityMedium}},
		},
		{
			name: "gemfile git dependency with ref is negative",
			file: packCFile("Gemfile", "other", `source "https://rubygems.org"

gem "rails", git: "https://github.com/rails/rails.git", ref: "8f0d4a3"`),
		},
		{
			name: "cargo git dependency without rev",
			file: packCFile("Cargo.toml", "other", `[dependencies]
serde = { git = "https://github.com/serde-rs/serde" }`),
			want: []packCWant{{"VGL-DEP-009", 2, model.SeverityMedium}},
		},
		{
			name: "cargo git dependency with rev is negative",
			file: packCFile("Cargo.toml", "other", `[dependencies]
serde = { git = "https://github.com/serde-rs/serde", rev = "8f0d4a3" }`),
		},
		{
			name: "pip index over http",
			file: packCFile("requirements.txt", "other", `--index-url http://pypi.internal.example.com/simple
requests==2.32.0`),
			want: []packCWant{{"VGL-DEP-010", 1, model.SeverityHigh}},
		},
		{
			name: "pip index over https is negative",
			file: packCFile("requirements.txt", "other", `--index-url https://pypi.org/simple
requests==2.32.0`),
		},
		{
			name: "lockfile resolves over http",
			file: packCFile("package-lock.json", "json", `{
  "packages": {
    "node_modules/left-pad": {
      "resolved": "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}`),
			want: []packCWant{{"VGL-DEP-011", 4, model.SeverityMedium}},
		},
		{
			name: "lockfile resolves over https is negative",
			file: packCFile("package-lock.json", "json", `{
  "packages": {
    "node_modules/left-pad": {
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}`),
		},
		{
			name: "maven repository over http",
			file: packCFile("pom.xml", "other", `<project>
  <repositories>
    <repository>
      <url>http://repo.internal.example.com/maven2</url>
    </repository>
  </repositories>
</project>`),
			want: []packCWant{{"VGL-DEP-012", 4, model.SeverityMedium}},
		},
		{
			name: "maven repository over https is negative",
			file: packCFile("pom.xml", "other", `<project>
  <repositories>
    <repository>
      <url>https://repo1.maven.org/maven2</url>
    </repository>
  </repositories>
</project>`),
		},
	}
	packCRunCases(t, cases)
}

// ---------------------------------------------------------------------------
// Secret masking
// ---------------------------------------------------------------------------

func TestPackCMasksSecrets(t *testing.T) {
	cases := []struct {
		name   string
		file   *File
		ruleID string
		secret string
	}{
		{
			name: "kubernetes env secret",
			file: packCFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: api
      image: myorg/api:1.4.0
      resources:
        limits:
          memory: 128Mi
      env:
        - name: DATABASE_PASSWORD
          value: "s3cr3t-hunter2-pass"`),
			ruleID: "VGL-CFG-020",
			secret: "s3cr3t-hunter2-pass",
		},
		{
			name: "terraform password",
			file: packCFile("infra/main.tf", "terraform", `resource "aws_db_instance" "db" {
  master_password = "S3cr3tPr0dPassw0rd!"
}`),
			ruleID: "VGL-CFG-025",
			secret: "S3cr3tPr0dPassw0rd!",
		},
		{
			name:   "short jwt secret",
			file:   packCFile(".env", "other", `JWT_SECRET=s3cr3t-value-here12`),
			ruleID: "VGL-AUTH-010",
			secret: "s3cr3t-value-here12",
		},
		{
			name:   "jwt fallback secret",
			file:   packCFile("src/auth/config.js", "javascript", `const secret = process.env.JWT_SECRET || 'dev-secret-value';`),
			ruleID: "VGL-AUTH-016",
			secret: "dev-secret-value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := packCRun(tc.file)
			found := 0
			for _, f := range got {
				if f.RuleID != tc.ruleID {
					continue
				}
				found++
				if strings.Contains(f.Evidence, tc.secret) {
					t.Errorf("%s: evidence leaks the secret: %q", f.RuleID, f.Evidence)
				}
				if strings.Contains(f.Location.Snippet, tc.secret) {
					t.Errorf("%s: snippet leaks the secret: %q", f.RuleID, f.Location.Snippet)
				}
				if !strings.Contains(f.Evidence, "********") {
					t.Errorf("%s: evidence is not masked: %q", f.RuleID, f.Evidence)
				}
			}
			if found != 1 {
				t.Fatalf("got %d findings for %s, want 1\n%s", found, tc.ruleID, packCDescribe(got))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Metadata and ID hygiene
// ---------------------------------------------------------------------------

func TestPackCMetadata(t *testing.T) {
	ranges := []struct {
		prefix string
		min    int
		max    int
		minN   int
	}{
		{"VGL-CFG-", 18, 30, 8},
		{"VGL-CI-", 12, 20, 5},
		{"VGL-AUTH-", 10, 16, 5},
		{"VGL-WEB-", 13, 20, 4},
		{"VGL-DEP-", 8, 12, 4},
	}

	pack := PackCRules()
	if len(pack) < 30 {
		t.Errorf("got %d rules, want at least 30", len(pack))
	}

	existing := map[string]bool{}
	for _, group := range [][]Rule{
		SecretsRules(), InjectionRules(), CryptoRules(), AuthRules(), WebRules(),
		ConfigRules(), CIRules(), DependencyRules(),
	} {
		for _, r := range group {
			existing[r.Meta().ID] = true
		}
	}

	counts := map[string]int{}
	seen := map[string]bool{}
	for _, r := range pack {
		m := r.Meta()
		if m.ID == "" || m.Title == "" || m.Description == "" {
			t.Errorf("rule %q has empty ID, title or description", m.ID)
			continue
		}
		if m.Severity.Rank() == 0 {
			t.Errorf("rule %s has invalid severity %q", m.ID, m.Severity)
		}
		if m.Category == "" {
			t.Errorf("rule %s has no category", m.ID)
		}
		if len(m.CWE) == 0 || len(m.OWASP) == 0 {
			t.Errorf("rule %s is missing CWE or OWASP metadata", m.ID)
		}
		if seen[m.ID] {
			t.Errorf("duplicate rule ID %q", m.ID)
		}
		seen[m.ID] = true
		if existing[m.ID] {
			t.Errorf("rule ID %q collides with an existing pack", m.ID)
		}

		matched := false
		for _, rg := range ranges {
			if !strings.HasPrefix(m.ID, rg.prefix) {
				continue
			}
			matched = true
			n, err := strconv.Atoi(strings.TrimPrefix(m.ID, rg.prefix))
			if err != nil {
				t.Errorf("rule ID %q is not numeric", m.ID)
				break
			}
			if n < rg.min || n > rg.max {
				t.Errorf("rule ID %s is outside %s%03d..%03d", m.ID, rg.prefix, rg.min, rg.max)
			}
			counts[rg.prefix]++
		}
		if !matched {
			t.Errorf("rule ID %q is outside the pack-C prefixes", m.ID)
		}
	}

	for _, rg := range ranges {
		if counts[rg.prefix] < rg.minN {
			t.Errorf("%s: got %d rules, want at least %d", rg.prefix, counts[rg.prefix], rg.minN)
		}
	}
}

func TestPackCPrecisionNoise(t *testing.T) {
	cases := []packCCase{
		{
			name: "generic secretKey is not a jwt secret",
			file: packCFile("src/users/telegram.ts", "typescript", `const secretKey = 'telegram-bot-secret';`),
		},
		{
			name: "jwt secret with jwt context still fires",
			file: packCFile("src/auth/jwt.ts", "typescript", `const JWT_SECRET = 'short-secret';`),
			want: []packCWant{{"VGL-AUTH-010", 1, model.SeverityHigh}},
		},
		{
			name: "credential in a redirect expression fires",
			file: packCFile("src/auth/callback.ts", "typescript", `res.redirect('/auth/success?token=' + token);`),
			want: []packCWant{{"VGL-WEB-016", 1, model.SeverityMedium}},
		},
		{
			name: "credential mentioned in documentation is negative",
			file: packCFile("src/auth/controller.ts", "typescript", `// Callback redirects to /auth/success?token=...&returnUrl=...`),
		},
		{
			name: "credential in a test fixture is negative",
			file: packCFile("src/auth/safe.test.ts", "typescript", `const url = 'http://localhost:4100/auth/success?token=tok-1';`),
		},
	}
	packCRunCases(t, cases)
}
