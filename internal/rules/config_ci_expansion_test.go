package rules

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ---------------------------------------------------------------------------
// Fixtures for the config/IaC/CI expansion wave (VGL-CFG-030..045, VGL-CI-018,
// VGL-CI-019). Each rule is exercised in isolation so unrelated rules (for
// example VGL-CI-001 on a tag-pinned checkout) cannot pollute the expectations.
// ---------------------------------------------------------------------------

type expansionWant struct {
	ruleID string
	line   int
}

type expansionCase struct {
	name string
	file *File
	want []expansionWant
}

func expansionFile(path, language, content string) *File {
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

func expansionRulesByID(t *testing.T) map[string]Rule {
	t.Helper()
	out := make(map[string]Rule)
	for _, r := range ConfigRules() {
		out[r.Meta().ID] = r
	}
	for _, r := range CIRules() {
		out[r.Meta().ID] = r
	}
	return out
}

func expansionRun(t *testing.T, ruleID string, cases []expansionCase) {
	t.Helper()
	r, ok := expansionRulesByID(t)[ruleID]
	if !ok {
		t.Fatalf("rule %s is not registered", ruleID)
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := r.Check(tc.file)
			sort.SliceStable(got, func(i, j int) bool {
				return got[i].Location.StartLine < got[j].Location.StartLine
			})
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d\n%s", len(got), len(tc.want), expansionDescribe(got))
			}
			for i, want := range tc.want {
				g := got[i]
				if g.RuleID != want.ruleID {
					t.Errorf("finding %d: rule = %q, want %q", i, g.RuleID, want.ruleID)
				}
				if g.Location.StartLine != want.line {
					t.Errorf("finding %d (%s): line = %d, want %d (%s)", i, g.RuleID, g.Location.StartLine, want.line, g.Evidence)
				}
				if g.Severity == "" || g.Confidence == "" {
					t.Errorf("finding %d (%s): missing severity or confidence", i, g.RuleID)
				}
				if g.Remediation == "" {
					t.Errorf("finding %d (%s): missing remediation", i, g.RuleID)
				}
				if g.Location.Path != tc.file.Path {
					t.Errorf("finding %d (%s): path = %q, want %q", i, g.RuleID, g.Location.Path, tc.file.Path)
				}
			}
		})
	}
}

func expansionDescribe(fs []model.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  ")
		b.WriteString(f.RuleID)
		b.WriteString(" line ")
		b.WriteString(strconv.Itoa(f.Location.StartLine))
		b.WriteString(": ")
		b.WriteString(f.Evidence)
		b.WriteString("\n")
	}
	return b.String()
}

func TestExpansionCFG030HostNamespaces(t *testing.T) {
	cases := []expansionCase{
		{
			name: "docker run shares pid and network",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker run --rm --pid=host --network=host alpine ps aux`),
			want: []expansionWant{
				{ruleID: "VGL-CFG-030", line: 2},
				{ruleID: "VGL-CFG-030", line: 2},
			},
		},
		{
			name: "continuation line carries ipc host",
			file: expansionFile("Makefile", "other", `run:
	docker run --rm \
		--ipc=host \
		alpine true`),
			want: []expansionWant{{ruleID: "VGL-CFG-030", line: 3}},
		},
		{
			name: "container namespaces are not host namespaces",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker run --rm --pid=container:sidecar --network=app-net alpine ps aux`),
			want: nil,
		},
		{
			name: "compose network_mode is owned by CFG-008",
			file: expansionFile("docker-compose.yml", "yaml", `services:
  app:
    image: alpine
    network_mode: host`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-030", cases)
}

func TestExpansionCFG032Unconfined(t *testing.T) {
	cases := []expansionCase{
		{
			name: "compose seccomp unconfined",
			file: expansionFile("docker-compose.yml", "yaml", `services:
  app:
    image: alpine
    security_opt:
      - seccomp:unconfined`),
			want: []expansionWant{{ruleID: "VGL-CFG-032", line: 5}},
		},
		{
			name: "kubernetes seccompProfile Unconfined",
			file: expansionFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  securityContext:
    seccompProfile:
      type: Unconfined`),
			want: []expansionWant{{ruleID: "VGL-CFG-032", line: 6}},
		},
		{
			name: "cli security-opt seccomp unconfined",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker run --security-opt seccomp=unconfined alpine true`),
			want: []expansionWant{{ruleID: "VGL-CFG-032", line: 2}},
		},
		{
			name: "compose no-new-privileges is hardening",
			file: expansionFile("docker-compose.yml", "yaml", `services:
  app:
    image: alpine
    security_opt:
      - no-new-privileges:true`),
			want: nil,
		},
		{
			name: "kubernetes RuntimeDefault is safe",
			file: expansionFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-032", cases)
}

func TestExpansionCFG033DangerousCapabilities(t *testing.T) {
	cases := []expansionCase{
		{
			name: "compose cap_add NET_ADMIN",
			file: expansionFile("docker-compose.yml", "yaml", `services:
  app:
    image: alpine
    cap_add:
      - NET_ADMIN`),
			want: []expansionWant{{ruleID: "VGL-CFG-033", line: 5}},
		},
		{
			name: "cli cap-add SYS_PTRACE",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker run --cap-add=SYS_PTRACE alpine true`),
			want: []expansionWant{{ruleID: "VGL-CFG-033", line: 2}},
		},
		{
			name: "kubernetes capabilities add inline",
			file: expansionFile("k8s/pod.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]`),
			want: []expansionWant{{ruleID: "VGL-CFG-033", line: 8}},
		},
		{
			name: "cap_drop ALL with NET_BIND_SERVICE is safe",
			file: expansionFile("docker-compose.yml", "yaml", `services:
  app:
    image: alpine
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE`),
			want: nil,
		},
		{
			name: "SYS_ADMIN belongs to CFG-010",
			file: expansionFile("docker-compose.yml", "yaml", `services:
  app:
    image: alpine
    cap_add:
      - SYS_ADMIN`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-033", cases)
}

func TestExpansionCFG036PrivilegedCLI(t *testing.T) {
	cases := []expansionCase{
		{
			name: "docker run privileged",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker run --privileged -v /:/host alpine`),
			want: []expansionWant{{ruleID: "VGL-CFG-036", line: 2}},
		},
		{
			name: "docker create privileged=true on a continuation",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker create \
  --privileged=true \
  alpine true`),
			want: []expansionWant{{ruleID: "VGL-CFG-036", line: 3}},
		},
		{
			name: "cap drop is safe",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE alpine`),
			want: nil,
		},
		{
			name: "privileged=false is safe",
			file: expansionFile("scripts/run.sh", "shell", `#!/bin/sh
docker run --privileged=false alpine`),
			want: nil,
		},
		{
			name: "compose privileged is owned by CFG-007",
			file: expansionFile("docker-compose.yml", "yaml", `services:
  app:
    image: alpine
    privileged: true`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-036", cases)
}

func TestExpansionCFG040IAMFullAdmin(t *testing.T) {
	cases := []expansionCase{
		{
			name: "terraform jsonencode wildcard policy",
			file: expansionFile("infra/iam.tf", "terraform", `resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-040", line: 6}},
		},
		{
			name: "terraform statement block wildcard policy",
			file: expansionFile("infra/iam.tf", "terraform", `data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-040", line: 3}},
		},
		{
			name: "terraform scoped policy is safe",
			file: expansionFile("infra/iam.tf", "terraform", `resource "aws_iam_policy" "read" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::app-bucket/*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "terraform deny admin is safe",
			file: expansionFile("infra/iam.tf", "terraform", `resource "aws_iam_policy" "deny" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "terraform permissions boundary is safe",
			file: expansionFile("infra/iam.tf", "terraform", `resource "aws_iam_policy" "boundary" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "app" {
  permissions_boundary = aws_iam_policy.boundary.arn
}`),
			want: nil,
		},
		{
			name: "terraform count zero is safe",
			file: expansionFile("infra/iam.tf", "terraform", `resource "aws_iam_policy" "admin" {
  count = 0
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "cloudformation wildcard policy",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Admin:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"`),
			want: []expansionWant{{ruleID: "VGL-CFG-040", line: 9}},
		},
		{
			name: "cloudformation scoped policy is safe",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Read:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "s3:GetObject"
            Resource: "arn:aws:s3:::app-bucket/*"`),
			want: nil,
		},
		{
			name: "cloudformation deny statement does not taint the next allow statement",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Policy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Deny
            Action: "*"
            Resource: "*"
          - Effect: Allow
            Action: "s3:GetObject"
            Resource: "arn:aws:s3:::app-bucket/*"`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-040", cases)
}

func TestExpansionCFG041SecurityGroupOpenAll(t *testing.T) {
	cases := []expansionCase{
		{
			name: "terraform ingress all protocols",
			file: expansionFile("infra/sg.tf", "terraform", `resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-041", line: 6}},
		},
		{
			name: "terraform ingress all ports",
			file: expansionFile("infra/sg.tf", "terraform", `resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-041", line: 6}},
		},
		{
			name: "terraform ingress 443 is safe",
			file: expansionFile("infra/sg.tf", "terraform", `resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`),
			want: nil,
		},
		{
			name: "terraform egress is skipped",
			file: expansionFile("infra/sg.tf", "terraform", `resource "aws_security_group" "eg" {
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`),
			want: nil,
		},
		{
			name: "cloudformation ingress all protocols",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: "-1"
          CidrIp: 0.0.0.0/0`),
			want: []expansionWant{{ruleID: "VGL-CFG-041", line: 8}},
		},
		{
			name: "cloudformation ingress 443 is safe",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0`),
			want: nil,
		},
		{
			name: "cloudformation private all-protocol rule does not taint the public 443 rule",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: "-1"
          CidrIp: 10.0.0.0/8
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-041", cases)
}

func TestExpansionCFG042S3PublicAccessBlock(t *testing.T) {
	cases := []expansionCase{
		{
			name: "terraform block public acls disabled",
			file: expansionFile("infra/s3.tf", "terraform", `resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls   = false
  block_public_policy = true
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-042", line: 2}},
		},
		{
			name: "terraform all flags enabled is safe",
			file: expansionFile("infra/s3.tf", "terraform", `resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`),
			want: nil,
		},
		{
			name: "terraform count zero is safe",
			file: expansionFile("infra/s3.tf", "terraform", `resource "aws_s3_bucket_public_access_block" "b" {
  count = 0
  block_public_acls = false
}`),
			want: nil,
		},
		{
			name: "cloudformation block public acls disabled",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: true`),
			want: []expansionWant{{ruleID: "VGL-CFG-042", line: 7}},
		},
		{
			name: "cloudformation all flags enabled is safe",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-042", cases)
}

func TestExpansionCFG044IMDSv1(t *testing.T) {
	cases := []expansionCase{
		{
			name: "terraform metadata http_tokens optional",
			file: expansionFile("infra/ec2.tf", "terraform", `resource "aws_instance" "web" {
  ami = "ami-123"
  metadata_options {
    http_tokens = "optional"
  }
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-044", line: 4}},
		},
		{
			name: "terraform http_tokens required is safe",
			file: expansionFile("infra/ec2.tf", "terraform", `resource "aws_instance" "web" {
  metadata_options {
    http_tokens = "required"
  }
}`),
			want: nil,
		},
		{
			name: "terraform disabled endpoint is safe",
			file: expansionFile("infra/ec2.tf", "terraform", `resource "aws_instance" "web" {
  metadata_options {
    http_endpoint = "disabled"
    http_tokens   = "optional"
  }
}`),
			want: nil,
		},
		{
			name: "terraform missing metadata options is not flagged",
			file: expansionFile("infra/ec2.tf", "terraform", `resource "aws_instance" "web" {
  ami = "ami-123"
}`),
			want: nil,
		},
		{
			name: "cloudformation HttpTokens optional",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Instance:
    Type: AWS::EC2::Instance
    Properties:
      MetadataOptions:
        HttpTokens: optional`),
			want: []expansionWant{{ruleID: "VGL-CFG-044", line: 7}},
		},
		{
			name: "cloudformation HttpTokens required is safe",
			file: expansionFile("infra/template.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Instance:
    Type: AWS::EC2::Instance
    Properties:
      MetadataOptions:
        HttpTokens: required`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-044", cases)
}

func TestExpansionCFG045NginxProxySSLVerify(t *testing.T) {
	cases := []expansionCase{
		{
			name: "proxy_ssl_verify off",
			file: expansionFile("nginx/nginx.conf", "other", `server {
    location /api/ {
        proxy_pass https://backend;
        proxy_ssl_verify off;
    }
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-045", line: 4}},
		},
		{
			name: "proxy_ssl_verify on is safe",
			file: expansionFile("nginx/nginx.conf", "other", `server {
    location /api/ {
        proxy_pass https://backend;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca.pem;
    }
}`),
			want: nil,
		},
		{
			name: "comment is skipped",
			file: expansionFile("nginx/nginx.conf", "other", `server {
    # proxy_ssl_verify off;
    proxy_ssl_verify on;
}`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-045", cases)
}

func TestExpansionCI018WorkflowRunCheckout(t *testing.T) {
	cases := []expansionCase{
		{
			name: "workflow_run head_sha alone is not fork-controlled",
			file: expansionFile(".github/workflows/report.yml", "yaml", `on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: npm ci && npm test`),
			want: nil,
		},
		{
			name: "on key with a trailing comment still opens the trigger block",
			file: expansionFile(".github/workflows/report.yml", "yaml", `on: # triggers
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.pull_requests[0].head.sha }}`),
			want: []expansionWant{{ruleID: "VGL-CI-018", line: 11}},
		},
		{
			name: "workflow_run checks out pull request head ref",
			file: expansionFile(".github/workflows/report.yml", "yaml", `on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.workflow_run.head_repository.full_name }}
          ref: ${{ github.event.workflow_run.pull_requests[0].head.ref }}`),
			want: []expansionWant{
				{ruleID: "VGL-CI-018", line: 11},
				{ruleID: "VGL-CI-018", line: 12},
			},
		},
		{
			name: "workflow_run default checkout is safe",
			file: expansionFile(".github/workflows/report.yml", "yaml", `on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "read the report as data only"`),
			want: nil,
		},
		{
			name: "pull_request_target allow-unsafe-pr-checkout",
			file: expansionFile(".github/workflows/build.yml", "yaml", `on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          allow-unsafe-pr-checkout: true`),
			want: []expansionWant{{ruleID: "VGL-CI-018", line: 10}},
		},
		{
			name: "pull_request_target safe checkout",
			file: expansionFile(".github/workflows/build.yml", "yaml", `on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          allow-unsafe-pr-checkout: false`),
			want: nil,
		},
		{
			name: "workflow_run expression without workflow_run trigger is safe",
			file: expansionFile(".github/workflows/report.yml", "yaml", `on:
  push:
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CI-018", cases)
}

func TestExpansionCI019GitHubScriptInjection(t *testing.T) {
	cases := []expansionCase{
		{
			name: "pull request title interpolated in script",
			file: expansionFile(".github/workflows/triage.yml", "yaml", `on: [pull_request]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const title = "${{ github.event.pull_request.title }}";
            core.info(title);`),
			want: []expansionWant{{ruleID: "VGL-CI-019", line: 9}},
		},
		{
			name: "issue body interpolated inline",
			file: expansionFile(".github/workflows/triage.yml", "yaml", `on: [issues]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: core.info("${{ github.event.issue.body }}")`),
			want: []expansionWant{{ruleID: "VGL-CI-019", line: 8}},
		},
		{
			name: "composite action head_ref interpolation",
			file: expansionFile("actions/triage/action.yml", "yaml", `runs:
  using: composite
  steps:
    - uses: actions/github-script@v7
      with:
        script: |
          core.info("${{ github.head_ref }}")`),
			want: []expansionWant{{ruleID: "VGL-CI-019", line: 7}},
		},
		{
			name: "env indirection is safe",
			file: expansionFile(".github/workflows/triage.yml", "yaml", `on: [pull_request]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        env:
          TITLE: ${{ github.event.pull_request.title }}
        with:
          script: |
            const title = process.env.TITLE;
            core.info(title);`),
			want: nil,
		},
		{
			name: "trusted values are safe",
			file: expansionFile(".github/workflows/triage.yml", "yaml", `on: [pull_request]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            core.info("${{ github.repository }}");
            core.info("${{ secrets.TOKEN }}");`),
			want: nil,
		},
		{
			name: "context payload is runtime data",
			file: expansionFile(".github/workflows/triage.yml", "yaml", `on: [pull_request]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            core.info(context.payload.pull_request.title);`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CI-019", cases)
}
