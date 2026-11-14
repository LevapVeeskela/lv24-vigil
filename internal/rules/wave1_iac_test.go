package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Wave-1 IaC/CI fixtures. Every case runs a single rule so sibling rules in the
// same family (for example VGL-CFG-040 on a wildcard action) cannot pollute the
// expectation.

func wave1Rule(t *testing.T, id string) Rule {
	t.Helper()
	r, ok := expansionRulesByID(t)[id]
	if !ok {
		t.Fatalf("rule %s is not registered", id)
	}
	return r
}

func TestWave1CFG046IAMTrustPolicy(t *testing.T) {
	cases := []expansionCase{
		{
			name: "terraform trust document allows every principal",
			file: expansionFile("infra/iam.tf", "terraform", `data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "deploy"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-046", line: 8}},
		},
		{
			name: "inline jsonencode trust policy allows AWS wildcard",
			file: expansionFile("infra/role.tf", "terraform", `resource "aws_iam_role" "ci" {
  name = "ci"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-046", line: 7}},
		},
		{
			name: "cloudformation assume role policy allows every principal",
			file: expansionFile("infra/role.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: sts:AssumeRole`),
			want: []expansionWant{{ruleID: "VGL-CFG-046", line: 10}},
		},
		{
			name: "cloudformation nested principal mapping allows every principal",
			file: expansionFile("infra/role-nested.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              AWS: "*"
            Action: sts:AssumeRole`),
			want: []expansionWant{{ruleID: "VGL-CFG-046", line: 10}},
		},
		{
			name: "cloudformation json nested principal allows every principal",
			file: expansionFile("infra/role.json", "json", `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "*"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        }
      }
    }
  }
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-046", line: 12}},
		},
		{
			name: "principal arn condition restricts the trust policy",
			file: expansionFile("infra/role-cond.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:PrincipalArn: arn:aws:iam::123456789012:root`),
			want: nil,
		},
		{
			name: "principal org id condition restricts the trust policy",
			file: expansionFile("infra/role-org.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:PrincipalOrgID: o-abc123`),
			want: nil,
		},
		{
			name: "source vpce condition restricts the trust policy",
			file: expansionFile("infra/role-vpce.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:SourceVpce: vpce-0123456789abcdef0`),
			want: nil,
		},
		{
			name: "spoofable aws referer condition does not restrict the trust policy",
			file: expansionFile("infra/role-referer.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: sts:AssumeRole
            Condition:
              StringLike:
                aws:Referer: https://example.com/hook`),
			want: []expansionWant{{ruleID: "VGL-CFG-046", line: 9}},
		},
		{
			name: "terraform trust action in a line comment is not code",
			file: expansionFile("infra/role-comment.tf", "terraform", `resource "aws_iam_role" "deploy" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      // Action = "sts:AssumeRole"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "deny trust statement is not reported",
			file: expansionFile("infra/role-deny.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Deny
            Principal: "*"
            Action: sts:AssumeRole`),
			want: nil,
		},
		{
			name: "count zero resource is disabled",
			file: expansionFile("infra/trust-disabled.tf", "terraform", `data "aws_iam_policy_document" "trust" {
  count = 0
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  assume_role_policy = data.aws_iam_policy_document.trust.json
}`),
			want: nil,
		},
		{
			name: "permission policy without trust context is not a trust finding",
			file: expansionFile("infra/bucket-access.tf", "terraform", `resource "aws_iam_policy" "read" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example/*"
    }]
  })
}`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-046", cases)
}

func TestWave1CFG047S3BucketPolicy(t *testing.T) {
	publicBucketPolicy := `resource "aws_s3_bucket_policy" "public" {
  bucket = "example"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example/*"
    }]
  })
}`
	cases := []expansionCase{
		{
			name: "terraform bucket policy allows every principal",
			file: expansionFile("infra/bucket.tf", "terraform", publicBucketPolicy),
			want: []expansionWant{{ruleID: "VGL-CFG-047", line: 7}},
		},
		{
			name: "block public policy suppresses the finding",
			file: expansionFile("infra/bucket-bpa.tf", "terraform", publicBucketPolicy+`

resource "aws_s3_bucket_public_access_block" "bpa" {
  bucket              = "example"
  block_public_policy = true
}`),
			want: nil,
		},
		{
			name: "disabled block public policy does not suppress",
			file: expansionFile("infra/bucket-bpa-off.tf", "terraform", publicBucketPolicy+`

resource "aws_s3_bucket_public_access_block" "bpa" {
  bucket              = "example"
  block_public_policy = false
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-047", line: 7}},
		},
		{
			name: "terraform inline bucket policy allows every principal",
			file: expansionFile("infra/bucket-inline.tf", "terraform", `resource "aws_s3_bucket" "site" {
  bucket = "example"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example/*"
    }]
  })
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-047", line: 6}},
		},
		{
			name: "deny bucket policy is not public access",
			file: expansionFile("infra/bucket-deny.tf", "terraform", `resource "aws_s3_bucket_policy" "deny" {
  bucket = "example"
  policy = jsonencode({
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example/*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "source vpce condition restricts the bucket policy",
			file: expansionFile("infra/bucket-vpce.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  PublicPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: example
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: arn:aws:s3:::example/*
            Condition:
              StringEquals:
                aws:SourceVpce: vpce-0123456789abcdef0`),
			want: nil,
		},
		{
			name: "unrelated aws_s3_bucket attribute is not a bucket policy",
			file: expansionFile("infra/bucket-role.tf", "terraform", `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

resource "aws_iam_role" "reader" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "generic iam policy with an inline policy is not a bucket policy",
			file: expansionFile("infra/policy.tf", "terraform", `resource "aws_iam_policy" "read" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example/*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "bucket policy action in a line comment is not code",
			file: expansionFile("infra/bucket-comment.tf", "terraform", `resource "aws_s3_bucket_policy" "public" {
  bucket = "example"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      // Action = "s3:GetObject"
      Resource  = "*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "count zero bucket policy is disabled",
			file: expansionFile("infra/bucket-disabled.tf", "terraform", `resource "aws_s3_bucket_policy" "public" {
  count  = 0
  bucket = "example"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example/*"
    }]
  })
}`),
			want: nil,
		},
		{
			name: "cloudformation bucket policy allows every principal",
			file: expansionFile("infra/bucket.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  PublicPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: example
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: arn:aws:s3:::example/*`),
			want: []expansionWant{{ruleID: "VGL-CFG-047", line: 10}},
		},
		{
			name: "cloudformation block public policy suppresses the finding",
			file: expansionFile("infra/bucket-cfn-bpa.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicPolicy: true
  PublicPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: example
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: arn:aws:s3:::example/*`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-047", cases)
}

func TestWave1CFG048ControlPlaneFlags(t *testing.T) {
	cases := []expansionCase{
		{
			name: "apiserver static pod has four insecure flags",
			file: expansionFile("k8s/manifests/kube-apiserver.yaml", "yaml", `apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=true
        - --authorization-mode=AlwaysAllow
        - --insecure-port=6443
        - --profiling=true`),
			want: []expansionWant{
				{ruleID: "VGL-CFG-048", line: 9},
				{ruleID: "VGL-CFG-048", line: 10},
				{ruleID: "VGL-CFG-048", line: 11},
				{ruleID: "VGL-CFG-048", line: 12},
			},
		},
		{
			name: "hardened apiserver flags are safe",
			file: expansionFile("k8s/manifests/kube-apiserver.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=false
        - --authorization-mode=Node,RBAC
        - --insecure-port=0
        - --profiling=false`),
			want: nil,
		},
		{
			name: "etcd insecure TLS flags are reported",
			file: expansionFile("k8s/manifests/etcd.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - command:
        - etcd
        - --client-cert-auth=false
        - --auto-tls=true
        - --peer-auto-tls=true`),
			want: []expansionWant{
				{ruleID: "VGL-CFG-048", line: 7},
				{ruleID: "VGL-CFG-048", line: 8},
				{ruleID: "VGL-CFG-048", line: 9},
			},
		},
		{
			name: "token auth file is reported",
			file: expansionFile("manifests/kube-apiserver.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - command:
        - kube-apiserver
        - --token-auth-file=/etc/kubernetes/token.csv`),
			want: []expansionWant{{ruleID: "VGL-CFG-048", line: 7}},
		},
		{
			name: "controller manager profiling is reported",
			file: expansionFile("manifests/kube-controller-manager.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - command:
        - kube-controller-manager
        - --profiling=true`),
			want: []expansionWant{{ruleID: "VGL-CFG-048", line: 7}},
		},
		{
			name: "unanchored deployment flags are ignored",
			file: expansionFile("k8s/deployment.yaml", "yaml", `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.k8s.io/kube-apiserver:v1.30
          args:
            - --anonymous-auth=true`),
			want: nil,
		},
		{
			name: "documentation manifest is skipped",
			file: expansionFile("docs/kube-apiserver.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=true`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-048", cases)
}

func TestWave1CFG049ComposeSecrets(t *testing.T) {
	cases := []expansionCase{
		{
			name: "environment and build args contain literal secrets",
			file: expansionFile("deploy/docker-compose.yml", "yaml", `services:
  app:
    build:
      context: .
      args:
        NPM_TOKEN: tok3n-abcdef123
    environment:
      - DB_PASSWORD=Sup3rS3cretValue
      - API_TOKEN=abc123XYZ987`),
			want: []expansionWant{
				{ruleID: "VGL-CFG-049", line: 6},
				{ruleID: "VGL-CFG-049", line: 8},
				{ruleID: "VGL-CFG-049", line: 9},
			},
		},
		{
			name: "interpolated value is a reference",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      - DB_PASSWORD=${DB_PASSWORD}`),
			want: nil,
		},
		{
			name: "placeholder is not a secret",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      DB_PASSWORD: changeme`),
			want: nil,
		},
		{
			name: "environment word values are not secrets",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      API_KEY: production
      DB_PASSWORD: development`),
			want: nil,
		},
		{
			name: "suffixed environment word values are not secrets",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      API_KEY: production2
      DB_PASSWORD: development_2
      SESSION_SECRET: staging-eu`),
			want: nil,
		},
		{
			name: "mixed values are still secrets",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      API_KEY: Tr0ub4dor&3xyz
      DB_PASSWORD: d3v3lopm3nt-key`),
			want: []expansionWant{
				{ruleID: "VGL-CFG-049", line: 4},
				{ruleID: "VGL-CFG-049", line: 5},
			},
		},
		{
			name: "dictionary word with a separator is not a secret",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      DB_PASSWORD: my-password
      API_KEY: staging-local`),
			want: nil,
		},
		{
			name: "file and path keys are references",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      DB_PASSWORD_FILE: /run/secrets/db-password
      TOKEN_PATH: /var/run/token`),
			want: nil,
		},
		{
			name: "quoted literal belongs to the generic secret rule",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      DB_PASSWORD: "Sup3rS3cretValue"`),
			want: nil,
		},
		{
			name: "quoted list literal belongs to the generic secret rule",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      - "DB_PASSWORD=Sup3rS3cretValue"`),
			want: nil,
		},
		{
			name: "args outside build are not build args",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    args:
      NPM_TOKEN: tok3n-abcdef123`),
			want: nil,
		},
		{
			name: "commented entry is ignored",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      # DB_PASSWORD: Sup3rS3cretValue
      - DEBUG=1`),
			want: nil,
		},
		{
			name: "low entropy repeated value is not a secret",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      DB_PASSWORD: aaaaaaaa`),
			want: nil,
		},
		{
			name: "non compose yaml is ignored",
			file: expansionFile("config/app.yaml", "yaml", `environment:
  DB_PASSWORD: Sup3rS3cretValue`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-049", cases)
}

func TestWave1CFG050S3Backend(t *testing.T) {
	cases := []expansionCase{
		{
			name: "s3 backend disables encryption",
			file: expansionFile("infra/backend.tf", "terraform", `terraform {
  backend "s3" {
    bucket  = "state"
    key     = "app.tfstate"
    region  = "eu-central-1"
    encrypt = false
  }
}`),
			want: []expansionWant{{ruleID: "VGL-CFG-050", line: 6}},
		},
		{
			name: "s3 backend with encryption enabled",
			file: expansionFile("infra/backend.tf", "terraform", `terraform {
  backend "s3" {
    bucket  = "state"
    encrypt = true
  }
}`),
			want: nil,
		},
		{
			name: "s3 backend without explicit encryption is safe by default",
			file: expansionFile("infra/backend.tf", "terraform", `terraform {
  backend "s3" {
    bucket = "state"
    key    = "app.tfstate"
  }
}`),
			want: nil,
		},
		{
			name: "local backend is not an s3 backend",
			file: expansionFile("infra/backend-local.tf", "terraform", `terraform {
  backend "local" {
    encrypt = false
  }
}`),
			want: nil,
		},
		{
			name: "encrypt outside the backend block is not a backend flag",
			file: expansionFile("infra/volume.tf", "terraform", `resource "aws_ebs_volume" "data" {
  availability_zone = "eu-central-1a"
  size              = 10
  encrypt           = false
}`),
			want: nil,
		},
		{
			name: "commented encrypt flag is not backend configuration",
			file: expansionFile("infra/backend-comment.tf", "terraform", `terraform {
  backend "s3" {
    bucket = "state"
    key    = "app.tfstate"
    // encrypt = false
  }
}`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CFG-050", cases)
}

func TestWave1CI023ScanAllowedToFail(t *testing.T) {
	cases := []expansionCase{
		{
			name: "trivy step is allowed to fail",
			file: expansionFile(".github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trivy
        uses: aquasecurity/trivy-action@0123456789abcdef0123456789abcdef01234567
        continue-on-error: true`),
			want: []expansionWant{{ruleID: "VGL-CI-023", line: 9}},
		},
		{
			name: "gitleaks step is allowed to fail",
			file: expansionFile(".github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@0123456789abcdef0123456789abcdef01234567
        continue-on-error: true`),
			want: []expansionWant{{ruleID: "VGL-CI-023", line: 9}},
		},
		{
			name: "sonarqube scan step is allowed to fail",
			file: expansionFile(".github/workflows/sonar.yml", "yaml", `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Sonar
        uses: SonarSource/sonarqube-scan-action@0123456789abcdef0123456789abcdef01234567
        continue-on-error: true`),
			want: []expansionWant{{ruleID: "VGL-CI-023", line: 9}},
		},
		{
			name: "detect-secrets step is allowed to fail",
			file: expansionFile(".github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Detect secrets
        run: detect-secrets scan --all-files
        continue-on-error: true`),
			want: []expansionWant{{ruleID: "VGL-CI-023", line: 9}},
		},
		{
			name: "job level continue-on-error with a scanner",
			file: expansionFile(".github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  security:
    name: Security scan
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - name: Semgrep
        uses: returntocorp/semgrep-action@0123456789abcdef0123456789abcdef01234567`),
			want: []expansionWant{{ruleID: "VGL-CI-023", line: 7}},
		},
		{
			name: "job level echo mentioning a scanner is not an invocation",
			file: expansionFile(".github/workflows/test.yml", "yaml", `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - name: Unit tests
        run: echo "run npm audit locally"`),
			want: nil,
		},
		{
			name: "step level echo mentioning a scanner is not an invocation",
			file: expansionFile(".github/workflows/test.yml", "yaml", `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Print the scan command
        run: printf '%s\n' "semgrep --config auto"
        continue-on-error: true`),
			want: nil,
		},
		{
			name: "job level continue-on-error with npm audit",
			file: expansionFile(".github/workflows/audit.yml", "yaml", `name: CI
on: push
jobs:
  security:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - name: Dependencies
        run: npm audit --audit-level=high`),
			want: []expansionWant{{ruleID: "VGL-CI-023", line: 6}},
		},
		{
			name: "job level continue-on-error with a multi-line npx scanner run",
			file: expansionFile(".github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  security:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - name: Scan
        run: |
          npm ci
          npx trivy fs .`),
			want: []expansionWant{{ruleID: "VGL-CI-023", line: 6}},
		},
		{
			name: "non security step may be allowed to fail",
			file: expansionFile(".github/workflows/test.yml", "yaml", `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Unit tests
        run: go test ./...
        continue-on-error: true`),
			want: nil,
		},
		{
			name: "continue-on-error false is safe",
			file: expansionFile(".github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trivy
        uses: aquasecurity/trivy-action@0123456789abcdef0123456789abcdef01234567
        continue-on-error: false`),
			want: nil,
		},
		{
			name: "gitlab pipeline is owned by the gitlab rule",
			file: expansionFile(".gitlab-ci.yml", "yaml", `trivy:
  script: trivy fs .
  continue-on-error: true`),
			want: nil,
		},
		{
			name: "example workflow is skipped",
			file: expansionFile("examples/.github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trivy
        uses: aquasecurity/trivy-action@0123456789abcdef0123456789abcdef01234567
        continue-on-error: true`),
			want: nil,
		},
	}
	expansionRun(t, "VGL-CI-023", cases)
}

func TestWave1NilFileSafe(t *testing.T) {
	for _, id := range []string{
		"VGL-CFG-046", "VGL-CFG-047", "VGL-CFG-048",
		"VGL-CFG-049", "VGL-CFG-050", "VGL-CI-023",
	} {
		if got := wave1Rule(t, id).Check(nil); len(got) != 0 {
			t.Errorf("%s returned %d findings for a nil file", id, len(got))
		}
	}
}

func TestWave1IaCSeverities(t *testing.T) {
	cases := []struct {
		id       string
		file     *File
		wantSev  model.Severity
		wantLine int
	}{
		{
			id: "VGL-CFG-046",
			file: expansionFile("infra/role.yaml", "yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: sts:AssumeRole`),
			wantSev:  model.SeverityHigh,
			wantLine: 9,
		},
		{
			id: "VGL-CFG-048",
			file: expansionFile("k8s/manifests/kube-apiserver.yaml", "yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
    - command:
        - kube-apiserver
        - --profiling=true`),
			wantSev:  model.SeverityMedium,
			wantLine: 7,
		},
		{
			id: "VGL-CFG-049",
			file: expansionFile("compose.yml", "yaml", `services:
  app:
    environment:
      DB_PASSWORD: Sup3rS3cretValue`),
			wantSev:  model.SeverityHigh,
			wantLine: 4,
		},
		{
			id: "VGL-CI-023",
			file: expansionFile(".github/workflows/scan.yml", "yaml", `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Grype
        uses: anchore/scan-action@0123456789abcdef0123456789abcdef01234567
        continue-on-error: true`),
			wantSev:  model.SeverityMedium,
			wantLine: 9,
		},
	}
	for _, tc := range cases {
		got := wave1Rule(t, tc.id).Check(tc.file)
		if len(got) != 1 {
			t.Fatalf("%s: got %d findings, want 1", tc.id, len(got))
		}
		if got[0].Severity != tc.wantSev {
			t.Errorf("%s: severity = %q, want %q", tc.id, got[0].Severity, tc.wantSev)
		}
		if got[0].Location.StartLine != tc.wantLine {
			t.Errorf("%s: line = %d, want %d", tc.id, got[0].Location.StartLine, tc.wantLine)
		}
		if got[0].Confidence == "" {
			t.Errorf("%s: finding has no confidence", tc.id)
		}
	}
}

func TestWave1DocsFixturesAndCommentsAreSkipped(t *testing.T) {
	cases := []struct {
		id      string
		path    string
		lang    string
		content string
	}{
		{
			id:   "VGL-CFG-046",
			path: "examples/iam.tf",
			lang: "terraform",
			content: `data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}
resource "aws_iam_role" "deploy" {
  assume_role_policy = data.aws_iam_policy_document.trust.json
}`,
		},
		{
			id:   "VGL-CFG-047",
			path: "tests/bucket.tf",
			lang: "terraform",
			content: `resource "aws_s3_bucket_policy" "public" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
    }]
  })
}`,
		},
		{
			id:   "VGL-CFG-048",
			path: "docs/kube-apiserver.yaml",
			lang: "yaml",
			content: `apiVersion: v1
kind: Pod
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=true`,
		},
		{
			id:   "VGL-CFG-049",
			path: "examples/docker-compose.yml",
			lang: "yaml",
			content: `services:
  app:
    environment:
      - DB_PASSWORD=Sup3rS3cretValue`,
		},
		{
			id:   "VGL-CFG-050",
			path: "docs/backend.tf",
			lang: "terraform",
			content: `terraform {
  backend "s3" {
    encrypt = false
  }
}`,
		},
		{
			id:   "VGL-CI-023",
			path: "examples/.github/workflows/scan.yml",
			lang: "yaml",
			content: `name: CI
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trivy
        uses: aquasecurity/trivy-action@0123456789abcdef0123456789abcdef01234567
        continue-on-error: true`,
		},
	}
	for _, tc := range cases {
		got := wave1Rule(t, tc.id).Check(expansionFile(tc.path, tc.lang, tc.content))
		if len(got) != 0 {
			t.Errorf("%s: %d findings in %s, want 0 (documentation, tests and examples are capped to zero)", tc.id, len(got), tc.path)
		}
	}
}

func TestWave1CFG049SnippetNeverLeaksSecrets(t *testing.T) {
	const secret = "Sup3rS3cretValue123"
	const neighbour = "tok3n-Neighbour987654321"
	f := expansionFile("deploy/docker-compose.yml", "yaml", `services:
  app:
    environment:
      - DB_PASSWORD=`+secret+`
      - API_TOKEN=`+neighbour)

	got := wave1Rule(t, "VGL-CFG-049").Check(f)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2", len(got))
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	report := string(encoded)
	for _, raw := range []string{secret, neighbour} {
		if strings.Contains(report, raw) {
			t.Errorf("serialized finding leaks the raw secret %q: %s", raw, report)
		}
	}
	for _, fd := range got {
		if strings.Contains(fd.Evidence, secret) || strings.Contains(fd.Evidence, neighbour) {
			t.Errorf("evidence leaks a raw secret: %q", fd.Evidence)
		}
		if strings.TrimSpace(fd.Location.Snippet) == "" {
			t.Error("snippet is empty; the finding lost its context")
		}
		// Snippet is a single redacted line, so a radius-1 neighbouring
		// credential must never reach it either.
		if strings.Contains(fd.Location.Snippet, secret) || strings.Contains(fd.Location.Snippet, neighbour) {
			t.Errorf("snippet leaks a raw secret: %q", fd.Location.Snippet)
		}
	}
	if !strings.Contains(got[0].Location.Snippet, MaskSecret(secret)) {
		t.Errorf("snippet does not mask the reported value: %q", got[0].Location.Snippet)
	}
}

func TestWave1IaCMetadata(t *testing.T) {
	ids := []string{
		"VGL-CFG-046", "VGL-CFG-047", "VGL-CFG-048",
		"VGL-CFG-049", "VGL-CFG-050", "VGL-CI-023",
	}
	byID := expansionRulesByID(t)
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			t.Errorf("rule %s is not registered", id)
			continue
		}
		m := r.Meta()
		if m.ID != id {
			t.Errorf("rule %s reports ID %q", id, m.ID)
		}
		if m.Title == "" {
			t.Errorf("%s: empty title", id)
		}
		if m.Description == "" {
			t.Errorf("%s: empty description", id)
		}
		if m.Severity.Rank() == 0 {
			t.Errorf("%s: invalid severity %q", id, m.Severity)
		}
		wantCategory := model.CategoryConfig
		if id == "VGL-CI-023" {
			wantCategory = model.CategoryCI
		}
		if m.Category != wantCategory {
			t.Errorf("%s: category = %q, want %q", id, m.Category, wantCategory)
		}
		if len(m.Languages) == 0 || len(m.CWE) == 0 || len(m.OWASP) == 0 || len(m.Tags) == 0 || len(m.References) == 0 {
			t.Errorf("%s: incomplete metadata (languages=%v cwe=%v owasp=%v tags=%v refs=%v)",
				id, m.Languages, m.CWE, m.OWASP, m.Tags, m.References)
		}
	}
}
