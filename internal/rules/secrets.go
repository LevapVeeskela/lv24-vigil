package rules

import (
	"encoding/base64"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// This file implements the secret-detection rule family (VGL-SEC-*).
//
// Design notes:
//   - Every candidate value is checked with LooksLikePlaceholder so docs,
//     fixtures and obvious dummies stay quiet.
//   - Findings never carry the raw credential: Evidence and Snippet are both
//     passed through MaskSecret (see the non-negotiable in CONTRACTS.md).
//   - Rules that only make sense in a dedicated file format (.env, *.tf,
//     .npmrc, Docker config) are gated on the path so the generic assignment
//     rule does not report the same value twice.

var (
	secAWSKeyIDRe = regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[0-9A-Z]{16}\b`)

	secAWSSecretRe = regexp.MustCompile(`(?i)aws_?(?:secret_?access_?key|secret_?key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`)

	secGitHubRe = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b`)

	secGitLabRe = regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,255}\b`)

	secSlackTokenRe = regexp.MustCompile(`\bx(?:ox[abposr]|app)-[A-Za-z0-9\-]{10,255}\b`)

	secSlackWebhookRe = regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+`)

	secStripeLiveRe = regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{20,255}\b`)

	secGoogleAPIRe = regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)

	secOpenAIRe = regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,255}\b`)

	secAnthropicRe = regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,255}\b`)

	secPrivateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)

	secJWTRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)

	secBasicAuthRe = regexp.MustCompile(`\b(?:https?|ftp)://[^\s:/@]+:([^\s@/"'<>\x60);,]+)@[^\s"'<>\x60);,]+`)

	secGenericAssignRe = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|credential|private[_-]?key)\s*["']?\s*[:=]\s*(['"])([^'"\n]{12,})['"]`)

	secConnStringRe = regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver)://[^\s:/@]*:([^\s@/"'<>\x60);,]+)@[^\s"'<>\x60);,]+`)

	secNPMTokenRe = regexp.MustCompile(`(?i)_auth(?:token)?\s*=\s*["']?([A-Za-z0-9+/=._\-]{16,})`)

	secHerokuAssignRe = regexp.MustCompile(`(?i)heroku[_-]?(?:api[_-]?)?key\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`)

	secHerokuTokenRe = regexp.MustCompile(`\bHRKU-[A-Za-z0-9_\-]{20,}\b`)

	secDigitalOceanRe = regexp.MustCompile(`\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b`)

	secTwilioAssignRe = regexp.MustCompile(`(?i)twilio[_-]?(?:auth[_-]?)?token\s*[:=]\s*["']?([0-9a-fA-F]{32})`)

	secTwilioKeyRe = regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)

	secSendGridRe = regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b`)

	secAzureKeyRe = regexp.MustCompile(`(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{40,})`)

	secTerraformAssignRe = regexp.MustCompile(`(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]{8,})"`)

	secTerraformKeyRe = regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api_?key|access_?key|private_?key|client_?secret|credential)`)

	secDockerAuthRe = regexp.MustCompile(`"auth"\s*:\s*"([A-Za-z0-9+/=]{16,})"`)

	secEnvLineRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$`)

	secEnvKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_?key|apikey|auth|credential|private_?key|access_?key|client_?secret|dsn|connection_?string)`)

	secProviderUnionRe = regexp.MustCompile(`^(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_\-]{20,}|x(?:ox[abposr]|app)-[A-Za-z0-9\-]{10,}|sk_live_[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_\-]{35}|sk-ant-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9_\-]{20,}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}|eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}|dop_v1_[a-f0-9]{64})$`)

	// secEnvNameRe matches an environment-variable name such as
	// TELEGRAM_BOT_TOKEN: a mapping target, never a credential value.
	secEnvNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

	// secLowerNameRe matches a lower-case identifier or kebab-case label such
	// as signing_secret, raw-token-value or assistant-token-should-be-ignored.
	secLowerNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

	// secHardRedactor masks well-known credential shapes that may appear on a
	// neighbouring line inside a snippet window.
	secHardRedactor = regexp.MustCompile(`(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_\-]{20,}|x(?:ox[abposr]|app)-[A-Za-z0-9\-]{10,}|sk_live_[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_\-]{35}|sk-ant-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9_\-]{20,}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}|eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}|dop_v1_[a-f0-9]{64}|HRKU-[A-Za-z0-9_\-]{20,})`)
)

const (
	secRemediationRotate = "Revoke and rotate the credential now. Remove it from the working tree and from git history, then load it at runtime from a secret manager or environment variable. Add a pre-commit secret scanner so it cannot be re-committed."

	secRemediationPrivateKey = "Treat the private key as compromised: revoke or reissue the certificate/key pair, remove the PEM block from the repository and purge it from git history. Store private keys in a secret manager or an HSM, never in source control."

	secRemediationEnv = "Do not commit environment files with real values. Keep only a placeholder .env.example in the repository, load production values from the deployment environment or a secret manager, and rotate anything that was committed."

	secRemediationTerraform = "Terraform state and variable files are frequently shared and cached. Mark the value sensitive, source it from a secret manager or an encrypted variable store, and rotate it if it was committed."

	secRemediationDocker = "Registry credentials in config.json are reusable by anyone who reads the file. Log out of the registry, rotate the token, and use a credential helper or CI-provided short-lived credentials instead."
)

// secMatch is one candidate secret at a 1-based line.
type secMatch struct {
	line  int
	value string
}

// secScan describes a line-oriented secret pattern.
type secScan struct {
	re           *regexp.Regexp
	group        int
	minEntropy   float64
	skipComments bool
	validate     func(f *File, line string, groups []string) bool
}

// secFindingOpts configures how matches become findings.
type secFindingOpts struct {
	severity    model.Severity
	confidence  model.Confidence
	remediation string
	references  []string
	label       string
	maskURL     bool
}

// secPattern is a declarative rule: one regex, optional gates, one finding per
// match. It keeps the rule list readable and the behaviour uniform.
type secPattern struct {
	meta         model.RuleMeta
	re           *regexp.Regexp
	group        int
	minEntropy   float64
	skipComments bool
	validate     func(f *File, line string, groups []string) bool
	opts         secFindingOpts
}

func (s secPattern) rule() Rule {
	return New(s.meta, func(f *File) []model.Finding {
		if f == nil {
			return nil
		}
		matches := secScanFile(f, secScan{
			re:           s.re,
			group:        s.group,
			minEntropy:   s.minEntropy,
			skipComments: s.skipComments,
			validate:     s.validate,
		})
		opts := s.opts
		if opts.severity == "" {
			opts.severity = s.meta.Severity
		}
		if len(opts.references) == 0 {
			opts.references = s.meta.References
		}
		return secFindings(f, matches, opts)
	})
}

// SecretsRules returns the deterministic hardcoded-secret rules.
func SecretsRules() []Rule {
	return []Rule{
		secPattern{
			meta: secMeta(
				"VGL-SEC-001",
				"AWS access key ID hardcoded in source",
				"An AWS access key ID is committed to the repository. Key IDs identify an IAM principal and are paired with a secret access key; a leak of both grants that principal's permissions. Even alone, the ID tells an attacker which account and user to target.",
				model.SeverityHigh,
				[]string{"CWE-798"},
				[]string{"aws", "cloud"},
				[]string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
			),
			re: secAWSKeyIDRe,
			opts: secFindingOpts{
				remediation: secRemediationRotate,
				label:       "AWS access key ID",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-002",
				"AWS secret access key hardcoded in source",
				"AWS secret access keys are the password half of an access key pair. Anyone with this value can sign requests as the IAM principal, subject only to that principal's policies. Leaked keys are routinely used to mine crypto and exfiltrate S3 data within minutes.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"aws", "cloud"},
				[]string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
			),
			re:         secAWSSecretRe,
			group:      1,
			minEntropy: 3.5,
			opts: secFindingOpts{
				remediation: secRemediationRotate,
				label:       "AWS secret access key",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-003",
				"GitHub token hardcoded in source",
				"A GitHub personal access token, OAuth token or fine-grained token is embedded in the repository. Depending on its scopes it can read private code, push commits, or act on the account through the API.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"github", "scm"},
				[]string{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository"},
			),
			re: secGitHubRe,
			opts: secFindingOpts{
				remediation: "Revoke the token at github.com/settings/tokens (or the App installation), rotate it, and replace it with short-lived credentials or a GitHub App. Purge the value from git history.",
				label:       "GitHub token",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-004",
				"GitLab personal access token hardcoded in source",
				"A GitLab personal access token is embedded in the repository. It grants API access as the owning user and may allow reading or modifying every project the user can reach.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"gitlab", "scm"},
				[]string{"https://docs.gitlab.com/ee/security/token_overview.html"},
			),
			re: secGitLabRe,
			opts: secFindingOpts{
				remediation: "Revoke the token in GitLab user settings, rotate it, and use project/group access tokens or CI job tokens with the minimum scope. Purge the value from git history.",
				label:       "GitLab token",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-005",
				"Slack token hardcoded in source",
				"A Slack bot, user or app token is committed. These tokens can read messages and files, post as the bot or user, and in some scopes administer the workspace.",
				model.SeverityHigh,
				[]string{"CWE-798"},
				[]string{"slack"},
				[]string{"https://api.slack.com/authentication/token-types"},
			),
			re: secSlackTokenRe,
			opts: secFindingOpts{
				remediation: "Rotate the token in the Slack app configuration, install it through a secret manager, and scope the token to the minimum required scopes.",
				label:       "Slack token",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-006",
				"Slack incoming webhook URL hardcoded in source",
				"A Slack webhook URL is a bearer credential: anyone who has it can post arbitrary messages into the channel, which is frequently abused for phishing.",
				model.SeverityHigh,
				[]string{"CWE-798"},
				[]string{"slack", "webhook"},
				[]string{"https://api.slack.com/messaging/webhooks"},
			),
			re: secSlackWebhookRe,
			opts: secFindingOpts{
				remediation: "Delete the webhook in the Slack app configuration, create a new one, and store the URL in a secret manager. Treat the old URL as compromised.",
				label:       "Slack webhook URL",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-007",
				"Stripe live secret key hardcoded in source",
				"A Stripe live-mode secret or restricted key is committed. Live keys can create charges, issue refunds, read customer data and payouts, and move real money.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"stripe", "payments"},
				[]string{"https://docs.stripe.com/keys#safe-keys"},
			),
			re: secStripeLiveRe,
			opts: secFindingOpts{
				remediation: "Roll the key in the Stripe dashboard immediately, move the new value to a secret manager, and restrict the key to the minimum permissions. Check the account for unauthorized activity.",
				label:       "Stripe live key",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-008",
				"Google API key hardcoded in source",
				"A Google API key is committed. Unrestricted keys can be used from any referrer or IP against billable APIs, which commonly leads to quota theft and unexpected charges.",
				model.SeverityHigh,
				[]string{"CWE-798"},
				[]string{"gcp", "cloud"},
				[]string{"https://cloud.google.com/docs/authentication/api-keys#securing"},
			),
			re: secGoogleAPIRe,
			opts: secFindingOpts{
				remediation: "Restrict the key by HTTP referrer, IP or API in Google Cloud Console, rotate it if it was exposed, and prefer service accounts or workload identity for server-side calls.",
				label:       "Google API key",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-009",
				"OpenAI API key hardcoded in source",
				"An OpenAI API key is committed. It can be used to run completions and embeddings billed to the account, and leaked keys are a common source of unexpected spend.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"openai", "llm"},
				[]string{"https://help.openai.com/en/articles/4936850-where-do-i-find-my-openai-api-key"},
			),
			re:    secOpenAIRe,
			group: 0,
			validate: func(_ *File, _ string, groups []string) bool {
				v := groups[0]
				if strings.HasPrefix(v, "sk-ant-") {
					return false // Anthropic keys have their own rule.
				}
				lower := strings.ToLower(v)
				for _, noise := range []string{"test", "example", "sample", "fake", "dummy", "mock"} {
					if strings.Contains(lower, noise) {
						return false
					}
				}
				return true
			},
			opts: secFindingOpts{
				remediation: "Revoke the key in the OpenAI dashboard, issue a replacement, and load it from a secret manager. Set per-project spend limits and monitor usage.",
				label:       "OpenAI API key",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-010",
				"Anthropic API key hardcoded in source",
				"An Anthropic API key is committed. It can be used to run billed model requests against the account and may expose prompt or customer data.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"anthropic", "llm"},
				[]string{"https://docs.anthropic.com/en/api/overview"},
			),
			re: secAnthropicRe,
			opts: secFindingOpts{
				remediation: "Revoke the key in the Anthropic Console, issue a replacement, and load it from a secret manager. Add spend alerts.",
				label:       "Anthropic API key",
			},
		}.rule(),

		secPrivateKeyRule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-012",
				"JWT literal hardcoded in source",
				"A JSON Web Token literal is embedded in the repository. A signed token can impersonate its subject until it expires; a token with a long lifetime or a privileged claim is effectively a permanent credential.",
				model.SeverityHigh,
				[]string{"CWE-798", "CWE-522"},
				[]string{"jwt", "token"},
				[]string{"https://cwe.mitre.org/data/definitions/522.html"},
			),
			re: secJWTRe,
			validate: func(_ *File, _ string, groups []string) bool {
				v := groups[0]
				// The canonical jwt.io example is documentation, not a leak.
				if strings.Contains(v, "eyJzdWIiOiIxMjM0NTY3ODkw") || strings.Contains(v, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV") {
					return false
				}
				return true
			},
			opts: secFindingOpts{
				remediation: "Treat the token as compromised, revoke the session or rotate the signing key, and issue tokens at runtime. Never commit captured tokens, even in tests.",
				label:       "JWT",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-013",
				"Credentials embedded in a URL",
				"A URL contains a username and password in clear text. URLs are logged by proxies, browsers, load balancers and error trackers, so the password leaks far beyond the repository.",
				model.SeverityHigh,
				[]string{"CWE-798", "CWE-522"},
				[]string{"credentials", "url"},
				[]string{"https://cwe.mitre.org/data/definitions/522.html"},
			),
			re: secBasicAuthRe,
			validate: func(_ *File, _ string, groups []string) bool {
				pw := secURLPassword(groups[0])
				return secStrongEnoughPassword(pw)
			},
			opts: secFindingOpts{
				remediation: "Remove the credentials from the URL, rotate the password, and use a token or client certificate issued at runtime. If a URL must be logged, strip the userinfo component first.",
				label:       "URL with credentials",
				maskURL:     true,
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-014",
				"Generic hardcoded password or secret assignment",
				"A quoted literal is assigned to a password, secret, token, API key or credential variable. Hardcoded secrets are copied into every clone, backup and container image, and rotating them requires a code change.",
				model.SeverityHigh,
				[]string{"CWE-798"},
				[]string{"credentials"},
				[]string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
			),
			re:           secGenericAssignRe,
			group:        2,
			minEntropy:   3.5,
			skipComments: true,
			validate: func(f *File, _ string, groups []string) bool {
				if len(groups) < 3 {
					return false
				}
				value := groups[2]
				if secDedicatedFile(f.Path) {
					return false // .env, *.tf, .npmrc and Docker config have their own rules.
				}
				lower := strings.ToLower(value)
				for _, ref := range []string{
					"process.env", "os.environ", "getenv", "environment.getenvironmentvariable",
					"${", "{{", "%s", "://", "config.", "settings.", "vault", "secretmanager",
					"secret_manager", "<", ">",
				} {
					if strings.Contains(lower, ref) {
						return false
					}
				}
				return !secLooksLikeProviderSecret(value) && !secLooksLikeNameOrLabel(value)
			},
			opts: secFindingOpts{
				severity:    model.SeverityHigh,
				confidence:  model.ConfidenceMedium,
				remediation: secRemediationRotate,
				label:       "hardcoded credential",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-015",
				"Database or message-broker connection string with credentials",
				"A connection URI contains an inline username and password. These strings end up in logs, crash reports, backups and container images, and the database account is usually over-privileged.",
				model.SeverityCritical,
				[]string{"CWE-798", "CWE-522"},
				[]string{"database", "connection-string"},
				[]string{"https://cwe.mitre.org/data/definitions/798.html"},
			),
			re: secConnStringRe,
			validate: func(_ *File, _ string, groups []string) bool {
				pw := secURLPassword(groups[0])
				return secStrongEnoughPassword(pw)
			},
			opts: secFindingOpts{
				remediation: "Rotate the database password, remove the inline credentials, and load the connection string from a secret manager. Create a dedicated least-privilege account per service.",
				label:       "connection string with credentials",
				maskURL:     true,
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-016",
				"npm registry auth token hardcoded in .npmrc",
				"An npm registry _authToken or _auth value is committed. It allows anyone to publish packages under the scope or read private packages, which is a direct supply-chain risk.",
				model.SeverityHigh,
				[]string{"CWE-798"},
				[]string{"npm", "supply-chain"},
				[]string{"https://docs.npmjs.com/cli/v10/configuring-npm/npmrc#auth-related-configuration"},
			),
			re:    secNPMTokenRe,
			group: 1,
			validate: func(_ *File, _ string, groups []string) bool {
				if len(groups) < 2 {
					return false
				}
				if strings.Contains(strings.ToLower(groups[0]), "_authtoken") {
					return len(groups[1]) >= 16
				}
				// A bare _auth value is base64("user:password"); decode it to
				// avoid flagging unrelated base64 blobs.
				raw, err := base64.StdEncoding.DecodeString(groups[1])
				return err == nil && strings.Contains(string(raw), ":")
			},
			opts: secFindingOpts{
				remediation: "Revoke the npm token, replace it with a granular access token scoped to the minimum packages and IP ranges, and inject it from CI secrets. Never commit .npmrc with auth entries.",
				label:       "npm auth token",
			},
		}.rule(),

		secEnvRule(),

		secHerokuRule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-019",
				"DigitalOcean personal access token hardcoded in source",
				"A DigitalOcean API token is committed. It can create, resize and destroy Droplets, read snapshots and manipulate DNS, giving an attacker control over the infrastructure.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"digitalocean", "cloud"},
				[]string{"https://docs.digitalocean.com/reference/api/create-personal-access-token/"},
			),
			re: secDigitalOceanRe,
			opts: secFindingOpts{
				remediation: "Revoke the token in the DigitalOcean control panel, issue a scoped replacement, and store it in a secret manager. Audit recent API activity.",
				label:       "DigitalOcean token",
			},
		}.rule(),

		secTwilioRule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-021",
				"SendGrid API key hardcoded in source",
				"A SendGrid API key is committed. It can send mail as the verified domain, which is routinely abused for phishing and destroys sender reputation.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"sendgrid", "email"},
				[]string{"https://docs.sendgrid.com/ui/account-and-settings/api-keys"},
			),
			re: secSendGridRe,
			opts: secFindingOpts{
				remediation: "Delete the key in SendGrid, create a restricted replacement with only the required permissions, and load it from a secret manager. Review the sender reputation and activity log.",
				label:       "SendGrid API key",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-022",
				"Azure Storage account key hardcoded in source",
				"An Azure Storage account key is committed. Account keys grant full control over every container, queue and table in the storage account, including deleting or exfiltrating data.",
				model.SeverityCritical,
				[]string{"CWE-798"},
				[]string{"azure", "cloud"},
				[]string{"https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"},
			),
			re:    secAzureKeyRe,
			group: 1,
			opts: secFindingOpts{
				remediation: "Rotate the storage account key immediately, move clients to managed identities or short-lived SAS tokens, and disable shared-key access where possible.",
				label:       "Azure Storage account key",
			},
		}.rule(),

		secPattern{
			meta: secMeta(
				"VGL-SEC-023",
				"Terraform variable contains a hardcoded secret",
				"A Terraform variable or resource argument contains a literal password, token or key. Terraform state and plan files store values in clear text, and they are often shared through remote backends or CI artifacts.",
				model.SeverityHigh,
				[]string{"CWE-798"},
				[]string{"terraform", "iac"},
				[]string{"https://developer.hashicorp.com/terraform/language/state/sensitive-data"},
			),
			re:         secTerraformAssignRe,
			group:      2,
			minEntropy: 3.0,
			validate: func(f *File, _ string, groups []string) bool {
				if !secIsTerraformFile(f) || len(groups) < 3 {
					return false
				}
				if !secTerraformKeyRe.MatchString(groups[1]) {
					return false
				}
				lower := strings.ToLower(groups[2])
				for _, ref := range []string{"var.", "local.", "data.", "module.", "env.", "${", "{{"} {
					if strings.Contains(lower, ref) {
						return false
					}
				}
				return true
			},
			opts: secFindingOpts{
				remediation: secRemediationTerraform,
				label:       "Terraform secret",
			},
		}.rule(),

		secDockerAuthRule(),
	}
}

func secMeta(id, title, description string, severity model.Severity, cwe, tags, refs []string) model.RuleMeta {
	return model.RuleMeta{
		ID:          id,
		Title:       title,
		Description: description,
		Severity:    severity,
		Category:    model.CategorySecrets,
		CWE:         cwe,
		OWASP:       []string{"A07:2021 - Identification and Authentication Failures"},
		Tags:        append([]string{"secrets"}, tags...),
		References:  refs,
	}
}

func secScanFile(f *File, s secScan) []secMatch {
	if f == nil || s.re == nil {
		return nil
	}
	var out []secMatch
	for i, line := range f.Lines {
		if s.skipComments && IsCommentLine(line, f.Language) {
			continue
		}
		for _, m := range s.re.FindAllStringSubmatch(line, -1) {
			idx := s.group
			if idx >= len(m) {
				idx = 0
			}
			value := strings.TrimSpace(m[idx])
			if value == "" || LooksLikePlaceholder(value) {
				continue
			}
			if s.minEntropy > 0 && Entropy(value) < s.minEntropy {
				continue
			}
			if s.validate != nil && !s.validate(f, line, m) {
				continue
			}
			out = append(out, secMatch{line: i + 1, value: value})
		}
	}
	return out
}

func secFindings(f *File, matches []secMatch, o secFindingOpts) []model.Finding {
	if f == nil || len(matches) == 0 {
		return nil
	}
	severity := o.severity
	if severity == "" {
		severity = model.SeverityHigh
	}
	severity = SeverityForLanguage(severity, f.Path)
	confidence := o.confidence
	if confidence == "" {
		confidence = model.ConfidenceHigh
	}
	out := make([]model.Finding, 0, len(matches))
	for _, m := range matches {
		masked := MaskSecret(m.value)
		if o.maskURL {
			masked = secMaskURL(m.value)
		}
		evidence := masked
		if o.label != "" {
			evidence = o.label + ": " + masked
		}
		out = append(out, model.Finding{
			Severity:   severity,
			Confidence: confidence,
			Location: model.Location{
				Path:      f.Path,
				StartLine: m.line,
				EndLine:   m.line,
				// Secret snippets are single-line: a radius-1 window could
				// expose a different credential on a neighbouring line.
				Snippet: secRedactSnippet(f, m.line, m.value),
			},
			Evidence:    evidence,
			Remediation: o.remediation,
			References:  append([]string(nil), o.references...),
		})
	}
	return out
}

func secRedactSnippet(f *File, line int, secret string) string {
	snippet := Snippet(f, line, 0)
	if secret != "" {
		snippet = strings.ReplaceAll(snippet, secret, MaskSecret(secret))
	}
	return secHardRedactor.ReplaceAllStringFunc(snippet, MaskSecret)
}

// secMaskURL keeps the URL readable while replacing the password component.
func secMaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return MaskSecret(raw)
	}
	u.User = url.UserPassword(u.User.Username(), "********")
	return u.String()
}

func secURLPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return ""
	}
	pw, _ := u.User.Password()
	return pw
}

func secStrongEnoughPassword(pw string) bool {
	if len(pw) < 8 || secWeakValue(pw) {
		return false
	}
	lower := strings.ToLower(pw)
	for _, marker := range []string{"${", "{{", "%s", "<", ">", "***", "example", "changeme"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

var secWeakValues = map[string]bool{
	"password": true, "passwd": true, "secret": true, "changeme": true,
	"admin": true, "root": true, "user": true, "guest": true,
	"postgres": true, "mysql": true, "mongodb": true, "redis": true,
	"example": true, "test": true, "demo": true, "default": true,
}

func secWeakValue(v string) bool {
	return secWeakValues[strings.ToLower(strings.TrimSpace(v))]
}

func secLooksLikeProviderSecret(v string) bool {
	return secProviderUnionRe.MatchString(strings.TrimSpace(v))
}

// secLooksLikeNameOrLabel reports whether a quoted value is a name, label or
// low-entropy placeholder rather than a credential. Generic secret assignments
// commonly point at an environment-variable name (TELEGRAM_BOT_TOKEN), a human
// label ("Webhook / forward secret") or a fixture identifier (signing_secret).
// None of those are secrets, and reporting them buries the real ones.
func secLooksLikeNameOrLabel(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " \t\r\n") {
		return true
	}
	if secEnvNameRe.MatchString(v) || secLowerNameRe.MatchString(v) {
		return true
	}
	hasDigit, hasSymbol := false, false
	for _, r := range v {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsLetter(r) || r == '_' || r == '-':
			// Word characters and word-joining separators are not symbols.
		default:
			hasSymbol = true
		}
	}
	if hasDigit || hasSymbol {
		return false
	}
	// No digit and no punctuation other than the word-joining -/_ characters.
	// Only a long, high-entropy value is still plausibly a credential.
	return len(v) < 24 || Entropy(v) < 3.8
}

// secDedicatedFile reports paths handled by a more specific secret rule.
func secDedicatedFile(p string) bool {
	if secIsEnvFile(p) || secIsTerraformPath(p) {
		return true
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	if base == ".npmrc" {
		return true
	}
	lowerPath := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	if strings.Contains(lowerPath, "docker") && base == "config.json" {
		return true
	}
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile")
}

func secIsEnvFile(p string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	if base != ".env" && !strings.HasPrefix(base, ".env.") && !strings.HasSuffix(base, ".env") {
		return false
	}
	for _, excluded := range []string{".example", ".sample", ".template", ".dist", ".defaults"} {
		if strings.HasSuffix(base, excluded) {
			return false
		}
	}
	return true
}

func secIsTerraformPath(p string) bool {
	ext := strings.ToLower(path.Ext(strings.ReplaceAll(p, "\\", "/")))
	return ext == ".tf" || ext == ".tfvars" || ext == ".hcl"
}

func secIsTerraformFile(f *File) bool {
	return f != nil && (f.Language == "terraform" || secIsTerraformPath(f.Path))
}

func secTrimQuotes(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func secEnvValueLooksReal(v string) bool {
	v = secTrimQuotes(v)
	if len(v) < 12 || LooksLikePlaceholder(v) {
		return false
	}
	lower := strings.ToLower(v)
	for _, marker := range []string{"${", "$(", "{{", "<", ">", "%s", "********", "file:", "/run/secrets/"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	// A URL without userinfo is an endpoint, not a credential.
	if strings.Contains(lower, "://") && !strings.Contains(lower, "@") {
		return false
	}
	return Entropy(v) >= 3.0
}

func secPrivateKeyRule() Rule {
	meta := secMeta(
		"VGL-SEC-011",
		"Private key block committed to the repository",
		"A PEM private key block is present in the repository. Anyone with the file can impersonate the server, decrypt traffic captured with the corresponding certificate, or sign tokens and artifacts. Git history keeps the key even after deletion.",
		model.SeverityCritical,
		[]string{"CWE-798", "CWE-321"},
		[]string{"private-key", "crypto"},
		[]string{"https://cwe.mitre.org/data/definitions/321.html"},
	)
	return New(meta, func(f *File) []model.Finding {
		if f == nil {
			return nil
		}
		var out []model.Finding
		for i, line := range f.Lines {
			header := secPrivateKeyRe.FindString(line)
			if header == "" {
				continue
			}
			out = append(out, model.Finding{
				Severity:   SeverityForLanguage(meta.Severity, f.Path),
				Confidence: model.ConfidenceHigh,
				Location: model.Location{
					Path:      f.Path,
					StartLine: i + 1,
					EndLine:   i + 1,
					// Only the header is safe to show: the key material is on
					// the following lines.
					Snippet: header,
				},
				Evidence:    "PEM private key block (content redacted)",
				Remediation: secRemediationPrivateKey,
				References:  append([]string(nil), meta.References...),
			})
		}
		return out
	})
}

func secEnvRule() Rule {
	meta := secMeta(
		"VGL-SEC-017",
		"Real secret value committed in an environment file",
		"An environment file contains a value that looks like a live credential. Environment files are frequently copied into images, backups and CI artifacts, and they are easy to commit by accident.",
		model.SeverityHigh,
		[]string{"CWE-798"},
		[]string{"dotenv", "credentials"},
		[]string{"https://12factor.net/config"},
	)
	return New(meta, func(f *File) []model.Finding {
		if f == nil || !secIsEnvFile(f.Path) {
			return nil
		}
		var matches []secMatch
		for i, line := range f.Lines {
			m := secEnvLineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			key, value := m[1], secTrimQuotes(m[2])
			if !secEnvKeyRe.MatchString(key) || !secEnvValueLooksReal(value) {
				continue
			}
			// Provider-shaped tokens are reported by their dedicated rule.
			if secLooksLikeProviderSecret(value) {
				continue
			}
			matches = append(matches, secMatch{line: i + 1, value: value})
		}
		return secFindings(f, matches, secFindingOpts{
			remediation: secRemediationEnv,
			references:  meta.References,
			label:       "environment value",
		})
	})
}

func secHerokuRule() Rule {
	meta := secMeta(
		"VGL-SEC-018",
		"Heroku API key hardcoded in source",
		"A Heroku API key is committed. It can manage apps, read config vars (which usually contain more credentials), scale dynos and access add-on data.",
		model.SeverityHigh,
		[]string{"CWE-798"},
		[]string{"heroku", "cloud"},
		[]string{"https://devcenter.heroku.com/articles/platform-api-reference#authentication"},
	)
	return New(meta, func(f *File) []model.Finding {
		if f == nil {
			return nil
		}
		matches := secScanFile(f, secScan{re: secHerokuAssignRe, group: 1})
		matches = append(matches, secScanFile(f, secScan{re: secHerokuTokenRe})...)
		return secFindings(f, matches, secFindingOpts{
			remediation: "Revoke the key in the Heroku account settings, issue a replacement, and load it from a secret manager. Rotate any config vars the key could read.",
			references:  meta.References,
			label:       "Heroku API key",
		})
	})
}

func secTwilioRule() Rule {
	meta := secMeta(
		"VGL-SEC-020",
		"Twilio credential hardcoded in source",
		"A Twilio auth token or API key is committed. It can send SMS and voice calls billed to the account, which is commonly abused for smishing and toll fraud.",
		model.SeverityHigh,
		[]string{"CWE-798"},
		[]string{"twilio", "telephony"},
		[]string{"https://www.twilio.com/docs/iam/keys/api-key"},
	)
	return New(meta, func(f *File) []model.Finding {
		if f == nil {
			return nil
		}
		matches := secScanFile(f, secScan{re: secTwilioAssignRe, group: 1})
		matches = append(matches, secScanFile(f, secScan{
			re: secTwilioKeyRe,
			validate: func(f *File, line string, _ []string) bool {
				return strings.Contains(strings.ToLower(line), "twilio") ||
					strings.Contains(strings.ToLower(f.Path), "twilio")
			},
		})...)
		return secFindings(f, matches, secFindingOpts{
			remediation: "Rotate the auth token or API key in the Twilio console, store the replacement in a secret manager, and review usage for unexpected calls.",
			references:  meta.References,
			label:       "Twilio credential",
		})
	})
}

func secDockerAuthRule() Rule {
	meta := secMeta(
		"VGL-SEC-024",
		"Registry credentials stored in a Docker config file",
		"A Docker config.json contains a base64 auth entry. Base64 is not encryption: anyone with the file can decode the registry username and password and push or pull images.",
		model.SeverityHigh,
		[]string{"CWE-798", "CWE-522"},
		[]string{"docker", "registry"},
		[]string{"https://docs.docker.com/engine/security/protect-access/"},
	)
	return New(meta, func(f *File) []model.Finding {
		if f == nil {
			return nil
		}
		var matches []secMatch
		for i, line := range f.Lines {
			m := secDockerAuthRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if !secDockerAuthContext(f, i+1) {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(m[1])
			if err != nil || !strings.Contains(string(decoded), ":") {
				continue
			}
			matches = append(matches, secMatch{line: i + 1, value: m[1]})
		}
		return secFindings(f, matches, secFindingOpts{
			remediation: secRemediationDocker,
			references:  meta.References,
			label:       "Docker registry auth",
		})
	})
}

func secDockerAuthContext(f *File, line int) bool {
	lowerPath := strings.ToLower(strings.ReplaceAll(f.Path, "\\", "/"))
	if strings.Contains(lowerPath, "docker") || strings.Contains(lowerPath, ".dockercfg") {
		return true
	}
	return strings.Contains(strings.ToLower(f.Window(line, 8)), `"auths"`)
}
