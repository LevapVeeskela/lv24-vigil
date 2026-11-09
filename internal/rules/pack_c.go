package rules

// Pack C: orchestration platforms (Kubernetes/Helm, Terraform, nginx), CI
// supply chain (GitLab, Jenkins, CircleCI, GitHub Actions), OAuth/OIDC and
// session hardening, GraphQL/API surfaces and dependency manifests.
//
// Helper names are prefixed "pc" so they cannot collide with the "pb" helpers
// used by the other rule packs.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	// Kubernetes / Helm.
	pcK8sRunAsNonRootFalseRe = regexp.MustCompile(`(?i)^\s*-?\s*runAsNonRoot\s*:\s*["']?false["']?\s*(?:#.*)?$`)
	pcImageDirectiveRe       = regexp.MustCompile(`(?i)^\s*-?\s*image\s*:\s*["']?([^"'\s#]+)`)
	pcK8sEnvNameRe           = regexp.MustCompile(`(?i)^\s*-\s*name\s*:\s*["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*$`)
	pcK8sValueRe             = regexp.MustCompile(`(?i)^\s*value\s*:\s*(.+?)\s*$`)
	pcK8sClusterAdminRe      = regexp.MustCompile(`(?i)^\s*-?\s*name\s*:\s*["']?cluster-admin["']?\s*$`)
	pcEnvSecretKeyRe         = regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|connection[_-]?string)`)
	pcK8sLimitsRe            = regexp.MustCompile(`(?i)\blimits\s*:`)

	// Terraform.
	pcTFPubliclyAccessibleRe = regexp.MustCompile(`(?i)^\s*publicly_accessible\s*=\s*true\b`)
	pcTFStorageEncryptedRe   = regexp.MustCompile(`(?i)^\s*storage_encrypted\s*=\s*false\b`)
	pcTFSecretAssignRe       = regexp.MustCompile(`(?i)^\s*([A-Za-z0-9_]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_]*)\s*=\s*"([^"]{6,})"\s*$`)
	pcTFForceDestroyRe       = regexp.MustCompile(`(?i)^\s*force_destroy\s*=\s*true\b`)
	pcTFAdminPortRe          = regexp.MustCompile(`(?i)(?:from_port|to_port|port|port_min|port_max)\s*=\s*["']?(9200|9300|27017|2375|2376|11211|15672|5601)["']?\b`)

	// nginx.
	pcNginxSSLProtocolsRe = regexp.MustCompile(`(?i)\bssl_protocols\s+([^;]+)`)

	// CI.
	pcNpmLifecycleRe        = regexp.MustCompile(`(?i)"(?:pre|post)?install"\s*:\s*"([^"]*)"`)
	pcDockerUsesRe          = regexp.MustCompile(`(?i)docker://([^\s"'#]+)`)
	pcGitLabDebugTraceRe    = regexp.MustCompile(`(?i)^\s*CI_DEBUG_TRACE\s*:\s*["']?(?:true|1|yes)["']?\s*$`)
	pcGitLabRemoteIncludeRe = regexp.MustCompile(`(?i)^\s*-\s*remote\s*:\s*["']?(https?://[^"'\s]+)["']?\s*$`)

	// Auth.
	pcJWTSecretKeyRe      = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])((?:jwt|jws|token|signing)[_-]?(?:secret|key)|(?:secret|signing)[_-]?key)\s*[:=]\s*(.+)$`)
	pcOAuthRedirectWildRe = regexp.MustCompile(`(?i)redirect[_-]?(?:uri|url)s?[^\n]{0,48}\*`)
	pcOIDCSkipCheckRe     = regexp.MustCompile(`(?i)\bskip[_-]?(?:issuer|audience|signature|client[_-]?id|token)[_-]?check\s*[:=]\s*true\b`)
	pcJWTIgnoreExpiryRe   = regexp.MustCompile(`(?i)\bignore[_-]?expiration\s*[:=]\s*true\b|\bverify[_-]?exp\s*[:=]\s*false\b|\bskip[_-]?expiry[_-]?check\s*[:=]\s*true\b`)
	pcOAuthImplicitRe     = regexp.MustCompile(`(?i)response[_-]?type\s*[:=]\s*["']?(?:token|id_token)\b`)
	pcJWTVerifyCallRe     = regexp.MustCompile(`(?i)\b(?:jwt|jsonwebtoken)\.verify\s*\(`)
	pcJWTSecretFallbackRe = regexp.MustCompile(`(?i)(?:process\.env|import\.meta\.env)\.[A-Za-z0-9_]*(?:SECRET|KEY|TOKEN)[A-Za-z0-9_]*\s*(?:\|\||\?\?)\s*["']([^"']+)["']`)
	pcPySecretFallbackRe  = regexp.MustCompile(`(?i)os\.(?:environ\.get|getenv)\(\s*["'][^"']*(?:SECRET|KEY|TOKEN)[^"']*["']\s*,\s*["']([^"']+)["']`)

	// Web.
	pcGraphQLServerRe   = regexp.MustCompile(`(?i)\bnew\s+ApolloServer\s*\(|\bgraphqlHTTP\s*\(|\bmakeExecutableSchema\s*\(|\bGraphQLServer\s*\(|\bApolloServer\s*\(|\bgraphene\.Schema\s*\(|\bGraphQLSchema\s*\(`)
	pcGraphQLLimitRe    = regexp.MustCompile(`(?i)depthlimit|depth_limit|maxdepth|max_depth|querydepth|query_depth|complexity|costanalysis|cost_analysis|validationrules|validation_rules`)
	pcSwaggerSetupRe    = regexp.MustCompile(`(?i)\bswagger(?:ui|module)?\.(?:setup|serve|init)\s*\(|\bSwaggerUI\s*\(|swagger[^\n]*enabled\s*[:=]\s*true`)
	pcCredentialQueryRe = regexp.MustCompile(`(?i)[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|password)=`)
	pcCredentialExprRe  = regexp.MustCompile(`(?i)[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|password)=\s*["']?\s*(?:\+|\$\{)`)
	pcRequestOriginRe   = regexp.MustCompile(`(?i)(?:req|request|r)\.(?:headers\.origin|headers\[\s*["']origin["']|get\(\s*["']origin["']|header\(\s*["']origin["']|Header\.Get\(\s*["']Origin["'])`)
	pcCORSOriginKeyRe   = regexp.MustCompile(`(?i)\borigin\s*:\s*(?:req|request)\.`)

	// Dependencies.
	pcGemfileGitRe    = regexp.MustCompile(`(?i)^\s*gem\s+["'][^"']+["'][^\n]*\bgit\s*:\s*["'][^"']+["']`)
	pcCargoGitRe      = regexp.MustCompile(`(?i)\bgit\s*=\s*["'][^"']+["']`)
	pcInsecureIndexRe = regexp.MustCompile(`(?i)(?:--(?:extra-)?index-url|index-url|registry)\s*[=:]?\s*["']?http://`)
	pcLockfileHTTPRe  = regexp.MustCompile(`(?i)"resolved"\s*:\s*"http://|^\s*resolved\s+"http://`)
	pcMavenHTTPURLRe  = regexp.MustCompile(`(?i)<url>\s*http://`)
)

// PackCRules returns the platform, CI supply-chain, OAuth/OIDC, API and
// dependency-manifest rules.
func PackCRules() []Rule {
	return []Rule{
		// ---------------------------------------------------------------
		// Kubernetes / Helm
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-CFG-018",
			Title:       "Kubernetes container explicitly allows running as root",
			Description: "runAsNonRoot:false lets the container start as UID 0 and defeats the pod security context. Set runAsNonRoot:true together with a numeric runAsUser.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"kubernetes", "container", "root"},
		}, pcK8sRunAsNonRootFalseRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-019",
			Title:       "Kubernetes image uses a mutable or missing tag",
			Description: "An image pinned to :latest or to no tag at all resolves to a different digest on every pull, so a compromised registry silently changes what runs. Pin a version or a digest.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"kubernetes", "supply-chain"},
		}, pcK8sMutableImageRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-020",
			Title:       "Kubernetes environment variable contains a literal secret",
			Description: "A credential written into a manifest's env value is stored in Git, the API server and every etcd backup. Reference a Secret with valueFrom.secretKeyRef instead.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-798"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"kubernetes", "secret"},
		}, pcK8sEnvSecretRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-021",
			Title:       "Kubernetes container has no resource limits",
			Description: "A container without CPU and memory limits can consume the whole node and starve every other workload. Set resources.limits for each container.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-770"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"kubernetes", "reliability"},
		}, pcK8sMissingLimitsRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-029",
			Title:       "Kubernetes binding grants cluster-admin",
			Description: "Binding a workload or user to the cluster-admin ClusterRole grants full control over every namespace and secret. Grant a narrowly scoped Role instead.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-269"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"kubernetes", "rbac"},
		}, pcK8sClusterAdminRule),

		// ---------------------------------------------------------------
		// Terraform
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-CFG-023",
			Title:       "Terraform database is publicly accessible",
			Description: "publicly_accessible=true attaches a public endpoint to the database. Keep it private and reach it through a bastion, VPN or VPC peering.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-284"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"terraform", "cloud", "database"},
		}, pcTFPubliclyAccessibleRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-024",
			Title:       "Terraform storage encryption disabled",
			Description: "storage_encrypted=false leaves database snapshots and volumes readable at rest. Enable encryption and use a customer-managed KMS key.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-311"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"terraform", "cloud", "storage"},
		}, pcTFStorageEncryptionRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-025",
			Title:       "Terraform file contains a hardcoded secret",
			Description: "A literal password, token or key in .tf is stored in version control and in state. Use a secret manager data source or a sensitive variable supplied at apply time.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-798"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"terraform", "secret"},
		}, pcTFHardcodedSecretRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-026",
			Title:       "Terraform stateful resource can be force-destroyed",
			Description: "force_destroy=true lets terraform destroy delete a bucket or table together with all of its data in one apply. Remove it for stateful resources.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-404"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"terraform", "cloud", "data-loss"},
		}, pcTFForceDestroyRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-027",
			Title:       "Terraform security group exposes a datastore or admin port",
			Description: "Ingress from 0.0.0.0/0 or ::/0 to Elasticsearch, MongoDB, Redis, Docker or other admin ports exposes unauthenticated services to the internet. Restrict the CIDR to known networks.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-284"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"terraform", "network"},
		}, pcTFAdminPortRule),

		// ---------------------------------------------------------------
		// nginx
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-CFG-028",
			Title:       "nginx enables deprecated TLS 1.0 or 1.1",
			Description: "TLS 1.0 and 1.1 are deprecated and vulnerable to downgrade and padding attacks. Configure ssl_protocols TLSv1.2 TLSv1.3.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-326"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"nginx", "tls"},
		}, pcNginxWeakTLSRule),

		// ---------------------------------------------------------------
		// CI supply chain
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-CI-012",
			Title:       "CircleCI image uses a mutable tag",
			Description: "A :latest or untagged executor image changes without review and runs with CI credentials. Pin a version or a digest.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"circleci", "supply-chain"},
		}, pcCircleCIImageRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-013",
			Title:       "npm lifecycle script downloads and executes remote code",
			Description: "preinstall/postinstall scripts run on every npm install, including on developer machines and CI. A script that pipes a remote download into a shell executes unreviewed code with the installer's privileges.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			Languages:   []string{"json"},
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"npm", "supply-chain"},
		}, pcNpmLifecycleRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-014",
			Title:       "GitHub Actions docker:// image uses a mutable tag",
			Description: "A docker:// step with :latest or no tag pulls whatever the registry serves at run time. Pin the image to a version or digest.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"github-actions", "supply-chain"},
		}, pcDockerActionImageRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-015",
			Title:       "GitLab CI enables CI_DEBUG_TRACE",
			Description: "CI_DEBUG_TRACE prints every command and its environment into the job log, including masked variables on older runners. Never enable it on a shared or production project.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-532"},
			OWASP:       []string{"A09:2021"},
			Tags:        []string{"gitlab-ci", "secret"},
		}, pcGitLabDebugTraceRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-016",
			Title:       "CI pipeline pipes a remote script into a shell",
			Description: "curl | sh in a Jenkins or CircleCI job executes whatever the remote host returns with the job's credentials. Download the script, verify a checksum and then run it.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCI,
			Languages:   []string{"groovy", "yaml"},
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"ci", "supply-chain"},
		}, pcNonGitHubPipeShellRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-017",
			Title:       "GitLab CI includes remote configuration over plain HTTP",
			Description: "include:remote over http:// can be modified in transit and is evaluated with the pipeline's variables. Use https:// and pin the template by commit.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"gitlab-ci", "supply-chain"},
		}, pcGitLabRemoteIncludeRule),

		// ---------------------------------------------------------------
		// OAuth / OIDC / JWT
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-AUTH-010",
			Title:       "JWT signing secret is too short",
			Description: "A signing secret shorter than 32 characters can be brute-forced offline, allowing an attacker to mint valid tokens. Use at least 256 bits of random key material.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-326"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"jwt", "secret"},
		}, pcJWTShortSecretRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-011",
			Title:       "OAuth redirect URI accepts a wildcard",
			Description: "A wildcard redirect_uri lets an attacker register a matching host and receive authorization codes. Register exact callback URLs.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-183"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"oauth", "redirect"},
		}, pcOAuthRedirectWildcardRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-012",
			Title:       "OIDC issuer or audience validation disabled",
			Description: "Skipping issuer, audience or signature checks accepts tokens minted for another application or by another issuer. Keep every OIDC validation enabled.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-345"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"oidc", "token"},
		}, pcOIDCSkipCheckRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-013",
			Title:       "JWT expiration validation disabled",
			Description: "ignoreExpiration or verify_exp=false accepts expired tokens forever, so a stolen token stays valid. Validate exp on every verification.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-613"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"jwt", "session"},
		}, pcJWTIgnoreExpiryRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-014",
			Title:       "OAuth implicit grant is used",
			Description: "response_type=token returns the access token in the URL fragment, where it leaks through history, logs and referrers. Use the authorization code flow with PKCE.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-598"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"oauth", "token"},
		}, pcOAuthImplicitRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-015",
			Title:       "JWT verified without an algorithm allow-list",
			Description: "Calling jwt.verify without algorithms accepts whatever the token header declares, enabling algorithm-confusion attacks. Pass an explicit algorithms list.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-347"},
			OWASP:       []string{"A07:2021"},
			Tags:        []string{"jwt", "auth"},
		}, pcJWTVerifyNoAlgRule),

		New(model.RuleMeta{
			ID:          "VGL-AUTH-016",
			Title:       "JWT secret falls back to a hardcoded default",
			Description: "A fallback such as process.env.JWT_SECRET || 'dev-secret' silently signs production tokens with a public value when the variable is unset. Fail fast instead.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAuth,
			CWE:         []string{"CWE-798"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"jwt", "secret"},
		}, pcJWTSecretFallbackRule),

		// ---------------------------------------------------------------
		// GraphQL / API
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-WEB-013",
			Title:       "GraphQL server has no query depth or complexity limit",
			Description: "Without a depth or cost limit a single nested query can exhaust CPU and memory. Add depthLimit and cost analysis validation rules.",
			Severity:    model.SeverityInfo,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-770"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"graphql", "dos"},
		}, pcGraphQLNoLimitRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-014",
			Title:       "Content-Security-Policy allows unsafe-inline or unsafe-eval",
			Description: "'unsafe-inline' and 'unsafe-eval' re-enable script injection that CSP exists to stop. Use nonces or hashes and move inline handlers to files.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"csp", "headers"},
		}, pcCSPUnsafeRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-015",
			Title:       "API documentation UI exposed in production",
			Description: "Swagger/OpenAPI UIs enumerate every route, parameter and model. Disable them in production or put them behind staff authentication.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-200"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"swagger", "api"},
		}, pcSwaggerInProductionRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-016",
			Title:       "API credential passed in the query string",
			Description: "Tokens in the query string are written to access logs, proxies and browser history. Send credentials in the Authorization header.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-598"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"api", "secret"},
		}, pcCredentialInQueryRule),

		New(model.RuleMeta{
			ID:          "VGL-WEB-017",
			Title:       "CORS origin is reflected from the request",
			Description: "Echoing the request Origin into Access-Control-Allow-Origin allows any site to read responses. Compare the origin against an allow-list.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryWeb,
			CWE:         []string{"CWE-942"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"cors", "headers"},
		}, pcCORSReflectRule),

		// ---------------------------------------------------------------
		// Dependency manifests
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-DEP-008",
			Title:       "Bundler dependency from git without a ref",
			Description: "A Gemfile gem pinned only to a git repository follows its default branch, so any push changes what the build installs. Pin a ref or a released version.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-829"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"bundler", "supply-chain"},
		}, pcGemfileGitRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-009",
			Title:       "Cargo dependency from git without rev or tag",
			Description: "A git dependency without rev or tag tracks the default branch, so builds are not reproducible. Pin rev or tag.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-829"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"cargo", "supply-chain"},
		}, pcCargoGitRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-010",
			Title:       "Package index is configured over plain HTTP",
			Description: "An index fetched over http:// can serve a tampered package or metadata to the installer. Use https:// and install the index CA certificate.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-319"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"supply-chain", "tls"},
		}, pcInsecureIndexRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-011",
			Title:       "Lockfile resolves a package over plain HTTP",
			Description: "A resolved URL over http:// lets a network attacker replace the tarball the lockfile pins. Regenerate the lockfile against an https registry.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"lockfile", "supply-chain"},
		}, pcLockfileHTTPRule),

		New(model.RuleMeta{
			ID:          "VGL-DEP-012",
			Title:       "Maven repository is configured over plain HTTP",
			Description: "A Maven repository over http:// can serve tampered artifacts that Maven will trust. Use https:// and enable checksum verification.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryDependency,
			CWE:         []string{"CWE-319"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"maven", "supply-chain"},
		}, pcMavenHTTPRule),
	}
}

// ---------------------------------------------------------------------------
// Shared pack-C helpers
// ---------------------------------------------------------------------------

// pcSecretFinding builds a finding whose snippet also hides the secret value.
func pcSecretFinding(f *File, line int, evidence, secret string) model.Finding {
	fd := pbFinding(f, line, evidence)
	if secret != "" {
		fd.Location.Snippet = strings.ReplaceAll(fd.Location.Snippet, secret, MaskSecret(secret))
	}
	return fd
}

// pcMutableImage explains why an image reference is not reproducible, or
// returns "" when it is pinned by tag or digest.
func pcMutableImage(image string) string {
	lower := strings.ToLower(strings.TrimSpace(image))
	if lower == "" {
		return ""
	}
	if strings.Contains(lower, "{{") || strings.Contains(lower, "${") || strings.Contains(lower, "$(") {
		return ""
	}
	if strings.Contains(lower, "@sha256:") {
		return ""
	}
	if strings.HasSuffix(lower, ":latest") {
		return "uses the mutable :latest tag"
	}
	last := lower
	if i := strings.LastIndex(last, "/"); i >= 0 {
		last = last[i+1:]
	}
	if !strings.Contains(last, ":") {
		return "uses an untagged image"
	}
	return ""
}

// pcIsNginxConf reports whether the file looks like an nginx configuration.
func pcIsNginxConf(f *File) bool {
	p := pbPathLower(f)
	if strings.Contains(p, "nginx") {
		return true
	}
	base := pbBaseLower(f.Path)
	if !strings.HasSuffix(base, ".conf") {
		return false
	}
	content := string(f.Content)
	return pbHasAny(content, "server {", "server{", "http {", "ssl_protocols", "add_header", "location ")
}

func pcIsCircleCI(f *File) bool {
	return pbBaseLower(f.Path) == "config.yml" && strings.Contains(pbPathLower(f), ".circleci/")
}

func pcIsBitbucket(f *File) bool {
	return pbBaseLower(f.Path) == "bitbucket-pipelines.yml"
}

// pcEnvBlockAbove reports whether the YAML item at idx belongs to an env: list.
func pcEnvBlockAbove(f *File, idx int) bool {
	curIndent := pbLineIndent(f.Lines[idx])
	for j := idx - 1; j >= 0 && j >= idx-8; j-- {
		line := f.Lines[j]
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := pbLineIndent(line)
		if indent >= curIndent {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line)) == "env:" {
			return true
		}
		if indent == 0 {
			return false
		}
	}
	return false
}

// pcRunsRemoteScript reports whether a lifecycle command downloads and then
// executes a remote script.
func pcRunsRemoteScript(v string) bool {
	lower := strings.ToLower(v)
	if !strings.Contains(lower, "curl") && !strings.Contains(lower, "wget") {
		return false
	}
	for _, marker := range []string{
		"| sh", "| bash", "|sh", "|bash", "| node", "|node", "| python", "|python",
		"sh -c", "bash -c", "&& sh", "&& bash", "; sh", "; bash",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// pcTrimScalar strips quotes, trailing comments and statement punctuation.
func pcTrimScalar(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimSuffix(v, ";")
	v = strings.TrimSuffix(v, ",")
	v = strings.TrimSpace(v)
	return strings.Trim(v, `"'`)
}

// pcLooksLiteralSecret rejects values that reference another variable or path
// rather than carrying the secret itself.
func pcLooksLiteralSecret(v string) bool {
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	for _, marker := range []string{
		"$", "{", "}", "(", ")", "/", "\\", " ", "\t",
		"env", "process.", "os.", "var.", "vault", "secretmanager", "config.",
	} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

// pcTopLevelCommas counts commas outside quotes and brackets.
func pcTopLevelCommas(s string) int {
	depth := 0
	commas := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				commas++
			}
		}
	}
	return commas
}

// pcProductionContext reports whether the file describes a production
// environment, by path name or by an explicit NODE_ENV/ENV setting.
func pcProductionContext(f *File) bool {
	p := pbPathLower(f)
	if pbHasAnyFold(p, "production", "/prod/", "prod.", ".prod.", "-prod", "_prod") {
		return true
	}
	c := string(f.Content)
	return pbHasAnyFold(c, "node_env=production", "node_env: production", `node_env = "production"`,
		"environment: production", "env: production", "app_env=production")
}

// ---------------------------------------------------------------------------
// Kubernetes / Helm checks
// ---------------------------------------------------------------------------

func pcK8sRunAsNonRootFalseRule(f *File) []model.Finding {
	if !pbIsKubernetes(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcK8sRunAsNonRootFalseRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "runAsNonRoot: false allows the container to run as UID 0")
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID."
		out = append(out, fd)
	}
	return out
}

func pcK8sMutableImageRule(f *File) []model.Finding {
	if !pbIsKubernetes(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcImageDirectiveRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		reason := pcMutableImage(m[1])
		if reason == "" {
			continue
		}
		fd := pbFinding(f, i+1, "image "+m[1]+" "+reason)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Pin the image to an immutable version tag or a sha256 digest and update it deliberately."
		out = append(out, fd)
	}
	return out
}

func pcK8sEnvSecretRule(f *File) []model.Finding {
	if !pbIsKubernetes(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcK8sEnvNameRe.FindStringSubmatch(line)
		if m == nil || !pcEnvSecretKeyRe.MatchString(m[1]) || !pcEnvBlockAbove(f, i) {
			continue
		}
		for j := i + 1; j < len(f.Lines) && j <= i+3; j++ {
			if strings.Contains(strings.ToLower(f.Lines[j]), "valuefrom") {
				break
			}
			vm := pcK8sValueRe.FindStringSubmatch(f.Lines[j])
			if vm == nil {
				continue
			}
			value := strings.Trim(strings.TrimSpace(vm[1]), `"'`)
			if value == "" || strings.Contains(value, "$") || strings.Contains(value, "{{") {
				break
			}
			if LooksLikePlaceholder(value) {
				break
			}
			evidence := fmt.Sprintf("env %s has a literal value: %s", m[1], MaskSecret(value))
			fd := pcSecretFinding(f, j+1, evidence, value)
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			fd.Remediation = "Move the value into a Kubernetes Secret and reference it with valueFrom.secretKeyRef."
			out = append(out, fd)
			break
		}
	}
	return out
}

func pcK8sMissingLimitsRule(f *File) []model.Finding {
	if !pbIsKubernetes(f) {
		return nil
	}
	if !strings.Contains(string(f.Content), "containers:") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcImageDirectiveRe.MatchString(line) {
			continue
		}
		start := i - 6
		if start < 0 {
			start = 0
		}
		end := i + 14
		if end > len(f.Lines) {
			end = len(f.Lines)
		}
		hasLimits := false
		for j := start; j < end; j++ {
			if pcK8sLimitsRe.MatchString(f.Lines[j]) {
				hasLimits = true
				break
			}
		}
		if hasLimits {
			continue
		}
		fd := pbFinding(f, i+1, "container has no resources.limits: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityLow)
		fd.Confidence = model.ConfidenceLow
		fd.Remediation = "Add resources.limits.cpu and resources.limits.memory to every container."
		out = append(out, fd)
	}
	return out
}

func pcK8sClusterAdminRule(f *File) []model.Finding {
	if !pbIsKubernetes(f) {
		return nil
	}
	if !strings.Contains(string(f.Content), "ClusterRoleBinding") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcK8sClusterAdminRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "binding references the cluster-admin ClusterRole")
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Create a namespaced Role with only the required verbs and bind the workload to it."
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// Terraform checks
// ---------------------------------------------------------------------------

func pcTFPubliclyAccessibleRule(f *File) []model.Finding {
	if !pbIsTerraform(f) {
		return nil
	}
	if !pbHasAnyFold(string(f.Content), "aws_db_instance", "aws_rds_cluster", "aws_redshift_cluster", "aws_docdb_cluster", "aws_neptune_cluster") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcTFPubliclyAccessibleRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "publicly_accessible = true exposes the database endpoint to the internet")
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set publicly_accessible = false and reach the database through a VPN, bastion or VPC peering."
		out = append(out, fd)
	}
	return out
}

func pcTFStorageEncryptionRule(f *File) []model.Finding {
	if !pbIsTerraform(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcTFStorageEncryptedRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "storage_encrypted = false disables encryption at rest")
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set storage_encrypted = true and configure a KMS key for the database or cluster."
		out = append(out, fd)
	}
	return out
}

func pcTFHardcodedSecretRule(f *File) []model.Finding {
	if !pbIsTerraform(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcTFSecretAssignRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		value := m[2]
		if strings.Contains(value, "${") || strings.Contains(value, "{{") || LooksLikePlaceholder(value) {
			continue
		}
		evidence := fmt.Sprintf("%s = %s", m[1], MaskSecret(value))
		fd := pcSecretFinding(f, i+1, evidence, value)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Read the value from a secret manager data source or a sensitive variable that is supplied at apply time."
		out = append(out, fd)
	}
	return out
}

func pcTFForceDestroyRule(f *File) []model.Finding {
	if !pbIsTerraform(f) {
		return nil
	}
	if !pbHasAnyFold(string(f.Content), "aws_s3_bucket", "aws_dynamodb_table", "aws_efs_file_system") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcTFForceDestroyRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "force_destroy = true lets terraform delete the resource and its data")
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Remove force_destroy (or set it to false) for buckets and tables that hold data."
		out = append(out, fd)
	}
	return out
}

func pcTFAdminPortRule(f *File) []model.Finding {
	if !pbIsTerraform(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbTerraformCIDRRe.MatchString(line) {
			continue
		}
		start := i - 12
		if start < 0 {
			start = 0
		}
		end := i + 13
		if end > len(f.Lines) {
			end = len(f.Lines)
		}
		port := ""
		for j := start; j < end; j++ {
			if m := pcTFAdminPortRe.FindStringSubmatch(f.Lines[j]); m != nil {
				port = m[1]
				break
			}
		}
		if port == "" {
			continue
		}
		fd := pbFinding(f, i+1, "public CIDR exposes datastore/admin port "+port)
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Restrict the CIDR to known networks and require authentication or a private endpoint."
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// nginx
// ---------------------------------------------------------------------------

func pcNginxWeakTLSRule(f *File) []model.Finding {
	if !pcIsNginxConf(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcNginxSSLProtocolsRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		weak := false
		for _, token := range strings.Fields(m[1]) {
			token = strings.ToLower(strings.Trim(token, `"'`))
			if token == "tlsv1" || token == "tlsv1.1" {
				weak = true
				break
			}
		}
		if !weak {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Use ssl_protocols TLSv1.2 TLSv1.3 and a modern ssl_ciphers list."
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// CI checks
// ---------------------------------------------------------------------------

func pcCircleCIImageRule(f *File) []model.Finding {
	if !pcIsCircleCI(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcImageDirectiveRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		reason := pcMutableImage(m[1])
		if reason == "" {
			continue
		}
		fd := pbFinding(f, i+1, "image "+m[1]+" "+reason)
		fd.Severity = pbSev(f, model.SeverityLow)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Pin the executor image to a version tag or a sha256 digest."
		out = append(out, fd)
	}
	return out
}

func pcNpmLifecycleRule(f *File) []model.Finding {
	if !pbIsPackageJSON(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcNpmLifecycleRe.FindStringSubmatch(line)
		if m == nil || !pcRunsRemoteScript(m[1]) {
			continue
		}
		fd := pbFinding(f, i+1, "lifecycle script executes remote code: "+Truncate(m[1], 120))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Remove the remote download from the lifecycle script; vendor a reviewed artifact or verify a checksum before running it."
		out = append(out, fd)
	}
	return out
}

func pcDockerActionImageRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcDockerUsesRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		reason := pcMutableImage(m[1])
		if reason == "" {
			continue
		}
		fd := pbFinding(f, i+1, "docker action "+m[1]+" "+reason)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Pin the container action to a version tag or a sha256 digest."
		out = append(out, fd)
	}
	return out
}

func pcGitLabDebugTraceRule(f *File) []model.Finding {
	if !pbIsGitLabCI(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcGitLabDebugTraceRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "CI_DEBUG_TRACE is enabled for the pipeline")
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Remove CI_DEBUG_TRACE and use protected, masked variables for debugging."
		out = append(out, fd)
	}
	return out
}

func pcNonGitHubPipeShellRule(f *File) []model.Finding {
	if !pbIsJenkins(f) && !pcIsCircleCI(f) && !pcIsBitbucket(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbCurlPipeShellRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Download the script to a file, verify its checksum or signature, then execute it."
		out = append(out, fd)
	}
	return out
}

func pcGitLabRemoteIncludeRule(f *File) []model.Finding {
	if !pbIsGitLabCI(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcGitLabRemoteIncludeRe.FindStringSubmatch(line)
		if m == nil || !strings.HasPrefix(strings.ToLower(m[1]), "http://") {
			continue
		}
		fd := pbFinding(f, i+1, "remote include fetched over plain HTTP: "+m[1])
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Use an https:// URL and pin the included template to an immutable revision."
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// OAuth / OIDC / JWT checks
// ---------------------------------------------------------------------------

func pcJWTShortSecretRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || pcTestPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pcJWTSecretKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// This rule is about JWT signing keys. A generic `secretKey` in a
		// Telegram/weather service is a different secret with different
		// requirements, so require JWT context nearby.
		context := strings.ToLower(f.Window(i+1, 2))
		if !strings.Contains(context, "jwt") && !strings.Contains(context, "jws") && !strings.Contains(context, "jsonwebtoken") {
			continue
		}
		key := m[1]
		value := pcTrimScalar(m[2])
		if !pcLooksLiteralSecret(value) || LooksLikePlaceholder(value) || len(value) >= 32 {
			continue
		}
		evidence := fmt.Sprintf("%s is only %d characters: %s", key, len(value), MaskSecret(value))
		fd := pcSecretFinding(f, i+1, evidence, value)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Generate at least 32 random bytes for the signing key and load it from a secret manager."
		out = append(out, fd)
	}
	return out
}

func pcOAuthRedirectWildcardRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcOAuthRedirectWildRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Register exact callback URLs and compare the redirect_uri with an allow-list before issuing a code."
		out = append(out, fd)
	}
	return out
}

func pcOIDCSkipCheckRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcOIDCSkipCheckRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Enable issuer, audience and signature validation in the OIDC client configuration."
		out = append(out, fd)
	}
	return out
}

func pcJWTIgnoreExpiryRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcJWTIgnoreExpiryRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Remove the expiration override and validate exp on every token verification."
		out = append(out, fd)
	}
	return out
}

func pcOAuthImplicitRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcOAuthImplicitRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Switch to response_type=code with PKCE and exchange the code on the backend."
		out = append(out, fd)
	}
	return out
}

func pcJWTVerifyNoAlgRule(f *File) []model.Finding {
	if f.Language != "javascript" && f.Language != "typescript" {
		return nil
	}
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		loc := pcJWTVerifyCallRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		args := line[loc[1]:]
		if end := strings.LastIndex(args, ")"); end >= 0 {
			args = args[:end]
		}
		// A call split over several lines is not judged from one line.
		if strings.Count(args, "(") != strings.Count(args, ")") {
			continue
		}
		if pcTopLevelCommas(args) != 1 {
			continue
		}
		if strings.Contains(strings.ToLower(f.Window(i+1, 4)), "algorithms") {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		fd.Remediation = "Pass an explicit algorithms allow-list, for example { algorithms: ['RS256'] }."
		out = append(out, fd)
	}
	return out
}

func pcJWTSecretFallbackRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		value := ""
		if m := pcJWTSecretFallbackRe.FindStringSubmatch(line); m != nil {
			value = m[1]
		} else if m := pcPySecretFallbackRe.FindStringSubmatch(line); m != nil {
			value = m[1]
		}
		if value == "" || LooksLikePlaceholder(value) {
			continue
		}
		evidence := fmt.Sprintf("secret falls back to a hardcoded default: %s", MaskSecret(value))
		fd := pcSecretFinding(f, i+1, evidence, value)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Fail fast when the environment variable is missing instead of falling back to a literal."
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// GraphQL / API checks
// ---------------------------------------------------------------------------

func pcGraphQLNoLimitRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) || pbDocsPath(f.Path) {
		return nil
	}
	content := string(f.Content)
	if !pbHasAnyFold(content, "graphql", "apollo", "gql") {
		return nil
	}
	if pcGraphQLLimitRe.MatchString(content) {
		return nil
	}
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcGraphQLServerRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "GraphQL server configured without a query depth or complexity limit")
		fd.Severity = pbSev(f, model.SeverityInfo)
		fd.Confidence = model.ConfidenceLow
		fd.Remediation = "Add depthLimit and query-complexity validation rules to the GraphQL server."
		return []model.Finding{fd}
	}
	return nil
}

func pcCSPUnsafeRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "unsafe-inline") && !strings.Contains(lower, "unsafe-eval") {
			continue
		}
		start := i - 3
		if start < 0 {
			start = 0
		}
		end := i + 4
		if end > len(f.Lines) {
			end = len(f.Lines)
		}
		ctx := strings.ToLower(strings.Join(f.Lines[start:end], "\n"))
		if !strings.Contains(ctx, "content-security-policy") && !strings.Contains(ctx, "script-src") && !strings.Contains(ctx, "csp") {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Replace 'unsafe-inline'/'unsafe-eval' with nonces or hashes and move inline handlers into files."
		out = append(out, fd)
	}
	return out
}

func pcSwaggerInProductionRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || !pcProductionContext(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcSwaggerSetupRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "API documentation UI registered in a production configuration")
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		fd.Remediation = "Disable the Swagger/OpenAPI UI in production or protect it with staff authentication."
		out = append(out, fd)
	}
	return out
}

func pcCredentialInQueryRule(f *File) []model.Finding {
	if !pbCodeLanguage(f.Language) && f.Language != "shell" {
		return nil
	}
	if pbDocsPath(f.Path) || pcTestPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcCredentialQueryRe.MatchString(line) {
			continue
		}
		// Require an actual URL expression, not prose that mentions a
		// credential in a query string. The old `http|url|api` check matched
		// documentation and `returnUrl` strings.
		if !pcCredentialURLContext(line) {
			continue
		}
		fd := pbFinding(f, i+1, "credential placed in a URL query string: "+Truncate(strings.TrimSpace(line), 160))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceMedium
		fd.Remediation = "Send the credential in the Authorization header instead of the query string."
		out = append(out, fd)
	}
	return out
}

func pcCredentialURLContext(line string) bool {
	if pcCredentialExprRe.MatchString(line) {
		return true
	}
	l := strings.ToLower(line)
	for _, marker := range []string{
		"redirect(", "redirects(", "location.href", "window.location", "fetch(",
		"axios.", "http.get", "requests.get", "client.get", "new url(",
		"href=", "navigate(",
	} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

// pcTestPath reports whether a path is a test, fixture or example file. Fake
// credentials there are not production secrets.
func pcTestPath(p string) bool {
	p = strings.ToLower(filepath.ToSlash(p))
	return strings.Contains(p, "/test/") || strings.Contains(p, "/tests/") ||
		strings.Contains(p, "_test.") || strings.Contains(p, ".test.") ||
		strings.Contains(p, ".spec.") || strings.Contains(p, "/fixtures/") ||
		strings.Contains(p, "/examples/") || strings.Contains(p, "/testdata/")
}

func pcCORSReflectRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		lower := strings.ToLower(line)
		hasHeader := strings.Contains(lower, "access-control-allow-origin") || pcCORSOriginKeyRe.MatchString(line)
		if !hasHeader || !pcRequestOriginRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Compare the request Origin with an allow-list and return a fixed value or no CORS header."
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// Dependency manifest checks
// ---------------------------------------------------------------------------

func pcGemfileGitRule(f *File) []model.Finding {
	if pbBaseLower(f.Path) != "gemfile" {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcGemfileGitRe.MatchString(line) {
			continue
		}
		if pbHasAnyFold(line, "ref:", "tag:", "branch:") {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Add ref: with a full commit SHA, or depend on a released gem version."
		out = append(out, fd)
	}
	return out
}

func pcCargoGitRule(f *File) []model.Finding {
	if pbBaseLower(f.Path) != "cargo.toml" {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcCargoGitRe.MatchString(line) {
			continue
		}
		start := i
		for start > 0 && !strings.HasPrefix(strings.TrimSpace(f.Lines[start]), "[") {
			start--
		}
		end := i + 1
		for end < len(f.Lines) && !strings.HasPrefix(strings.TrimSpace(f.Lines[end]), "[") {
			end++
		}
		block := strings.Join(f.Lines[start:end], "\n")
		if pbHasAnyFold(block, "rev =", "rev=", "tag =", "tag=", "branch =", "branch=") {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Pin the dependency with rev = \"<sha>\" or tag = \"<version>\"."
		out = append(out, fd)
	}
	return out
}

func pcInsecureIndexRule(f *File) []model.Finding {
	base := pbBaseLower(f.Path)
	ok := base == ".npmrc" || base == ".yarnrc" || base == ".yarnrc.yml" ||
		base == "pip.conf" || base == "pip.ini" || base == "pyproject.toml" ||
		strings.HasPrefix(base, "requirements")
	if !ok {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcInsecureIndexRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Point the index at https:// and install the index CA certificate in the trust store."
		out = append(out, fd)
	}
	return out
}

func pcLockfileHTTPRule(f *File) []model.Finding {
	switch pbBaseLower(f.Path) {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml":
	default:
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcLockfileHTTPRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Regenerate the lockfile against an https:// registry so every resolved URL is TLS protected."
		out = append(out, fd)
	}
	return out
}

func pcMavenHTTPRule(f *File) []model.Finding {
	if pbBaseLower(f.Path) != "pom.xml" || !strings.Contains(string(f.Content), "<repository") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pcMavenHTTPURLRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Use an https:// repository URL and keep checksum verification enabled."
		out = append(out, fd)
	}
	return out
}
