package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	pbDockerFromRe      = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)
	pbAptInstallRe      = regexp.MustCompile(`(?i)\bapt(?:-get)?\s+(?:-\S+\s+)*install\b`)
	pbDockerAddURLRe    = regexp.MustCompile(`(?i)^\s*ADD\s+https?://`)
	pbDockerSecretKeyRe = regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)`)
	pbCurlPipeShellRe   = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b`)
	pbComposeImageRe    = regexp.MustCompile(`(?i)^\s*image:\s*["']?([^"'\s#]+)`)
	pbPublicS3Re        = regexp.MustCompile(`(?i)\bacl\s*=\s*["'](?:public-read|public-read-write)["']|AccessControl\s*[:=]\s*["']?PublicRead`)
	pbNginxAutoindexRe  = regexp.MustCompile(`(?i)^\s*autoindex\s+on\s*;`)
	pbTerraformCIDRRe   = regexp.MustCompile(`(?i)["']?(?:0\.0\.0\.0/0|::/0)["']?`)
	pbTerraformPortRe   = regexp.MustCompile(`(?i)(?:from_port|to_port|port|port_min|port_max)\s*=\s*["']?(22|3389|3306|5432|6379)["']?\b`)
	pbK8sPrivilegedRe   = regexp.MustCompile(`(?i)^\s*-?\s*privileged\s*:\s*true\b`)
	pbK8sHostPathRe     = regexp.MustCompile(`(?i)^\s*-?\s*hostPath\s*:`)
	pbK8sRunAsRootRe    = regexp.MustCompile(`(?i)^\s*-?\s*runAsUser\s*:\s*0\b`)
	pbK8sHostNetworkRe  = regexp.MustCompile(`(?i)^\s*-?\s*hostNetwork\s*:\s*true\b`)
	pbK8sHostPIDRe      = regexp.MustCompile(`(?i)^\s*-?\s*host(?:PID|IPC)\s*:\s*true\b`)
	pbK8sPrivEscRe      = regexp.MustCompile(`(?i)^\s*-?\s*allowPrivilegeEscalation\s*:\s*true\b`)

	// Docker socket mounts. A bare string constant or a client option that
	// happens to contain the path is not a mount; only compose volume entries,
	// docker CLI volume flags and Kubernetes hostPath volumes are.
	pbDockerSocketVolumeRe = regexp.MustCompile(`(?i)^\s*-\s*["']?/var/run/docker\.sock(?::|["']?\s*$)`)
	pbDockerSocketFlagRe   = regexp.MustCompile(`(?i)(?:^|\s)(?:--volume(?:=|\s+)|-v(?:=|\s+))["']?/var/run/docker\.sock(?:[:,"'\s]|$)`)

	// Runtime container CLI invocations (CFG-030, CFG-032, CFG-033, CFG-036).
	// Only run/create are runtime; docker build has no runtime namespaces.
	pbCfgDockerRuntimeRe = regexp.MustCompile(`(?i)^\s*(?:sudo\s+)?(?:docker\s+compose\s+run|docker\s+container\s+(?:run|create)|docker\s+(?:run|create)|docker-compose\s+run|podman\s+(?:run|create))\b`)
	pbCfgPrivilegedRe    = regexp.MustCompile(`(?i)(?:^|\s)--privileged(?:=true)?(?:\s|$)`)
	pbCfgHostNamespaceRe = regexp.MustCompile(`(?i)(?:^|\s)--(network|net|pid|ipc|uts)(?:=|\s+)["']?host["']?\b`)
	pbCfgUnconfinedRe    = regexp.MustCompile(`(?i)(?:seccomp|apparmor)\s*[:=]\s*["']?unconfined["']?\b`)
	pbCfgK8sProfileKeyRe = regexp.MustCompile(`(?i)^\s*-?\s*(?:seccompProfile|appArmorProfile)\s*:`)
	pbCfgCapAddCLIRe     = regexp.MustCompile(`(?i)--cap-add(?:=|\s+)["']?(?:CAP_)?(?:ALL|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|SYS_RAWIO|SYS_BOOT|BPF|PERFMON)\b`)
	pbCfgCapGrantKeyRe   = regexp.MustCompile(`(?i)^\s*-?\s*(?:cap_add|capabilities\.add|add)\s*:`)
	pbCfgCapAddListRe    = regexp.MustCompile(`(?i)\badd\s*:\s*\[([^\]]*)\]`)
	pbCfgDangerousCapRe  = regexp.MustCompile(`(?i)\b(?:CAP_)?(ALL|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|SYS_RAWIO|SYS_BOOT|BPF|PERFMON)\b`)

	// Infrastructure as code (CFG-040, CFG-041, CFG-042, CFG-044).
	pbIacActionWildcardRe   = regexp.MustCompile(`(?i)["']?(?:action|actions)["']?\s*(?:=|:)\s*(?:\[\s*)?["']\*["']`)
	pbIacResourceWildcardRe = regexp.MustCompile(`(?i)["']?(?:resource|resources)["']?\s*(?:=|:)\s*(?:\[\s*)?["']\*["']`)
	pbIacDenyEffectRe       = regexp.MustCompile(`(?i)["']?effect["']?\s*(?:=|:)\s*["']?deny["']?`)
	pbIacNotWildcardRe      = regexp.MustCompile(`(?i)["']?(?:not_action|notaction|not_resource|notresource)["']?\s*(?:=|:)`)
	pbIacCountZeroRe        = regexp.MustCompile(`(?i)^\s*count\s*=\s*0\b`)
	pbIacResourceHeaderRe   = regexp.MustCompile(`(?i)^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"`)
	pbIacPublicCIDRRe       = regexp.MustCompile(`(?i)["']?(?:0\.0\.0\.0/0|::/0)["']?`)
	pbIacTFAllProtocolRe    = regexp.MustCompile(`(?i)\b(?:protocol|ip_protocol)\s*=\s*"-1"`)
	pbIacTFFromPortZeroRe   = regexp.MustCompile(`(?i)\bfrom_port\s*=\s*0\b`)
	pbIacTFToPortAllRe      = regexp.MustCompile(`(?i)\bto_port\s*=\s*65535\b`)
	pbIacTFEgressTypeRe     = regexp.MustCompile(`(?i)\btype\s*=\s*"egress"`)
	pbIacCFNPublicCIDRRe    = regexp.MustCompile(`(?i)\bcidr_?ip(?:v6)?\s*:\s*["']?(?:0\.0\.0\.0/0|::/0)["']?`)
	pbIacCFNAllProtocolRe   = regexp.MustCompile(`(?i)\b(?:IpProtocol|protocol)\s*:\s*["']?-1["']?`)
	pbIacCFNFromPortZeroRe  = regexp.MustCompile(`(?i)\bFromPort\s*:\s*["']?0["']?`)
	pbIacCFNToPortAllRe     = regexp.MustCompile(`(?i)\bToPort\s*:\s*["']?65535["']?`)
	pbIacS3BPAOffRe         = regexp.MustCompile(`(?i)^\s*-?\s*(?:block_?public_?acls|block_?public_?policy|ignore_?public_?acls|restrict_?public_?buckets)\s*[:=]\s*false\b`)
	pbIacBPAConfigKeyRe     = regexp.MustCompile(`(?i)publicaccessblockconfiguration`)
	pbIacIMDSOptionalRe     = regexp.MustCompile(`(?i)\bhttp_tokens\s*=\s*["']optional["']`)
	pbIacCFNIMDSOptionalRe  = regexp.MustCompile(`(?i)\bhttp_?tokens\s*:\s*["']?optional["']?`)
	pbIacIMDSEndpointOffRe  = regexp.MustCompile(`(?i)\bhttp_endpoint\s*[:=]\s*["']?disabled["']?`)

	// nginx upstream TLS verification (CFG-045).
	pbCfgNginxProxySSLVerifyOffRe = regexp.MustCompile(`(?i)^\s*proxy_ssl_verify\s+["']?off["']?\s*;\s*(?:#.*)?$`)

	// Wave-1 IaC rules (CFG-046..CFG-050). Bounded line and block matching
	// only; no HCL or YAML parser is involved.
	pbW1IacPrincipalWildcardRe = regexp.MustCompile(`(?i)^\s*["']?principal[s]?["']?\s*[:=]\s*(?:\[\s*)?["']\*["']`)
	pbW1IacPrincipalInlineRe   = regexp.MustCompile(`(?i)["']?principal[s]?["']?\s*[:=]\s*\{[^}]*["']?aws["']?\s*[:=]\s*(?:\[\s*)?["']\*["']`)
	pbW1IacAWSWildcardRe       = regexp.MustCompile(`(?i)^\s*["']?aws["']?\s*[:=]\s*(?:\[\s*)?["']\*["']`)
	pbW1IacIDsWildcardRe       = regexp.MustCompile(`(?i)^\s*identifiers\s*=\s*\[\s*["']\*["']`)
	pbW1IacPrincipalKeyRe      = regexp.MustCompile(`(?i)["']?principal[s]?["']?\s*(?::|=|\{)`)
	pbW1IacActionKeyRe         = regexp.MustCompile(`(?i)["']?(?:action|actions|not_?action)["']?\s*[:=]`)
	pbW1IacEffectKeyRe         = regexp.MustCompile(`(?i)["']?effect["']?\s*[:=]`)
	// aws:Referer is client-supplied and spoofable, so it is deliberately not
	// in this list: only conditions the caller cannot forge restrict a policy.
	pbW1IacRestrictiveCondRe = regexp.MustCompile(`(?i)aws:principalarn|aws:sourcearn|aws:sourceaccount|sts:externalid|aws:principalorgid|aws:sourcevpce|aws:sourceip`)
	pbW1IacAssumeRoleRe      = regexp.MustCompile(`(?i)sts:assumerole`)
	pbW1IacS3ActionRe        = regexp.MustCompile(`(?i)\bs3:|\barn:aws:s3`)
	pbW1IacTrustGateRe       = regexp.MustCompile(`(?i)assume_role_policy`)
	pbW1IacCFNTrustGateRe    = regexp.MustCompile(`(?i)assumerolepolicydocument`)
	pbW1IacS3PolicyGateRe    = regexp.MustCompile(`(?i)^\s*resource\s+"aws_s3_bucket_policy"`)
	pbW1IacTFS3BucketBlockRe = regexp.MustCompile(`(?i)^\s*resource\s+"aws_s3_bucket"`)
	pbW1IacTFInlinePolicyRe  = regexp.MustCompile(`(?i)^\s*policy\s*=\s*\S`)
	// An environment label is the word plus optional digits and short
	// separator-delimited suffixes: production2, development_2 and staging-eu
	// are labels, not credentials.
	pbW1IacEnvWordRe        = regexp.MustCompile(`(?i)^(?:production|development|staging|testing|local|default|example|sample|changeme|placeholder|password|secret)(?:[0-9]{1,4})?(?:[-_.][0-9a-z]{0,4})*$`)
	pbW1IacBPAHeaderRe      = regexp.MustCompile(`(?i)^\s*resource\s+"aws_s3_bucket_public_access_block"`)
	pbW1IacTFS3BPAPolicyRe  = regexp.MustCompile(`(?i)^\s*block_public_policy\s*=\s*true\b`)
	pbW1IacCFNS3BPAPolicyRe = regexp.MustCompile(`(?i)["']?block_?public_?policy["']?\s*:\s*["']?true\b`)
	pbW1IacS3BackendRe      = regexp.MustCompile(`(?i)^\s*backend\s+"s3"\s*\{`)
	pbW1IacEncryptFalseRe   = regexp.MustCompile(`(?i)^\s*encrypt\s*=\s*false\b`)

	pbW1IacControlPlaneBinRe = regexp.MustCompile(`(?i)(kube-apiserver|kube-controller-manager|kube-scheduler|kubelet|etcd)`)
	pbW1IacAnonAuthRe        = regexp.MustCompile(`(?i)--anonymous-auth(?:=|\s+)["']?true\b`)
	pbW1IacAuthModeRe        = regexp.MustCompile(`(?i)--authorization-mode(?:=|\s+)["']?([A-Za-z0-9,_-]+)`)
	pbW1IacInsecurePortRe    = regexp.MustCompile(`(?i)--insecure-port(?:=|\s+)["']?([0-9]+)\b`)
	pbW1IacProfilingRe       = regexp.MustCompile(`(?i)--profiling(?:=|\s+)["']?true\b`)
	pbW1IacStaticAuthFileRe  = regexp.MustCompile(`(?i)--(?:token-auth-file|basic-auth-file)(?:=|\s+)["']?[^\s"'#]+`)
	pbW1IacEtcdClientCertRe  = regexp.MustCompile(`(?i)--client-cert-auth(?:=|\s+)["']?false\b`)
	pbW1IacEtcdAutoTLSRe     = regexp.MustCompile(`(?i)--(auto-tls|peer-auto-tls)(?:=|\s+)["']?true\b`)

	pbW1IacComposeListRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.+)$`)
	pbW1IacComposeMapRe  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)\s*:\s*(.+)$`)
	pbW1IacSecretKeyRe   = regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|credential|apikey|api[_-]key|private[_-]key|access[_-]key|signing[_-]key)|(?:^|[_-])key(?:$|[_-])`)
)

// ConfigRules returns the container, orchestration and infrastructure rules.
func ConfigRules() []Rule {
	return []Rule{
		New(model.RuleMeta{
			ID:          "VGL-CFG-001",
			Title:       "Container runs as root",
			Description: "A Dockerfile without a non-root USER runs the process as root. Create an unprivileged user and switch to it before the entrypoint.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"dockerfile"},
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "container"},
		}, pbDockerRootRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-002",
			Title:       "Docker base image is mutable or untagged",
			Description: "FROM :latest or an untagged image makes builds non-reproducible and can silently pull a compromised or breaking release. Pin a version or digest.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryConfig,
			Languages:   []string{"dockerfile"},
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"docker", "supply-chain"},
		}, pbDockerFromRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-003",
			Title:       "apt-get install pulls recommended packages",
			Description: "Installing recommended packages enlarges the image and attack surface. Use --no-install-recommends and clean the apt cache.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryConfig,
			Languages:   []string{"dockerfile"},
			CWE:         []string{"CWE-1127"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"docker", "image"},
		}, pbAptInstallRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-004",
			Title:       "ADD fetches a remote URL without verification",
			Description: "ADD https://... downloads content at build time without a checksum. Prefer COPY with a verified artifact or pin and verify the download.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"dockerfile"},
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"docker", "supply-chain"},
		}, pbDockerAddURLRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-005",
			Title:       "Secret stored in a Docker ARG or ENV",
			Description: "ARG and ENV values are baked into image layers and visible in image history. Pass secrets at runtime or use BuildKit secret mounts.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"dockerfile"},
			CWE:         []string{"CWE-798"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"docker", "secret"},
		}, pbDockerSecretRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-006",
			Title:       "Remote script piped into a shell in Dockerfile",
			Description: "curl | sh executes whatever the remote server returns. Download, verify a checksum or signature, then execute.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"dockerfile"},
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"docker", "supply-chain"},
		}, pbDockerCurlPipeRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-007",
			Title:       "Docker Compose container runs privileged",
			Description: "privileged:true grants all capabilities and host device access, effectively escaping container isolation. Drop it and add only the needed capabilities.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "compose"},
		}, pbComposePrivilegedRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-008",
			Title:       "Docker Compose uses host networking",
			Description: "network_mode:host removes network isolation and exposes every host port. Use a user-defined bridge network and publish only required ports.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-668"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "compose"},
		}, pbComposeHostNetworkRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-009",
			Title:       "Docker socket mounted into a container",
			Description: "Mounting /var/run/docker.sock gives the container control over the host Docker daemon, which is equivalent to root on the host.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "container"},
		}, pbDockerSocketRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-010",
			Title:       "SYS_ADMIN capability granted",
			Description: "CAP_SYS_ADMIN is one of the most powerful capabilities and enables container escapes. Remove it or replace it with the narrowest capability that works.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "capabilities"},
		}, pbSysAdminRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-011",
			Title:       "Docker Compose image uses a mutable tag",
			Description: "image:...:latest (or no tag) makes deployments non-reproducible. Pin a version or digest.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-1104"},
			OWASP:       []string{"A06:2021"},
			Tags:        []string{"docker", "compose"},
		}, pbComposeImageRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-012",
			Title:       "Kubernetes workload has elevated privileges or host access",
			Description: "privileged, hostPath, hostNetwork, hostPID, allowPrivilegeEscalation and runAsUser:0 break pod isolation. Use a restricted security context and drop all capabilities.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"kubernetes", "container"},
		}, pbKubernetesRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-013",
			Title:       "Terraform security group opens a sensitive port to the internet",
			Description: "Ingress from 0.0.0.0/0 or ::/0 to SSH, RDP, database or Redis ports exposes administrative services to the whole internet. Restrict the CIDR to known networks.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-284"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"terraform", "network"},
		}, pbTerraformPublicPortRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-014",
			Title:       "Object storage bucket allows public ACL",
			Description: "public-read or public-read-write exposes every object to the internet. Use private ACLs and grant access through signed URLs or a CDN policy.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-284"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"cloud", "storage"},
		}, pbPublicS3Rule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-015",
			Title:       "EBS volume encryption disabled",
			Description: "Unencrypted EBS volumes expose data at rest if the volume or its snapshots leak. Set encrypted = true and use a KMS key.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-311"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"cloud", "storage"},
		}, pbUnencryptedEBSRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-016",
			Title:       "nginx directory listing enabled",
			Description: "autoindex on exposes directory contents, including backups and temporary files. Turn it off or protect the location.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-548"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"nginx", "config"},
		}, pbNginxAutoindexRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-017",
			Title:       "Environment file present in the repository",
			Description: "A committed .env file commonly carries credentials and deployment secrets. Keep .env out of version control and commit a redacted .env.example instead.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-538"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"secret", "config"},
		}, pbEnvFileRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-030",
			Title:       "Docker CLI shares a host network, PID, IPC or UTS namespace",
			Description: "--network host, --pid host, --ipc host and --uts host each remove a container namespace boundary, exposing host ports, processes or IPC. Use a user-defined network and keep host namespaces private.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"shell", "yaml"},
			CWE:         []string{"CWE-250", "CWE-668"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "container"},
		}, pbCfgHostNamespaceRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-032",
			Title:       "Container disables seccomp or AppArmor confinement",
			Description: "seccomp:unconfined and apparmor:unconfined (or type: Unconfined) turn off the runtime's last confinement layers, a common prerequisite for container escapes. Keep the default profile or load a restrictive one.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml", "shell"},
			CWE:         []string{"CWE-693", "CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "kubernetes", "container"},
		}, pbCfgUnconfinedRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-033",
			Title:       "Container grants a dangerous Linux capability",
			Description: "NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, SYS_RAWIO, SYS_BOOT, BPF, PERFMON and ALL are explicit privilege grants with known escape primitives. Drop them and add only the narrowest capability that works.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml", "shell"},
			CWE:         []string{"CWE-250", "CWE-269"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "kubernetes", "capabilities"},
		}, pbCfgDangerousCapabilityRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-036",
			Title:       "Docker CLI runs a container privileged",
			Description: "docker run --privileged grants all capabilities, access to every host device and a nearly unconfined LSM profile. Drop --privileged and add only the capabilities the workload needs.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"shell", "yaml"},
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"docker", "container"},
		}, pbCfgPrivilegedCLIRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-040",
			Title:       "IAM policy grants full administrative access",
			Description: "Action \"*\" together with Resource \"*\" grants every API action on every AWS resource, including IAM and CloudTrail changes. Scope actions and resources to what the workload needs.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform", "yaml", "json"},
			CWE:         []string{"CWE-269", "CWE-732"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"aws", "iam", "terraform", "cloudformation"},
		}, pbIacIAMFullAdminRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-041",
			Title:       "Security group allows all traffic from the internet",
			Description: "An ingress rule that combines a public CIDR with protocol -1 (or ports 0-65535) exposes every service on the instance. Restrict the CIDR and open only the required ports.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform", "yaml", "json"},
			CWE:         []string{"CWE-284", "CWE-668"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"aws", "network", "terraform", "cloudformation"},
		}, pbIacSecurityGroupOpenAllRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-042",
			Title:       "S3 public access block is explicitly disabled",
			Description: "Block Public Access overrides public ACLs and bucket policies. Setting any of the four flags to false re-opens a public path that ACL-only checks do not see.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform", "yaml", "json"},
			CWE:         []string{"CWE-284", "CWE-732"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"aws", "storage", "terraform", "cloudformation"},
		}, pbIacS3PublicAccessBlockRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-044",
			Title:       "EC2 instance metadata allows IMDSv1",
			Description: "http_tokens = \"optional\" keeps IMDSv1 enabled, so any SSRF or misconfigured workload can read the instance role credentials from 169.254.169.254. Require IMDSv2 with http_tokens = \"required\".",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform", "yaml", "json"},
			CWE:         []string{"CWE-918", "CWE-522"},
			OWASP:       []string{"A10:2021", "A07:2021"},
			Tags:        []string{"aws", "ec2", "terraform", "cloudformation"},
		}, pbIacIMDSv1Rule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-045",
			Title:       "nginx disables upstream TLS certificate verification",
			Description: "proxy_ssl_verify off makes nginx accept any certificate from the upstream, so a man-in-the-middle can read or modify proxied traffic. Enable verification and pin a trusted CA bundle.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			CWE:         []string{"CWE-295", "CWE-319"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"nginx", "tls"},
		}, pbCfgNginxProxySSLVerifyRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-046",
			Title:       "IAM trust policy allows every principal",
			Description: "A trust policy that allows Principal \"*\" lets any AWS account assume the role. Without a Condition that restricts the caller, an attacker who knows the role ARN can obtain its credentials. Restrict the principal to known accounts, roles or federated identities.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform", "yaml", "json"},
			CWE:         []string{"CWE-269", "CWE-732"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"aws", "iam", "terraform", "cloudformation"},
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
				"https://cwe.mitre.org/data/definitions/269.html",
			},
		}, pbW1IacIAMTrustRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-047",
			Title:       "S3 bucket policy grants public access",
			Description: "A bucket policy that allows Principal \"*\" without a restrictive Condition exposes the bucket to every AWS account and anonymous caller. Grant access to named principals or add a source restriction, and keep Block Public Policy enabled.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform", "yaml", "json"},
			CWE:         []string{"CWE-284", "CWE-732"},
			OWASP:       []string{"A01:2021"},
			Tags:        []string{"aws", "storage", "terraform", "cloudformation"},
			References: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
				"https://cwe.mitre.org/data/definitions/284.html",
			},
		}, pbW1IacS3BucketPolicyRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-048",
			Title:       "Kubernetes control-plane component uses insecure flags",
			Description: "Static pod and kubelet manifests that enable anonymous authentication, AlwaysAllow authorization, a non-zero insecure port, profiling, static token files or etcd plaintext peer TLS remove control-plane security controls. Follow the CIS Kubernetes benchmark flags.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-306", "CWE-284"},
			OWASP:       []string{"A01:2021", "A05:2021"},
			Tags:        []string{"kubernetes", "control-plane", "hardening"},
			References: []string{
				"https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		}, pbW1IacControlPlaneRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-049",
			Title:       "Docker Compose service embeds a secret in environment or build args",
			Description: "A literal password, token, key or credential in a Compose environment or build.args value is committed to the repository and baked into build metadata. Interpolate it from the shell or an env_file and pass it at runtime.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-798", "CWE-522"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"docker", "compose", "secret"},
			References: []string{
				"https://docs.docker.com/compose/environment-variables/set-environment-variables/",
				"https://cwe.mitre.org/data/definitions/798.html",
			},
		}, pbW1IacComposeSecretRule),

		New(model.RuleMeta{
			ID:          "VGL-CFG-050",
			Title:       "Terraform S3 backend stores state without encryption",
			Description: "The S3 backend can hold Terraform state with plaintext secrets. Setting encrypt = false disables SSE for the state object. Leave encryption enabled (or omit the attribute so the SSE-S3 default applies).",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryConfig,
			Languages:   []string{"terraform"},
			CWE:         []string{"CWE-311", "CWE-522"},
			OWASP:       []string{"A02:2021"},
			Tags:        []string{"terraform", "aws", "storage", "secret"},
			References: []string{
				"https://developer.hashicorp.com/terraform/language/settings/backends/s3",
				"https://cwe.mitre.org/data/definitions/311.html",
			},
		}, pbW1IacS3BackendRule),
	}
}

func pbPathLower(f *File) string {
	return strings.ToLower(strings.ReplaceAll(f.Path, "\\", "/"))
}

func pbBaseLower(path string) string {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pbIsDockerfile(f *File) bool {
	base := pbBaseLower(f.Path)
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile")
}

func pbIsCompose(f *File) bool {
	base := pbBaseLower(f.Path)
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	return strings.Contains(base, "compose")
}

func pbIsKubernetes(f *File) bool {
	if pbIsCompose(f) {
		return false
	}
	path := pbPathLower(f)
	pathish := pbHasAnyFold(path, "/k8s/", "/kubernetes/", "/manifests/", "deployment", "statefulset", "daemonset")
	content := string(f.Content)
	return (f.Language == "yaml" && strings.Contains(content, "apiVersion:") && strings.Contains(content, "kind:")) ||
		(pathish && strings.Contains(content, "kind:"))
}

func pbIsTerraform(f *File) bool {
	base := pbBaseLower(f.Path)
	return f.Language == "terraform" || strings.HasSuffix(base, ".tf") || strings.HasSuffix(base, ".tfvars")
}

func pbIsEnvFile(f *File) bool {
	base := pbBaseLower(f.Path)
	if base == ".envrc" {
		return false
	}
	if base != ".env" && !strings.HasPrefix(base, ".env.") {
		return false
	}
	return !pbHasAnyFold(base, ".example", ".sample", ".template", ".dist")
}

func pbDockerRootRule(f *File) []model.Finding {
	if !pbIsDockerfile(f) {
		return nil
	}
	fromLine := 0
	userLine := 0
	userVal := ""
	for i, line := range f.Lines {
		t := strings.TrimSpace(line)
		up := strings.ToUpper(t)
		if strings.HasPrefix(up, "FROM ") {
			if fromLine == 0 {
				fromLine = i + 1
			}
			// USER is per build stage; only the final stage matters.
			userLine = 0
			userVal = ""
			continue
		}
		if strings.HasPrefix(up, "USER ") {
			userLine = i + 1
			userVal = strings.ToLower(strings.TrimSpace(t[5:]))
		}
	}
	if fromLine == 0 {
		fromLine = 1
	}
	if userLine > 0 && userVal != "" && userVal != "root" && userVal != "0" {
		return nil
	}
	sev := model.SeverityMedium
	line := fromLine
	evidence := "Dockerfile has no USER instruction; the container runs as root"
	if userLine > 0 {
		sev = model.SeverityHigh
		line = userLine
		evidence = "container explicitly runs as root (USER " + userVal + ")"
	}
	fd := pbFinding(f, line, evidence)
	fd.Severity = pbSev(f, sev)
	fd.Confidence = model.ConfidenceHigh
	return []model.Finding{fd}
}

func pbDockerFromRule(f *File) []model.Finding {
	if !pbIsDockerfile(f) {
		return nil
	}
	var out []model.Finding
	stages := map[string]bool{}
	for i, line := range f.Lines {
		m := pbDockerFromRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		image := m[1]
		stage := ""
		if len(m) > 2 {
			stage = strings.ToLower(m[2])
		}
		lower := strings.ToLower(image)
		reason := ""
		switch {
		case strings.Contains(lower, "@sha256:"):
		case strings.Contains(lower, "$"):
		case strings.HasSuffix(lower, ":latest"):
			reason = "uses the mutable :latest tag"
		case !strings.Contains(lower, ":") && lower != "scratch" && !stages[lower]:
			reason = "uses an untagged base image"
		}
		if reason != "" {
			fd := pbFinding(f, i+1, "FROM "+image+" "+reason)
			fd.Severity = pbSev(f, model.SeverityLow)
			fd.Confidence = model.ConfidenceHigh
			out = append(out, fd)
		}
		if stage != "" {
			stages[stage] = true
		}
	}
	return out
}

func pbAptInstallRule(f *File) []model.Finding {
	if !pbIsDockerfile(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbAptInstallRe.MatchString(line) {
			continue
		}
		if strings.Contains(line, "--no-install-recommends") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityLow)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbDockerAddURLRule(f *File) []model.Finding {
	if !pbIsDockerfile(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbDockerAddURLRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbDockerSecretRule(f *File) []model.Finding {
	if !pbIsDockerfile(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		t := strings.TrimSpace(line)
		up := strings.ToUpper(t)
		if !strings.HasPrefix(up, "ARG ") && !strings.HasPrefix(up, "ENV ") {
			continue
		}
		rest := strings.TrimSpace(t[4:])
		key, val := "", ""
		if eq := strings.Index(rest, "="); eq >= 0 {
			key = strings.TrimSpace(rest[:eq])
			val = strings.TrimSpace(rest[eq+1:])
		} else {
			fields := strings.Fields(rest)
			if len(fields) >= 2 {
				key = fields[0]
				val = strings.Join(fields[1:], " ")
			}
		}
		if key == "" || val == "" || !pbDockerSecretKeyRe.MatchString(key) {
			continue
		}
		if strings.Contains(val, "$") {
			continue
		}
		val = strings.Trim(val, `"'`)
		if LooksLikePlaceholder(val) {
			continue
		}
		evidence := fmt.Sprintf("%s %s=%s", strings.Fields(t)[0], key, MaskSecret(val))
		fd := pbFinding(f, i+1, evidence)
		fd.SecretValues = []string{val}
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbDockerCurlPipeRule(f *File) []model.Finding {
	if !pbIsDockerfile(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbCurlPipeShellRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbComposePrivilegedRule(f *File) []model.Finding {
	if !pbIsCompose(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbK8sPrivilegedRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbComposeHostNetworkRule(f *File) []model.Finding {
	if !pbIsCompose(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbHasAnyFold(line, "network_mode: host", "network_mode: \"host\"", "network_mode: 'host'") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbDockerSocketRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !strings.Contains(line, "/var/run/docker.sock") {
			continue
		}
		if !pbDockerSocketMounted(f, i) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

// pbDockerSocketMounted reports whether the socket path on line idx is a real
// mount. The same path appears in client defaults, env constants and tests; a
// bare string assignment there does not hand the container the host daemon.
func pbDockerSocketMounted(f *File, idx int) bool {
	line := f.Lines[idx]
	if pbDockerSocketVolumeRe.MatchString(line) || pbDockerSocketFlagRe.MatchString(line) {
		return true
	}
	trimmed := strings.ToLower(strings.TrimSpace(line))
	if pbNearHostPath(f, idx) {
		return true
	}
	// Compose long syntax: the host side is the source: entry under volumes:.
	if strings.HasPrefix(trimmed, "source:") || strings.HasPrefix(trimmed, "- source:") {
		if pbInsideYAMLVolumesBlock(f, idx) {
			return true
		}
	}
	return false
}

func pbNearHostPath(f *File, idx int) bool {
	for j := idx; j >= 0 && j >= idx-4; j-- {
		if strings.Contains(strings.ToLower(f.Lines[j]), "hostpath") {
			return true
		}
	}
	return false
}

func pbInsideYAMLVolumesBlock(f *File, idx int) bool {
	curIndent := pbLineIndent(f.Lines[idx])
	for j := idx - 1; j >= 0 && j >= idx-20; j-- {
		line := f.Lines[j]
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := pbLineIndent(line)
		if indent >= curIndent {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "volumes:") {
			return true
		}
		if indent == 0 {
			return false
		}
	}
	return false
}

func pbLineIndent(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' {
			n++
			continue
		}
		if r == '\t' {
			n += 2
			continue
		}
		break
	}
	return n
}

func pbSysAdminRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !strings.Contains(line, "SYS_ADMIN") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbComposeImageRule(f *File) []model.Finding {
	if !pbIsCompose(f) {
		return nil
	}
	hasBuild := pbHasAnyFold(string(f.Content), "build:")
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pbComposeImageRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		image := m[1]
		lower := strings.ToLower(image)
		reason := ""
		switch {
		case strings.Contains(lower, "@sha256:"):
		case strings.HasSuffix(lower, ":latest"):
			reason = "uses the mutable :latest tag"
		case !strings.Contains(lower, ":") && !hasBuild:
			reason = "uses an untagged image"
		}
		if reason == "" {
			continue
		}
		fd := pbFinding(f, i+1, "image "+image+" "+reason)
		fd.Severity = pbSev(f, model.SeverityLow)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbKubernetesRule(f *File) []model.Finding {
	if !pbIsKubernetes(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		sev := model.SeverityHigh
		reason := ""
		switch {
		case pbK8sPrivilegedRe.MatchString(line):
			reason = "privileged container"
		case pbK8sHostPathRe.MatchString(line):
			reason = "hostPath volume"
		case pbK8sRunAsRootRe.MatchString(line):
			sev = model.SeverityMedium
			reason = "container runs as UID 0"
		case pbK8sHostNetworkRe.MatchString(line):
			sev = model.SeverityMedium
			reason = "hostNetwork enabled"
		case pbK8sHostPIDRe.MatchString(line):
			sev = model.SeverityMedium
			reason = "host PID/IPC namespace shared"
		case pbK8sPrivEscRe.MatchString(line):
			sev = model.SeverityMedium
			reason = "allowPrivilegeEscalation enabled"
		default:
			continue
		}
		fd := pbFinding(f, i+1, reason+": "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, sev)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbTerraformPublicPortRule(f *File) []model.Finding {
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
			if m := pbTerraformPortRe.FindStringSubmatch(f.Lines[j]); m != nil {
				port = m[1]
				break
			}
		}
		if port == "" {
			continue
		}
		fd := pbFinding(f, i+1, "public CIDR opens sensitive port "+port)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbPublicS3Rule(f *File) []model.Finding {
	if !pbIsTerraform(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbPublicS3Re.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbUnencryptedEBSRule(f *File) []model.Finding {
	if !pbIsTerraform(f) {
		return nil
	}
	content := string(f.Content)
	if !pbHasAny(content, "aws_ebs_volume", "root_block_device", "ebs_block_device") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbHasAnyFold(line, "encrypted = false", "encrypted=false") {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbNginxAutoindexRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbNginxAutoindexRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbEnvFileRule(f *File) []model.Finding {
	if !pbIsEnvFile(f) {
		return nil
	}
	fd := pbFinding(f, 1, "environment file committed: "+f.Path)
	fd.Severity = pbSev(f, model.SeverityMedium)
	fd.Confidence = model.ConfidenceMedium
	return []model.Finding{fd}
}

// ---------------------------------------------------------------------------
// Container runtime CLI helpers (CFG-030, CFG-032, CFG-033, CFG-036)
// ---------------------------------------------------------------------------

// pbCfgComment reports whether a line is a comment in an executable context.
// The scanner labels Makefiles and extensionless scripts "other", where
// IsCommentLine does not know about "#", so this helper handles both styles.
func pbCfgComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//")
}

// pbCfgCLIScriptFile reports whether f can contain an executable container
// invocation. Documentation, prose and example directories are skipped because
// they describe flags rather than run them.
func pbCfgCLIScriptFile(f *File) bool {
	if pbDocsPath(f.Path) {
		return false
	}
	p := pbPathLower(f)
	if strings.HasPrefix(p, "examples/") || strings.Contains(p, "/examples/") {
		return false
	}
	switch f.Language {
	case "shell", "yaml", "other":
		return true
	}
	return false
}

type pbCfgShellCommand struct {
	start int
	end   int
	text  string
}

// pbCfgShellCommands joins backslash-continued lines into logical commands so a
// flag on a continuation line still belongs to the docker invocation above it.
func pbCfgShellCommands(f *File) []pbCfgShellCommand {
	var out []pbCfgShellCommand
	for i := 0; i < len(f.Lines); i++ {
		line := f.Lines[i]
		if strings.TrimSpace(line) == "" || pbCfgComment(line) {
			continue
		}
		start := i
		parts := make([]string, 0, 4)
		for i < len(f.Lines) && len(parts) < 20 {
			cur := f.Lines[i]
			trimmed := strings.TrimRight(cur, " \t")
			continued := strings.HasSuffix(trimmed, "\\")
			if continued {
				parts = append(parts, strings.TrimSuffix(trimmed, "\\"))
			} else {
				parts = append(parts, cur)
			}
			if !continued {
				break
			}
			i++
		}
		out = append(out, pbCfgShellCommand{start: start + 1, end: i + 1, text: strings.Join(parts, " ")})
	}
	return out
}

// pbCfgFlagLine returns the physical line carrying flag, falling back to the
// first line of the logical command when the flag is split across lines.
func pbCfgFlagLine(f *File, cmd pbCfgShellCommand, flag string) int {
	needle := strings.ToLower(flag)
	for j := cmd.start - 1; j < cmd.end && j < len(f.Lines); j++ {
		if strings.Contains(strings.ToLower(f.Lines[j]), needle) {
			return j + 1
		}
	}
	return cmd.start
}

func pbCfgHostNamespaceRule(f *File) []model.Finding {
	if !pbCfgCLIScriptFile(f) {
		return nil
	}
	var out []model.Finding
	for _, cmd := range pbCfgShellCommands(f) {
		if !pbCfgDockerRuntimeRe.MatchString(cmd.text) {
			continue
		}
		seen := map[string]bool{}
		for _, m := range pbCfgHostNamespaceRe.FindAllStringSubmatch(cmd.text, -1) {
			name := strings.ToLower(m[1])
			if name == "net" {
				name = "network"
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			line := pbCfgFlagLine(f, cmd, "--"+m[1])
			fd := pbFinding(f, line, strings.TrimSpace(m[0])+" in: "+strings.TrimSpace(cmd.text))
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			fd.Remediation = "Remove the host namespace flag and use a user-defined network or a shared container namespace only when required."
			out = append(out, fd)
		}
	}
	return out
}

func pbCfgPrivilegedCLIRule(f *File) []model.Finding {
	if !pbCfgCLIScriptFile(f) {
		return nil
	}
	var out []model.Finding
	for _, cmd := range pbCfgShellCommands(f) {
		if !pbCfgDockerRuntimeRe.MatchString(cmd.text) || !pbCfgPrivilegedRe.MatchString(cmd.text) {
			continue
		}
		line := pbCfgFlagLine(f, cmd, "--privileged")
		fd := pbFinding(f, line, strings.TrimSpace(cmd.text))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Drop --privileged and grant only the specific capabilities and devices the container needs."
		out = append(out, fd)
	}
	return out
}

func pbCfgUnconfinedRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	if pbIsKubernetes(f) {
		return pbCfgK8sUnconfinedFindings(f)
	}
	if !pbIsCompose(f) && !pbCfgCLIScriptFile(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbCfgComment(line) || !pbCfgUnconfinedRe.MatchString(line) {
			continue
		}
		// Shell and generic YAML need the actual CLI flag; a bare string in a
		// manifest or workflow variable is not a runtime option.
		if !pbIsCompose(f) && !pbHasAnyFold(line, "--security-opt") {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Remove the unconfined option and keep the runtime default profile or load a restrictive custom one."
		out = append(out, fd)
	}
	return out
}

func pbCfgK8sUnconfinedFindings(f *File) []model.Finding {
	var out []model.Finding
	for i, line := range f.Lines {
		if pbCfgComment(line) || !pbCfgK8sProfileKeyRe.MatchString(line) {
			continue
		}
		if pbHasAnyFold(line, "unconfined") && pbHasAnyFold(line, "type") {
			fd := pbFinding(f, i+1, strings.TrimSpace(line))
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			fd.Remediation = "Use seccompProfile.type RuntimeDefault or Localhost and an AppArmor RuntimeDefault profile."
			out = append(out, fd)
			continue
		}
		indent := pbLineIndent(line)
		for j := i + 1; j < len(f.Lines) && j <= i+4; j++ {
			next := f.Lines[j]
			if strings.TrimSpace(next) == "" || pbCfgComment(next) {
				continue
			}
			if pbLineIndent(next) <= indent {
				break
			}
			if !pbHasAnyFold(next, "type") {
				continue
			}
			if pbHasAnyFold(next, "unconfined") {
				fd := pbFinding(f, j+1, strings.TrimSpace(next))
				fd.Severity = pbSev(f, model.SeverityHigh)
				fd.Confidence = model.ConfidenceHigh
				fd.Remediation = "Use seccompProfile.type RuntimeDefault or Localhost and an AppArmor RuntimeDefault profile."
				out = append(out, fd)
			}
			break
		}
	}
	return out
}

func pbCfgDangerousCapabilityRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) {
		return nil
	}
	if !pbIsCompose(f) && !pbIsKubernetes(f) && !pbCfgCLIScriptFile(f) {
		return nil
	}
	var out []model.Finding
	emit := func(line int, capability string, source string) {
		fd := pbFinding(f, line, capability+" granted: "+strings.TrimSpace(source))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Remove the capability from the add list; if it is unavoidable, isolate the workload and document why."
		out = append(out, fd)
	}
	for i, line := range f.Lines {
		if pbCfgComment(line) {
			continue
		}
		if pbCfgCapAddCLIRe.MatchString(line) {
			if capability, ok := pbCfgDangerousCapability(pbCfgCapAddCLIRe.FindString(line)); ok {
				emit(i+1, capability, line)
			}
			continue
		}
		// Single-line map form: capabilities: { add: ["NET_ADMIN"] }.
		if m := pbCfgCapAddListRe.FindStringSubmatch(line); m != nil {
			if pbHasAnyFold(line, "capabilit") || pbHasAnyFold(line, "cap_add") || pbCfgCapabilitiesContext(f, i) {
				if capability, ok := pbCfgDangerousCapability(m[1]); ok {
					emit(i+1, capability, line)
					continue
				}
			}
		}
		if !pbCfgCapGrantKeyRe.MatchString(line) {
			continue
		}
		if !pbHasAnyFold(line, "cap_add") && !pbCfgCapabilitiesContext(f, i) {
			continue
		}
		if capability, ok := pbCfgDangerousCapability(line); ok {
			emit(i+1, capability, line)
			continue
		}
		indent := pbLineIndent(line)
		for j := i + 1; j < len(f.Lines) && j <= i+12; j++ {
			next := f.Lines[j]
			if strings.TrimSpace(next) == "" || pbCfgComment(next) {
				continue
			}
			if pbLineIndent(next) <= indent {
				break
			}
			if !strings.HasPrefix(strings.TrimSpace(next), "-") {
				continue
			}
			if capability, ok := pbCfgDangerousCapability(next); ok {
				emit(j+1, capability, next)
			}
		}
	}
	return out
}

// pbCfgCapabilitiesContext reports whether an add: key belongs to a
// capabilities: block rather than an unrelated YAML mapping.
func pbCfgCapabilitiesContext(f *File, idx int) bool {
	curIndent := pbLineIndent(f.Lines[idx])
	for j := idx; j >= 0 && j >= idx-5; j-- {
		line := f.Lines[j]
		if strings.TrimSpace(line) == "" || pbCfgComment(line) {
			continue
		}
		if pbHasAnyFold(line, "capabilities") {
			return true
		}
		if j < idx && pbLineIndent(line) < curIndent {
			return false
		}
	}
	return false
}

// pbCfgDangerousCapability returns the dangerous capability named in s. The
// SYS_ADMIN capability is deliberately absent: VGL-CFG-010 owns it.
func pbCfgDangerousCapability(s string) (string, bool) {
	m := pbCfgDangerousCapRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return strings.ToUpper(m[1]), true
}

func pbCfgNginxProxySSLVerifyRule(f *File) []model.Finding {
	if pbDocsPath(f.Path) || !pcIsNginxConf(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbCfgComment(line) || !pbCfgNginxProxySSLVerifyOffRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set proxy_ssl_verify on and point proxy_ssl_trusted_certificate at a CA bundle that signs the upstream certificate."
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// Terraform and CloudFormation helpers (CFG-040, CFG-041, CFG-042, CFG-044)
// ---------------------------------------------------------------------------

// pbIacIsCloudFormation reports whether f is a CloudFormation template. The
// AWSTemplateFormatVersion marker or a Resources block plus an AWS:: type keeps
// generic YAML and Kubernetes manifests out.
func pbIacIsCloudFormation(f *File) bool {
	if pbIsCompose(f) || pbIsKubernetes(f) {
		return false
	}
	if f.Language != "yaml" && f.Language != "json" {
		return false
	}
	content := string(f.Content)
	if strings.Contains(content, "AWSTemplateFormatVersion") {
		return true
	}
	hasResources := strings.Contains(content, "Resources:") || strings.Contains(content, `"Resources"`)
	hasType := strings.Contains(content, "Type: AWS::") || strings.Contains(content, `"Type": "AWS::`) || strings.Contains(content, `"Type":"AWS::`)
	return hasResources && hasType
}

func pbIacAnyLineMatch(lines []string, re *regexp.Regexp) bool {
	for _, line := range lines {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// pbIacBraceBlock returns the 0-based inclusive bounds of the innermost
// brace-delimited block containing lines[idx]. It is a bounded scanner, not a
// parser, which is enough for Terraform statement and metadata blocks.
func pbIacBraceBlock(lines []string, idx int) (int, int, bool) {
	curIndent := pbLineIndent(lines[idx])
	for j := idx; j >= 0 && j >= idx-40; j-- {
		line := lines[j]
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || !strings.Contains(line, "{") {
			continue
		}
		if j != idx && pbLineIndent(line) >= curIndent {
			continue
		}
		depth := 0
		for k := j; k < len(lines); k++ {
			depth += strings.Count(lines[k], "{") - strings.Count(lines[k], "}")
			if depth <= 0 {
				return j, k, true
			}
		}
		return j, len(lines) - 1, true
	}
	return 0, 0, false
}

// pbIacStatementWindow prefers the enclosing statement block and falls back to
// a +/-15 line window for inline jsonencode objects.
func pbIacStatementWindow(lines []string, idx int) (int, int) {
	if open, close, ok := pbIacBraceBlock(lines, idx); ok && pbHasAnyFold(lines[open], "statement") {
		return open, close + 1
	}
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 16
	if end > len(lines) {
		end = len(lines)
	}
	return start, end
}

func pbIacResourceBlock(lines []string, idx int) (int, int, bool) {
	for j := idx; j >= 0; j-- {
		if !pbIacResourceHeaderRe.MatchString(lines[j]) {
			continue
		}
		_, close, ok := pbIacBraceBlock(lines, j)
		if !ok || close < idx {
			return 0, 0, false
		}
		return j, close, true
	}
	return 0, 0, false
}

// pbIacBoundaryOnly reports whether the policy document enclosing idx is only
// referenced by a permissions_boundary. A permissive boundary does not grant
// access by itself, so flagging it would be a false positive.
func pbIacBoundaryOnly(f *File, idx int) bool {
	start, end, ok := pbIacResourceBlock(f.Lines, idx)
	if !ok {
		return false
	}
	m := pbIacResourceHeaderRe.FindStringSubmatch(f.Lines[start])
	if m == nil {
		return false
	}
	addr := m[2] + "." + m[3]
	if strings.EqualFold(m[1], "data") {
		addr = "data." + addr
	}
	refRe := regexp.MustCompile(regexp.QuoteMeta(addr) + `\.`)
	boundaryRe := regexp.MustCompile(`(?i)permissions_boundary\s*=\s*` + regexp.QuoteMeta(addr) + `\.`)
	total, boundary := 0, 0
	for i, line := range f.Lines {
		if i >= start && i <= end {
			continue
		}
		if pbCfgComment(line) || !refRe.MatchString(line) {
			continue
		}
		total++
		if boundaryRe.MatchString(line) {
			boundary++
		}
	}
	return total > 0 && total == boundary
}

func pbIacIAMFullAdminRule(f *File) []model.Finding {
	if pbIsTerraform(f) {
		return pbIacTerraformIAMFullAdmin(f)
	}
	if pbIacIsCloudFormation(f) {
		return pbIacCloudFormationIAMFullAdmin(f)
	}
	return nil
}

func pbIacTerraformIAMFullAdmin(f *File) []model.Finding {
	if !pbHasAnyFold(string(f.Content), "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy_document") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbIacActionWildcardRe.MatchString(line) {
			continue
		}
		start, end := pbIacStatementWindow(f.Lines, i)
		window := f.Lines[start:end]
		if !pbIacAnyLineMatch(window, pbIacResourceWildcardRe) {
			continue
		}
		if pbIacAnyLineMatch(window, pbIacDenyEffectRe) || pbIacAnyLineMatch(window, pbIacNotWildcardRe) {
			continue
		}
		if pbIacTerraformCountZero(f.Lines, i) || pbIacBoundaryOnly(f, i) {
			continue
		}
		fd := pbFinding(f, i+1, "wildcard Action and Resource in an IAM policy: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Replace Action \"*\" and Resource \"*\" with the specific actions and ARNs the workload needs; keep break-glass admin in a separate audited role."
		out = append(out, fd)
	}
	return out
}

func pbIacTerraformCountZero(lines []string, idx int) bool {
	start, end, ok := pbIacResourceBlock(lines, idx)
	if !ok {
		return false
	}
	return pbIacAnyLineMatch(lines[start:end+1], pbIacCountZeroRe)
}

func pbIacCloudFormationIAMFullAdmin(f *File) []model.Finding {
	if !pbHasAny(string(f.Content), "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbIacActionWildcardRe.MatchString(line) {
			continue
		}
		start, end := pbIacYAMLItemWindow(f.Lines, i)
		window := f.Lines[start:end]
		if !pbIacAnyLineMatch(window, pbIacResourceWildcardRe) {
			continue
		}
		if pbIacAnyLineMatch(window, pbIacDenyEffectRe) || pbIacAnyLineMatch(window, pbIacNotWildcardRe) {
			continue
		}
		fd := pbFinding(f, i+1, "wildcard Action and Resource in a CloudFormation IAM policy: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Replace Action \"*\" and Resource \"*\" with the specific actions and ARNs the workload needs."
		out = append(out, fd)
	}
	return out
}

// pbIacYAMLItemWindow bounds the YAML list item or mapping that contains
// lines[idx]. It keeps one statement or ingress rule from borrowing the
// wildcard or protocol of its neighbour.
func pbIacYAMLItemWindow(lines []string, idx int) (int, int) {
	curIndent := pbLineIndent(lines[idx])
	start := idx
	for j := idx - 1; j >= 0 && j >= idx-30; j-- {
		line := lines[j]
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if pbLineIndent(line) >= curIndent {
			continue
		}
		start = j
		break
	}
	if start == idx {
		// No enclosing key within the bound: fall back to the documented
		// +/-15 line window so an inline JSON statement is still inspected.
		s := idx - 15
		if s < 0 {
			s = 0
		}
		e := idx + 16
		if e > len(lines) {
			e = len(lines)
		}
		return s, e
	}
	startIndent := pbLineIndent(lines[start])
	end := len(lines)
	for j := start + 1; j < len(lines); j++ {
		line := lines[j]
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if pbLineIndent(line) <= startIndent {
			end = j
			break
		}
	}
	return start, end
}

func pbIacSecurityGroupOpenAllRule(f *File) []model.Finding {
	if pbIsTerraform(f) {
		return pbIacTerraformSGOpenAll(f)
	}
	if pbIacIsCloudFormation(f) {
		return pbIacCloudFormationSGOpenAll(f)
	}
	return nil
}

func pbIacTerraformSGOpenAll(f *File) []model.Finding {
	if !pbHasAny(string(f.Content), "aws_security_group", "aws_vpc_security_group_ingress_rule") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbHasAnyFold(line, "cidr") || !pbIacPublicCIDRRe.MatchString(line) {
			continue
		}
		if pbIacTerraformEgress(f.Lines, i) {
			continue
		}
		start, end := pbIacBlockWindow(f.Lines, i)
		window := f.Lines[start:end]
		allProtocols := pbIacAnyLineMatch(window, pbIacTFAllProtocolRe)
		allPorts := pbIacAnyLineMatch(window, pbIacTFFromPortZeroRe) && pbIacAnyLineMatch(window, pbIacTFToPortAllRe)
		if !allProtocols && !allPorts {
			continue
		}
		fd := pbFinding(f, i+1, "public ingress opens every protocol or port: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Restrict cidr_blocks to known networks and allow only the ports the service needs."
		out = append(out, fd)
	}
	return out
}

func pbIacTerraformEgress(lines []string, idx int) bool {
	if open, _, ok := pbIacBraceBlock(lines, idx); ok && pbHasAnyFold(lines[open], "egress") {
		return true
	}
	start, end := pbIacBlockWindow(lines, idx)
	return pbIacAnyLineMatch(lines[start:end], pbIacTFEgressTypeRe)
}

func pbIacBlockWindow(lines []string, idx int) (int, int) {
	if open, close, ok := pbIacBraceBlock(lines, idx); ok {
		return open, close + 1
	}
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 16
	if end > len(lines) {
		end = len(lines)
	}
	return start, end
}

func pbIacCloudFormationSGOpenAll(f *File) []model.Finding {
	if !pbHasAny(string(f.Content), "AWS::EC2::SecurityGroup") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbIacCFNPublicCIDRRe.MatchString(line) {
			continue
		}
		if pbIacCloudFormationEgress(f, i) {
			continue
		}
		start, end := pbIacYAMLItemWindow(f.Lines, i)
		window := f.Lines[start:end]
		allProtocols := pbIacAnyLineMatch(window, pbIacCFNAllProtocolRe)
		allPorts := pbIacAnyLineMatch(window, pbIacCFNFromPortZeroRe) && pbIacAnyLineMatch(window, pbIacCFNToPortAllRe)
		if !allProtocols && !allPorts {
			continue
		}
		fd := pbFinding(f, i+1, "public ingress opens every protocol or port: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Restrict CidrIp to known networks and allow only the ports the service needs."
		out = append(out, fd)
	}
	return out
}

func pbIacCloudFormationEgress(f *File, idx int) bool {
	if pbHasAnyFold(f.Lines[idx], "securitygroupegress") {
		return true
	}
	curIndent := pbLineIndent(f.Lines[idx])
	for j := idx - 1; j >= 0 && j >= idx-30; j-- {
		line := f.Lines[j]
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if pbHasAnyFold(t, "securitygroupegress") && pbLineIndent(line) < curIndent {
			return true
		}
		if pbHasAnyFold(t, "aws::ec2::securitygroupegress") {
			return true
		}
		if pbHasAnyFold(t, "type: aws::") && !pbHasAnyFold(t, "securitygroupegress") {
			return false
		}
	}
	return false
}

func pbIacS3PublicAccessBlockRule(f *File) []model.Finding {
	if pbIsTerraform(f) {
		return pbIacTerraformS3BPA(f)
	}
	if pbIacIsCloudFormation(f) {
		return pbIacCloudFormationS3BPA(f)
	}
	return nil
}

func pbIacTerraformS3BPA(f *File) []model.Finding {
	if !pbHasAnyFold(string(f.Content), "aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbIacS3BPAOffRe.MatchString(line) {
			continue
		}
		start, end, ok := pbIacResourceBlock(f.Lines, i)
		if !ok || !pbHasAnyFold(f.Lines[start], "aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block") {
			continue
		}
		if pbIacAnyLineMatch(f.Lines[start:end+1], pbIacCountZeroRe) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set all four public access block flags to true unless a documented public bucket is intentional."
		out = append(out, fd)
	}
	return out
}

func pbIacCloudFormationS3BPA(f *File) []model.Finding {
	if !pbHasAny(string(f.Content), "AWS::S3::Bucket") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbIacS3BPAOffRe.MatchString(line) || !pbIacBPAConfigAbove(f, i) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set all four PublicAccessBlockConfiguration flags to true unless a documented public bucket is intentional."
		out = append(out, fd)
	}
	return out
}

func pbIacBPAConfigAbove(f *File, idx int) bool {
	curIndent := pbLineIndent(f.Lines[idx])
	for j := idx; j >= 0 && j >= idx-12; j-- {
		line := f.Lines[j]
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if j == idx {
			if pbIacBPAConfigKeyRe.MatchString(line) {
				return true
			}
			continue
		}
		if pbLineIndent(line) >= curIndent {
			continue
		}
		return pbIacBPAConfigKeyRe.MatchString(line)
	}
	return false
}

func pbIacIMDSv1Rule(f *File) []model.Finding {
	if pbIsTerraform(f) {
		return pbIacTerraformIMDSv1(f)
	}
	if pbIacIsCloudFormation(f) {
		return pbIacCloudFormationIMDSv1(f)
	}
	return nil
}

func pbIacTerraformIMDSv1(f *File) []model.Finding {
	if !pbHasAny(string(f.Content), "aws_instance", "aws_launch_template", "aws_launch_configuration") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbIacIMDSOptionalRe.MatchString(line) {
			continue
		}
		start, end, ok := pbIacBraceBlock(f.Lines, i)
		if !ok || !pbHasAnyFold(f.Lines[start], "metadata_options") {
			continue
		}
		if pbIacAnyLineMatch(f.Lines[start:end+1], pbIacIMDSEndpointOffRe) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set metadata_options.http_tokens = \"required\" so the instance requires IMDSv2 session tokens."
		out = append(out, fd)
	}
	return out
}

func pbIacCloudFormationIMDSv1(f *File) []model.Finding {
	if !pbHasAny(string(f.Content), "AWS::EC2::Instance", "AWS::EC2::LaunchTemplate") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbIacCFNIMDSOptionalRe.MatchString(line) || !pbIacMetadataOptionsAbove(f, i) {
			continue
		}
		start := i - 6
		if start < 0 {
			start = 0
		}
		end := i + 7
		if end > len(f.Lines) {
			end = len(f.Lines)
		}
		if pbIacAnyLineMatch(f.Lines[start:end], pbIacIMDSEndpointOffRe) {
			continue
		}
		fd := pbFinding(f, i+1, strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Set MetadataOptions.HttpTokens to required so the instance requires IMDSv2 session tokens."
		out = append(out, fd)
	}
	return out
}

func pbIacMetadataOptionsAbove(f *File, idx int) bool {
	curIndent := pbLineIndent(f.Lines[idx])
	for j := idx; j >= 0 && j >= idx-8; j-- {
		line := f.Lines[j]
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if j == idx {
			if pbHasAnyFold(line, "metadataoptions") {
				return true
			}
			continue
		}
		if pbLineIndent(line) >= curIndent {
			continue
		}
		return pbHasAnyFold(line, "metadataoptions")
	}
	return false
}

// ---------------------------------------------------------------------------
// Wave-1 IaC rules (CFG-046, CFG-047, CFG-048, CFG-049, CFG-050)
// ---------------------------------------------------------------------------

// pbW1IacSkipPath reports whether the file is documentation, a test fixture or
// an example. Those files describe flags and secrets rather than run them.
func pbW1IacSkipPath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	return isDocsPath(p) || isTestPath(p)
}

// pbW1IacComment reports whether line is a comment in a wave-1 IaC file. The
// shared IsCommentLine knows "#" for terraform but not HCL's "//" line
// comments, so those are skipped here without changing the shared helper for
// every other rule family.
func pbW1IacComment(f *File, line string) bool {
	if pbComment(f, line) {
		return true
	}
	return pbIsTerraform(f) && strings.HasPrefix(strings.TrimSpace(line), "//")
}

// pbW1IacAnyCodeLineMatch applies re to non-comment lines of window.
func pbW1IacAnyCodeLineMatch(f *File, window []string, re *regexp.Regexp) bool {
	for _, line := range window {
		if pbW1IacComment(f, line) {
			continue
		}
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// pbW1IacPolicyWindow bounds the policy statement that contains lines[idx]. It
// prefers the enclosing brace block that carries the statement keywords, then
// an indentation-based YAML list item, and finally a small line window so inline
// JSON stays inspectable.
func pbW1IacPolicyWindow(f *File, idx int) (int, int) {
	lines := f.Lines
	if open, close, ok := pbW1IacBraceWindow(f, idx); ok {
		return open, close
	}
	if start, end, ok := pbW1IacListItemWindow(f, idx); ok {
		return start, end
	}
	start, end := pbIacYAMLItemWindow(lines, idx)
	if end-start > 40 {
		start = idx - 12
		if start < 0 {
			start = 0
		}
		end = idx + 13
		if end > len(lines) {
			end = len(lines)
		}
	}
	return start, end
}

// pbW1IacBraceWindow expands the innermost brace block until it either opens a
// Statement block or contains both Effect and Action keys. That covers nested
// Principal objects in HCL and pretty-printed CloudFormation JSON.
func pbW1IacBraceWindow(f *File, idx int) (int, int, bool) {
	lines := f.Lines
	open, close, ok := pbIacBraceBlock(lines, idx)
	if !ok {
		return 0, 0, false
	}
	for depth := 0; depth < 4; depth++ {
		window := lines[open : close+1]
		if pbHasAnyFold(lines[open], "statement") || pbW1IacPolicyKeywords(f, window) {
			return open, close + 1, true
		}
		parentOpen, parentClose, ok := pbW1IacParentBraceBlock(lines, open, close)
		if !ok {
			break
		}
		open, close = parentOpen, parentClose
	}
	return 0, 0, false
}

func pbW1IacParentBraceBlock(lines []string, open, close int) (int, int, bool) {
	openIndent := pbLineIndent(lines[open])
	for j := open - 1; j >= 0 && j >= open-15; j-- {
		if !strings.Contains(lines[j], "{") || pbLineIndent(lines[j]) >= openIndent {
			continue
		}
		if o, c, ok := pbIacBraceBlock(lines, j); ok && o <= open && c >= close {
			return o, c, true
		}
	}
	return 0, 0, false
}

func pbW1IacPolicyKeywords(f *File, window []string) bool {
	hasEffect, hasAction := false, false
	for _, line := range window {
		if pbW1IacComment(f, line) {
			continue
		}
		if pbW1IacEffectKeyRe.MatchString(line) {
			hasEffect = true
		}
		if pbW1IacActionKeyRe.MatchString(line) {
			hasAction = true
		}
	}
	return hasEffect && hasAction
}

// pbW1IacListItemWindow bounds the YAML list item that contains lines[idx]. It
// keeps a nested Principal: mapping attached to its statement item.
func pbW1IacListItemWindow(f *File, idx int) (int, int, bool) {
	lines := f.Lines
	curIndent := pbLineIndent(lines[idx])
	for j := idx; j >= 0 && j >= idx-30; j-- {
		line := lines[j]
		t := strings.TrimSpace(line)
		if t == "" || pbW1IacComment(f, line) {
			continue
		}
		if pbLineIndent(line) >= curIndent || !strings.HasPrefix(t, "- ") {
			continue
		}
		base := pbLineIndent(line)
		end := len(lines)
		for k := j + 1; k < len(lines); k++ {
			kt := strings.TrimSpace(lines[k])
			if kt == "" || pbW1IacComment(f, lines[k]) {
				continue
			}
			if pbLineIndent(lines[k]) <= base {
				end = k
				break
			}
		}
		if end-j > 40 {
			end = j + 40
		}
		return j, end, true
	}
	return 0, 0, false
}

// pbW1IacPublicStatement reports whether the statement around idx grants a
// wildcard principal, has no Deny effect and has no restrictive Condition.
func pbW1IacPublicStatement(f *File, idx int) bool {
	start, end := pbW1IacPolicyWindow(f, idx)
	window := f.Lines[start:end]
	if !pbW1IacAnyCodeLineMatch(f, window, pbW1IacPrincipalKeyRe) {
		return false
	}
	if pbW1IacAnyCodeLineMatch(f, window, pbIacDenyEffectRe) {
		return false
	}
	return !pbW1IacAnyCodeLineMatch(f, window, pbW1IacRestrictiveCondRe)
}

func pbW1IacWildcardPrincipalLine(line string) bool {
	return pbW1IacPrincipalWildcardRe.MatchString(line) ||
		pbW1IacPrincipalInlineRe.MatchString(line) ||
		pbW1IacAWSWildcardRe.MatchString(line) ||
		pbW1IacIDsWildcardRe.MatchString(line)
}

func pbW1IacIAMTrustRule(f *File) []model.Finding {
	if f == nil || pbW1IacSkipPath(f.Path) {
		return nil
	}
	isTF := pbIsTerraform(f)
	isCFN := pbIacIsCloudFormation(f)
	if !isTF && !isCFN {
		return nil
	}
	content := string(f.Content)
	if isTF && !pbW1IacTrustGateRe.MatchString(content) {
		return nil
	}
	if isCFN && !pbW1IacCFNTrustGateRe.MatchString(content) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbW1IacComment(f, line) || !pbW1IacWildcardPrincipalLine(line) {
			continue
		}
		if !pbW1IacPublicStatement(f, i) {
			continue
		}
		start, end := pbW1IacPolicyWindow(f, i)
		if !pbW1IacAnyCodeLineMatch(f, f.Lines[start:end], pbW1IacAssumeRoleRe) {
			continue
		}
		if isTF && pbIacTerraformCountZero(f.Lines, i) {
			continue
		}
		fd := pbFinding(f, i+1, "IAM trust policy allows every principal: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Replace the wildcard principal with the accounts, roles or federated identities that need to assume the role, and add a Condition such as aws:PrincipalArn or sts:ExternalId."
		out = append(out, fd)
	}
	return out
}

// pbW1IacTerraformS3PolicyContext reports whether the Terraform file actually
// carries an S3 bucket policy. A bare aws_s3_bucket resource, an attribute
// reference such as bucket = aws_s3_bucket.logs.id, or a generic aws_iam_policy
// that happens to grant an S3 action is not a bucket policy and must not title
// CFG-047. Only an aws_s3_bucket_policy resource or an inline policy attribute
// inside an aws_s3_bucket block qualifies.
func pbW1IacTerraformS3PolicyContext(f *File) bool {
	for _, line := range f.Lines {
		if pbW1IacComment(f, line) {
			continue
		}
		if pbW1IacS3PolicyGateRe.MatchString(line) {
			return true
		}
	}
	return pbW1IacInlineS3BucketPolicy(f)
}

// pbW1IacInlineS3BucketPolicy reports whether an inline policy attribute belongs
// to an aws_s3_bucket block (the deprecated inline bucket policy form). The same
// attribute on aws_iam_policy or aws_iam_role is not a bucket policy.
func pbW1IacInlineS3BucketPolicy(f *File) bool {
	for i, line := range f.Lines {
		if pbW1IacComment(f, line) || !pbW1IacTFInlinePolicyRe.MatchString(line) {
			continue
		}
		open, _, ok := pbIacResourceBlock(f.Lines, i)
		if ok && pbW1IacTFS3BucketBlockRe.MatchString(f.Lines[open]) {
			return true
		}
	}
	return false
}

func pbW1IacS3BucketPolicyRule(f *File) []model.Finding {
	if f == nil || pbW1IacSkipPath(f.Path) {
		return nil
	}
	isTF := pbIsTerraform(f)
	isCFN := pbIacIsCloudFormation(f)
	if !isTF && !isCFN {
		return nil
	}
	content := string(f.Content)
	if isTF {
		if !pbW1IacTerraformS3PolicyContext(f) {
			return nil
		}
		if pbW1IacTerraformS3BlockSuppressed(f) {
			return nil
		}
	} else {
		if !pbHasAnyFold(content, "aws::s3::bucketpolicy") {
			return nil
		}
		if pbW1IacCFNS3BlockSuppressed(f) {
			return nil
		}
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbW1IacComment(f, line) || !pbW1IacWildcardPrincipalLine(line) {
			continue
		}
		if !pbW1IacPublicStatement(f, i) {
			continue
		}
		start, end := pbW1IacPolicyWindow(f, i)
		if !pbW1IacAnyCodeLineMatch(f, f.Lines[start:end], pbW1IacS3ActionRe) {
			continue
		}
		if isTF && pbIacTerraformCountZero(f.Lines, i) {
			continue
		}
		fd := pbFinding(f, i+1, "S3 bucket policy allows every principal: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = "Replace the wildcard principal with the accounts, roles or CloudFront identity that need access, add a Condition, and keep Block Public Policy enabled."
		out = append(out, fd)
	}
	return out
}

func pbW1IacTerraformS3BlockSuppressed(f *File) bool {
	for i, line := range f.Lines {
		if pbW1IacComment(f, line) || !pbW1IacBPAHeaderRe.MatchString(line) {
			continue
		}
		open, close, ok := pbIacBraceBlock(f.Lines, i)
		if !ok {
			open, close = i, len(f.Lines)-1
		}
		for j := open; j <= close && j < len(f.Lines); j++ {
			if pbW1IacComment(f, f.Lines[j]) {
				continue
			}
			if pbW1IacTFS3BPAPolicyRe.MatchString(f.Lines[j]) {
				return true
			}
		}
	}
	return false
}

func pbW1IacCFNS3BlockSuppressed(f *File) bool {
	for _, line := range f.Lines {
		if pbW1IacComment(f, line) {
			continue
		}
		if pbW1IacCFNS3BPAPolicyRe.MatchString(line) {
			return true
		}
	}
	return false
}

func pbW1IacS3BackendRule(f *File) []model.Finding {
	if f == nil || !pbIsTerraform(f) || pbW1IacSkipPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbW1IacComment(f, line) || !pbW1IacS3BackendRe.MatchString(line) {
			continue
		}
		_, close, ok := pbIacBraceBlock(f.Lines, i)
		if !ok {
			continue
		}
		for j := i; j <= close && j < len(f.Lines); j++ {
			if pbW1IacComment(f, f.Lines[j]) || !pbW1IacEncryptFalseRe.MatchString(f.Lines[j]) {
				continue
			}
			fd := pbFinding(f, j+1, "Terraform S3 backend disables state encryption: "+strings.TrimSpace(f.Lines[j]))
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			fd.Remediation = "Remove encrypt = false or set it to true; Terraform state commonly contains plaintext secrets. Use SSE-S3 or an SSE-KMS key."
			out = append(out, fd)
			break
		}
	}
	return out
}

// pbW1IacBinaryFromName maps a static pod or config filename to a component.
func pbW1IacBinaryFromName(base string) string {
	switch {
	case strings.Contains(base, "kube-apiserver"):
		return "apiserver"
	case strings.Contains(base, "kube-controller-manager"):
		return "controller-manager"
	case strings.Contains(base, "kube-scheduler"):
		return "scheduler"
	case strings.Contains(base, "kubelet"):
		return "kubelet"
	case strings.Contains(base, "etcd"):
		return "etcd"
	}
	return ""
}

func pbW1IacBinaryToken(line string) string {
	m := pbW1IacControlPlaneBinRe.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return pbW1IacBinaryFromName(strings.ToLower(m[1]))
}

// pbW1IacBinaryFromCommand returns the component only from a command or YAML
// list line; an image reference does not run the binary.
func pbW1IacBinaryFromCommand(line string) string {
	if pbHasAnyFold(line, "image:") {
		return ""
	}
	t := strings.TrimSpace(line)
	lower := strings.ToLower(t)
	if !strings.HasPrefix(lower, "command:") && !strings.HasPrefix(lower, "args:") &&
		!strings.HasPrefix(lower, "- ") && !strings.Contains(lower, "command: [") {
		return ""
	}
	return pbW1IacBinaryToken(line)
}

func pbW1IacBinaryForLine(f *File, idx int, fileBin string) string {
	if fileBin != "" {
		return fileBin
	}
	if b := pbW1IacBinaryToken(f.Lines[idx]); b != "" {
		return b
	}
	for j := idx - 1; j >= 0 && j >= idx-15; j-- {
		line := f.Lines[j]
		if pbComment(f, line) {
			continue
		}
		if b := pbW1IacBinaryFromCommand(line); b != "" {
			return b
		}
	}
	return ""
}

type pbW1IacFlagHit struct {
	evidence    string
	severity    model.Severity
	remediation string
}

func pbW1IacFlagIssues(line, bin string) []pbW1IacFlagHit {
	var out []pbW1IacFlagHit
	add := func(sev model.Severity, flag, remediation string) {
		out = append(out, pbW1IacFlagHit{
			evidence:    bin + " uses insecure flag " + flag + ": " + strings.TrimSpace(line),
			severity:    sev,
			remediation: remediation,
		})
	}
	if bin == "apiserver" || bin == "kubelet" {
		if pbW1IacAnonAuthRe.MatchString(line) {
			add(model.SeverityHigh, "--anonymous-auth=true",
				"Set --anonymous-auth=false so unauthenticated requests are rejected.")
		}
	}
	if bin == "apiserver" {
		if m := pbW1IacInsecurePortRe.FindStringSubmatch(line); m != nil {
			if port, err := strconv.Atoi(m[1]); err == nil && port > 0 {
				add(model.SeverityHigh, "--insecure-port="+m[1],
					"Set --insecure-port=0 and expose the API server only over TLS.")
			}
		}
		if pbW1IacStaticAuthFileRe.MatchString(line) {
			for _, match := range pbW1IacStaticAuthFileRe.FindAllString(line, -1) {
				flag := "--token-auth-file"
				if strings.Contains(strings.ToLower(match), "basic-auth-file") {
					flag = "--basic-auth-file"
				}
				add(model.SeverityHigh, flag,
					"Remove --token-auth-file and --basic-auth-file; use a supported authenticator such as OIDC or webhook.")
			}
		}
	}
	if bin == "apiserver" || bin == "controller-manager" || bin == "scheduler" || bin == "kubelet" {
		if pbW1IacProfilingRe.MatchString(line) {
			add(model.SeverityMedium, "--profiling=true",
				"Set --profiling=false to keep CPU and memory profiles off the network.")
		}
	}
	if bin == "apiserver" || bin == "kubelet" {
		if m := pbW1IacAuthModeRe.FindStringSubmatch(line); m != nil {
			if reason, sev, bad := pbW1IacAuthModeIssue(m[1], bin); bad {
				add(sev, "--authorization-mode="+m[1], reason)
			}
		}
	}
	if bin == "etcd" {
		if pbW1IacEtcdClientCertRe.MatchString(line) {
			add(model.SeverityHigh, "--client-cert-auth=false",
				"Enable --client-cert-auth so etcd requires a client certificate.")
		}
		seenTLS := map[string]bool{}
		for _, m := range pbW1IacEtcdAutoTLSRe.FindAllStringSubmatch(line, -1) {
			flag := "--" + strings.ToLower(m[1]) + "=true"
			if seenTLS[flag] {
				continue
			}
			seenTLS[flag] = true
			add(model.SeverityHigh, flag,
				"Issue explicit server and peer certificates instead of enabling auto TLS.")
		}
	}
	return out
}

func pbW1IacAuthModeIssue(mode, bin string) (string, model.Severity, bool) {
	parts := map[string]bool{}
	for _, p := range strings.Split(strings.ToUpper(mode), ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts[p] = true
		}
	}
	if parts["ALWAYSALLOW"] {
		return "AlwaysAllow disables authorization; enable RBAC and Node authorization.", model.SeverityHigh, true
	}
	if bin == "kubelet" {
		return "", "", false
	}
	if !parts["RBAC"] || !parts["NODE"] {
		return "Authorization mode does not enable both RBAC and Node.", model.SeverityMedium, true
	}
	return "", "", false
}

func pbW1IacControlPlaneRule(f *File) []model.Finding {
	if f == nil || pbW1IacSkipPath(f.Path) {
		return nil
	}
	if f.Language != "yaml" && f.Language != "json" {
		return nil
	}
	fileBin := pbW1IacBinaryFromName(pbBaseLower(f.Path))
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		bin := pbW1IacBinaryForLine(f, i, fileBin)
		if bin == "" {
			continue
		}
		for _, hit := range pbW1IacFlagIssues(line, bin) {
			fd := pbFinding(f, i+1, hit.evidence)
			fd.Severity = pbSev(f, hit.severity)
			fd.Confidence = model.ConfidenceHigh
			fd.Remediation = hit.remediation
			out = append(out, fd)
		}
	}
	return out
}

// pbW1IacComposeEntry parses an unquoted environment or args entry. Quoted
// values are left to VGL-SEC-014 so one literal secret is not reported twice.
func pbW1IacComposeEntry(line string) (string, string, bool) {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "- ") {
		t = strings.TrimSpace(t[2:])
	}
	if strings.HasPrefix(t, `"`) || strings.HasPrefix(t, `'`) {
		return "", "", false
	}
	if m := pbW1IacComposeListRe.FindStringSubmatch(t); m != nil {
		if pbW1IacComposeQuotedValue(m[2]) {
			return "", "", false
		}
		return m[1], m[2], true
	}
	if m := pbW1IacComposeMapRe.FindStringSubmatch(t); m != nil {
		if pbW1IacComposeQuotedValue(m[2]) {
			return "", "", false
		}
		return m[1], m[2], true
	}
	return "", "", false
}

// pbW1IacComposeQuotedValue reports a quoted literal. VGL-SEC-014 already
// reports those values, so CFG-049 must stay quiet to avoid double reporting.
func pbW1IacComposeQuotedValue(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, `"`) || strings.HasPrefix(v, `'`)
}

// pbW1IacComposeSecretContext returns "environment" or "build.args" when the
// entry at idx belongs to one of those Compose blocks.
func pbW1IacComposeSecretContext(f *File, idx int) (string, bool) {
	curIndent := pbLineIndent(f.Lines[idx])
	for j := idx - 1; j >= 0 && j >= idx-40; j-- {
		line := f.Lines[j]
		t := strings.TrimSpace(line)
		if t == "" || pbComment(f, line) {
			continue
		}
		indent := pbLineIndent(line)
		if indent >= curIndent {
			continue
		}
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "environment:"):
			return "environment", true
		case strings.HasPrefix(lower, "args:"):
			if pbW1IacArgsUnderBuild(f, j, indent) {
				return "build.args", true
			}
			return "", false
		default:
			if indent == 0 {
				return "", false
			}
		}
	}
	return "", false
}

func pbW1IacArgsUnderBuild(f *File, idx, indent int) bool {
	for j := idx - 1; j >= 0 && j >= idx-15; j-- {
		line := f.Lines[j]
		t := strings.TrimSpace(line)
		if t == "" || pbComment(f, line) {
			continue
		}
		if pbLineIndent(line) < indent {
			return strings.HasPrefix(strings.ToLower(t), "build:")
		}
	}
	return false
}

func pbW1IacComposeSecretKeyExcluded(key string) bool {
	lower := strings.ToLower(key)
	if strings.HasSuffix(lower, "_file") || strings.HasSuffix(lower, "_path") ||
		strings.HasSuffix(lower, ".file") || strings.HasSuffix(lower, ".path") {
		return true
	}
	return strings.Contains(lower, "public")
}

func pbW1IacComposeValue(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return strings.TrimSpace(strings.Trim(v, `"'`))
}

func pbW1IacLiteralSecret(v string) bool {
	if len(v) < 8 || LooksLikePlaceholder(v) || pbW1IacEnvWordRe.MatchString(v) {
		return false
	}
	if strings.Contains(v, "${") || strings.Contains(v, "{{") || strings.Contains(v, "$(") ||
		strings.HasPrefix(v, "$") || strings.Contains(v, "://") {
		return false
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		return false
	}
	digits := true
	hasStrong, hasLower, hasUpper := false, false, false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			hasStrong = true
		case r >= 'a' && r <= 'z':
			digits = false
			hasLower = true
		case r >= 'A' && r <= 'Z':
			digits = false
			hasUpper = true
		default:
			digits = false
			// Hyphens, underscores, dots and spaces separate words; they add
			// no secret material to an otherwise dictionary-shaped value.
			if r != '-' && r != '_' && r != '.' && r != ' ' {
				hasStrong = true
			}
		}
	}
	if digits {
		return false
	}
	// A plain word carries no secret material: environment labels such as
	// "production" or "development" reach this point without a digit or symbol.
	// Require a digit/symbol, or a long mixed-case token that is not a word.
	if !hasStrong && (len(v) < 12 || !hasLower || !hasUpper) {
		return false
	}
	return Entropy(v) >= 3.0
}

func pbW1IacComposeSecretRule(f *File) []model.Finding {
	if f == nil || !pbIsCompose(f) || pbW1IacSkipPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		key, value, ok := pbW1IacComposeEntry(line)
		if !ok || !pbW1IacSecretKeyRe.MatchString(key) || pbW1IacComposeSecretKeyExcluded(key) {
			continue
		}
		context, ok := pbW1IacComposeSecretContext(f, i)
		if !ok {
			continue
		}
		value = pbW1IacComposeValue(value)
		if !pbW1IacLiteralSecret(value) {
			continue
		}
		fd := pbFinding(f, i+1, "compose "+context+" contains a literal secret for "+key+": "+key+"="+MaskSecret(value))
		// pbFinding uses a radius-1 snippet, which would copy the neighbouring
		// environment entry into reports verbatim. Keep a single redacted line so
		// neither this value nor a neighbouring credential reaches JSON/SARIF.
		fd.Location.Snippet = secRedactSnippet(f, i+1, value)
		fd.SecretValues = []string{value}
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceMedium
		fd.Remediation = "Remove the literal value, interpolate it from the shell (${VAR}) or an env_file that is not committed, and rotate the exposed credential."
		out = append(out, fd)
	}
	return out
}
