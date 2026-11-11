package rules

import (
	"fmt"
	"regexp"
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
