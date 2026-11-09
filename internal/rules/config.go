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
