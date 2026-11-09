package rules

import (
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	pbActionUsesRe       = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*([^\s#]+)`)
	pbActionSHARe        = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	pbPRTargetRefRe      = regexp.MustCompile(`(?i)ref:\s*.*(?:github\.event\.pull_request\.head|github\.head_ref)`)
	pbRunInjectionRe     = regexp.MustCompile(`(?i)\$\{\{\s*github\.(?:event\.(?:pull_request|issue|comment|discussion|review)\.(?:title|body|head\.ref|head\.label|user\.login)|head_ref)\s*\}\}`)
	pbWriteAllRe         = regexp.MustCompile(`(?i)^\s*permissions:\s*write-all\b`)
	pbSecretsInheritRe   = regexp.MustCompile(`(?i)^\s*secrets:\s*inherit\b`)
	pbCIPipeShellRe      = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b`)
	pbEchoSecretRe       = regexp.MustCompile(`(?i)\b(?:echo|printf)\b[^\n]*\$\{\{\s*secrets\.`)
	pbSelfHostedRe       = regexp.MustCompile(`(?i)^\s*runs-on:\s*.*\bself-hosted\b`)
	pbUploadArtifactRe   = regexp.MustCompile(`(?i)\buses:\s*actions/upload-artifact@`)
	pbHiddenArtifactRe   = regexp.MustCompile(`(?i)^\s*(?:path|include-hidden-files):`)
	pbGitLabJobRe        = regexp.MustCompile(`^([A-Za-z0-9_.-]+):\s*(?:#.*)?$`)
	pbGitLabAllowFailRe  = regexp.MustCompile(`(?i)^\s*allow_failure:\s*true\b`)
	pbJenkinsInjectionRe = regexp.MustCompile(`(?i)\b(?:sh|bat)\s*(?:\(\s*)?(?:script\s*:\s*)?["'].*\$\{?(?:params\.|env\.|BUILD_|JOB_)`)
)

// CIRules returns the CI/CD pipeline rules.
func CIRules() []Rule {
	return []Rule{
		New(model.RuleMeta{
			ID:          "VGL-CI-001",
			Title:       "GitHub Action is not pinned to a commit SHA",
			Description: "Tags and branches are mutable; a compromised or retagged action executes attacker code with your token. Pin third-party actions to a full 40-character commit SHA.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-1357"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"github-actions", "supply-chain"},
		}, pbActionPinRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-002",
			Title:       "pull_request_target checks out untrusted PR code",
			Description: "pull_request_target runs with repository secrets and a write token; checking out the PR head lets the contributor execute code in that privileged context. Use pull_request or split the workflow.",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-829"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"github-actions", "supply-chain"},
		}, pbPRTargetCheckoutRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-003",
			Title:       "Untrusted event data interpolated into a shell command",
			Description: "PR titles, issue bodies and branch names are attacker-controlled. Direct ${{ }} interpolation into run: enables shell injection. Pass values through env: and quote them.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-78"},
			OWASP:       []string{"A03:2021"},
			Tags:        []string{"github-actions", "injection"},
		}, pbRunInjectionRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-004",
			Title:       "Workflow grants write-all permissions",
			Description: "permissions:write-all gives every job the maximum token scope. Declare only the scopes each job needs, usually contents:read.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-250"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"github-actions", "permissions"},
		}, pbWriteAllRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-005",
			Title:       "Reusable workflow inherits all secrets",
			Description: "secrets:inherit passes every caller secret to the called workflow. Pass only the secrets that workflow needs explicitly.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-200"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"github-actions", "secret"},
		}, pbSecretsInheritRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-006",
			Title:       "Remote script piped into a shell in CI",
			Description: "curl | bash executes whatever the remote server returns with CI credentials. Download and verify a checksum or pin the script by commit.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-494"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"ci", "supply-chain"},
		}, pbCIPipeShellRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-007",
			Title:       "Secret printed to CI logs",
			Description: "echoing a secret exposes it in build logs, which are often readable by more people than the secret itself. Mask it or avoid printing it.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-532"},
			OWASP:       []string{"A09:2021"},
			Tags:        []string{"ci", "secret"},
		}, pbEchoSecretRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-008",
			Title:       "Self-hosted runner used",
			Description: "Self-hosted runners on public repositories can be reached by fork PRs and persist state between jobs. Prefer GitHub-hosted runners or require approval for outside contributors.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-284"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"github-actions", "runner"},
		}, pbSelfHostedRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-009",
			Title:       "Artifact upload may include hidden files",
			Description: "Uploading hidden files can publish .env, .git or credential files. Use an explicit allow-list of artifact paths.",
			Severity:    model.SeverityLow,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-538"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"github-actions", "artifact"},
		}, pbHiddenArtifactRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-010",
			Title:       "GitLab security job is allowed to fail",
			Description: "allow_failure:true on a security job lets vulnerable code merge. Remove it for blocking scanners or route the job to a required approval.",
			Severity:    model.SeverityInfo,
			Category:    model.CategoryCI,
			Languages:   []string{"yaml"},
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"A08:2021"},
			Tags:        []string{"gitlab-ci", "ci"},
		}, pbGitLabAllowFailureRule),

		New(model.RuleMeta{
			ID:          "VGL-CI-011",
			Title:       "Jenkins shell step interpolates build parameters",
			Description: "Interpolating params or environment values into sh/bat allows command injection through build parameters. Use withEnv and single-quoted shell variables.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryCI,
			CWE:         []string{"CWE-78"},
			OWASP:       []string{"A03:2021"},
			Tags:        []string{"jenkins", "injection"},
		}, pbJenkinsInjectionRule),
	}
}

func pbIsGitHubWorkflow(f *File) bool {
	p := pbPathLower(f)
	base := pbBaseLower(f.Path)
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	return strings.Contains(p, ".github/workflows/")
}

func pbIsGitLabCI(f *File) bool {
	return pbBaseLower(f.Path) == ".gitlab-ci.yml" || strings.HasSuffix(pbPathLower(f), "/.gitlab-ci.yml")
}

func pbIsJenkins(f *File) bool {
	base := pbBaseLower(f.Path)
	if strings.Contains(base, "jenkinsfile") || f.Language == "groovy" {
		return true
	}
	return strings.Contains(string(f.Content), "pipeline {") && pbHasAnyFold(string(f.Content), "agent ", "stages")
}

func pbActionPinRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) {
			continue
		}
		m := pbActionUsesRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		target := m[1]
		lower := strings.ToLower(target)
		if strings.HasPrefix(lower, "docker://") || strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
			continue
		}
		at := strings.LastIndex(target, "@")
		if at < 0 || at == len(target)-1 {
			fd := pbFinding(f, i+1, "action is used without a version: "+target)
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			out = append(out, fd)
			continue
		}
		ref := target[at+1:]
		if pbActionSHARe.MatchString(ref) {
			continue
		}
		fd := pbFinding(f, i+1, "action is pinned to "+ref+", not a commit SHA: "+target)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbPRTargetCheckoutRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	if !pbHasAnyFold(string(f.Content), "pull_request_target") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbPRTargetRefRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, "pull_request_target workflow checks out untrusted PR code: "+strings.TrimSpace(line))
		fd.Severity = pbSev(f, model.SeverityCritical)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbRunInjectionRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	var out []model.Finding
	inRun := false
	runIndent := 0
	for i, line := range f.Lines {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		directive := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		if strings.HasPrefix(directive, "run:") {
			inline := !strings.HasSuffix(directive, "|") && !strings.HasSuffix(directive, ">") &&
				!strings.HasSuffix(directive, "|-") && !strings.HasSuffix(directive, ">-")
			if pbRunInjectionRe.MatchString(line) {
				fd := pbFinding(f, i+1, line)
				fd.Severity = pbSev(f, model.SeverityHigh)
				fd.Confidence = model.ConfidenceHigh
				out = append(out, fd)
			}
			inRun = !inline
			runIndent = indent
			continue
		}
		if !inRun {
			continue
		}
		if trimmed != "" && indent <= runIndent {
			inRun = false
			continue
		}
		if pbRunInjectionRe.MatchString(line) {
			fd := pbFinding(f, i+1, line)
			fd.Severity = pbSev(f, model.SeverityHigh)
			fd.Confidence = model.ConfidenceHigh
			out = append(out, fd)
		}
	}
	return out
}

func pbWriteAllRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbWriteAllRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbSecretsInheritRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbSecretsInheritRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityLow)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbCIPipeShellRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) && !pbIsGitLabCI(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbCIPipeShellRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityMedium)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbEchoSecretRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) && !pbIsGitLabCI(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbEchoSecretRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceHigh
		out = append(out, fd)
	}
	return out
}

func pbSelfHostedRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbSelfHostedRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceLow
		out = append(out, fd)
	}
	return out
}

func pbHiddenArtifactRule(f *File) []model.Finding {
	if !pbIsGitHubWorkflow(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if !pbUploadArtifactRe.MatchString(line) {
			continue
		}
		end := i + 12
		if end > len(f.Lines) {
			end = len(f.Lines)
		}
		for j := i + 1; j < end; j++ {
			candidate := f.Lines[j]
			if !pbHiddenArtifactRe.MatchString(candidate) {
				continue
			}
			lower := strings.ToLower(candidate)
			hidden := strings.Contains(lower, "include-hidden-files: true") ||
				strings.Contains(lower, ".*") || strings.Contains(lower, "**/.*")
			if !hidden {
				continue
			}
			fd := pbFinding(f, j+1, candidate)
			fd.Severity = pbSev(f, model.SeverityLow)
			fd.Confidence = model.ConfidenceMedium
			out = append(out, fd)
			break
		}
	}
	return out
}

func pbGitLabAllowFailureRule(f *File) []model.Finding {
	if !pbIsGitLabCI(f) {
		return nil
	}
	reserved := map[string]bool{
		"stages": true, "variables": true, "include": true, "image": true,
		"services": true, "before_script": true, "after_script": true,
		"cache": true, "default": true, "workflow": true, "pages": true,
	}
	securityNames := []string{"security", "scan", "audit", "sast", "dast", "dependency", "secret", "trivy", "grype", "semgrep", "codeql", "snyk", "vuln"}
	var out []model.Finding
	for i, line := range f.Lines {
		m := pbGitLabJobRe.FindStringSubmatch(line)
		if m == nil || reserved[strings.ToLower(m[1])] {
			continue
		}
		if !pbHasAnyFold(m[1], securityNames...) {
			continue
		}
		for j := i + 1; j < len(f.Lines); j++ {
			next := f.Lines[j]
			if pbGitLabJobRe.MatchString(next) && !strings.HasPrefix(next, " ") && !strings.HasPrefix(next, "\t") {
				break
			}
			if !pbGitLabAllowFailRe.MatchString(next) {
				continue
			}
			fd := pbFinding(f, j+1, next)
			fd.Severity = pbSev(f, model.SeverityInfo)
			fd.Confidence = model.ConfidenceHigh
			out = append(out, fd)
			break
		}
	}
	return out
}

func pbJenkinsInjectionRule(f *File) []model.Finding {
	if !pbIsJenkins(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if pbComment(f, line) || !pbJenkinsInjectionRe.MatchString(line) {
			continue
		}
		fd := pbFinding(f, i+1, line)
		fd.Severity = pbSev(f, model.SeverityHigh)
		fd.Confidence = model.ConfidenceMedium
		out = append(out, fd)
	}
	return out
}
