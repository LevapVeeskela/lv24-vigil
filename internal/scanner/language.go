package scanner

import (
	"path"
	"strings"
)

// Language labels returned by DetectLanguage.
const (
	LanguageGo         = "go"
	LanguagePython     = "python"
	LanguageJavaScript = "javascript"
	LanguageTypeScript = "typescript"
	LanguageJava       = "java"
	LanguagePHP        = "php"
	LanguageRuby       = "ruby"
	LanguageCSharp     = "csharp"
	LanguageRust       = "rust"
	LanguageSQL        = "sql"
	LanguageYAML       = "yaml"
	LanguageJSON       = "json"
	LanguageDockerfile = "dockerfile"
	LanguageTerraform  = "terraform"
	LanguageShell      = "shell"
	LanguageHTML       = "html"
	LanguageXML        = "xml"
	LanguageMarkdown   = "markdown"
	LanguageOther      = "other"
)

// DetectLanguage maps a path to a coarse language label. Only the file name
// and extension are inspected; the file is never opened.
func DetectLanguage(p string) string {
	normalized := strings.ReplaceAll(p, "\\", "/")
	base := strings.ToLower(path.Base(normalized))
	switch {
	case base == "dockerfile", base == "containerfile",
		strings.HasPrefix(base, "dockerfile."), strings.HasPrefix(base, "containerfile."),
		strings.HasSuffix(base, ".dockerfile"):
		return LanguageDockerfile
	}

	switch strings.ToLower(path.Ext(base)) {
	case ".go":
		return LanguageGo
	case ".py", ".pyi":
		return LanguagePython
	case ".js", ".jsx", ".mjs", ".cjs":
		return LanguageJavaScript
	case ".ts", ".tsx", ".mts", ".cts":
		return LanguageTypeScript
	case ".java":
		return LanguageJava
	case ".php":
		return LanguagePHP
	case ".rb":
		return LanguageRuby
	case ".cs":
		return LanguageCSharp
	case ".rs":
		return LanguageRust
	case ".sql":
		return LanguageSQL
	case ".yaml", ".yml":
		return LanguageYAML
	case ".json", ".jsonc":
		return LanguageJSON
	case ".tf", ".tfvars", ".hcl":
		return LanguageTerraform
	case ".sh", ".bash", ".zsh", ".ksh":
		return LanguageShell
	case ".html", ".htm":
		return LanguageHTML
	case ".xml", ".xsd", ".xsl", ".xslt":
		return LanguageXML
	case ".md", ".markdown", ".mdx":
		return LanguageMarkdown
	default:
		return LanguageOther
	}
}
