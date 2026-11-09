package scanner

import "testing"

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.go", LanguageGo},
		{"internal/app.py", LanguagePython},
		{"web/app.js", LanguageJavaScript},
		{"web/app.jsx", LanguageJavaScript},
		{"web/app.mjs", LanguageJavaScript},
		{"web/app.ts", LanguageTypeScript},
		{"web/app.tsx", LanguageTypeScript},
		{"Main.java", LanguageJava},
		{"index.php", LanguagePHP},
		{"lib/tool.rb", LanguageRuby},
		{"Program.cs", LanguageCSharp},
		{"src/main.rs", LanguageRust},
		{"schema.sql", LanguageSQL},
		{"config.yaml", LanguageYAML},
		{"config.yml", LanguageYAML},
		{"package.json", LanguageJSON},
		{"Dockerfile", LanguageDockerfile},
		{"docker/Dockerfile.dev", LanguageDockerfile},
		{"infra/main.tf", LanguageTerraform},
		{"scripts/run.sh", LanguageShell},
		{"scripts/run.bash", LanguageShell},
		{"public/index.html", LanguageHTML},
		{"feed.xml", LanguageXML},
		{"README.md", LanguageMarkdown},
		{"docs/guide.markdown", LanguageMarkdown},
		{"Makefile", LanguageOther},
		{"LICENSE", LanguageOther},
		{"archive.bin", LanguageOther},
	}
	for _, tc := range tests {
		if got := DetectLanguage(tc.path); got != tc.want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
