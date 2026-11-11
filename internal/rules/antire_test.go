package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// ---------------------------------------------------------------------------
// Anti-RE rule tests: one vulnerable and one safe fixture per rule, plus the
// scoping negatives (release block, debug manifest, network security config
// override, plist value placement, test paths and unresolved values).
// ---------------------------------------------------------------------------

func antireTestRule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range AntiRERules() {
		if r.Meta().ID == id {
			return r
		}
	}
	t.Fatalf("rule %s is not registered", id)
	return nil
}

func antireTestDescribe(fs []model.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  %s:%d %s\n", f.RuleID, f.Location.StartLine, f.Evidence)
	}
	return b.String()
}

type antireCase struct {
	name     string
	path     string
	language string
	content  string
	want     []int
}

func antireTestCases(t *testing.T, id string, cases []antireCase) {
	t.Helper()
	rule := antireTestRule(t, id)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rule.Check(packBFile(tc.path, tc.language, tc.content))
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d\n%s", len(got), len(tc.want), antireTestDescribe(got))
			}
			for i, want := range tc.want {
				g := got[i]
				if g.RuleID != id {
					t.Errorf("finding %d: ruleId = %q, want %q", i, g.RuleID, id)
				}
				if g.Location.StartLine != want {
					t.Errorf("finding %d: line = %d, want %d", i, g.Location.StartLine, want)
				}
				if g.Severity == "" || g.Confidence == "" {
					t.Errorf("finding %d: missing severity/confidence", i)
				}
				if strings.TrimSpace(g.Evidence) == "" {
					t.Errorf("finding %d: empty evidence", i)
				}
				if strings.TrimSpace(g.Remediation) == "" {
					t.Errorf("finding %d: empty remediation", i)
				}
			}
		})
	}
}

func TestAntiRERegistry(t *testing.T) {
	if model.CategoryAntiRE != "anti-re" {
		t.Fatalf("CategoryAntiRE = %q, want anti-re", model.CategoryAntiRE)
	}
	wantSeverity := map[string]model.Severity{
		"VGL-ARE-001": model.SeverityMedium,
		"VGL-ARE-002": model.SeverityHigh,
		"VGL-ARE-003": model.SeverityHigh,
		"VGL-ARE-004": model.SeverityMedium,
		"VGL-ARE-005": model.SeverityMedium,
		"VGL-ARE-006": model.SeverityMedium,
		"VGL-ARE-010": model.SeverityHigh,
		"VGL-ARE-011": model.SeverityMedium,
		"VGL-ARE-020": model.SeverityMedium,
		"VGL-ARE-030": model.SeverityHigh,
		"VGL-ARE-031": model.SeverityHigh,
		"VGL-ARE-040": model.SeverityHigh,
		"VGL-ARE-041": model.SeverityMedium,
		"VGL-ARE-050": model.SeverityMedium,
		"VGL-ARE-051": model.SeverityMedium,
		"VGL-ARE-052": model.SeverityHigh,
		"VGL-ARE-053": model.SeverityMedium,
		"VGL-ARE-054": model.SeverityHigh,
		"VGL-ARE-055": model.SeverityMedium,
		"VGL-ARE-056": model.SeverityMedium,
		"VGL-ARE-057": model.SeverityHigh,
		"VGL-ARE-058": model.SeverityMedium,
		"VGL-ARE-059": model.SeverityMedium,
	}
	rules := AntiRERules()
	if len(rules) != len(wantSeverity) {
		t.Fatalf("AntiRERules() returned %d rules, want %d", len(rules), len(wantSeverity))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		m := r.Meta()
		if seen[m.ID] {
			t.Errorf("duplicate rule ID %q", m.ID)
		}
		seen[m.ID] = true
		if !strings.HasPrefix(m.ID, "VGL-ARE-") {
			t.Errorf("rule %q does not use the VGL-ARE- prefix", m.ID)
		}
		if m.Category != model.CategoryAntiRE {
			t.Errorf("rule %q category = %q, want anti-re", m.ID, m.Category)
		}
		sev, ok := wantSeverity[m.ID]
		if !ok {
			t.Errorf("unexpected rule %q", m.ID)
			continue
		}
		if m.Severity != sev {
			t.Errorf("rule %q severity = %q, want %q", m.ID, m.Severity, sev)
		}
		if len(m.CWE) == 0 || len(m.OWASP) == 0 || len(m.Tags) == 0 {
			t.Errorf("rule %q is missing CWE/OWASP/tags", m.ID)
		}
	}

	registered := map[string]bool{}
	for _, r := range Default().All() {
		registered[r.Meta().ID] = true
	}
	for id := range wantSeverity {
		if !registered[id] {
			t.Errorf("rule %s is not in the default registry", id)
		}
	}
}

func TestAntiRE001GradleMinify(t *testing.T) {
	antireTestCases(t, "VGL-ARE-001", []antireCase{
		{
			name:     "groovy release disables minify",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins {
    id 'com.android.application'
}

android {
    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
        }
    }
}`,
			want: []int{8},
		},
		{
			name:     "kotlin release disables minify",
			path:     "app/build.gradle.kts",
			language: "other",
			content: `plugins {
    id("com.android.application")
}

android {
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}`,
			want: []int{8},
		},
		{
			name:     "release enables minify",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'com.android.application' }
android {
    buildTypes {
        release {
            minifyEnabled true
        }
    }
}`,
		},
		{
			name:     "debug block must not fire",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'com.android.application' }
android {
    buildTypes {
        debug {
            minifyEnabled false
        }
        release {
            minifyEnabled true
        }
    }
}`,
		},
		{
			name:     "no release block",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'com.android.application' }
android {
    buildTypes {
        debug {
            minifyEnabled false
        }
    }
}`,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'com.android.application' }
android {
    buildTypes {
        release {
            minifyEnabled project.hasProperty("noMinify")
        }
    }
}`,
		},
		{
			name:     "non android project is out of scope",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'java' }
release {
    minifyEnabled false
}`,
		},
	})
}

func TestAntiRE002GradleDebugSigning(t *testing.T) {
	antireTestCases(t, "VGL-ARE-002", []antireCase{
		{
			name:     "release uses debug signing config",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'com.android.application' }
android {
    buildTypes {
        release {
            signingConfig signingConfigs.debug
        }
    }
}`,
			want: []int{5},
		},
		{
			name:     "release uses debug keystore",
			path:     "app/build.gradle.kts",
			language: "other",
			content: `plugins { id("com.android.application") }
android {
    buildTypes {
        release {
            storeFile file("debug.keystore")
        }
    }
}`,
			want: []int{5},
		},
		{
			name:     "release uses release signing config",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'com.android.application' }
android {
    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}`,
		},
		{
			name:     "debug block must not fire",
			path:     "app/build.gradle",
			language: "other",
			content: `plugins { id 'com.android.application' }
android {
    buildTypes {
        debug {
            signingConfig signingConfigs.debug
        }
        release {
            signingConfig signingConfigs.release
        }
    }
}`,
		},
	})
}

func TestAntiRE003DebuggableManifest(t *testing.T) {
	vulnerable := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:label="App"
        android:debuggable="true" />
</manifest>`
	antireTestCases(t, "VGL-ARE-003", []antireCase{
		{
			name:     "release manifest is debuggable",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content:  vulnerable,
			want:     []int{4},
		},
		{
			name:     "debuggable false is safe",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:debuggable="false" />
</manifest>`,
		},
		{
			name:     "debug source set is skipped",
			path:     "app/src/debug/AndroidManifest.xml",
			language: "xml",
			content:  vulnerable,
		},
		{
			name:     "debug build output is skipped",
			path:     "app/build/intermediates/merged_manifests/debug/AndroidManifest.xml",
			language: "xml",
			content:  vulnerable,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:debuggable="${debuggable}" />
</manifest>`,
		},
		{
			name:     "comment is skipped",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- android:debuggable="true" -->
</manifest>`,
		},
	})
}

func TestAntiRE004AllowBackup(t *testing.T) {
	antireTestCases(t, "VGL-ARE-004", []antireCase{
		{
			name:     "backup allowed",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:allowBackup="true" />
</manifest>`,
			want: []int{2},
		},
		{
			name:     "backup disabled",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:allowBackup="false" />
</manifest>`,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:allowBackup="@bool/allow_backup" />
</manifest>`,
		},
	})

	rule := antireTestRule(t, "VGL-ARE-004")
	got := rule.Check(packBFile("app/src/main/AndroidManifest.xml", "xml", `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:allowBackup="true"
        android:fullBackupContent="@xml/backup_rules" />
</manifest>`))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "backup rules policy") {
		t.Errorf("remediation does not mention the existing backup rules: %q", got[0].Remediation)
	}
}

func TestAntiRE005CleartextTraffic(t *testing.T) {
	antireTestCases(t, "VGL-ARE-005", []antireCase{
		{
			name:     "cleartext allowed",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="true" />
</manifest>`,
			want: []int{2},
		},
		{
			name:     "cleartext disabled",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="false" />
</manifest>`,
		},
		{
			name:     "network security config overrides the flag",
			path:     "app/src/main/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config" />
</manifest>`,
		},
		{
			name:     "debug manifest is skipped",
			path:     "app/src/debug/AndroidManifest.xml",
			language: "xml",
			content: `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="true" />
</manifest>`,
		},
	})
}

func TestAntiRE006NetworkSecurityConfig(t *testing.T) {
	antireTestCases(t, "VGL-ARE-006", []antireCase{
		{
			name:     "base config permits cleartext",
			path:     "app/src/main/res/xml/network_security_config.xml",
			language: "xml",
			content: `<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
</network-security-config>`,
			want: []int{2},
		},
		{
			name:     "multi line domain config permits cleartext",
			path:     "app/src/main/res/xml/network_security_config.xml",
			language: "xml",
			content: `<network-security-config>
    <domain-config
        cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
</network-security-config>`,
			want: []int{3},
		},
		{
			name:     "debug overrides are skipped",
			path:     "app/src/main/res/xml/network_security_config.xml",
			language: "xml",
			content: `<network-security-config>
    <debug-overrides>
        <domain-config cleartextTrafficPermitted="true">
            <domain includeSubdomains="true">localhost</domain>
        </domain-config>
    </debug-overrides>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>`,
		},
		{
			name:     "cleartext denied",
			path:     "app/src/main/res/xml/network_security_config.xml",
			language: "xml",
			content: `<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>`,
		},
		{
			name:     "comment is skipped",
			path:     "app/src/main/res/xml/network_security_config.xml",
			language: "xml",
			content: `<network-security-config>
    <!-- <base-config cleartextTrafficPermitted="true" /> -->
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>`,
		},
	})
}

func TestAntiRE010GetTaskAllow(t *testing.T) {
	antireTestCases(t, "VGL-ARE-010", []antireCase{
		{
			name:     "value on the next line",
			path:     "ios/Runner/Runner.entitlements",
			language: "xml",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>`,
			want: []int{5},
		},
		{
			name:     "value on the same line",
			path:     "ios/Runner/Runner.entitlements",
			language: "xml",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>get-task-allow</key><true/>
</dict>
</plist>`,
			want: []int{4},
		},
		{
			name:     "false is safe",
			path:     "ios/Runner/Runner.entitlements",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <false/>
</dict>
</plist>`,
		},
		{
			name:     "true value of the next key is not attributed",
			path:     "ios/Runner/Runner.entitlements",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>get-task-allow</key><false/><key>application-identifier</key><true/>
</dict>
</plist>`,
		},
		{
			name:     "debug entitlements are skipped",
			path:     "ios/Runner/RunnerDebug.entitlements",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>`,
		},
		{
			name:     "dev directory is skipped",
			path:     "config/dev/Runner.entitlements",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>`,
		},
		{
			name:     "test path is skipped",
			path:     "ios/tests/Runner.entitlements",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>`,
		},
	})
}

func TestAntiRE011ATSArbitraryLoads(t *testing.T) {
	antireTestCases(t, "VGL-ARE-011", []antireCase{
		{
			name:     "arbitrary loads enabled",
			path:     "ios/Runner/Info.plist",
			language: "xml",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>`,
			want: []int{7},
		},
		{
			name:     "same line form",
			path:     "ios/Runner/Info.plist",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>NSAllowsArbitraryLoads</key><true/>
</dict>
</plist>`,
			want: []int{3},
		},
		{
			name:     "web content variant is a different key",
			path:     "ios/Runner/Info.plist",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>NSAllowsArbitraryLoadsInWebContent</key>
    <true/>
</dict>
</plist>`,
		},
		{
			name:     "false is safe",
			path:     "ios/Runner/Info.plist",
			language: "xml",
			content: `<plist version="1.0">
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
</dict>
</plist>`,
		},
	})
}

func TestAntiRE020FlutterObfuscation(t *testing.T) {
	antireTestCases(t, "VGL-ARE-020", []antireCase{
		{
			name:     "shell release apk without obfuscation",
			path:     "scripts/build.sh",
			language: "shell",
			content: `#!/usr/bin/env bash
set -euo pipefail
flutter pub get
flutter build apk --release`,
			want: []int{4},
		},
		{
			name:     "backslash continuation is one command",
			path:     "scripts/build.sh",
			language: "shell",
			content: `flutter build \
  appbundle \
  --release`,
			want: []int{1},
		},
		{
			name:     "obfuscation is safe",
			path:     "scripts/build.sh",
			language: "shell",
			content:  `flutter build apk --release --obfuscate --split-debug-info=build/symbols`,
		},
		{
			name:     "debug build is skipped",
			path:     "scripts/build.sh",
			language: "shell",
			content:  `flutter build apk --debug`,
		},
		{
			name:     "profile build is skipped",
			path:     "scripts/build.sh",
			language: "shell",
			content:  `flutter build appbundle --profile`,
		},
		{
			name:     "simulator build is skipped",
			path:     "scripts/build.sh",
			language: "shell",
			content:  `flutter build ios --simulator`,
		},
		{
			name:     "yaml ci step",
			path:     ".github/workflows/release.yml",
			language: "yaml",
			content: `name: ci
jobs:
  build:
    steps:
      - run: flutter build ipa`,
			want: []int{5},
		},
		{
			name:     "makefile target",
			path:     "Makefile",
			language: "other",
			content:  ".PHONY: build\nbuild:\n\tflutter build appbundle",
			want:     []int{3},
		},
		{
			name:     "one build without obfuscation next to an obfuscated one",
			path:     "scripts/build.sh",
			language: "shell",
			content:  `flutter build apk --obfuscate && flutter build ipa`,
			want:     []int{1},
		},
		{
			name:     "test path is skipped",
			path:     "ci/test/build.sh",
			language: "shell",
			content:  `flutter build apk --release`,
		},
		{
			name:     "flutter test is not a build",
			path:     "scripts/build.sh",
			language: "shell",
			content:  `flutter test --coverage`,
		},
	})
}

func TestAntiRE030ElectronWebSecurity(t *testing.T) {
	antireTestCases(t, "VGL-ARE-030", []antireCase{
		{
			name:     "web security disabled",
			path:     "src/main.ts",
			language: "typescript",
			content: `const { BrowserWindow } = require('electron');

const win = new BrowserWindow({
  webPreferences: {
    webSecurity: false,
  },
});`,
			want: []int{5},
		},
		{
			name:     "web security enabled",
			path:     "src/main.ts",
			language: "typescript",
			content: `const win = new BrowserWindow({
  webPreferences: {
    webSecurity: true,
  },
});`,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "src/main.ts",
			language: "typescript",
			content: `const win = new BrowserWindow({
  webPreferences: {
    webSecurity: process.env.WEB_SECURITY,
  },
});`,
		},
		{
			name:     "comment is skipped",
			path:     "src/main.ts",
			language: "typescript",
			content: `// webSecurity: false
const win = new BrowserWindow({ webPreferences: { webSecurity: true } });`,
		},
		{
			name:     "test path is skipped",
			path:     "src/__tests__/main.ts",
			language: "typescript",
			content:  `const win = new BrowserWindow({ webPreferences: { webSecurity: false } });`,
		},
	})
}

func TestAntiRE031NodeIsolation(t *testing.T) {
	antireTestCases(t, "VGL-ARE-031", []antireCase{
		{
			name:     "node integration without isolation",
			path:     "src/main.js",
			language: "javascript",
			content: `const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,
    contextIsolation: false,
  },
});`,
			want: []int{3},
		},
		{
			name:     "context isolation enabled",
			path:     "src/main.js",
			language: "javascript",
			content: `const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,
    contextIsolation: true,
  },
});`,
		},
		{
			name:     "node integration disabled",
			path:     "src/main.js",
			language: "javascript",
			content: `const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: false,
  },
});`,
		},
		{
			name:     "test path is skipped",
			path:     "src/__tests__/main.js",
			language: "javascript",
			content: `const win = new BrowserWindow({
  webPreferences: { nodeIntegration: true, contextIsolation: false },
});`,
		},
	})

	var b strings.Builder
	b.WriteString("const win = new BrowserWindow({\n  webPreferences: {\n    nodeIntegration: true,\n")
	for i := 0; i < 40; i++ {
		b.WriteString("    // padding\n")
	}
	b.WriteString("    contextIsolation: false,\n  },\n});\n")
	rule := antireTestRule(t, "VGL-ARE-031")
	if got := rule.Check(packBFile("src/main.js", "javascript", b.String())); len(got) != 0 {
		t.Fatalf("settings more than 30 lines apart produced %d findings\n%s", len(got), antireTestDescribe(got))
	}
}

func TestAntiRE040NodeInspector(t *testing.T) {
	antireTestCases(t, "VGL-ARE-040", []antireCase{
		{
			name:     "package start script enables the inspector",
			path:     "package.json",
			language: "json",
			content: `{
  "name": "app",
  "scripts": {
    "start": "node --inspect=0.0.0.0:9229 dist/server.js"
  },
  "dependencies": {}
}`,
			want: []int{4},
		},
		{
			name:     "dev script is skipped",
			path:     "package.json",
			language: "json",
			content: `{
  "scripts": {
    "dev": "node --inspect dist/server.js"
  }
}`,
		},
		{
			name:     "test script is skipped",
			path:     "package.json",
			language: "json",
			content: `{
  "scripts": {
    "test": "node --inspect-brk node_modules/jest/bin/jest.js"
  }
}`,
		},
		{
			name:     "nodemon is skipped",
			path:     "package.json",
			language: "json",
			content: `{
  "scripts": {
    "start": "nodemon --inspect dist/server.js"
  }
}`,
		},
		{
			name:     "ts-node-dev is skipped",
			path:     "package.json",
			language: "json",
			content: `{
  "scripts": {
    "start": "ts-node-dev --inspect src/server.ts"
  }
}`,
		},
		{
			name:     "plain start script is safe",
			path:     "package.json",
			language: "json",
			content: `{
  "scripts": {
    "start": "node dist/server.js"
  }
}`,
		},
		{
			name:     "dockerfile command enables the inspector",
			path:     "Dockerfile",
			language: "dockerfile",
			content: `FROM node:22
CMD ["node", "--inspect=0.0.0.0:9229", "dist/server.js"]`,
			want: []int{2},
		},
		{
			name:     "dockerfile command is safe",
			path:     "Dockerfile",
			language: "dockerfile",
			content: `FROM node:22
CMD ["node", "dist/server.js"]`,
		},
		{
			name:     "multi-stage dev inspector before the final stage is skipped",
			path:     "Dockerfile",
			language: "dockerfile",
			content: `FROM node:22 AS dev
CMD ["node", "--inspect=0.0.0.0:9229", "server.js"]

FROM node:22 AS runtime
CMD ["node", "server.js"]`,
		},
		{
			name:     "multi-stage final stage inspector is reported",
			path:     "Dockerfile",
			language: "dockerfile",
			content: `FROM node:22 AS build
RUN npm run build

FROM node:22 AS runtime
CMD ["node", "--inspect=0.0.0.0:9229", "server.js"]`,
			want: []int{5},
		},
		{
			name:     "dev compose file is skipped",
			path:     "docker-compose.dev.yml",
			language: "yaml",
			content: `services:
  app:
    command: node --inspect=0.0.0.0:9229 dist/server.js`,
		},
		{
			name:     "development node env is skipped",
			path:     "scripts/start.sh",
			language: "shell",
			content:  `NODE_ENV=development node --inspect dist/server.js`,
		},
		{
			name:     "inspect port alone is not the inspector",
			path:     "scripts/start.sh",
			language: "shell",
			content:  `node --inspect-port=9229 dist/server.js`,
		},
	})
}

func TestAntiRE041SourceMaps(t *testing.T) {
	antireTestCases(t, "VGL-ARE-041", []antireCase{
		{
			name:     "vite sourcemap enabled",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content: `import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    sourcemap: true,
  },
});`,
			want: []int{5},
		},
		{
			name:     "vite sourcemap disabled",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content: `export default defineConfig({
  build: {
    sourcemap: false,
  },
});`,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content: `export default defineConfig({
  build: {
    sourcemap: process.env.SOURCEMAP,
  },
});`,
		},
		{
			name:     "dev config path is skipped",
			path:     "frontend/vite.config.dev.ts",
			language: "typescript",
			content: `export default defineConfig({
  build: {
    sourcemap: true,
  },
});`,
		},
		{
			name:     "test config path is skipped",
			path:     "frontend/test/vite.config.ts",
			language: "typescript",
			content: `export default defineConfig({
  build: {
    sourcemap: true,
  },
});`,
		},
		{
			name:     "webpack devtool source-map",
			path:     "frontend/webpack.config.js",
			language: "javascript",
			content: `module.exports = {
  mode: 'production',
  devtool: "source-map",
};`,
			want: []int{3},
		},
		{
			name:     "next production browser source maps",
			path:     "frontend/next.config.js",
			language: "javascript",
			content: `module.exports = {
  productionBrowserSourceMaps: true,
};`,
			want: []int{2},
		},
		{
			name:     "angular production source map",
			path:     "frontend/angular.json",
			language: "json",
			content: `{
  "projects": {
    "app": {
      "architect": {
        "build": {
          "configurations": {
            "production": {
              "sourceMap": true
            }
          }
        }
      }
    }
  }
}`,
			want: []int{8},
		},
		{
			name:     "angular development source map is not production",
			path:     "frontend/angular.json",
			language: "json",
			content: `{
  "projects": {
    "app": {
      "architect": {
        "build": {
          "configurations": {
            "development": {
              "sourceMap": true
            }
          }
        }
      }
    }
  }
}`,
		},
	})

	var longProduction strings.Builder
	longProduction.WriteString("{\n  \"configurations\": {\n    \"production\": {\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&longProduction, "      \"budget%d\": {},\n", i)
	}
	longProduction.WriteString("      \"sourceMap\": true\n    }\n  }\n}\n")
	rule := antireTestRule(t, "VGL-ARE-041")
	if got := rule.Check(packBFile("frontend/angular.json", "json", longProduction.String())); len(got) != 1 {
		t.Fatalf("long production block produced %d findings, want 1\n%s", len(got), antireTestDescribe(got))
	}
}

// ---------------------------------------------------------------------------
// Second wave: release configuration for Rust, .NET, iOS, Android, Electron and
// JavaScript builds.
// ---------------------------------------------------------------------------

func TestAntiRE050CargoReleaseProfile(t *testing.T) {
	antireTestCases(t, "VGL-ARE-050", []antireCase{
		{
			name:     "release profile keeps debug info and disables stripping",
			path:     "Cargo.toml",
			language: "toml",
			content: `[package]
name = "app"
version = "0.1.0"

[profile.release]
debug = true
strip = false`,
			want: []int{6, 7},
		},
		{
			name:     "release profile keeps line tables",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.release]
debug = "line-tables-only"`,
			want: []int{2},
		},
		{
			name:     "numeric debug level",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.release]
debug = 2`,
			want: []int{2},
		},
		{
			name:     "quoted strip none",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.release]
strip = "none"`,
			want: []int{2},
		},
		{
			name:     "safe release profile",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.release]
debug = false
strip = "symbols"
lto = true`,
		},
		{
			name:     "dev profile must not fire",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.dev]
debug = true
strip = false`,
		},
		{
			name:     "workspace inheritance is unresolved",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.release]
debug = { workspace = true }`,
		},
		{
			name:     "comment is skipped",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.release]
# debug = true`,
		},
		{
			name:     "section after release is out of scope",
			path:     "Cargo.toml",
			language: "toml",
			content: `[profile.release]
debug = false

[profile.bench]
debug = true`,
		},
	})
}

func TestAntiRE051DotNetRelease(t *testing.T) {
	antireTestCases(t, "VGL-ARE-051", []antireCase{
		{
			name:     "release group keeps portable pdb and disables optimize",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|AnyCPU'">
    <DebugType>portable</DebugType>
    <Optimize>false</Optimize>
  </PropertyGroup>
</Project>`,
			want: []int{3, 4},
		},
		{
			name:     "release group keeps debug symbols",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup Condition=" '$(Configuration)' == 'Release' ">
    <DebugSymbols>true</DebugSymbols>
  </PropertyGroup>
</Project>`,
			want: []int{3},
		},
		{
			name:     "multi line property group",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup
      Condition="'$(Configuration)' == 'Release'">
    <DebugType>full</DebugType>
  </PropertyGroup>
</Project>`,
			want: []int{4},
		},
		{
			name:     "props file release group",
			path:     "Directory.Build.props",
			language: "xml",
			content: `<Project>
  <PropertyGroup Condition="'$(Configuration)' == 'Release'">
    <DebugType>pdbonly</DebugType>
  </PropertyGroup>
</Project>`,
			want: []int{3},
		},
		{
			name:     "safe release group",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<PropertyGroup Condition="'$(Configuration)' == 'Release'">
  <DebugType>none</DebugType>
  <DebugSymbols>false</DebugSymbols>
  <Optimize>true</Optimize>
</PropertyGroup>`,
		},
		{
			name:     "debug group must not fire",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<PropertyGroup Condition="'$(Configuration)' == 'Debug'">
  <DebugType>full</DebugType>
  <Optimize>false</Optimize>
</PropertyGroup>`,
		},
		{
			name:     "not equal release must not fire",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<PropertyGroup Condition="'$(Configuration)' != 'Release'">
  <DebugType>full</DebugType>
</PropertyGroup>`,
		},
		{
			name:     "group without a condition is out of scope",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<PropertyGroup>
  <Optimize>false</Optimize>
</PropertyGroup>`,
		},
		{
			name:     "comment is skipped",
			path:     "src/App/App.csproj",
			language: "xml",
			content: `<PropertyGroup Condition="'$(Configuration)' == 'Release'">
  <!-- <DebugType>full</DebugType> -->
</PropertyGroup>`,
		},
	})
}

func TestAntiRE052IOSTestability(t *testing.T) {
	antireTestCases(t, "VGL-ARE-052", []antireCase{
		{
			name:     "pbxproj release enables testability",
			path:     "ios/Runner.xcodeproj/project.pbxproj",
			language: "other",
			content: `/* Begin XCBuildConfiguration section */
		97C146ED1CF9000F007C117D /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ENABLE_TESTABILITY = YES;
			};
			name = Debug;
		};
		97C146EE1CF9000F007C117D /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ENABLE_TESTABILITY = YES;
			};
			name = Release;
		};
/* End XCBuildConfiguration section */`,
			want: []int{12},
		},
		{
			name:     "xcconfig release enables testability",
			path:     "ios/Config/Release.xcconfig",
			language: "other",
			content:  `ENABLE_TESTABILITY = YES;`,
			want:     []int{1},
		},
		{
			name:     "xcconfig prod enables testability",
			path:     "ios/Config/App-Prod.xcconfig",
			language: "other",
			content:  `ENABLE_TESTABILITY = YES;`,
			want:     []int{1},
		},
		{
			name:     "xcconfig distribution enables testability",
			path:     "ios/Config/Distribution.xcconfig",
			language: "other",
			content:  `ENABLE_TESTABILITY = YES;`,
			want:     []int{1},
		},
		{
			name:     "pbxproj debug config must not fire",
			path:     "ios/Runner.xcodeproj/project.pbxproj",
			language: "other",
			content: `		97C146ED1CF9000F007C117D /* Debug */ = {
			buildSettings = {
				ENABLE_TESTABILITY = YES;
			};
		};`,
		},
		{
			name:     "xcconfig debug file is skipped",
			path:     "ios/Config/Debug.xcconfig",
			language: "other",
			content:  `ENABLE_TESTABILITY = YES;`,
		},
		{
			name:     "xcconfig safe value",
			path:     "ios/Config/Release.xcconfig",
			language: "other",
			content:  `ENABLE_TESTABILITY = NO;`,
		},
		{
			name:     "comment is skipped",
			path:     "ios/Config/Release.xcconfig",
			language: "other",
			content: `/* Release */
// ENABLE_TESTABILITY = YES;`,
		},
	})
}

func TestAntiRE053IOSDebugSymbols(t *testing.T) {
	antireTestCases(t, "VGL-ARE-053", []antireCase{
		{
			name:     "pbxproj release keeps dwarf and skips stripping",
			path:     "ios/Runner.xcodeproj/project.pbxproj",
			language: "other",
			content: `		97C146EE1CF9000F007C117D /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				DEBUG_INFORMATION_FORMAT = dwarf;
				STRIP_INSTALLED_PRODUCT = NO;
				COPY_PHASE_STRIP = NO;
				DEPLOYMENT_POSTPROCESSING = NO;
			};
			name = Release;
		};`,
			want: []int{4, 5, 6, 7},
		},
		{
			name:     "release with dsym and stripping is safe",
			path:     "ios/Runner.xcodeproj/project.pbxproj",
			language: "other",
			content: `		97C146EE /* Release */ = {
			buildSettings = {
				DEBUG_INFORMATION_FORMAT = dwarf-with-dsym;
				STRIP_INSTALLED_PRODUCT = YES;
				COPY_PHASE_STRIP = YES;
				DEPLOYMENT_POSTPROCESSING = YES;
			};
		};`,
		},
		{
			name:     "pbxproj debug config must not fire",
			path:     "ios/Runner.xcodeproj/project.pbxproj",
			language: "other",
			content: `		97C146ED /* Debug */ = {
			buildSettings = {
				DEBUG_INFORMATION_FORMAT = dwarf;
				STRIP_INSTALLED_PRODUCT = NO;
			};
		};`,
		},
		{
			name:     "xcconfig release keeps dwarf",
			path:     "ios/Config/Release.xcconfig",
			language: "other",
			content:  `DEBUG_INFORMATION_FORMAT = dwarf;`,
			want:     []int{1},
		},
		{
			name:     "xcconfig without a release name is skipped",
			path:     "ios/Config/Base.xcconfig",
			language: "other",
			content:  `DEBUG_INFORMATION_FORMAT = dwarf;`,
		},
	})
}

func TestAntiRE054WebViewDebug(t *testing.T) {
	antireTestCases(t, "VGL-ARE-054", []antireCase{
		{
			name:     "kotlin enables webview debugging",
			path:     "app/src/main/java/com/example/MainActivity.kt",
			language: "other",
			content: `package com.example.app

import android.webkit.WebView

fun enableDebug(webView: WebView) {
    WebView.setWebContentsDebuggingEnabled(true)
}`,
			want: []int{6},
		},
		{
			name:     "java enables webview debugging",
			path:     "app/src/main/java/com/example/MainActivity.java",
			language: "java",
			content: `public class MainActivity {
    void onCreate() {
        setWebContentsDebuggingEnabled(true);
    }
}`,
			want: []int{3},
		},
		{
			name:     "debugging disabled is safe",
			path:     "app/src/main/java/com/example/MainActivity.kt",
			language: "other",
			content:  `WebView.setWebContentsDebuggingEnabled(false)`,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "app/src/main/java/com/example/MainActivity.kt",
			language: "other",
			content:  `WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)`,
		},
		{
			name:     "same line build config guard is skipped",
			path:     "app/src/main/java/com/example/MainActivity.kt",
			language: "other",
			content:  `if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)`,
		},
		{
			name:     "debug source set is skipped",
			path:     "app/src/debug/java/com/example/DebugWebView.kt",
			language: "other",
			content:  `WebView.setWebContentsDebuggingEnabled(true)`,
		},
		{
			name:     "androidTest is skipped",
			path:     "app/src/androidTest/java/com/example/WebViewTest.kt",
			language: "other",
			content:  `WebView.setWebContentsDebuggingEnabled(true)`,
		},
		{
			name:     "comment is skipped",
			path:     "app/src/main/java/com/example/MainActivity.kt",
			language: "other",
			content:  `// WebView.setWebContentsDebuggingEnabled(true)`,
		},
	})
}

func TestAntiRE055ReactNativeHermes(t *testing.T) {
	antireTestCases(t, "VGL-ARE-055", []antireCase{
		{
			name:     "gradle properties disable hermes",
			path:     "android/gradle.properties",
			language: "other",
			content: `org.gradle.jvmargs=-Xmx2048m
hermesEnabled=false`,
			want: []int{2},
		},
		{
			name:     "react native config disables hermes",
			path:     "react-native.config.js",
			language: "javascript",
			content: `module.exports = {
  hermesEnabled: false,
};`,
			want: []int{2},
		},
		{
			name:     "assignment form",
			path:     "react-native.config.js",
			language: "javascript",
			content:  `hermesEnabled = false`,
			want:     []int{1},
		},
		{
			name:     "hermes enabled is safe",
			path:     "android/gradle.properties",
			language: "other",
			content:  `hermesEnabled=true`,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "react-native.config.js",
			language: "javascript",
			content:  `hermesEnabled = isHermesEnabled`,
		},
		{
			name:     "comment is skipped",
			path:     "android/gradle.properties",
			language: "other",
			content:  `# hermesEnabled=false`,
		},
		{
			name:     "other config file is out of scope",
			path:     "android/settings.gradle",
			language: "other",
			content:  `hermesEnabled = false`,
		},
	})
}

func TestAntiRE056ElectronASAR(t *testing.T) {
	antireTestCases(t, "VGL-ARE-056", []antireCase{
		{
			name:     "electron builder yaml disables asar",
			path:     "electron-builder.yml",
			language: "yaml",
			content: `appId: com.example.app
asar: false
directories:
  output: dist`,
			want: []int{2},
		},
		{
			name:     "package json build config disables asar",
			path:     "package.json",
			language: "json",
			content: `{
  "name": "app",
  "build": {
    "appId": "com.example.app",
    "asar": false
  }
}`,
			want: []int{5},
		},
		{
			name:     "asar object form",
			path:     "package.json",
			language: "json",
			content: `{
  "build": {
    "asar": { "enabled": false }
  }
}`,
			want: []int{3},
		},
		{
			name:     "forge config disables asar",
			path:     "forge.config.js",
			language: "javascript",
			content: `module.exports = {
  packagerConfig: {
    asar: false,
  },
};`,
			want: []int{3},
		},
		{
			name:     "asar enabled is safe",
			path:     "electron-builder.yml",
			language: "yaml",
			content:  `asar: true`,
		},
		{
			name:     "asar outside the build block is not packaging config",
			path:     "package.json",
			language: "json",
			content: `{
  "name": "app",
  "asar": false,
  "build": {
    "appId": "com.example.app"
  }
}`,
		},
		{
			name:     "dev path is skipped",
			path:     "dev/electron-builder.yml",
			language: "yaml",
			content:  `asar: false`,
		},
		{
			name:     "test path is skipped",
			path:     "test/electron-builder.yml",
			language: "yaml",
			content:  `asar: false`,
		},
		{
			name:     "comment is skipped",
			path:     "electron-builder.yml",
			language: "yaml",
			content:  `# asar: false`,
		},
	})
}

func TestAntiRE057ElectronFuseNode(t *testing.T) {
	antireTestCases(t, "VGL-ARE-057", []antireCase{
		{
			name:     "run as node fuse enabled",
			path:     "electron/fuses.js",
			language: "javascript",
			content: `const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

module.exports = async (context) => {
  await flipFuses(context.electronZipDir, {
    version: FuseVersion.V1,
    RunAsNode: true,
  });
};`,
			want: []int{6},
		},
		{
			name:     "node cli inspect fuse enabled",
			path:     "electron/fuses.js",
			language: "javascript",
			content: `await flipFuses(path, {
  EnableNodeCliInspectArguments: true,
});`,
			want: []int{2},
		},
		{
			name:     "node options fuse enabled",
			path:     "electron/fuses.js",
			language: "javascript",
			content: `await flipFuses(path, {
  EnableNodeOptionsEnvironmentVariable: true,
});`,
			want: []int{2},
		},
		{
			name:     "lowercase run as node",
			path:     "scripts/fuses.ts",
			language: "typescript",
			content:  `const fuses = { runAsNode: true };`,
			want:     []int{1},
		},
		{
			name:     "release safe fuses",
			path:     "electron/fuses.js",
			language: "javascript",
			content: `await flipFuses(path, {
  RunAsNode: false,
  EnableNodeCliInspectArguments: false,
  EnableNodeOptionsEnvironmentVariable: false,
});`,
		},
		{
			name:     "test path is skipped",
			path:     "test/fuses.js",
			language: "javascript",
			content:  `const fuses = { RunAsNode: true };`,
		},
		{
			name:     "unrelated file is out of scope",
			path:     "src/main.ts",
			language: "typescript",
			content:  `const options = { RunAsNode: true };`,
		},
		{
			name:     "comment is skipped",
			path:     "electron/fuses.js",
			language: "javascript",
			content:  `// RunAsNode: true`,
		},
	})
}

func TestAntiRE058ElectronFuseAsar(t *testing.T) {
	antireTestCases(t, "VGL-ARE-058", []antireCase{
		{
			name:     "asar integrity and only load disabled",
			path:     "electron/fuses.js",
			language: "javascript",
			content: `await flipFuses(path, {
  EnableEmbeddedAsarIntegrityValidation: false,
  OnlyLoadAppFromAsar: false,
});`,
			want: []int{2, 3},
		},
		{
			name:     "release safe fuses",
			path:     "electron/fuses.js",
			language: "javascript",
			content: `await flipFuses(path, {
  EnableEmbeddedAsarIntegrityValidation: true,
  OnlyLoadAppFromAsar: true,
});`,
		},
		{
			name:     "lowercase embedded asar integrity",
			path:     "scripts/fuses.ts",
			language: "typescript",
			content:  `const fuses = { embeddedAsarIntegrityValidation: false };`,
			want:     []int{1},
		},
		{
			name:     "test path is skipped",
			path:     "test/fuses.js",
			language: "javascript",
			content:  `const fuses = { OnlyLoadAppFromAsar: false };`,
		},
	})
}

func TestAntiRE059JSMinify(t *testing.T) {
	antireTestCases(t, "VGL-ARE-059", []antireCase{
		{
			name:     "vite disables minify",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content: `import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    minify: false,
  },
});`,
			want: []int{5},
		},
		{
			name:     "webpack disables minimize",
			path:     "frontend/webpack.config.js",
			language: "javascript",
			content: `module.exports = {
  optimization: {
    minimize: false,
  },
};`,
			want: []int{3},
		},
		{
			name:     "angular production disables minimize",
			path:     "frontend/angular.json",
			language: "json",
			content: `{
  "projects": {
    "app": {
      "architect": {
        "build": {
          "configurations": {
            "production": {
              "optimization": { "minimize": false }
            }
          }
        }
      }
    }
  }
}`,
			want: []int{8},
		},
		{
			name:     "next config quoted minify",
			path:     "frontend/next.config.js",
			language: "javascript",
			content: `module.exports = {
  "minify": false,
};`,
			want: []int{2},
		},
		{
			name:     "dotted build minify form",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content: `export default {
  build.minify: false,
};`,
			want: []int{2},
		},
		{
			name:     "minify enabled is safe",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content: `export default defineConfig({
  build: {
    minify: 'esbuild',
  },
});`,
		},
		{
			name:     "unresolved value is not a finding",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content: `export default defineConfig({
  build: {
    minify: process.env.MINIFY,
  },
});`,
		},
		{
			name:     "dev config path is skipped",
			path:     "frontend/vite.config.dev.ts",
			language: "typescript",
			content: `export default defineConfig({
  build: {
    minify: false,
  },
});`,
		},
		{
			name:     "test config path is skipped",
			path:     "frontend/test/webpack.config.js",
			language: "javascript",
			content: `module.exports = {
  optimization: {
    minimize: false,
  },
};`,
		},
		{
			name:     "comment is skipped",
			path:     "frontend/vite.config.ts",
			language: "typescript",
			content:  `// minify: false`,
		},
	})
}
