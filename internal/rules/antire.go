package rules

// Anti-RE (anti-reverse-engineering) hardening rules.
//
// These are positive posture checks for mobile and desktop builds: missing
// obfuscation, debug signing, debug-info leaks and disabled isolation. They
// report a missing control, never an exploit: a finding here does not mean the
// application is vulnerable, and a clean result does not mean it is protected.
//
// Every rule is deterministic, read-only and offline. Helper names are
// prefixed "antire" so they cannot collide with the other rule packs.

import (
	"regexp"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

var (
	// Android / Gradle.
	antireReleaseOpenRe = regexp.MustCompile(`(?i)\b(?:release\s*\{|(?:getbyname|named|create)\s*\(\s*["']release["']\s*\)\s*\{)`)
	antireMinifyOffRe   = regexp.MustCompile(`(?i)\b(?:is)?minifyenabled\s*(?:=\s*)?false\b`)
	antireDebugSignRe   = regexp.MustCompile(`(?i)signingconfigs\s*(?:\.\s*(?:debug\b|getbyname\s*\(\s*["']debug["']\s*\))|\[\s*["']debug["']\s*\])|debug\.keystore`)
	antireDebuggableRe  = regexp.MustCompile(`(?i)\bandroid:debuggable\s*=\s*["']true["']`)
	antireAllowBackupRe = regexp.MustCompile(`(?i)\bandroid:allowbackup\s*=\s*["']true["']`)
	antireCleartextRe   = regexp.MustCompile(`(?i)\bandroid:usescleartexttraffic\s*=\s*["']true["']`)
	antireNSCleartextRe = regexp.MustCompile(`(?i)\bcleartexttrafficpermitted\s*=\s*["']true["']`)

	// Flutter build scripts.
	antireFlutterBuildRe = regexp.MustCompile(`(?i)\bflutter\s+build\b`)

	// Electron / Node.
	antireWebSecurityRe      = regexp.MustCompile(`(?i)\bwebsecurity\s*:\s*false\b`)
	antireNodeIntegrationRe  = regexp.MustCompile(`(?i)\bnodeintegration\s*:\s*true\b`)
	antireContextIsolationRe = regexp.MustCompile(`(?i)\bcontextisolation\s*:\s*false\b`)
	antireInspectorRe        = regexp.MustCompile(`--inspect(?:-brk)?(?:=[^\s"']*)?(?:[\s"']|$)`)
	antireNodeToolRe         = regexp.MustCompile(`(?i)\b(?:node|npx|npm|yarn|pnpm)\b`)
	antireDevModeRe          = regexp.MustCompile(`(?i)\bnode_env\s*=\s*development\b|\b--mode[= ]development\b|\b(?:start|serve|run):dev\b`)
	antireScriptKeyRe        = regexp.MustCompile(`^\s*"([^"]+)"\s*:`)

	// Production source maps.
	antireViteSourcemapRe  = regexp.MustCompile(`\bsourcemap\s*:\s*true\b`)
	antireNextSourceMapRe  = regexp.MustCompile(`\bproductionBrowserSourceMaps\s*:\s*true\b`)
	antireDevtoolRe        = regexp.MustCompile(`\bdevtool\s*:\s*["']source-map["']`)
	antireAngularSourceMap = regexp.MustCompile(`"sourceMap"\s*:\s*true\b`)

	// Rust / Cargo release profile. Both expressions are anchored so a value
	// that is a table, a workspace reference or an expression never matches.
	antireCargoDebugRe = regexp.MustCompile(`(?i)^\s*debug\s*=\s*(?:true|[12]|"(?:full|line-tables-only|line-directives-only)")\s*(?:#.*)?$`)
	antireCargoStripRe = regexp.MustCompile(`(?i)^\s*strip\s*=\s*(?:false|"none")\s*(?:#.*)?$`)

	// .NET / MSBuild release property groups.
	antireMSBuildNotReleaseRe  = regexp.MustCompile(`(?i)!=\s*['"]?\s*release`)
	antireDotNetDebugTypeRe    = regexp.MustCompile(`(?i)<DebugType>\s*(?:full|portable|pdbonly)\s*</DebugType>`)
	antireDotNetDebugSymbolsRe = regexp.MustCompile(`(?i)<DebugSymbols>\s*true\s*</DebugSymbols>`)
	antireDotNetOptimizeRe     = regexp.MustCompile(`(?i)<Optimize>\s*false\s*</Optimize>`)

	// iOS / Xcode release configurations.
	antireTestabilityRe    = regexp.MustCompile(`(?i)\bENABLE_TESTABILITY\s*=\s*YES\s*(?:;|$)`)
	antireDwarfRe          = regexp.MustCompile(`(?i)\bDEBUG_INFORMATION_FORMAT\s*=\s*dwarf\s*(?:;|$)`)
	antireStripProductRe   = regexp.MustCompile(`(?i)\bSTRIP_INSTALLED_PRODUCT\s*=\s*NO\s*(?:;|$)`)
	antireCopyPhaseStripRe = regexp.MustCompile(`(?i)\bCOPY_PHASE_STRIP\s*=\s*NO\s*(?:;|$)`)
	antireDeployPostprocRe = regexp.MustCompile(`(?i)\bDEPLOYMENT_POSTPROCESSING\s*=\s*NO\s*(?:;|$)`)

	// Android WebView and React Native build switches.
	antireWebViewDebugRe = regexp.MustCompile(`(?i)\bsetWebContentsDebuggingEnabled\s*\(\s*true\s*\)`)
	antireHermesOffRe    = regexp.MustCompile(`(?i)\bhermesEnabled\s*[:=]\s*false\b`)

	// Electron packaging and fuses.
	antireAsarOffRe     = regexp.MustCompile(`(?i)\basar["']?\s*:\s*false\b|\basar["']?\s*:\s*\{\s*["']?enabled["']?\s*:\s*false\b`)
	antireFuseNodeOnRe  = regexp.MustCompile(`(?i)\b(?:RunAsNode|EnableNodeCliInspectArguments|EnableNodeOptionsEnvironmentVariable)\s*:\s*true\b`)
	antireFuseAsarOffRe = regexp.MustCompile(`(?i)\b(?:EnableEmbeddedAsarIntegrityValidation|EmbeddedAsarIntegrityValidation|OnlyLoadAppFromAsar)\s*:\s*false\b`)

	// JavaScript production minification.
	antireJSMinifyOffRe   = regexp.MustCompile(`(?i)\bminify["']?\s*:\s*false\b`)
	antireJSMinimizeOffRe = regexp.MustCompile(`(?i)\bminimize["']?\s*:\s*false\b`)
)

const (
	antireFixGradleMinify = "Enable code shrinking for release builds: set minifyEnabled true (Groovy) or " +
		"isMinifyEnabled = true (Kotlin DSL) and keep the R8/ProGuard rules file."
	antireFixGradleSigning = "Sign release builds with a dedicated release keystore; never reuse " +
		"signingConfigs.debug or a debug.keystore for distributed artifacts."
	antireFixDebuggable = "Remove android:debuggable from the release manifest (or set it to false); " +
		"debug builds get it from the debug variant automatically."
	antireFixBackup = "Set android:allowBackup=\"false\", or restrict backup with fullBackupContent/" +
		"dataExtractionRules so tokens, databases and preferences never leave the device."
	antireFixCleartext = "Serve traffic over HTTPS: remove android:usesCleartextTraffic or set it to " +
		"false, and keep cleartext exceptions in a network security config for debug domains only."
	antireFixNetworkConfig = "Set cleartextTrafficPermitted=\"false\" on base-config/domain-config and " +
		"keep any cleartext exception inside debug-overrides."
	antireFixGetTaskAllow = "Remove get-task-allow from release entitlements; it lets a debugger attach " +
		"to the shipped app."
	antireFixATS = "Remove NSAllowsArbitraryLoads; use per-domain NSExceptionDomains exceptions or " +
		"NSAllowsLocalNetworking instead of disabling App Transport Security."
	antireFixFlutter = "Build release artifacts with --obfuscate (and --split-debug-info) so Dart " +
		"symbol names are not shipped in the binary."
	antireFixWebSecurity = "Keep webSecurity enabled (true); disabling it turns off the same-origin " +
		"policy for the renderer."
	antireFixNodeIsolation = "Set contextIsolation: true and nodeIntegration: false in webPreferences; " +
		"expose only the APIs you need through a preload script."
	antireFixInspector = "Remove --inspect/--inspect-brk from production start commands; debug the " +
		"process locally instead of exposing the Node inspector."
	antireFixSourceMap = "Disable production source maps (sourcemap/productionBrowserSourceMaps false, " +
		"devtool off) or upload them privately instead of shipping them."
	antireFixCargoDebug = "In [profile.release] set debug = false (or 0) and strip = \"symbols\" (or true) " +
		"so the shipped Rust binary carries no DWARF debug information."
	antireFixDotNetDebug = "In the Release PropertyGroup set <DebugType>none</DebugType> and " +
		"<Optimize>true</Optimize>, and drop <DebugSymbols>true</DebugSymbols>, so the published " +
		"assembly is optimized and has no PDB."
	antireFixTestability = "Set ENABLE_TESTABILITY = NO in the Release build configuration; testability " +
		"exposes internal symbols at runtime and is only needed for Debug/Test builds."
	antireFixIOSDebugSymbols = "For Release set DEBUG_INFORMATION_FORMAT = dwarf-with-dsym (upload the " +
		"dSYM to the crash service), STRIP_INSTALLED_PRODUCT = YES, COPY_PHASE_STRIP = YES and " +
		"DEPLOYMENT_POSTPROCESSING = YES."
	antireFixWebViewDebug = "Remove setWebContentsDebuggingEnabled(true) from production sources, or gate " +
		"it behind a debug-only check so release builds cannot attach Chrome DevTools to the WebView."
	antireFixHermes = "Keep hermesEnabled=true for release builds: Hermes bytecode is harder to read " +
		"than a plain JavaScript bundle and is the default engine on current React Native versions."
	antireFixAsar = "Package the application into an ASAR archive (asar: true / asar.enabled: true) so " +
		"the shipped JavaScript is not a directory of readable files."
	antireFixElectronFuseDebug = "Build with RunAsNode, EnableNodeCliInspectArguments and " +
		"EnableNodeOptionsEnvironmentVariable disabled; those fuses let anyone run the packaged " +
		"binary as plain Node or attach the V8 inspector."
	antireFixElectronFuseAsar = "Enable EnableEmbeddedAsarIntegrityValidation and OnlyLoadAppFromAsar so " +
		"a modified app.asar is rejected at startup instead of being loaded."
	antireFixMinify = "Enable production minification (minify/minimize true) and keep source maps out of " +
		"the shipped bundle so names, comments and module structure are not shipped."
)

// AntiRERules returns the anti-reverse-engineering hardening rules.
func AntiRERules() []Rule {
	return []Rule{
		// ---------------------------------------------------------------
		// Android
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-ARE-001",
			Title:       "Android release build disables code shrinking",
			Description: "minifyEnabled false in the release build type ships unshrunk, unobfuscated bytecode, which makes decompilation and repackaging much cheaper. Enable R8 for release.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"android", "gradle", "obfuscation", "anti-re"},
		}, antireGradleMinifyRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-002",
			Title:       "Android release build is signed with a debug key",
			Description: "A release build type that uses signingConfigs.debug or a debug.keystore is signed with the public Android debug key. Anyone can forge an update for that application id.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-321"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"android", "gradle", "signing", "anti-re"},
		}, antireGradleDebugSigningRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-003",
			Title:       "Android manifest marks the app debuggable",
			Description: "android:debuggable=\"true\" in a shipped manifest lets anyone attach a debugger, read process memory and run code in the app context. It must not appear in a release manifest.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"android", "manifest", "debug", "anti-re"},
		}, antireDebuggableRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-004",
			Title:       "Android backup is enabled without a restrictive policy",
			Description: "android:allowBackup=\"true\" lets adb or cloud backup copy application data off the device, including tokens, databases and preferences. Disable it or constrain it with backup rules.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-200"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"android", "manifest", "backup", "anti-re"},
		}, antireAllowBackupRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-005",
			Title:       "Android manifest allows cleartext traffic",
			Description: "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP for every host, so a network attacker can read or modify traffic. Use HTTPS and a network security config instead.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-319"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"android", "manifest", "cleartext", "anti-re"},
		}, antireCleartextRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-006",
			Title:       "Network security config permits cleartext traffic",
			Description: "A base-config or domain-config with cleartextTrafficPermitted=\"true\" re-enables unencrypted HTTP for those hosts. Keep cleartext exceptions inside debug-overrides only.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-319"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"android", "network-security-config", "cleartext", "anti-re"},
		}, antireNetworkConfigRule),

		// ---------------------------------------------------------------
		// iOS
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-ARE-010",
			Title:       "iOS entitlements allow debugger attachment",
			Description: "get-task-allow is a development entitlement that lets a debugger attach to the process. A distributed build must not carry it.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"ios", "entitlements", "debug", "anti-re"},
		}, antireGetTaskAllowRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-011",
			Title:       "App Transport Security allows arbitrary loads",
			Description: "NSAllowsArbitraryLoads disables App Transport Security for every HTTP connection, allowing cleartext and weak TLS. Use narrow per-domain exceptions instead.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-319"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"ios", "plist", "ats", "cleartext", "anti-re"},
		}, antireATSArbitraryLoadsRule),

		// ---------------------------------------------------------------
		// Flutter
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-ARE-020",
			Title:       "Flutter release build ships without obfuscation",
			Description: "flutter build apk/appbundle/ipa (or any --release build) without --obfuscate keeps Dart symbol names in the binary, which makes reverse engineering and patch analysis easier.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"flutter", "obfuscation", "ci", "anti-re"},
		}, antireFlutterObfuscationRule),

		// ---------------------------------------------------------------
		// Electron / Node
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-ARE-030",
			Title:       "Electron renderer disables web security",
			Description: "webSecurity: false turns off the same-origin policy in the renderer, so any injected content can read other origins and local resources. Keep it enabled.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			Languages:   []string{"javascript", "typescript"},
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"electron", "chromium", "anti-re"},
		}, antireElectronWebSecurityRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-031",
			Title:       "Electron renderer exposes Node integration without isolation",
			Description: "nodeIntegration: true together with contextIsolation: false gives renderer content direct access to Node APIs and the main process. Use a preload script with contextIsolation enabled.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			Languages:   []string{"javascript", "typescript"},
			CWE:         []string{"CWE-829"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"electron", "node-integration", "anti-re"},
		}, antireNodeIsolationRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-040",
			Title:       "Production Node process starts with the inspector",
			Description: "--inspect/--inspect-brk opens the V8 inspector, which allows arbitrary code execution in the process once reachable. Production start commands must not enable it.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"node", "inspector", "debug", "anti-re"},
		}, antireNodeInspectorRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-041",
			Title:       "Production build ships source maps",
			Description: "Publishing source maps with the production bundle restores original names, comments and structure, which removes most of the cost of reverse engineering the frontend.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-540"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"sourcemap", "build", "anti-re"},
		}, antireProductionSourceMapRule),

		// ---------------------------------------------------------------
		// Release build configuration (Rust, .NET, iOS, Android, Electron)
		// ---------------------------------------------------------------
		New(model.RuleMeta{
			ID:          "VGL-ARE-050",
			Title:       "Rust release profile keeps debug information",
			Description: "A [profile.release] with debug = true/1/2 or without stripping keeps DWARF line tables, type names and variable names in the shipped executable, which restores most of the source structure for a reverse engineer.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-540"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"rust", "cargo", "debug-info", "anti-re"},
		}, antireCargoDebugRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-051",
			Title:       ".NET Release build keeps debug symbols or disables optimization",
			Description: "DebugType portable/full/pdbonly, DebugSymbols true or Optimize false in a Release PropertyGroup ships a debuggable, unoptimized assembly and keeps the PDB mapping, so decompiled CIL reads like the original source.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-540"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"dotnet", "msbuild", "debug", "anti-re"},
		}, antireDotNetDebugRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-052",
			Title:       "iOS Release build enables testability",
			Description: "ENABLE_TESTABILITY = YES in a Release configuration exposes internal symbols to the runtime and is only meant for the Debug or Test configuration.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"ios", "xcode", "testability", "anti-re"},
		}, antireIOSTestabilityRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-053",
			Title:       "iOS Release build keeps debug symbols or skips stripping",
			Description: "DEBUG_INFORMATION_FORMAT = dwarf, STRIP_INSTALLED_PRODUCT = NO, COPY_PHASE_STRIP = NO or DEPLOYMENT_POSTPROCESSING = NO leaves DWARF data and symbol names inside the shipped app binary.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-540"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"ios", "xcode", "debug-symbols", "anti-re"},
		}, antireIOSDebugSymbolsRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-054",
			Title:       "Android WebView debugging is enabled",
			Description: "setWebContentsDebuggingEnabled(true) in production sources lets anyone with adb attach Chrome DevTools to the app's WebViews and inspect or modify page content.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"android", "webview", "debug", "anti-re"},
		}, antireWebViewDebugRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-055",
			Title:       "React Native release disables the Hermes engine",
			Description: "hermesEnabled=false ships the plain JavaScript bundle instead of Hermes bytecode, which is far easier to read and patch after unpacking the application.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"MASVS-RESILIENCE"},
			Tags:        []string{"react-native", "hermes", "anti-re"},
		}, antireHermesDisabledRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-056",
			Title:       "Electron app ships an unpacked ASAR archive",
			Description: "asar: false (or asar.enabled: false) ships the application sources as plain files on disk instead of an archive, so the whole renderer and main-process code is readable without any tooling.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"electron", "asar", "packaging", "anti-re"},
		}, antireElectronAsarRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-057",
			Title:       "Electron fuse enables Node CLI inspect or RunAsNode",
			Description: "RunAsNode, EnableNodeCliInspectArguments and EnableNodeOptionsEnvironmentVariable let anyone run the packaged binary as plain Node or attach the V8 inspector, which turns the application into a scriptable host.",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-489"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"electron", "fuses", "debug", "anti-re"},
		}, antireElectronFuseDebugRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-058",
			Title:       "Electron fuse disables ASAR integrity or only-load",
			Description: "Disabling EnableEmbeddedAsarIntegrityValidation or OnlyLoadAppFromAsar lets a modified app.asar load without detection, so the shipped code can be replaced on disk.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-693"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"electron", "fuses", "integrity", "anti-re"},
		}, antireElectronFuseAsarRule),

		New(model.RuleMeta{
			ID:          "VGL-ARE-059",
			Title:       "JavaScript production build disables minification",
			Description: "minify/minimize false in a production build config ships readable variable names, comments and module structure, which removes most of the work of recovering the frontend source.",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAntiRE,
			CWE:         []string{"CWE-693", "CWE-540"},
			OWASP:       []string{"A05:2021"},
			Tags:        []string{"javascript", "build", "minify", "anti-re"},
		}, antireJSMinifyRule),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// antireComment reports whether line is a comment. It extends pbComment with
// the comment markers that XML, YAML, Makefile and shell files use, because
// the language label for those files is not always specific.
func antireComment(f *File, line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "<!--") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "--") {
		return true
	}
	return pbComment(f, line)
}

// antireTestPath reports whether the file is a test, fixture or example.
func antireTestPath(f *File) bool {
	return isTestPath(pbPathLower(f))
}

// antireDevPath reports whether a path belongs to a debug or development
// variant (RunnerDebug.entitlements, config/dev/..., src/debug/...).
func antireDevPath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, seg := range strings.Split(p, "/") {
		if strings.Contains(seg, "debug") || strings.Contains(seg, "development") {
			return true
		}
		if strings.Contains(seg, "dev") && !strings.Contains(seg, "device") {
			return true
		}
	}
	return false
}

// antireBraceDelta counts net braces on a line, ignoring strings and comments.
func antireBraceDelta(line string) int {
	delta := 0
	var quote rune
	escaped := false
	block := false
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if block {
			if c == '*' && i+1 < len(runes) && runes[i+1] == '/' {
				block = false
				i++
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '{':
			delta++
		case '}':
			delta--
		case '/':
			if i+1 < len(runes) {
				switch runes[i+1] {
				case '/':
					return delta
				case '*':
					block = true
					i++
				}
			}
		}
	}
	return delta
}

// antireRange is a 1-based inclusive line range.
type antireRange struct {
	start int
	end   int
}

// antireReleaseBlocks finds every release { ... } block and returns its line
// range. A missing release block means the caller has nothing to check.
func antireReleaseBlocks(f *File) []antireRange {
	var out []antireRange
	for i := 0; i < len(f.Lines); i++ {
		if antireComment(f, f.Lines[i]) || !antireReleaseOpenRe.MatchString(f.Lines[i]) {
			continue
		}
		depth := 0
		opened := false
		end := len(f.Lines)
		for j := i; j < len(f.Lines); j++ {
			depth += antireBraceDelta(f.Lines[j])
			if depth > 0 {
				opened = true
			}
			if opened && depth <= 0 {
				end = j + 1
				break
			}
		}
		out = append(out, antireRange{start: i + 1, end: end})
		i = end - 1
	}
	return out
}

// antirePlistBool finds a plist key whose value is <true/>. It accepts the
// same-line form (<key>k</key><true/>) and a value on one of the next three
// lines. A new <key> stops the search so unrelated values are not attributed
// to the key.
func antirePlistBool(f *File, key string) (int, bool) {
	tag := "<key>" + key + "</key>"
	for i, line := range f.Lines {
		if antireComment(f, line) {
			continue
		}
		idx := strings.Index(line, tag)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(tag):]
		if next := strings.Index(rest, "<key>"); next >= 0 {
			rest = rest[:next]
		}
		if antireTrueTag(rest) {
			return i + 1, true
		}
		for j := i + 1; j <= i+3 && j < len(f.Lines); j++ {
			if antireComment(f, f.Lines[j]) {
				continue
			}
			candidate := f.Lines[j]
			if next := strings.Index(candidate, "<key>"); next >= 0 {
				candidate = candidate[:next]
			}
			if antireTrueTag(candidate) {
				return j + 1, true
			}
			if strings.Contains(f.Lines[j], "<key>") {
				break
			}
		}
	}
	return 0, false
}

// antireTrueTag reports whether s contains a literal plist <true/> value.
func antireTrueTag(s string) bool {
	return strings.Contains(s, "<true/>") || strings.Contains(s, "<true />")
}

// antireCommand is one logical command: backslash-continued lines are joined
// and reported at the line where the command starts.
type antireCommand struct {
	line int
	text string
}

// antireLogicalCommands joins shell-style backslash continuations.
func antireLogicalCommands(f *File) []antireCommand {
	var out []antireCommand
	var b strings.Builder
	start := 0
	for i, line := range f.Lines {
		right := strings.TrimRight(line, " \t\r")
		continued := strings.HasSuffix(right, "\\")
		part := strings.TrimSuffix(right, "\\")
		if b.Len() == 0 {
			start = i + 1
		} else {
			b.WriteString(" ")
		}
		b.WriteString(strings.TrimSpace(part))
		if continued {
			continue
		}
		out = append(out, antireCommand{line: start, text: b.String()})
		b.Reset()
	}
	if b.Len() > 0 {
		out = append(out, antireCommand{line: start, text: b.String()})
	}
	return out
}

// antireSplitCommands splits a logical command on shell separators so a
// missing flag in one build does not hide behind another build's flags.
func antireSplitCommands(cmd string) []string {
	return strings.FieldsFunc(cmd, func(r rune) bool {
		return r == '&' || r == ';' || r == '|'
	})
}

// antireFlutterNeedsObfuscation reports whether the command contains a
// release-style flutter build without --obfuscate.
func antireFlutterNeedsObfuscation(cmd string) bool {
	for _, seg := range antireSplitCommands(cmd) {
		low := strings.ToLower(seg)
		idx := strings.Index(low, "flutter build")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(low[idx+len("flutter build"):])
		if strings.Contains(rest, "--obfuscate") {
			continue
		}
		if strings.Contains(rest, "--debug") || strings.Contains(rest, "--profile") {
			continue
		}
		target := ""
		if fields := strings.Fields(rest); len(fields) > 0 {
			target = fields[0]
		}
		if strings.Contains(rest, "--release") || target == "apk" || target == "appbundle" || target == "ipa" {
			return true
		}
	}
	return false
}

// antireFlutterScript reports whether the file is a build script or CI config.
func antireFlutterScript(f *File) bool {
	base := pbBaseLower(f.Path)
	switch base {
	case "makefile", "gnumakefile", "fastfile":
		return true
	}
	for _, suffix := range []string{".yml", ".yaml", ".sh", ".bash", ".zsh"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// antireJSPath reports whether the file is JavaScript or TypeScript.
func antireJSPath(f *File) bool {
	return f.Language == "javascript" || f.Language == "typescript"
}

// antireNodeRuntimeFile reports whether the file can hold a production Node
// start command.
func antireNodeRuntimeFile(f *File) bool {
	base := pbBaseLower(f.Path)
	switch {
	case base == "package.json", base == "procfile":
		return true
	case base == "dockerfile", strings.HasPrefix(base, "dockerfile."), strings.HasSuffix(base, ".dockerfile"):
		return true
	case strings.HasSuffix(base, ".sh"), strings.HasSuffix(base, ".bash"), strings.HasSuffix(base, ".zsh"):
		return true
	case strings.HasSuffix(base, ".service"):
		return true
	case (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) && strings.Contains(base, "compose"):
		return true
	}
	return false
}

// antireDevScriptFile reports whether the file name itself marks a dev, debug
// or test script (dev.sh, docker-compose.dev.yml, Dockerfile.debug).
func antireDevScriptFile(base string) bool {
	return strings.Contains(base, "dev") || strings.Contains(base, "debug") || strings.Contains(base, "test")
}

// antireDevScriptName reports whether a package.json script name is a
// development, debug or test script (dev, start:dev, test:ci, debug).
func antireDevScriptName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, part := range strings.Split(n, ":") {
		switch part {
		case "dev", "develop", "development", "debug", "test":
			return true
		}
	}
	return false
}

// antireDevScriptLine reports whether the command line is obviously a
// development invocation.
func antireDevScriptLine(line string) bool {
	low := strings.ToLower(line)
	if strings.Contains(low, "nodemon") || strings.Contains(low, "ts-node-dev") {
		return true
	}
	return antireDevModeRe.MatchString(line)
}

// antirePackageScriptKeys maps each 1-based line of package.json to the
// scripts.<name> key that contains it.
func antirePackageScriptKeys(f *File) map[int]string {
	out := map[int]string{}
	if pbBaseLower(f.Path) != "package.json" {
		return out
	}
	inScripts := false
	key := ""
	for i, line := range f.Lines {
		t := strings.TrimSpace(line)
		if !inScripts {
			if strings.Contains(t, `"scripts"`) && strings.Contains(t, "{") {
				inScripts = true
			}
			continue
		}
		if strings.HasPrefix(t, "}") {
			inScripts = false
			continue
		}
		if m := antireScriptKeyRe.FindStringSubmatch(t); m != nil {
			key = m[1]
		}
		if key != "" {
			out[i+1] = key
		}
	}
	return out
}

// antireSourceMapConfig reports whether the file is a production build config
// that can emit source maps.
func antireSourceMapConfig(f *File) bool {
	base := pbBaseLower(f.Path)
	if base == "angular.json" {
		return true
	}
	for _, prefix := range []string{"vite.config.", "webpack.config.", "next.config."} {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

// antireNearProduction reports whether the nearest configuration key at or
// above idx is "production". angular.json groups build options under a named
// configuration, so the closest key decides; a fixed line window would either
// miss long production blocks or attribute development options to production.
func antireNearProduction(f *File, idx int) bool {
	for i := idx; i >= 0 && idx-i <= 200; i-- {
		line := f.Lines[i]
		if strings.Contains(line, `"production"`) {
			return true
		}
		for _, key := range []string{`"development"`, `"test"`, `"staging"`, `"local"`, `"e2e"`} {
			if strings.Contains(line, key) {
				return false
			}
		}
	}
	return false
}

// antireFinding builds a finding with the shared evidence/snippet and the
// anti-RE defaults.
func antireFinding(f *File, line int, severity model.Severity, remediation string) model.Finding {
	fd := pbFinding(f, line, f.Line(line))
	fd.Severity = severity
	fd.Confidence = model.ConfidenceHigh
	fd.Remediation = remediation
	return fd
}

// antireGradleApp reports whether the file is an Android application build
// script.
func antireGradleApp(f *File) bool {
	base := pbBaseLower(f.Path)
	if base != "build.gradle" && base != "build.gradle.kts" {
		return false
	}
	return strings.Contains(string(f.Content), "com.android.application")
}

// antireManifest reports whether the file is a production Android manifest.
func antireManifest(f *File) bool {
	if pbBaseLower(f.Path) != "androidmanifest.xml" {
		return false
	}
	return !antireDebugVariantPath(pbPathLower(f))
}

// antireDebugVariantPath reports whether the manifest belongs to a debug
// source set or a debug build output.
func antireDebugVariantPath(p string) bool {
	return strings.Contains(p, "/debug/") || strings.Contains(p, "src/debug")
}

// antireNetworkSecurityConfig reports whether the file is an Android network
// security config.
func antireNetworkSecurityConfig(f *File) bool {
	base := pbBaseLower(f.Path)
	return base == "network_security_config.xml" ||
		(strings.HasSuffix(base, ".xml") && strings.Contains(base, "network_security_config"))
}

// ---------------------------------------------------------------------------
// Android rules
// ---------------------------------------------------------------------------

func antireGradleMinifyRule(f *File) []model.Finding {
	if !antireGradleApp(f) {
		return nil
	}
	var out []model.Finding
	for _, r := range antireReleaseBlocks(f) {
		for line := r.start; line <= r.end && line <= len(f.Lines); line++ {
			text := f.Line(line)
			if antireComment(f, text) || !antireMinifyOffRe.MatchString(text) {
				continue
			}
			out = append(out, antireFinding(f, line, model.SeverityMedium, antireFixGradleMinify))
		}
	}
	return out
}

func antireGradleDebugSigningRule(f *File) []model.Finding {
	if !antireGradleApp(f) {
		return nil
	}
	var out []model.Finding
	for _, r := range antireReleaseBlocks(f) {
		for line := r.start; line <= r.end && line <= len(f.Lines); line++ {
			text := f.Line(line)
			if antireComment(f, text) || !antireDebugSignRe.MatchString(text) {
				continue
			}
			out = append(out, antireFinding(f, line, model.SeverityHigh, antireFixGradleSigning))
		}
	}
	return out
}

func antireDebuggableRule(f *File) []model.Finding {
	if !antireManifest(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireDebuggableRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityHigh, antireFixDebuggable))
	}
	return out
}

func antireAllowBackupRule(f *File) []model.Finding {
	if !antireManifest(f) {
		return nil
	}
	content := string(f.Content)
	hasRules := strings.Contains(content, "fullBackupContent") ||
		strings.Contains(content, "dataExtractionRules")
	remediation := antireFixBackup
	if hasRules {
		remediation += " A backup rules policy is already referenced; verify it excludes credentials, tokens and databases."
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireAllowBackupRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, remediation))
	}
	return out
}

func antireCleartextRule(f *File) []model.Finding {
	if !antireManifest(f) {
		return nil
	}
	if strings.Contains(string(f.Content), "android:networkSecurityConfig") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireCleartextRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixCleartext))
	}
	return out
}

func antireNetworkConfigRule(f *File) []model.Finding {
	if !antireNetworkSecurityConfig(f) {
		return nil
	}
	inDebugOverrides := false
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "<debug-overrides") {
			if !strings.Contains(low, "/>") && !strings.Contains(low, "</debug-overrides>") {
				inDebugOverrides = true
			}
			continue
		}
		if strings.Contains(low, "</debug-overrides>") {
			inDebugOverrides = false
			continue
		}
		if inDebugOverrides || !antireNSCleartextRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixNetworkConfig))
	}
	return out
}

// ---------------------------------------------------------------------------
// iOS rules
// ---------------------------------------------------------------------------

func antireGetTaskAllowRule(f *File) []model.Finding {
	base := pbBaseLower(f.Path)
	if !strings.HasSuffix(base, ".entitlements") && !strings.HasSuffix(base, ".plist") {
		return nil
	}
	if antireTestPath(f) || antireDevPath(f.Path) {
		return nil
	}
	line, ok := antirePlistBool(f, "get-task-allow")
	if !ok {
		return nil
	}
	return []model.Finding{antireFinding(f, line, model.SeverityHigh, antireFixGetTaskAllow)}
}

func antireATSArbitraryLoadsRule(f *File) []model.Finding {
	if !strings.HasSuffix(pbBaseLower(f.Path), ".plist") {
		return nil
	}
	if antireTestPath(f) {
		return nil
	}
	line, ok := antirePlistBool(f, "NSAllowsArbitraryLoads")
	if !ok {
		return nil
	}
	return []model.Finding{antireFinding(f, line, model.SeverityMedium, antireFixATS)}
}

// ---------------------------------------------------------------------------
// Flutter rules
// ---------------------------------------------------------------------------

func antireFlutterObfuscationRule(f *File) []model.Finding {
	if !antireFlutterScript(f) || antireTestPath(f) {
		return nil
	}
	var out []model.Finding
	seen := map[int]bool{}
	for _, cmd := range antireLogicalCommands(f) {
		if seen[cmd.line] || antireComment(f, cmd.text) {
			continue
		}
		if !antireFlutterBuildRe.MatchString(cmd.text) || !antireFlutterNeedsObfuscation(cmd.text) {
			continue
		}
		seen[cmd.line] = true
		fd := pbFinding(f, cmd.line, cmd.text)
		fd.Severity = model.SeverityMedium
		fd.Confidence = model.ConfidenceHigh
		fd.Remediation = antireFixFlutter
		out = append(out, fd)
	}
	return out
}

// ---------------------------------------------------------------------------
// Electron / Node rules
// ---------------------------------------------------------------------------

func antireElectronWebSecurityRule(f *File) []model.Finding {
	if !antireJSPath(f) || antireTestPath(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireWebSecurityRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityHigh, antireFixWebSecurity))
	}
	return out
}

func antireNodeIsolationRule(f *File) []model.Finding {
	if !antireJSPath(f) || antireTestPath(f) {
		return nil
	}
	var nodeLines, isolationLines []int
	for i, line := range f.Lines {
		if antireComment(f, line) {
			continue
		}
		if antireNodeIntegrationRe.MatchString(line) {
			nodeLines = append(nodeLines, i+1)
		}
		if antireContextIsolationRe.MatchString(line) {
			isolationLines = append(isolationLines, i+1)
		}
	}
	var out []model.Finding
	for _, nodeLine := range nodeLines {
		for _, isolationLine := range isolationLines {
			delta := nodeLine - isolationLine
			if delta < 0 {
				delta = -delta
			}
			if delta > 30 {
				continue
			}
			out = append(out, antireFinding(f, nodeLine, model.SeverityHigh, antireFixNodeIsolation))
			break
		}
	}
	return out
}

func antireNodeInspectorRule(f *File) []model.Finding {
	if !antireNodeRuntimeFile(f) || antireTestPath(f) {
		return nil
	}
	if antireDevScriptFile(pbBaseLower(f.Path)) {
		return nil
	}
	// A multi-stage Dockerfile may enable the inspector in a builder or dev
	// stage that never reaches the final image. Only the last stage is
	// shipped, so an earlier FROM line bounds the production surface.
	lastFrom := 0
	if antireDockerfileFile(f) {
		lastFrom = antireLastFromLine(f)
	}
	scriptKeys := antirePackageScriptKeys(f)
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireInspectorRe.MatchString(line) {
			continue
		}
		if lastFrom > 0 && i+1 < lastFrom {
			continue
		}
		if !antireNodeToolRe.MatchString(line) {
			continue
		}
		if antireDevScriptLine(line) {
			continue
		}
		if key, ok := scriptKeys[i+1]; ok && antireDevScriptName(key) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityHigh, antireFixInspector))
	}
	return out
}

// antireDockerfileFile reports whether f is a Dockerfile.
func antireDockerfileFile(f *File) bool {
	base := pbBaseLower(f.Path)
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") ||
		strings.HasSuffix(base, ".dockerfile")
}

// antireLastFromLine returns the 1-based line of the last FROM instruction, or
// 0 when the file has none.
func antireLastFromLine(f *File) int {
	last := 0
	for i, line := range f.Lines {
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, "FROM ") || strings.HasPrefix(upper, "FROM\t") {
			last = i + 1
		}
	}
	return last
}

// ---------------------------------------------------------------------------
// Source map rules
// ---------------------------------------------------------------------------

func antireProductionSourceMapRule(f *File) []model.Finding {
	if !antireSourceMapConfig(f) {
		return nil
	}
	p := pbPathLower(f)
	if antireTestPath(f) || strings.Contains(p, "dev") ||
		strings.Contains(p, "test") || strings.Contains(p, "example") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) {
			continue
		}
		hit := antireViteSourcemapRe.MatchString(line) ||
			antireNextSourceMapRe.MatchString(line) ||
			antireDevtoolRe.MatchString(line)
		if !hit && antireAngularSourceMap.MatchString(line) {
			hit = antireNearProduction(f, i)
		}
		if !hit {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixSourceMap))
	}
	return out
}

// ---------------------------------------------------------------------------
// Release configuration helpers
// ---------------------------------------------------------------------------

// antireTOMLTables maps each 1-based line to the TOML table that contains it
// (lower-cased, without brackets). Values inside [profile.dev] therefore never
// look like release settings.
func antireTOMLTables(f *File) []string {
	out := make([]string, len(f.Lines))
	current := ""
	for i, line := range f.Lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			header := t
			if idx := strings.Index(header, "#"); idx >= 0 {
				header = header[:idx]
			}
			header = strings.TrimSpace(header)
			if strings.HasSuffix(header, "]") {
				current = strings.ToLower(strings.Trim(header, "[] "))
			}
		}
		out[i] = current
	}
	return out
}

// antireMSBuildReleaseGroups maps each 1-based line to whether it sits inside a
// <PropertyGroup> whose Condition targets Release. Groups conditioned on Debug,
// or on "!= Release", are not a release surface.
func antireMSBuildReleaseGroups(f *File) []bool {
	out := make([]bool, len(f.Lines))
	active := false
	for i, line := range f.Lines {
		low := strings.ToLower(line)
		if idx := strings.Index(low, "<propertygroup"); idx >= 0 {
			raw := low[idx:]
			for j := i + 1; j < len(f.Lines) && j <= i+3 && !strings.Contains(raw, ">"); j++ {
				raw += " " + strings.ToLower(f.Lines[j])
			}
			selfClosing := false
			tag := raw
			if end := strings.Index(raw, ">"); end >= 0 {
				selfClosing = end > 0 && raw[end-1] == '/'
				tag = raw[:end]
			}
			active = !selfClosing &&
				strings.Contains(tag, "release") &&
				!strings.Contains(tag, "debug") &&
				!antireMSBuildNotReleaseRe.MatchString(tag)
		}
		out[i] = active
		if strings.Contains(low, "</propertygroup") {
			active = false
		}
	}
	return out
}

// antireReleaseConfigName reports whether an xcconfig file name marks a release
// or distribution configuration.
func antireReleaseConfigName(base string) bool {
	return strings.Contains(base, "release") || strings.Contains(base, "prod") ||
		strings.Contains(base, "distribution")
}

// antirePbxReleaseLines maps each 1-based line of a project.pbxproj to whether
// it belongs to a Release build configuration, using the nearest preceding
// /* Debug */ or /* Release */ marker.
func antirePbxReleaseLines(f *File) []bool {
	out := make([]bool, len(f.Lines))
	release := false
	for i, line := range f.Lines {
		low := strings.ToLower(line)
		switch {
		case strings.Contains(low, "/* debug */"):
			release = false
		case strings.Contains(low, "/* release */"):
			release = true
		}
		out[i] = release
	}
	return out
}

// antireIOSReleaseScope returns, per 1-based line, whether the line belongs to
// a Release configuration. It returns nil when the file is not an iOS build
// configuration in scope.
func antireIOSReleaseScope(f *File) []bool {
	base := pbBaseLower(f.Path)
	switch {
	case base == "project.pbxproj":
		return antirePbxReleaseLines(f)
	case strings.HasSuffix(base, ".xcconfig"):
		if !antireReleaseConfigName(base) {
			return nil
		}
		out := make([]bool, len(f.Lines))
		for i := range out {
			out[i] = true
		}
		return out
	}
	return nil
}

// antireJSONBuildBlock maps each 1-based line of a package.json to whether it
// sits inside the top-level "build" object, which is where electron-builder
// reads its configuration. A top-level "asar" key elsewhere is not packaging
// configuration.
func antireJSONBuildBlock(f *File) []bool {
	out := make([]bool, len(f.Lines))
	depth := 0
	active := false
	for i, line := range f.Lines {
		t := strings.TrimSpace(line)
		if !active {
			if !strings.Contains(t, `"build"`) || !strings.Contains(t, "{") {
				continue
			}
			active = true
			depth = 0
		}
		depth += antireBraceDelta(line)
		out[i] = true
		if depth <= 0 {
			active = false
		}
	}
	return out
}

// antireAndroidSourceFile reports whether the file is Java or Kotlin source.
func antireAndroidSourceFile(f *File) bool {
	base := pbBaseLower(f.Path)
	return strings.HasSuffix(base, ".java") || strings.HasSuffix(base, ".kt")
}

// antireAndroidTestPath reports whether an Android source file belongs to a
// unit-test or instrumentation-test source set. It deliberately avoids
// isTestPath: that helper treats any "/example/" segment as a fixture, which
// would silently skip every production file under a com/example/... package.
func antireAndroidTestPath(p string) bool {
	for _, marker := range []string{
		"src/test", "src/androidtest", "/test/", "/androidtest/",
		"_test.", ".test.", "_spec.", ".spec.",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

// antireElectronBuilderFile reports whether the file can hold electron-builder
// or Electron Forge packaging configuration.
func antireElectronBuilderFile(f *File) bool {
	base := pbBaseLower(f.Path)
	switch base {
	case "electron-builder.yml", "electron-builder.yaml", "electron-builder.json",
		"forge.config.js", "forge.config.cjs", "forge.config.mjs", "forge.config.ts",
		"package.json":
		return true
	}
	return false
}

// antireElectronFuseFile reports whether the file is an Electron fuse
// configuration, by name or by content.
func antireElectronFuseFile(f *File) bool {
	base := pbBaseLower(f.Path)
	if strings.Contains(base, "electron") || strings.Contains(base, "fuse") {
		return true
	}
	content := strings.ToLower(string(f.Content))
	return strings.Contains(content, "electron") || strings.Contains(content, "fuses")
}

// antireJSBuildConfigFile reports whether the file is a production JavaScript
// build config that can control minification. It is the same file set as the
// source map rule.
func antireJSBuildConfigFile(f *File) bool {
	return antireSourceMapConfig(f)
}

// ---------------------------------------------------------------------------
// Release configuration rules
// ---------------------------------------------------------------------------

func antireCargoDebugRule(f *File) []model.Finding {
	if pbBaseLower(f.Path) != "cargo.toml" || antireTestPath(f) {
		return nil
	}
	tables := antireTOMLTables(f)
	var out []model.Finding
	for i, line := range f.Lines {
		if tables[i] != "profile.release" || antireComment(f, line) {
			continue
		}
		if !antireCargoDebugRe.MatchString(line) && !antireCargoStripRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixCargoDebug))
	}
	return out
}

func antireDotNetDebugRule(f *File) []model.Finding {
	base := pbBaseLower(f.Path)
	if !strings.HasSuffix(base, ".csproj") && !strings.HasSuffix(base, ".props") &&
		!strings.HasSuffix(base, ".targets") {
		return nil
	}
	if antireTestPath(f) {
		return nil
	}
	groups := antireMSBuildReleaseGroups(f)
	var out []model.Finding
	for i, line := range f.Lines {
		if !groups[i] || antireComment(f, line) {
			continue
		}
		if !antireDotNetDebugTypeRe.MatchString(line) &&
			!antireDotNetDebugSymbolsRe.MatchString(line) &&
			!antireDotNetOptimizeRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixDotNetDebug))
	}
	return out
}

func antireIOSTestabilityRule(f *File) []model.Finding {
	scope := antireIOSReleaseScope(f)
	if scope == nil || antireTestPath(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if !scope[i] || antireComment(f, line) || !antireTestabilityRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityHigh, antireFixTestability))
	}
	return out
}

func antireIOSDebugSymbolsRule(f *File) []model.Finding {
	scope := antireIOSReleaseScope(f)
	if scope == nil || antireTestPath(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if !scope[i] || antireComment(f, line) {
			continue
		}
		hit := antireDwarfRe.MatchString(line) ||
			antireStripProductRe.MatchString(line) ||
			antireCopyPhaseStripRe.MatchString(line) ||
			antireDeployPostprocRe.MatchString(line)
		if !hit {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixIOSDebugSymbols))
	}
	return out
}

func antireWebViewDebugRule(f *File) []model.Finding {
	if !antireAndroidSourceFile(f) {
		return nil
	}
	p := pbPathLower(f)
	if antireAndroidTestPath(p) || antireDebugVariantPath(p) || strings.Contains(p, "androidtest") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireWebViewDebugRe.MatchString(line) {
			continue
		}
		// A guard on the same line (if (BuildConfig.DEBUG) ...) only enables
		// debugging in debug builds, which is the intended pattern.
		if strings.Contains(line, "BuildConfig.DEBUG") {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityHigh, antireFixWebViewDebug))
	}
	return out
}

func antireHermesDisabledRule(f *File) []model.Finding {
	base := pbBaseLower(f.Path)
	if base != "gradle.properties" && base != "react-native.config.js" {
		return nil
	}
	if antireTestPath(f) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireHermesOffRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixHermes))
	}
	return out
}

func antireElectronAsarRule(f *File) []model.Finding {
	if !antireElectronBuilderFile(f) || antireTestPath(f) || antireDevPath(f.Path) {
		return nil
	}
	var buildBlock []bool
	if pbBaseLower(f.Path) == "package.json" {
		buildBlock = antireJSONBuildBlock(f)
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireAsarOffRe.MatchString(line) {
			continue
		}
		if buildBlock != nil && !buildBlock[i] {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixAsar))
	}
	return out
}

func antireElectronFuseDebugRule(f *File) []model.Finding {
	if !antireElectronFuseFile(f) || antireTestPath(f) || antireDevPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireFuseNodeOnRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityHigh, antireFixElectronFuseDebug))
	}
	return out
}

func antireElectronFuseAsarRule(f *File) []model.Finding {
	if !antireElectronFuseFile(f) || antireTestPath(f) || antireDevPath(f.Path) {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) || !antireFuseAsarOffRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixElectronFuseAsar))
	}
	return out
}

func antireJSMinifyRule(f *File) []model.Finding {
	if !antireJSBuildConfigFile(f) {
		return nil
	}
	p := pbPathLower(f)
	if antireTestPath(f) || strings.Contains(p, "dev") ||
		strings.Contains(p, "test") || strings.Contains(p, "example") {
		return nil
	}
	var out []model.Finding
	for i, line := range f.Lines {
		if antireComment(f, line) {
			continue
		}
		if !antireJSMinifyOffRe.MatchString(line) && !antireJSMinimizeOffRe.MatchString(line) {
			continue
		}
		out = append(out, antireFinding(f, i+1, model.SeverityMedium, antireFixMinify))
	}
	return out
}
