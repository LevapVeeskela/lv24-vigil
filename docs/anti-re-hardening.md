# Anti-RE hardening vs. a reverse-engineering toolkit

Vigil's `VGL-ARE` family checks whether a mobile or desktop release still carries
the controls that make reverse engineering expensive. This page maps those checks
to the surfaces a reverse-engineering toolkit actually inspects, using the REA
6.8.0 tool inventory as the reference model. It also lists what neither side
covers.

The short version: **Vigil cannot prevent reverse engineering.** It reports
missing release controls before the artifact ships; it never proves that a
shipped artifact is hard to reverse.

## Threat model

REA is a reference, read-only reverse-engineering MCP. It opens artifacts and
reports what they contain; it does not patch, unpack protected code or bypass a
control. The capability groups that matter for a shipped application are:

- **Native binaries** — ELF, PE and Mach-O sections, symbols, imports, TLS
  callbacks, load configuration, entropy and hardening flags.
- **Managed code** — .NET assemblies, CIL metadata, members, custom attributes
  and `#US` user strings.
- **Android** — APK manifest and components, DEX classes and methods, JNI
  `RegisterNatives` bindings, APK signature schemes.
- **iOS/macOS** — Mach-O load commands, code signature, entitlements and
  hardened-runtime state.
- **Electron and JavaScript** — fuse wire and its implications, ASAR contents,
  static JS application graphs, source recovery.
- **Firmware** — Binwalk/Unblob regions and extracted children.
- **Live runtime** — Frida instrumentation, GDB/Rizin debugging and ADB device
  facts.

A release that keeps symbols, debug info, source maps, debug flags or permissive
runtime switches makes every one of those inspections cheaper. That is the risk
Vigil measures. The rules read repository files — build scripts, manifests,
plists, Electron configs, JavaScript build configs — and never open the built
artifact. A clean `vigil hardening` result therefore means "no known missing
control in the checked-in release configuration", not "the shipped binary is
protected". A build pipeline can override what the repository says.

## How to run

```bash
vigil hardening .                 # human summary, grouped by platform
vigil hardening . --format json   # full scan result
vigil hardening . --fail-on high  # exit 2 when a high gap is found
```

MCP: call `vigil_hardening` with `path`, `minSeverity`, `maxFindings` and
`noBaseline`. The prompt `anti_re_hardening` wraps the tool in a review workflow.
The command is deterministic, offline, runs no model and ignores the configured
OSV lookup.

## Capability map

REA capability names below are the published tool names. "Vigil rule(s)" names
the `VGL-ARE` checks that make the corresponding inspection more expensive; an
em dash means Vigil has no rule for that surface, which is a gap, not a pass.

| REA capability / tool | What it exposes | Vigil rule(s) | What is still not covered |
|---|---|---|---|
| `open_binary` + `list_symbols` / `decompile_all` | Symbol and function names, decompiled C, call structure — the cheapest path from an artifact to readable logic | `VGL-ARE-001` (R8 shrink/rename), `VGL-ARE-020` (Flutter `--obfuscate`), `VGL-ARE-041` (production source maps), `VGL-ARE-050` (Rust debug info), `VGL-ARE-051` (.NET symbols), `VGL-ARE-053` (iOS symbols) | Symbol quality after obfuscation, inlining, stripped-binary verification. Vigil never reads the built binary, so it cannot confirm stripping happened. |
| `list_strings` / `search_strings` | Literals, URLs, error messages, feature names and embedded configuration; provider string inventory (packed or undefined strings may be missing) | `VGL-ARE-041` (source maps restore names and comments), `VGL-ARE-059` (JavaScript minification), `VGL-ARE-055` (Hermes disabled ships a plain JS bundle), `VGL-ARE-004` (backup can expose app data), `VGL-ARE-005`/`006`/`011` (cleartext endpoints) | Secret literals in binaries (that is source secret scanning, not the ARE family), encrypted string tables, packer-hidden strings. |
| `inspect_binary_hardening` | PIE/NX/RELRO/stack-protector/FORTIFY/CET/BTI-PAC, PE dynamic base/CFG/Authenticode/debug directory, Mach-O encrypted flag, `__RESTRICT`, code-signature presence | `VGL-ARE-050` (Rust debug directory or DWARF), `VGL-ARE-051` (.NET PDB), `VGL-ARE-053` (iOS DWARF), `VGL-ARE-010` (debugger entitlement), `VGL-ARE-002` (debug signing) | Compiler and linker mitigations (PIE, NX, RELRO, CFG, stack protector) have no Vigil rule. This is a deliberate scope boundary, not an implicit pass. |
| `inspect_pe_imports` / `inspect_pe_load_config` | Imported APIs such as `IsDebuggerPresent`, `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`, TLS callbacks and load-config fields | — | Presence or absence of native anti-debug imports and TLS callbacks. Vigil cannot tell whether a PE contains anti-debug code. |
| `inspect_managed_artifact` / `inspect_managed_members` | Assembly identity and MVID, custom attributes (`DebuggableAttribute`, `SuppressIldasmAttribute`), member signatures, CIL bodies and `#US` strings | `VGL-ARE-051` (.NET release debug symbols or disabled optimization) | Obfuscation quality, encrypted method bodies and ConfuserEx-style packing. |
| `inspect_android_package` / `inspect_android_class` / `inspect_android_jni_bindings` | Manifest and exported components, permissions, DEX prototypes and smali, `RegisterNatives`/`JNINativeMethod` candidates | `VGL-ARE-001`, `VGL-ARE-003`, `VGL-ARE-004`, `VGL-ARE-005`, `VGL-ARE-006`, `VGL-ARE-054` (WebView debugging) | Root, jailbreak, Frida and Xposed detection presence; native anti-debug code; exported-component review (outside the anti-RE family). |
| `inspect_apk_signature` | v1/v2/v3/v3.1 signers, certificate digests, rotation lineage and source stamp | `VGL-ARE-002` (debug key) | Key custody, Play App Signing configuration and certificate pinning to the signing identity. |
| `inspect_macho` / `inspect_signature` | Load commands, segments, entitlements, hardened runtime and code-signing identity | `VGL-ARE-010` (`get-task-allow`), `VGL-ARE-052` (testability), `VGL-ARE-053` (debug symbols) | Hardened-runtime enforcement, `__RESTRICT`, injected dylib load commands and jailbreak checks. |
| `inspect_electron_fuses` | Per-fuse state and derived implications: `RunAsNode`, `NODE_OPTIONS`, inspector arguments, ASAR integrity validation, only-load-from-ASAR | `VGL-ARE-057` (RunAsNode/inspect fuse), `VGL-ARE-058` (ASAR integrity/only-load fuse), `VGL-ARE-030`/`031` (renderer isolation), `VGL-ARE-040` (Node inspector) | Whether the built application actually applies the fuses, and the fuse state of already-shipped binaries. |
| `analyze_javascript_application` / `recover_javascript_sources` | Static graph, routes, data flow, integrity contradictions and source recovery (Wakaru unminify) | `VGL-ARE-041` (source maps), `VGL-ARE-059` (minification), `VGL-ARE-055` (Hermes), `VGL-ARE-030`/`031` | Obfuscation strength, control-flow flattening, string-array obfuscation. Vigil does not deobfuscate or measure it. |
| `inspect_artifact` | Container identity (ASAR, PyInstaller, Node SEA, UnityFS, APK/IPA), declared integrity, unpacked/encrypted flags and integrity contradictions | `VGL-ARE-056` (unpacked ASAR), `VGL-ARE-058` (ASAR integrity fuse), `VGL-ARE-020` (Flutter artifacts), `VGL-ARE-002` (signing) | Whether declared integrity is enforced at runtime; encrypted container contents. |
| `frida` / `gdb` / `rizin` debug / `adb` | Attach, breakpoints, memory, device facts such as emulator or debuggable state | `VGL-ARE-003` (debuggable), `VGL-ARE-010` (`get-task-allow`), `VGL-ARE-040` (inspector), `VGL-ARE-054` (WebView debugging) | Runtime detection of Frida, Xposed, root or jailbreak. Vigil only checks release configuration; it never runs on a device. |
| `inspect_firmware_regions` / `extract_firmware` | Binwalk signatures, extracted children, uncovered ranges and extraction gaps | — | Firmware packing and encryption, secure boot and image signing are outside the `VGL-ARE` family. |

## Rule map

| Rule | Missing control it reports | REA capability it counters |
|---|---|---|
| `VGL-ARE-001` | Android release build disables R8 shrinking and renaming | `list_symbols`, `decompile_all`, `inspect_android_class` |
| `VGL-ARE-002` | Android release build is signed with the debug key | `inspect_apk_signature`, `inspect_artifact` |
| `VGL-ARE-003` | Shipped manifest sets `android:debuggable="true"` | `adb`, `frida`, `gdb`/`rizin` attach |
| `VGL-ARE-004` | `android:allowBackup="true"` without a restrictive policy | `adb` device and backup inspection |
| `VGL-ARE-005` | Manifest allows cleartext traffic | `list_strings`, runtime traffic capture |
| `VGL-ARE-006` | Network security config permits cleartext | `list_strings`, runtime traffic capture |
| `VGL-ARE-010` | iOS entitlements keep `get-task-allow` | `inspect_macho`, `inspect_signature`, debugger attach |
| `VGL-ARE-011` | App Transport Security allows arbitrary loads | `list_strings`, runtime traffic capture |
| `VGL-ARE-020` | Flutter release build ships without `--obfuscate` | `decompile_all`, `list_symbols` |
| `VGL-ARE-030` | Electron renderer disables `webSecurity` | `analyze_javascript_application`, Electron page inspection |
| `VGL-ARE-031` | Electron exposes Node integration without context isolation | `analyze_javascript_application`, `inspect_electron_fuses` |
| `VGL-ARE-040` | Production Node process starts with `--inspect` | JavaScript runtime observation, inspector attach |
| `VGL-ARE-041` | Production build ships source maps | `recover_javascript_sources`, `analyze_javascript_application`, `list_strings` |
| `VGL-ARE-050` | Rust release profile keeps debug information | `open_binary`, `list_symbols`, `decompile_all`, `inspect_binary_hardening` |
| `VGL-ARE-051` | .NET Release build keeps debug symbols or disables optimization | `inspect_managed_artifact`, `inspect_managed_members` |
| `VGL-ARE-052` | iOS Release build enables testability | `inspect_macho`, `inspect_signature`, debugger attach |
| `VGL-ARE-053` | iOS Release build keeps debug symbols or skips stripping | `open_binary`, `list_symbols`, `inspect_macho` |
| `VGL-ARE-054` | Android WebView debugging is enabled | `adb` + Chrome DevTools attach, `inspect_android_package` |
| `VGL-ARE-055` | React Native release disables the Hermes engine | `list_strings`, `analyze_javascript_application`, `recover_javascript_sources` |
| `VGL-ARE-056` | Electron app ships an unpacked ASAR archive | `inspect_artifact` |
| `VGL-ARE-057` | Electron fuse enables Node CLI inspect or RunAsNode | `inspect_electron_fuses`, JavaScript runtime observation |
| `VGL-ARE-058` | Electron fuse disables ASAR integrity or only-load | `inspect_electron_fuses`, `inspect_artifact` |
| `VGL-ARE-059` | JavaScript production build disables minification | `analyze_javascript_application`, `recover_javascript_sources`, `list_strings` |

The exact title of each rule is the one printed by `vigil rules`; this table
describes the control, not a second catalog.

## What is not covered

These are deliberate gaps. Do not read a clean hardening report as coverage of
them:

- **Runtime root, jailbreak, Frida and Xposed detection.** Vigil checks whether
  a release enables debug surfaces; it does not check whether the app detects an
  instrumented device at runtime.
- **Certificate pinning.** No rule verifies that a client pins its server
  certificate or public key.
- **Firmware packing and encryption.** `inspect_firmware_regions` and
  `extract_firmware` have no counterpart in `VGL-ARE`.
- **Application-specific anti-debug code.** A program that calls
  `ptrace(PTRACE_TRACEME)`, checks `TracerPid` or uses timing checks is invisible
  to a repository-configuration scan.
- **Server-side controls.** Attestation, Play Integrity, App Attest, device
  binding and backend rate limits are not visible in the client repository.
- **Built-artifact verification.** Vigil reads source and configuration. It
  cannot prove that a given binary was produced by that configuration, that
  symbols were stripped, or that an obfuscator ran.
- **Compiler and linker mitigations.** PIE, NX, RELRO, stack protector, CFG and
  Authenticode presence are REA facts that Vigil does not check.

## Honesty rules

- A control **raises the cost** of reverse engineering. It does not make an
  application unreversible.
- A missing control is **not proof of a vulnerability**. It is a release
  hygiene gap; exploitability depends on the asset, the threat actor and the
  rest of the design.
- A clean result is **not proof of protection**. Absence of a finding only means
  the rule did not match the scanned files.
- **No rule claims a bypass.** Vigil does not defeat, unpack, decrypt or patch
  anything, and it never asserts that an existing control can be circumvented.
- REA's own tool list is a reference model. A given deployment may not expose
  every tool; the mapping describes the surface, not a guaranteed attack path.

## See also

- [rules.md](rules.md) — the rule catalog and severity model.
- [mcp.md](mcp.md) — `vigil_hardening` and the `anti_re_hardening` prompt.
- [cli.md](cli.md) — `vigil hardening` flags and output.
