package osv

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf16"
)

// linkDirForTest links link to the directory target with a symlink, or with an
// NTFS junction where symlinks need a privilege the test does not have.
func linkDirForTest(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	}
	if runtime.GOOS != "windows" {
		t.Skip("cannot create a directory link on this system")
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Skipf("cannot create a junction: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

// A lockfile v1 entry stores a git, file or alias spec in "version". Such a
// value is not a registry version: it must never be sent to OSV or written to
// an SBOM, and a git URL can carry a credential.
func TestParsePackageLockSkipsNonRegistryVersions(t *testing.T) {
	const lock = `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "private-lib": {"version": "git+https://FAKETOKEN123:x-oauth-basic@github.com/org/private-lib.git#0123456789abcdef"},
	    "local-lib": {"version": "file:../local"},
	    "shorthand": {"version": "github:org/repo#abc123"},
	    "str": {"version": "npm:string-width@4.2.3"},
	    "lodash": {"version": "4.17.21", "dependencies": {
	      "nested-git": {"version": "git+ssh://git@github.com/x/y.git#abcdef"},
	      "nested-ok": {"version": "1.0.0-beta.1"}
	    }}
	  }
	}`
	pkgs, err := parsePackageLock("package-lock.json", []byte(lock))
	if err != nil {
		t.Fatalf("parsePackageLock: %v", err)
	}
	for _, p := range pkgs {
		if strings.Contains(p.Version, "FAKETOKEN123") || strings.ContainsAny(p.Version, ":/#@") {
			t.Errorf("package %q kept a non-registry version %q", p.Name, p.Version)
		}
	}
	idx := indexPackages(pkgs)
	requirePackage(t, idx, "lodash", "4.17.21")
	requirePackage(t, idx, "nested-ok", "1.0.0-beta.1")
	requirePackage(t, idx, "string-width", "4.2.3")
	for _, name := range []string{"private-lib", "local-lib", "shorthand", "nested-git", "str"} {
		if _, ok := idx[name]; ok {
			t.Errorf("%q is not a registry package and must be skipped", name)
		}
	}
}

// In lockfile v2/v3 an aliased install lives under the alias path and records
// the published package in "name". Querying the alias would miss the real
// package and could match an unrelated one.
func TestParsePackageLockAliasUsesRealName(t *testing.T) {
	const lock = `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app"},
	    "node_modules/str": {"name": "string-width", "version": "4.2.3"},
	    "node_modules/plain": {"version": "1.0.0"},
	    "node_modules/git-dep": {"version": "git+https://user:FAKETOKEN123@example.com/x.git#abc"}
	  }
	}`
	pkgs, err := parsePackageLock("package-lock.json", []byte(lock))
	if err != nil {
		t.Fatalf("parsePackageLock: %v", err)
	}
	idx := indexPackages(pkgs)
	requirePackage(t, idx, "string-width", "4.2.3")
	requirePackage(t, idx, "plain", "1.0.0")
	if _, ok := idx["str"]; ok {
		t.Error("the alias name must not be reported as a package")
	}
	if _, ok := idx["git-dep"]; ok {
		t.Error("a git version in packages must be skipped")
	}
}

// "<2.0.0" and ">1.0.0" do not admit the version they name, so using it would
// query (and inventory) a version outside the declared range.
func TestConcreteNPMVersionRejectsUpperAndExclusiveBounds(t *testing.T) {
	for _, spec := range []string{"<2.0.0", "<=2.0.0", "< 2.0.0", ">1.0.0", "> 1.0.0", "<2.0.0 || >=3.0.0"} {
		if got := concreteNPMVersion(spec); got != "" {
			t.Errorf("concreteNPMVersion(%q) = %q, want no version", spec, got)
		}
	}
	for spec, want := range map[string]string{">=1.2.3 <2.0.0": "1.2.3", "^1.2.3": "1.2.3", "=1.2.3": "1.2.3"} {
		if got := concreteNPMVersion(spec); got != want {
			t.Errorf("concreteNPMVersion(%q) = %q, want %q", spec, got, want)
		}
	}
}

// The include check must follow links: "-r link/private.txt" through a symlink
// or junction would otherwise read a file outside the scan root and send its
// pins to OSV.
func TestCollectPackagesRequirementsIncludeLinkEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	outside := filepath.Join(parent, "outside")
	writeFixture(t, root, "requirements.txt", "-r linked/private.txt\nkept==1.0.0\n")
	writeFixture(t, outside, "private.txt", "secretpkg-internal==9.9.9\n")
	linkDirForTest(t, outside, filepath.Join(root, "linked"))

	pkgs, warnings, err := collectPackages(context.Background(), root, true, DefaultMaxPackages)
	if err != nil {
		t.Fatalf("collectPackages: %v", err)
	}
	idx := indexPackages(pkgs)
	requirePackage(t, idx, "kept", "1.0.0")
	if _, ok := idx["secretpkg-internal"]; ok {
		t.Error("an include that leaves the scan root through a link must not be read")
	}
	if joined := strings.Join(warnings, "\n"); !strings.Contains(joined, "outside the scan root") {
		t.Fatalf("warnings do not mention the escaping include: %v", warnings)
	}
}

// pip reads requirements files with a UTF-8 BOM and UTF-16 files (what
// "pip freeze > requirements.txt" writes in Windows PowerShell 5.1). Dropping
// their pins silently would report a vulnerable project as clean.
func TestCollectPackagesRequirementsBOMAndUTF16(t *testing.T) {
	encodeUTF16 := func(order binary.ByteOrder, bom []byte, text string) []byte {
		out := append([]byte(nil), bom...)
		for _, unit := range utf16.Encode([]rune(text)) {
			var b [2]byte
			order.PutUint16(b[:], unit)
			out = append(out, b[:]...)
		}
		return out
	}
	tests := map[string][]byte{
		"utf-8 bom": append([]byte{0xEF, 0xBB, 0xBF}, []byte("requests==2.19.0\nflask==0.12\n")...),
		"utf-16 le": encodeUTF16(binary.LittleEndian, []byte{0xFF, 0xFE}, "requests==2.19.0\r\nflask==0.12\r\n"),
		"utf-16 be": encodeUTF16(binary.BigEndian, []byte{0xFE, 0xFF}, "requests==2.19.0\nflask==0.12\n"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), data, 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			idx := indexPackages(collectForTest(t, dir, true))
			requirePackage(t, idx, "requests", "2.19.0")
			requirePackage(t, idx, "flask", "0.12")
		})
	}
}

// An include that cannot be read must be reported without the absolute local
// path: the warning is copied into SBOM properties and scan results.
func TestCollectPackagesRequirementsIncludeErrorHasNoAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "-r missing-file.txt\nkept==1.0.0\n")

	_, warnings, err := collectPackages(context.Background(), dir, true, DefaultMaxPackages)
	if err != nil {
		t.Fatalf("collectPackages: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "missing-file.txt") {
		t.Fatalf("warnings do not mention the missing include: %v", warnings)
	}
	resolved, _ := filepath.EvalSymlinks(dir)
	for _, leak := range []string{dir, resolved, filepath.ToSlash(dir)} {
		if leak != "" && strings.Contains(joined, leak) {
			t.Fatalf("warning leaks the absolute path %q: %v", leak, warnings)
		}
	}
}

// A 307 replays the POST body. The default client must not follow a redirect
// to another origin, or the dependency inventory reaches a host the user never
// configured.
func TestAuditRefusesCrossOriginRedirect(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{}]}`))
	}))
	defer other.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer mirror.Close()

	dir := t.TempDir()
	writeFixture(t, dir, "requirements.txt", "requests==2.19.0\n")

	opts := DefaultOptions()
	opts.BaseURL = mirror.URL
	res, err := Audit(context.Background(), dir, opts)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if n := leaked.Load(); n != 0 {
		t.Fatalf("the inventory was replayed to another origin %d time(s)", n)
	}
	if joined := strings.Join(res.Errors, "\n"); !strings.Contains(joined, "redirect") {
		t.Fatalf("the refused redirect is not reported: %v", res.Errors)
	}
}
