package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Wave-1 SAST coverage: VGL-INJ-049/060/061/062, VGL-WEB-023/024/025,
// VGL-AUTH-021, plus the VGL-WEB-002/003 sink expansions.

func wave1SASTFile(p, language, content string) *File {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return &File{
		Path:     p,
		AbsPath:  p,
		Content:  []byte(content),
		Lines:    lines,
		Language: language,
		Size:     len(content),
	}
}

func wave1SASTRule(t *testing.T, rs []Rule, id string) Rule {
	t.Helper()
	for _, r := range rs {
		if r.Meta().ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not registered", id)
	return nil
}

func wave1SASTLines(findings []model.Finding) []int {
	out := make([]int, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Location.StartLine)
	}
	return out
}

func wave1SASTHasPrefix(values []string, prefix string) bool {
	for _, v := range values {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

func wave1SASTCheck(t *testing.T, rule Rule, path, language, content string) []model.Finding {
	t.Helper()
	return rule.Check(wave1SASTFile(path, language, content))
}

func TestWave1RulesMetadata(t *testing.T) {
	groups := []struct {
		id     string
		rules  []Rule
		cwe    string
		owasp  string
		refLen int
	}{
		{"VGL-INJ-049", InjectionRules(), "CWE-502", "A08:2021", 1},
		{"VGL-INJ-060", InjectionRules(), "CWE-90", "A03:2021", 1},
		{"VGL-INJ-061", InjectionRules(), "CWE-79", "A03:2021", 1},
		{"VGL-INJ-062", InjectionRules(), "CWE-643", "A03:2021", 1},
		{"VGL-WEB-023", WebRules(), "CWE-200", "A05:2021", 1},
		{"VGL-WEB-024", WebRules(), "CWE-22", "A01:2021", 1},
		{"VGL-WEB-025", WebRules(), "CWE-434", "A04:2021", 1},
		{"VGL-AUTH-021", AuthRules(), "CWE-295", "A07:2021", 1},
	}
	for _, g := range groups {
		rule := wave1SASTRule(t, g.rules, g.id)
		m := rule.Meta()
		if m.Title == "" || m.Description == "" || m.Severity == "" || m.Category == "" {
			t.Errorf("%s: incomplete metadata: %+v", g.id, m)
		}
		if len(m.Languages) == 0 {
			t.Errorf("%s: no language gate", g.id)
		}
		if !slices.Contains(m.CWE, g.cwe) {
			t.Errorf("%s: CWE = %v, want %s", g.id, m.CWE, g.cwe)
		}
		if !wave1SASTHasPrefix(m.OWASP, g.owasp) {
			t.Errorf("%s: OWASP = %v, want prefix %s", g.id, m.OWASP, g.owasp)
		}
		if len(m.References) < g.refLen {
			t.Errorf("%s: references = %v", g.id, m.References)
		}
	}
}

func TestWave1InjectionPositive(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		path    string
		lang    string
		content string
		want    []int
	}{
		{
			name:   "snakeyaml default constructor with load",
			ruleID: "VGL-INJ-049",
			path:   "src/main/java/com/acme/ConfigLoader.java",
			lang:   "java",
			content: `import org.yaml.snakeyaml.Yaml;

public class ConfigLoader {
    public Object load(InputStream in) {
        Yaml yaml = new Yaml();
        return yaml.load(in);
    }
}`,
			want: []int{5},
		},
		{
			name:   "snakeyaml explicit unsafe constructor",
			ruleID: "VGL-INJ-049",
			path:   "src/main/java/com/acme/Loader.java",
			lang:   "java",
			content: `Yaml yaml = new Yaml(new Constructor(Config.class));
Object value = yaml.load(payload);`,
			want: []int{1},
		},
		{
			name:   "ldap java dynamic filter",
			ruleID: "VGL-INJ-060",
			path:   "src/main/java/com/acme/Ldap.java",
			lang:   "java",
			content: `DirContext ctx = new InitialDirContext(env);
String filter = "(&(uid=" + user + ")(objectClass=person))";
ctx.search("ou=users", filter, new SearchControls());`,
			want: []int{3},
		},
		{
			name:   "ldap python percent format",
			ruleID: "VGL-INJ-060",
			path:   "app/directory.py",
			lang:   "python",
			content: `import ldap
base = "ou=users,dc=example,dc=com"
filter_str = "(uid=%s)" % username
ldap.search_s(base, ldap.SCOPE_SUBTREE, filter_str)`,
			want: []int{4},
		},
		{
			name:   "ldap csharp filter assignment",
			ruleID: "VGL-INJ-060",
			path:   "src/Directory/Lookup.cs",
			lang:   "csharp",
			content: `using System.DirectoryServices;
var searcher = new DirectorySearcher(entry);
searcher.Filter = "(&(uid=" + user + "))";`,
			want: []int{3},
		},
		{
			name:   "ldap php interpolation",
			ruleID: "VGL-INJ-060",
			path:   "public/directory.php",
			lang:   "php",
			content: `<?php
$conn = ldap_connect("ldap://localhost");
$result = ldap_search($conn, $base, "(&(uid=$user))");`,
			want: []int{3},
		},
		{
			name:   "ldap java direct request parameter",
			ruleID: "VGL-INJ-060",
			path:   "src/main/java/com/acme/Ldap.java",
			lang:   "java",
			content: `DirContext ctx = new InitialDirContext(env);
String base = "ou=users";
ctx.search(base, request.getParameter("uid"), new SearchControls());`,
			want: []int{3},
		},
		{
			name:   "ldap python direct request accessor",
			ruleID: "VGL-INJ-060",
			path:   "app/directory.py",
			lang:   "python",
			content: `import ldap
base = "ou=users,dc=example,dc=com"
ldap.search_s(base, ldap.SCOPE_SUBTREE, request.args.get("uid"))`,
			want: []int{3},
		},
		{
			name:   "ldap csharp unrelated escape variable does not guard",
			ruleID: "VGL-INJ-060",
			path:   "src/Directory/Search.cs",
			lang:   "csharp",
			content: `using System.DirectoryServices;
var escape = EscapeMode.Strict;
var searcher = new DirectorySearcher(entry);
searcher.Filter = "(&(uid=" + user + "))";`,
			want: []int{4},
		},
		{
			name:   "xpath python direct parameter",
			ruleID: "VGL-INJ-062",
			path:   "app/search.py",
			lang:   "python",
			content: `def find(tree, user_input):
    return tree.xpath(user_input)`,
			want: []int{2},
		},
		{
			name:   "xpath javascript document evaluate",
			ruleID: "VGL-INJ-062",
			path:   "src/search.js",
			lang:   "javascript",
			content: `function find(doc, userInput) {
  return document.evaluate(userInput, doc, null, XPathResult.ANY_TYPE, null);
}`,
			want: []int{2},
		},
		{
			name:   "jinja autoescape disabled",
			ruleID: "VGL-INJ-061",
			path:   "src/web/render.py",
			lang:   "python",
			content: `from jinja2 import Environment
env = Environment(
    loader=loader,
    autoescape=False,
)`,
			want: []int{4},
		},
		{
			name:   "xpath java evaluate",
			ruleID: "VGL-INJ-062",
			path:   "src/main/java/com/acme/UserSearch.java",
			lang:   "java",
			content: `import javax.xml.xpath.XPath;
XPath xpath = XPathFactory.newInstance().newXPath();
NodeList nodes = (NodeList) xpath.evaluate("//user[@id='" + id + "']", doc, XPathConstants.NODESET);`,
			want: []int{3},
		},
		{
			name:   "xpath python fstring",
			ruleID: "VGL-INJ-062",
			path:   "app/search.py",
			lang:   "python",
			content: `from lxml import etree
def find(tree, user_id):
    return tree.xpath(f"//user[@id='{user_id}']")`,
			want: []int{3},
		},
		{
			name:   "xpath csharp interpolation",
			ruleID: "VGL-INJ-062",
			path:   "src/Xml/Users.cs",
			lang:   "csharp",
			content: `using System.Xml.XPath;
var node = doc.XPathSelectElement($"//user[@id='{id}']");`,
			want: []int{2},
		},
		{
			name:   "xpath php concatenation",
			ruleID: "VGL-INJ-062",
			path:   "public/users.php",
			lang:   "php",
			content: `<?php
$doc->loadXML($xml);
$xpath = new DOMXPath($doc);
$nodes = $xpath->query("//user[@id='" . $_GET['id'] . "']");`,
			want: []int{4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := wave1SASTRule(t, InjectionRules(), tc.ruleID)
			got := wave1SASTLines(wave1SASTCheck(t, rule, tc.path, tc.lang, tc.content))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("lines = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWave1InjectionNegatives(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		path    string
		lang    string
		content string
	}{
		{
			name:   "snakeyaml safe constructor",
			ruleID: "VGL-INJ-049",
			path:   "src/main/java/com/acme/Safe.java",
			lang:   "java",
			content: `Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
Object value = yaml.load(payload);`,
		},
		{
			name:    "snakeyaml without load",
			ruleID:  "VGL-INJ-049",
			path:    "src/main/java/com/acme/Bean.java",
			lang:    "java",
			content: `Yaml yaml = new Yaml();`,
		},
		{
			name:   "snakeyaml literal document",
			ruleID: "VGL-INJ-049",
			path:   "src/main/java/com/acme/Literal.java",
			lang:   "java",
			content: `Yaml yaml = new Yaml();
Object value = yaml.load("a: 1");`,
		},
		{
			name:   "snakeyaml receiver mismatch properties load",
			ruleID: "VGL-INJ-049",
			path:   "src/main/java/com/acme/Props.java",
			lang:   "java",
			content: `Yaml yaml = new Yaml();
Properties props = new Properties();
props.load(in);
yaml.toString();`,
		},
		{
			name:   "ldap java constant filter",
			ruleID: "VGL-INJ-060",
			path:   "src/main/java/com/acme/Ldap.java",
			lang:   "java",
			content: `DirContext ctx = new InitialDirContext(env);
ctx.search("ou=users", "(uid=admin)", new SearchControls());`,
		},
		{
			name:   "ldap java escaped value",
			ruleID: "VGL-INJ-060",
			path:   "src/main/java/com/acme/Ldap.java",
			lang:   "java",
			content: `DirContext ctx = new InitialDirContext(env);
String filter = "(uid=" + LdapEncoder.filterEncode(user) + ")";
ctx.search("ou=users", filter, new SearchControls());`,
		},
		{
			name:   "ldap python escape_filter_chars",
			ruleID: "VGL-INJ-060",
			path:   "app/directory.py",
			lang:   "python",
			content: `import ldap
from ldap.filter import escape_filter_chars

def find(username):
    flt = "(uid=%s)" % escape_filter_chars(username)
    return ldap.search_s("ou=users", ldap.SCOPE_SUBTREE, flt)`,
		},
		{
			name:   "ldap python constant filter",
			ruleID: "VGL-INJ-060",
			path:   "app/directory.py",
			lang:   "python",
			content: `import ldap
ldap.search_s("ou=users", ldap.SCOPE_SUBTREE, "(uid=admin)")`,
		},
		{
			name:   "ldap php single quoted literal",
			ruleID: "VGL-INJ-060",
			path:   "public/directory.php",
			lang:   "php",
			content: `<?php
$conn = ldap_connect("ldap://localhost");
$base = "ou=users";
$result = ldap_search($conn, $base, '(&(uid=$user))');`,
		},
		{
			name:   "ldap php escaped dollar",
			ruleID: "VGL-INJ-060",
			path:   "public/directory.php",
			lang:   "php",
			content: `<?php
$conn = ldap_connect("ldap://localhost");
$base = "ou=users";
$result = ldap_search($conn, $base, "(&(uid=\$user))");`,
		},
		{
			name:   "python re search is not ldap",
			ruleID: "VGL-INJ-060",
			path:   "app/parse.py",
			lang:   "python",
			content: `import re
match = re.search(pattern, text)`,
		},
		{
			name:   "jinja autoescape enabled",
			ruleID: "VGL-INJ-061",
			path:   "src/web/render.py",
			lang:   "python",
			content: `from jinja2 import Environment
env = Environment(autoescape=True)`,
		},
		{
			name:    "jinja literal outside environment",
			ruleID:  "VGL-INJ-061",
			path:    "src/web/render.py",
			lang:    "python",
			content: `settings = {"autoescape": False}`,
		},
		{
			name:   "jinja test fixture skipped",
			ruleID: "VGL-INJ-061",
			path:   "tests/test_render.py",
			lang:   "python",
			content: `from jinja2 import Environment
env = Environment(autoescape=False)`,
		},
		{
			name:   "jinja autoescape in inline comment",
			ruleID: "VGL-INJ-061",
			path:   "src/web/render.py",
			lang:   "python",
			content: `from jinja2 import Environment
env = Environment(autoescape=True)  # never autoescape=False`,
		},
		{
			name:   "jinja autoescape in docstring",
			ruleID: "VGL-INJ-061",
			path:   "src/web/render.py",
			lang:   "python",
			content: `from jinja2 import Environment
"""The old code used Environment(autoescape=False)."""`,
		},
		{
			name:   "xpath literal expression",
			ruleID: "VGL-INJ-062",
			path:   "src/main/java/com/acme/Fixed.java",
			lang:   "java",
			content: `import javax.xml.xpath.XPath;
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.evaluate("//user[@id='1']", doc);`,
		},
		{
			name:   "regex compile is not xpath",
			ruleID: "VGL-INJ-062",
			path:   "src/main/java/com/acme/Regex.java",
			lang:   "java",
			content: `// xpath is not used in this file
Pattern pattern = Pattern.compile(userInput);`,
		},
		{
			name:   "xpath variable pattern compile",
			ruleID: "VGL-INJ-062",
			path:   "src/main/java/com/acme/XPathPattern.java",
			lang:   "java",
			content: `// xpath request routing
Pattern xpathPattern = Pattern.compile(userInput);`,
		},
		{
			name:   "pdo query with xpath mention",
			ruleID: "VGL-INJ-062",
			path:   "public/users.php",
			lang:   "php",
			content: `<?php
// xpath is handled by another endpoint
$sql = "SELECT * FROM users WHERE id=" . $_GET['id'];
$rows = $pdo->query($sql);`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := wave1SASTRule(t, InjectionRules(), tc.ruleID)
			if got := wave1SASTCheck(t, rule, tc.path, tc.lang, tc.content); len(got) != 0 {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

func TestWave1WebPositive(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		path    string
		lang    string
		content string
		want    []int
	}{
		{
			name:   "phpinfo",
			ruleID: "VGL-WEB-023",
			path:   "public/info.php",
			lang:   "php",
			content: `<?php
phpinfo();
?>`,
			want: []int{2},
		},
		{
			name:   "zip slip go join",
			ruleID: "VGL-WEB-024",
			path:   "internal/extract/extract.go",
			lang:   "go",
			content: `package extract

import ("archive/zip"; "os"; "path/filepath")

func extract(zr *zip.Reader, dest string) {
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		os.Create(target)
	}
}`,
			want: []int{7},
		},
		{
			name:   "zip slip python extractall",
			ruleID: "VGL-WEB-024",
			path:   "app/unpack.py",
			lang:   "python",
			content: `import tarfile

def extract(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest)`,
			want: []int{5},
		},
		{
			name:   "zip slip java new file",
			ruleID: "VGL-WEB-024",
			path:   "src/Unpack.java",
			lang:   "java",
			content: `import java.io.File;
import java.nio.file.Files;
import java.util.zip.ZipEntry;

class Unpack {
    File unpack(File destDir, ZipEntry entry, java.io.InputStream in) throws Exception {
        File out = new File(destDir, entry.getName());
        Files.copy(in, out.toPath());
        return out;
    }
}`,
			want: []int{7},
		},
		{
			name:   "upload php move uploaded file",
			ruleID: "VGL-WEB-025",
			path:   "public/upload.php",
			lang:   "php",
			content: `<?php
$upload = $_FILES['upload'];
move_uploaded_file($upload['tmp_name'], $dir . '/' . $_FILES['upload']['name']);`,
			want: []int{3},
		},
		{
			name:   "upload python one hop",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def save(file, upload_dir):
    filename = file.filename
    target = os.path.join(upload_dir, filename)
    file.save(target)`,
			want: []int{3},
		},
		{
			name:   "upload python direct write mode",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def save(file, upload_dir):
    with open(file.filename, "wb") as fh:
        fh.write(file.read())`,
			want: []int{2},
		},
		{
			name:   "upload python request files same line",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def save(request, upload_dir):
    request.files["doc"].save(os.path.join(upload_dir, request.files["doc"].filename))`,
			want: []int{2},
		},
		{
			name:   "upload python os replace",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def save(file):
    os.replace(file.filename, "/srv/uploads/fixed.bin")`,
			want: []int{2},
		},
		{
			name:   "upload python path write text",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def save(file):
    Path(file.filename).write_text("data")`,
			want: []int{2},
		},
		{
			name:   "upload go same line",
			ruleID: "VGL-WEB-025",
			path:   "internal/upload/upload.go",
			lang:   "go",
			content: `package upload

func store(header *multipart.FileHeader, dir string) error {
	dst := filepath.Join(dir, header.Filename)
	return os.WriteFile(dst, nil, 0o644)
}`,
			want: []int{4},
		},
		{
			name:   "upload java one hop",
			ruleID: "VGL-WEB-025",
			path:   "src/main/java/com/acme/Upload.java",
			lang:   "java",
			content: `File save(MultipartFile file, File uploadDir) throws IOException {
    String name = file.getOriginalFilename();
    File target = new File(uploadDir, name);
    file.transferTo(target);
    return target;
}`,
			want: []int{3},
		},
		{
			name:   "zip slip clean alone is not containment",
			ruleID: "VGL-WEB-024",
			path:   "internal/extract/extract.go",
			lang:   "go",
			content: `package extract

import ("archive/zip"; "os"; "path/filepath")

func extract(zr *zip.Reader, dest string) error {
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		cleaned := filepath.Clean(target)
		_ = cleaned
		return os.WriteFile(target, nil, 0o644)
	}
	return nil
}`,
			want: []int{7},
		},
		{
			name:   "zip slip realpath alone is not containment",
			ruleID: "VGL-WEB-024",
			path:   "app/unpack.py",
			lang:   "python",
			content: `import os
import tarfile

def extract(path, dest):
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            target = os.path.join(dest, member.name)
            real = os.path.realpath(target)
            with open(target, "wb") as out:
                out.write(tar.extractfile(member).read())`,
			want: []int{7},
		},
		{
			name:   "zip slip unrelated filter variable does not guard",
			ruleID: "VGL-WEB-024",
			path:   "app/unpack.py",
			lang:   "python",
			content: `import tarfile

def extract(path, dest):
    filter = None
    with tarfile.open(path) as tar:
        tar.extractall(dest)`,
			want: []int{6},
		},
		{
			name:   "zip slip php extractTo",
			ruleID: "VGL-WEB-024",
			path:   "public/unpack.php",
			lang:   "php",
			content: `<?php
$zip = new ZipArchive();
$zip->open($archive);
$zip->extractTo($dest);`,
			want: []int{4},
		},
		{
			name:   "zip slip ruby file join",
			ruleID: "VGL-WEB-024",
			path:   "lib/unpack.rb",
			lang:   "ruby",
			content: `require "rubygems/package"

def extract(io, dest)
  Gem::Package::TarReader.new(io) do |tar|
    tar.each do |entry|
      path = File.join(dest, entry.full_name)
      File.open(path, "wb") { |f| f.write(entry.read) }
    end
  end
end`,
			want: []int{6},
		},
		{
			name:   "zip slip java nio resolve",
			ruleID: "VGL-WEB-024",
			path:   "src/main/java/com/acme/Unpack.java",
			lang:   "java",
			content: `import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;

class Unpack {
    void unpack(Path destDir, ZipEntry entry, InputStream in) throws Exception {
        Path target = destDir.resolve(entry.getName());
        Files.copy(in, target);
    }
}`,
			want: []int{8},
		},
		{
			name:   "zip slip java nio paths get",
			ruleID: "VGL-WEB-024",
			path:   "src/main/java/com/acme/Unpack.java",
			lang:   "java",
			content: `import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;

class Unpack {
    void unpack(String destDir, ZipEntry entry, byte[] bytes) throws Exception {
        Path target = Paths.get(destDir, entry.getName());
        Files.write(target, bytes);
    }
}`,
			want: []int{8},
		},
		{
			name:   "upload esm writeFile join",
			ruleID: "VGL-WEB-025",
			path:   "src/upload.mjs",
			lang:   "javascript",
			content: `import { writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function store(uploadDir, file, data) {
  await writeFile(join(uploadDir, file.originalname), data);
}`,
			want: []int{5},
		},
		{
			name:   "upload esm writeFileSync join variable",
			ruleID: "VGL-WEB-025",
			path:   "src/upload.js",
			lang:   "javascript",
			content: `import { writeFileSync } from "node:fs";
import { join } from "node:path";

export function store(uploadDir, file, data) {
  const dest = join(uploadDir, file.originalname);
  writeFileSync(dest, data);
}`,
			want: []int{5},
		},
		{
			name:   "upload django uploaded file name",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `from django.core.files.uploadedfile import UploadedFile

def store(request, upload_dir):
    doc = request.FILES["doc"]
    target = os.path.join(upload_dir, doc.name)
    with open(target, "wb") as fh:
        fh.write(doc.read())`,
			want: []int{5},
		},
		{
			name:   "upload django request files name accessor",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def store(request, upload_dir):
    with open(os.path.join(upload_dir, request.FILES["doc"].name), "wb") as fh:
        fh.write(b"x")`,
			want: []int{2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := wave1SASTRule(t, WebRules(), tc.ruleID)
			got := wave1SASTLines(wave1SASTCheck(t, rule, tc.path, tc.lang, tc.content))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("lines = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWave1WebNegatives(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		path    string
		lang    string
		content string
	}{
		{
			name:   "phpinfo in comment",
			ruleID: "VGL-WEB-023",
			path:   "public/info.php",
			lang:   "php",
			content: `<?php
// phpinfo();
echo "ok";`,
		},
		{
			name:   "phpinfo in string",
			ruleID: "VGL-WEB-023",
			path:   "public/info.php",
			lang:   "php",
			content: `<?php
$doc = "phpinfo() is disabled";`,
		},
		{
			name:   "phpinfo in inline hash comment",
			ruleID: "VGL-WEB-023",
			path:   "public/info.php",
			lang:   "php",
			content: `<?php
echo "ok"; # phpinfo() was removed`,
		},
		{
			name:    "phpinfo language gate",
			ruleID:  "VGL-WEB-023",
			path:    "src/app.js",
			lang:    "javascript",
			content: `const doc = "phpinfo()";`,
		},
		{
			name:   "zip slip guarded by rel",
			ruleID: "VGL-WEB-024",
			path:   "internal/extract/extract.go",
			lang:   "go",
			content: `package extract

import ("archive/zip"; "path/filepath"; "strings")

func extract(zr *zip.Reader, dest string) error {
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		rel, err := filepath.Rel(dest, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return err
		}
	}
	return nil
}`,
		},
		{
			name:   "zip slip python filter",
			ruleID: "VGL-WEB-024",
			path:   "app/unpack.py",
			lang:   "python",
			content: `import tarfile
def extract(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest, filter="data")`,
		},
		{
			name:   "zip slip python multiline filter",
			ruleID: "VGL-WEB-024",
			path:   "app/unpack.py",
			lang:   "python",
			content: `import tarfile

def extract(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(
            dest,
            filter="data",
        )`,
		},
		{
			name:   "zip join constant name",
			ruleID: "VGL-WEB-024",
			path:   "internal/extract/extract.go",
			lang:   "go",
			content: `package extract

import ("archive/zip"; "path/filepath")

func extract(zr *zip.Reader, dest string) {
	for range zr.File {
		target := filepath.Join(dest, "fixed.txt")
		_ = target
	}
}`,
		},
		{
			name:   "upload sanitized",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def save(file, upload_dir):
    target = os.path.join(upload_dir, secure_filename(file.filename))
    file.save(target)`,
		},
		{
			name:    "upload multer generated name",
			ruleID:  "VGL-WEB-025",
			path:    "src/upload.js",
			lang:    "javascript",
			content: `const dest = path.join(uploadDir, file.filename);`,
		},
		{
			name:   "upload constant destination",
			ruleID: "VGL-WEB-025",
			path:   "public/upload.php",
			lang:   "php",
			content: `<?php
move_uploaded_file($_FILES['upload']['tmp_name'], "/srv/uploads/fixed.bin");`,
		},
		{
			name:   "upload python self filename read",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `class Handler:
    def load(self):
        with open(self.filename) as fh:
            return fh.read()`,
		},
		{
			name:   "upload python move without upload source",
			ruleID: "VGL-WEB-025",
			path:   "app/files.py",
			lang:   "python",
			content: `import shutil
shutil.move(src, dst)`,
		},
		{
			name:   "upload python filename log only",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def save(file):
    log(file.filename)`,
		},
		{
			name:   "upload python join without write",
			ruleID: "VGL-WEB-025",
			path:   "app/uploads.py",
			lang:   "python",
			content: `def target(file, upload_dir):
    return os.path.join(upload_dir, file.filename)`,
		},
		{
			name:   "zip slip guarded by destination prefix",
			ruleID: "VGL-WEB-024",
			path:   "internal/extract/extract.go",
			lang:   "go",
			content: `package extract

import ("archive/zip"; "os"; "path/filepath"; "strings")

func extract(zr *zip.Reader, dest string) error {
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(target, dest+string(os.PathSeparator)) {
			return nil
		}
		return os.WriteFile(target, nil, 0o644)
	}
	return nil
}`,
		},
		{
			name:   "zip slip read only archive mention",
			ruleID: "VGL-WEB-024",
			path:   "app/unpack.py",
			lang:   "python",
			content: `import os
import zipfile

def read(path, dest):
    with zipfile.ZipFile(path) as z:
        member = z.infolist()[0]
        target = os.path.join(dest, member.filename)
        return open(target).read()`,
		},
		{
			name:   "zip slip join without write",
			ruleID: "VGL-WEB-024",
			path:   "internal/extract/extract.go",
			lang:   "go",
			content: `package extract

import ("archive/zip"; "path/filepath")

func extract(zr *zip.Reader, dest string) {
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		_ = target
	}
}`,
		},
		{
			name:   "upload go stat join",
			ruleID: "VGL-WEB-025",
			path:   "internal/upload/upload.go",
			lang:   "go",
			content: `package upload

import ("os"; "path/filepath")

func probe(header *multipart.FileHeader, tmp string) error {
	_, err := os.Stat(filepath.Join(tmp, header.Filename))
	return err
}`,
		},
		{
			name:   "upload java new file read only",
			ruleID: "VGL-WEB-025",
			path:   "src/main/java/com/acme/Probe.java",
			lang:   "java",
			content: `class Probe {
    File probe(File dir, MultipartFile file) {
        return new File(dir, file.getOriginalFilename());
    }
}`,
		},
		{
			name:   "upload js path join read only",
			ruleID: "VGL-WEB-025",
			path:   "src/probe.js",
			lang:   "javascript",
			content: `export function target(uploadDir, file) {
  return path.join(uploadDir, file.originalname);
}`,
		},
		{
			name:   "upload js res download serves file",
			ruleID: "VGL-WEB-025",
			path:   "src/download.js",
			lang:   "javascript",
			content: `app.get("/files/:name", (req, res) => {
  res.download(path.join(uploadDir, file.originalname));
});`,
		},
		{
			name:   "upload python plain attribute name",
			ruleID: "VGL-WEB-025",
			path:   "app/labels.py",
			lang:   "python",
			content: `def label(user):
    return os.path.join("/tmp", user.name)`,
		},
		{
			name:   "upload python read only attribute name",
			ruleID: "VGL-WEB-025",
			path:   "app/labels.py",
			lang:   "python",
			content: `def show(user):
    with open(user.name) as fh:
        return fh.read()`,
		},
		{
			name:   "zip slip java nio containment",
			ruleID: "VGL-WEB-024",
			path:   "src/main/java/com/acme/Unpack.java",
			lang:   "java",
			content: `import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;

class Unpack {
    void unpack(Path destDir, ZipEntry entry, InputStream in) throws Exception {
        Path target = destDir.resolve(entry.getName());
        if (!target.normalize().startsWith(destDir + File.separator)) {
            throw new IllegalStateException("zip slip");
        }
        Files.copy(in, target);
    }
}`,
		},
		{
			name:   "zip slip java nio read only resolve",
			ruleID: "VGL-WEB-024",
			path:   "src/main/java/com/acme/Read.java",
			lang:   "java",
			content: `import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;

class Read {
    byte[] read(Path destDir, ZipEntry entry) throws Exception {
        Path target = destDir.resolve(entry.getName());
        try (InputStream in = Files.newInputStream(target)) {
            return in.readAllBytes();
        }
    }
}`,
		},
		{
			name:   "zip slip ruby read only join",
			ruleID: "VGL-WEB-024",
			path:   "lib/peek.rb",
			lang:   "ruby",
			content: `def peek(entry, dest)
  path = File.join(dest, entry.full_name)
  File.read(path)
end`,
		},
		{
			name:   "zip slip php listing only",
			ruleID: "VGL-WEB-024",
			path:   "public/list.php",
			lang:   "php",
			content: `<?php
$zip = new ZipArchive();
$zip->open($archive);
$names = [];
for ($i = 0; $i < $zip->numFiles; $i++) {
    $names[] = $zip->getNameIndex($i);
}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := wave1SASTRule(t, WebRules(), tc.ruleID)
			if got := wave1SASTCheck(t, rule, tc.path, tc.lang, tc.content); len(got) != 0 {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

func TestWave1UploadSameLineConfidence(t *testing.T) {
	rule := wave1SASTRule(t, WebRules(), "VGL-WEB-025")

	same := wave1SASTCheck(t, rule, "src/upload.js", "javascript",
		`fs.writeFileSync(path.join(uploadDir, file.originalname), data)`)
	if len(same) != 1 || same[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("same-expression finding = %+v, want one high-confidence finding", same)
	}

	minified := wave1SASTCheck(t, rule, "src/upload.js", "javascript",
		`const name=file.originalname;fs.writeFileSync(path.join(dir,name),data)`)
	if len(minified) != 1 || minified[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("cross-statement finding = %+v, want one medium-confidence finding", minified)
	}

	lookalike := wave1SASTCheck(t, rule, "src/upload.js", "javascript",
		`const label="file.originalname";fs.writeFileSync(dest,data)`)
	if len(lookalike) != 0 {
		t.Fatalf("minified lookalike flagged: %+v", lookalike)
	}
}

func TestWave1AutoescapeConfidence(t *testing.T) {
	rule := wave1SASTRule(t, InjectionRules(), "VGL-INJ-061")
	got := wave1SASTCheck(t, rule, "src/web/render.py", "python", `from jinja2 import Environment
env = Environment(
    loader=loader,
    autoescape=False,
)`)
	if len(got) != 1 || got[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("findings = %+v, want one medium-confidence finding", got)
	}
}

func TestWave1AuthSSHHostKey(t *testing.T) {
	rule := wave1SASTRule(t, AuthRules(), "VGL-AUTH-021")
	positives := []struct {
		name    string
		path    string
		lang    string
		content string
		want    []int
	}{
		{
			name: "paramiko autoadd",
			path: "app/ssh.py",
			lang: "python",
			content: `import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())`,
			want: []int{3},
		},
		{
			name: "go insecure ignore host key",
			path: "internal/ssh/client.go",
			lang: "go",
			content: `package ssh
var config = &ssh.ClientConfig{
	HostKeyCallback: ssh.InsecureIgnoreHostKey(),
}`,
			want: []int{3},
		},
		{
			name: "node host verifier true",
			path: "src/ssh.js",
			lang: "javascript",
			content: `const { Client } = require('ssh2');
const conn = new Client({ hostVerifier: () => true });`,
			want: []int{2},
		},
		{
			name:    "node host verifier function form",
			path:    "src/ssh.ts",
			lang:    "typescript",
			content: `const conn = new Client({ hostVerifier: function (key) { return true; } });`,
			want:    []int{1},
		},
	}
	for _, tc := range positives {
		t.Run(tc.name, func(t *testing.T) {
			got := wave1SASTLines(wave1SASTCheck(t, rule, tc.path, tc.lang, tc.content))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("lines = %v, want %v", got, tc.want)
			}
		})
	}

	negatives := []struct {
		name    string
		path    string
		lang    string
		content string
	}{
		{
			name:    "paramiko reject policy",
			path:    "app/ssh.py",
			lang:    "python",
			content: `client.set_missing_host_key_policy(paramiko.RejectPolicy())`,
		},
		{
			name:    "go fixed host key",
			path:    "internal/ssh/client.go",
			lang:    "go",
			content: `config := &ssh.ClientConfig{HostKeyCallback: ssh.FixedHostKey(key)}`,
		},
		{
			name:    "node known keys verifier",
			path:    "src/ssh.js",
			lang:    "javascript",
			content: `const conn = new Client({ hostVerifier: (key) => knownKeys.includes(key) });`,
		},
		{
			name: "ssh config file excluded",
			path: ".ssh/config",
			lang: "shell",
			content: `Host *
  StrictHostKeyChecking no
  hostVerifier: () => true`,
		},
		{
			name:    "documentation path",
			path:    "docs/ssh.md",
			lang:    "python",
			content: `client.set_missing_host_key_policy(paramiko.AutoAddPolicy())`,
		},
		{
			name: "autoadd in inline comment",
			path: "app/ssh.py",
			lang: "python",
			content: `import paramiko
client = paramiko.SSHClient()  # AutoAddPolicy() would accept any host key`,
		},
		{
			name: "autoadd in docstring",
			path: "app/ssh.py",
			lang: "python",
			content: `import paramiko
"""AutoAddPolicy() accepts every host key."""
client = paramiko.SSHClient()`,
		},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			if got := wave1SASTCheck(t, rule, tc.path, tc.lang, tc.content); len(got) != 0 {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

func TestWave1ExistingWeb003JavaSinks(t *testing.T) {
	rule := wave1SASTRule(t, WebRules(), "VGL-WEB-003")
	got := wave1SASTCheck(t, rule, "src/main/java/com/acme/Login.java", "java", `public void go(HttpServletRequest request, HttpServletResponse response) throws IOException {
    response.sendRedirect(request.getParameter("next"));
}`)
	if lines := wave1SASTLines(got); !slices.Equal(lines, []int{2}) {
		t.Fatalf("sendRedirect lines = %v, want [2]", lines)
	}

	got = wave1SASTCheck(t, rule, "src/main/java/com/acme/Login.java", "java", `public String go(HttpServletRequest request) {
    String next = request.getParameter("next");
    return "redirect:" + next;
}`)
	if lines := wave1SASTLines(got); !slices.Equal(lines, []int{3}) {
		t.Fatalf("spring redirect lines = %v, want [3]", lines)
	}

	if got := wave1SASTCheck(t, rule, "src/main/java/com/acme/Login.java", "java",
		`response.sendRedirect("/login");`); len(got) != 0 {
		t.Fatalf("constant redirect flagged: %+v", got)
	}
}

func TestWave1ExistingWeb002JavaAndPHP(t *testing.T) {
	rule := wave1SASTRule(t, WebRules(), "VGL-WEB-002")
	got := wave1SASTCheck(t, rule, "src/main/java/com/acme/Files.java", "java", `String name = request.getParameter("file");
File f = new File("/srv/files", name);`)
	if lines := wave1SASTLines(got); !slices.Equal(lines, []int{2}) {
		t.Fatalf("java traversal lines = %v, want [2]", lines)
	}

	got = wave1SASTCheck(t, rule, "public/download.php", "php", `<?php
$path = $_GET['file'];
readfile("/var/www/files/" . $path);`)
	if lines := wave1SASTLines(got); !slices.Equal(lines, []int{3}) {
		t.Fatalf("php traversal lines = %v, want [3]", lines)
	}

	if got := wave1SASTCheck(t, rule, "src/main/java/com/acme/Files.java", "java",
		`File f = new File("/srv/files", "fixed.txt");`); len(got) != 0 {
		t.Fatalf("constant java path flagged: %+v", got)
	}
}

func TestWave1SeverityCapsForFixtures(t *testing.T) {
	zipRule := wave1SASTRule(t, WebRules(), "VGL-WEB-024")
	got := wave1SASTCheck(t, zipRule, "tests/extract/extract.go", "go", `package extract

import ("archive/zip"; "path/filepath")

func extract(zr *zip.Reader, dest string) {
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		os.Create(target)
	}
}`)
	if len(got) != 1 || got[0].Severity != model.SeverityMedium {
		t.Fatalf("fixture findings = %+v, want one medium finding", got)
	}
}

func TestWave1RulesHandleNilFile(t *testing.T) {
	for _, group := range [][]Rule{InjectionRules(), WebRules(), AuthRules()} {
		for _, r := range group {
			id := r.Meta().ID
			if !slices.Contains([]string{
				"VGL-INJ-049", "VGL-INJ-060", "VGL-INJ-061", "VGL-INJ-062",
				"VGL-WEB-023", "VGL-WEB-024", "VGL-WEB-025", "VGL-AUTH-021",
			}, id) {
				continue
			}
			if got := r.Check(nil); len(got) != 0 {
				t.Errorf("%s: nil file produced %d findings", id, len(got))
			}
		}
	}
}
