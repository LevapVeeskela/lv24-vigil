package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// TestInjectionExpansionRulesRegistered locks the new IDs into the pack.
func TestInjectionExpansionRulesRegistered(t *testing.T) {
	byID := injRulesByID(t)
	for _, id := range []string{
		"VGL-INJ-038",
		"VGL-INJ-039",
		"VGL-INJ-040",
		"VGL-INJ-041",
		"VGL-INJ-042",
		"VGL-INJ-043",
		"VGL-INJ-044",
		"VGL-INJ-045",
		"VGL-INJ-046",
		"VGL-INJ-048",
	} {
		rule := byID[id]
		if rule == nil {
			t.Fatalf("rule %s not registered", id)
		}
		if got := rule.Check(nil); len(got) != 0 {
			t.Errorf("%s: nil file produced %d findings", id, len(got))
		}
	}
}

func TestInjectionExpansionPositive(t *testing.T) {
	byID := injRulesByID(t)
	cases := []struct {
		name      string
		ruleID    string
		path      string
		content   string
		wantLines []int
	}{
		{
			name:   "go sql concatenation",
			ruleID: "VGL-INJ-038",
			path:   "internal/store/users.go",
			content: `package store

import "database/sql"

func find(db *sql.DB, id string) {
	rows, err := db.Query("SELECT * FROM users WHERE id = " + id)
	_, _ = rows, err
}
`,
			wantLines: []int{6},
		},
		{
			name:   "go sql sprintf through variable",
			ruleID: "VGL-INJ-038",
			path:   "internal/store/users.go",
			content: `package store

import "database/sql"

func find(db *sql.DB, name string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	rows, err := db.Query(q)
	_, _ = rows, err
}
`,
			wantLines: []int{7},
		},
		{
			name:   "go sql querycontext second arg",
			ruleID: "VGL-INJ-038",
			path:   "internal/store/users.go",
			content: `package store

func remove(ctx context.Context, db *sql.DB, id string) {
	q := fmt.Sprintf("DELETE FROM users WHERE id = %d", id)
	_, err := db.QueryContext(ctx, q)
	_ = err
}
`,
			wantLines: []int{5},
		},
		{
			name:   "java xxe unhardened factory",
			ruleID: "VGL-INJ-039",
			path:   "src/main/java/parse/Parser.java",
			content: `package parse;

import javax.xml.parsers.DocumentBuilderFactory;

class Parser {
    Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(in);
    }
}
`,
			wantLines: []int{7},
		},
		{
			name:   "java xxe expand references is not hardening",
			ruleID: "VGL-INJ-039",
			path:   "src/main/java/parse/Parser.java",
			content: `package parse;

class Parser {
    void parse() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setExpandEntityReferences(false);
    }
}
`,
			wantLines: []int{5},
		},
		{
			name:   "java jndi request param",
			ruleID: "VGL-INJ-040",
			path:   "src/main/java/lookup/LookupController.java",
			content: `package lookup;

import javax.naming.InitialContext;

@RestController
class LookupController {
    @GetMapping("/lookup")
    public Object lookup(@RequestParam String name) throws Exception {
        return new InitialContext().lookup(name);
    }
}
`,
			wantLines: []int{9},
		},
		{
			name:   "java jndi inline request source",
			ruleID: "VGL-INJ-040",
			path:   "src/main/java/lookup/LookupController.java",
			content: `package lookup;

import javax.naming.InitialContext;

class LookupController {
    Object resolve(HttpServletRequest request) throws Exception {
        return new InitialContext().lookup(request.getParameter("name"));
    }
}
`,
			wantLines: []int{7},
		},
		{
			name:   "ruby unsafe deserialization",
			ruleID: "VGL-INJ-041",
			path:   "app/models/user.rb",
			content: `# frozen_string_literal: true

user = Marshal.load(Base64.decode64(params[:user]))
prefs = JSON.load(params[:prefs])
obj = YAML.unsafe_load(request.body.read)
oj = Oj.load(params[:oj])
`,
			wantLines: []int{3, 4, 5, 6},
		},
		{
			name:   "dotnet legacy formatters",
			ruleID: "VGL-INJ-042",
			path:   "src/State.cs",
			content: `using System.Web.UI;

class State {
    void Load(System.IO.Stream input) {
        var formatter = new LosFormatter();
        var state = formatter.Deserialize(input);
        var js = new JavaScriptSerializer(new SimpleTypeResolver());
        var obj = js.Deserialize<object>(input);
    }
}
`,
			wantLines: []int{5, 6, 7},
		},
		{
			name:   "newtonsoft type name handling",
			ruleID: "VGL-INJ-043",
			path:   "src/JsonSetup.cs",
			content: `using Newtonsoft.Json;

var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All
};
`,
			wantLines: []int{5},
		},
		{
			name:   "python popen and getoutput",
			ruleID: "VGL-INJ-044",
			path:   "tools/ping.py",
			content: `import os
import subprocess

host = request.args["host"]
out = os.popen("ping -c 1 " + host).read()
out2 = subprocess.getoutput(f"nslookup {host}")
`,
			wantLines: []int{5, 6},
		},
		{
			name:   "python pickle model loaders",
			ruleID: "VGL-INJ-045",
			path:   "ml/load.py",
			content: `import torch
import numpy
import pandas
import joblib
import dill

model = torch.load(upload_path)
arr = numpy.load(path, allow_pickle=True)
frame = pandas.read_pickle(cache_path)
loaded = joblib.load(model_path)
other = dill.load(blob)
`,
			wantLines: []int{7, 8, 9, 10, 11},
		},
		{
			name:   "python torch weights_only false",
			ruleID: "VGL-INJ-045",
			path:   "ml/load.py",
			content: `import torch

model = torch.load(path, weights_only=False)
`,
			wantLines: []int{3},
		},
		{
			name:   "php extract and parse str",
			ruleID: "VGL-INJ-046",
			path:   "public/index.php",
			content: `<?php
$action = $_GET['action'];
extract($_REQUEST);
if ($is_admin) { echo "admin"; }
parse_str($_SERVER['QUERY_STRING']);
`,
			wantLines: []int{3, 5},
		},
		{
			name:   "ef core raw sql interpolation",
			ruleID: "VGL-INJ-048",
			path:   "src/Repo.cs",
			content: `using Microsoft.EntityFrameworkCore;

class Repo {
    void Load(AppDbContext db, string email, int id) {
        var users = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'").ToList();
        db.Database.ExecuteSqlRaw("DELETE FROM Users WHERE Id = " + id);
        db.Database.ExecuteSqlRaw(string.Format("DELETE FROM Users WHERE Id = {0}", id));
    }
}
`,
			wantLines: []int{5, 6, 7},
		},
		{
			name:   "ef core raw sql multiline",
			ruleID: "VGL-INJ-048",
			path:   "src/Repo.cs",
			content: `using Microsoft.EntityFrameworkCore;

class Repo {
    void Load(AppDbContext db, string email) {
        var users = db.Users.FromSqlRaw(
            $"SELECT * FROM Users WHERE Email = '{email}'").ToList();
    }
}
`,
			wantLines: []int{5},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := byID[tc.ruleID]
			if rule == nil {
				t.Fatalf("rule %s not registered", tc.ruleID)
			}
			got := rule.Check(injTestFile(tc.path, tc.content))
			lines := make([]int, 0, len(got))
			for _, f := range got {
				lines = append(lines, f.Location.StartLine)
			}
			if !slices.Equal(lines, tc.wantLines) {
				t.Fatalf("lines = %v, want %v (findings: %+v)", lines, tc.wantLines, got)
			}
		})
	}
}

func TestInjectionExpansionSafe(t *testing.T) {
	byID := injRulesByID(t)
	cases := []struct {
		name    string
		ruleID  string
		path    string
		content string
	}{
		{
			name:   "go parameterized queries",
			ruleID: "VGL-INJ-038",
			path:   "internal/store/users.go",
			content: `package store

import "database/sql"

func find(db *sql.DB, name string) {
	rows, err := db.Query("SELECT * FROM users WHERE name = $1", name)
	q := "SELECT * FROM users WHERE name = $1"
	rows2, err2 := db.Query(q)
	_, err3 := db.Exec("UPDATE users SET name = $1 WHERE id = $2", name, 1)
	_, _, _, _ = rows, rows2, err, err2
	_ = err3
}
`,
		},
		{
			name:   "java xxe hardened factory",
			ruleID: "VGL-INJ-039",
			path:   "src/main/java/parse/Parser.java",
			content: `package parse;

import javax.xml.parsers.DocumentBuilderFactory;

class Parser {
    Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(in);
    }
}
`,
		},
		{
			name:   "java jndi allowlisted literal",
			ruleID: "VGL-INJ-040",
			path:   "src/main/java/lookup/LookupController.java",
			content: `package lookup;

import javax.naming.InitialContext;
import java.util.Set;

class LookupController {
    private static final Set<String> ALLOWED = Set.of("java:comp/env/jdbc/app");

    public Object lookup(String name) throws Exception {
        if (!ALLOWED.contains(name)) throw new IllegalArgumentException();
        return new InitialContext().lookup(name);
    }

    Object fixed() throws Exception {
        return new InitialContext().lookup("java:comp/env/jdbc/app");
    }
}
`,
		},
		{
			name:   "ruby safe deserialization",
			ruleID: "VGL-INJ-041",
			path:   "app/models/user.rb",
			content: `# frozen_string_literal: true

user = JSON.parse(Base64.decode64(params[:user]))
prefs = JSON.parse(params[:prefs])
obj = YAML.safe_load(request.body.read, permitted_classes: [Date])
dump = Marshal.dump(user)
adds = JSON.load(payload, create_additions: false)
compat = Oj.load(payload, mode: :compat)
literal = Marshal.load("\x04\b[\"safe\"]")
`,
		},
		{
			name:   "dotnet modern serializers",
			ruleID: "VGL-INJ-042",
			path:   "src/State.cs",
			content: `using System.Text.Json;

class State {
    void Load(string json) {
        var order = JsonSerializer.Deserialize<Order>(json);
        var t = typeof(LosFormatter);
        var f = new DataContractSerializer(typeof(Order));
    }
}
`,
		},
		{
			name:   "newtonsoft type name handling none",
			ruleID: "VGL-INJ-043",
			path:   "src/JsonSetup.cs",
			content: `using Newtonsoft.Json;

var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
var obj = JsonConvert.DeserializeObject<Order>(json, settings);
`,
		},
		{
			name:   "python argv subprocess",
			ruleID: "VGL-INJ-044",
			path:   "tools/ping.py",
			content: `import os
import subprocess

out = os.popen("ls -l")
cmd = "uptime"
out2 = os.popen(cmd)
out3 = subprocess.run(["ping", host], capture_output=True)
out4 = subprocess.getoutput("date")
`,
		},
		{
			name:   "python safe model loaders",
			ruleID: "VGL-INJ-045",
			path:   "ml/load.py",
			content: `import torch
import numpy

model = torch.load(path, weights_only=True)
arr = numpy.load(path)
frame = pandas.read_csv(path)
model2 = torch.jit.load(path)
`,
		},
		{
			name:   "php explicit request keys",
			ruleID: "VGL-INJ-046",
			path:   "public/index.php",
			content: `<?php
$input = $_REQUEST;
$name = $input['name'] ?? '';
parse_str($_SERVER['QUERY_STRING'], $query);
extract($row, EXTR_SKIP);
extract($data);
$req = $request->all();
`,
		},
		{
			name:   "ef core parameterized raw sql",
			ruleID: "VGL-INJ-048",
			path:   "src/Repo.cs",
			content: `using Microsoft.EntityFrameworkCore;

class Repo {
    void Load(AppDbContext db, string email, int id) {
        var users = db.Users.FromSql($"SELECT * FROM Users WHERE Email = {email}").ToList();
        var users2 = db.Users.FromSqlRaw("SELECT * FROM Users WHERE Email = {0}", email).ToList();
        db.Database.ExecuteSqlInterpolated($"DELETE FROM Users WHERE Id = {id}");
        db.Database.ExecuteSqlRaw("DELETE FROM Audit");
    }
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := byID[tc.ruleID]
			if rule == nil {
				t.Fatalf("rule %s not registered", tc.ruleID)
			}
			if got := rule.Check(injTestFile(tc.path, tc.content)); len(got) != 0 {
				t.Fatalf("expected no findings, got %+v", got)
			}
		})
	}
}

func TestInjectionExpansionConfidence(t *testing.T) {
	byID := injRulesByID(t)

	// Go SQL through a variable is one hop away from the sink: medium.
	goFindings := byID["VGL-INJ-038"].Check(injTestFile("internal/store/users.go", `package store

func find(db *sql.DB, name string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	rows, err := db.Query(q)
	_, _ = rows, err
}
`))
	if len(goFindings) != 1 || goFindings[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("go one-hop findings = %+v, want one medium finding", goFindings)
	}

	// A file that hardens one parser but not this instance: medium.
	var b strings.Builder
	b.WriteString("class Parser {\n")
	b.WriteString("    void parse() throws Exception {\n")
	b.WriteString("        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n")
	for i := 0; i < 30; i++ {
		b.WriteString("        // padding\n")
	}
	b.WriteString("        dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n")
	b.WriteString("    }\n}\n")
	xxe := byID["VGL-INJ-039"].Check(injTestFile("src/main/java/Parser.java", b.String()))
	if len(xxe) != 1 || xxe[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("far-hardening findings = %+v, want one medium finding", xxe)
	}

	// A SerializationBinder nearby lowers confidence to medium.
	tnh := byID["VGL-INJ-043"].Check(injTestFile("src/JsonSetup.cs", `using Newtonsoft.Json;

var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.Auto,
    SerializationBinder = new SafeBinder()
};
`))
	if len(tnh) != 1 || tnh[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("binder findings = %+v, want one medium finding", tnh)
	}
}
