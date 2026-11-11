package rules

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func injTestFile(p, content string) *File {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return &File{
		Path:     p,
		Content:  []byte(content),
		Lines:    lines,
		Language: secTestLanguage(p),
		Size:     len(content),
	}
}

func injRulesByID(t *testing.T) map[string]Rule {
	t.Helper()
	out := make(map[string]Rule, len(InjectionRules()))
	for _, r := range InjectionRules() {
		id := r.Meta().ID
		if _, exists := out[id]; exists {
			t.Fatalf("duplicate injection rule id %q", id)
		}
		out[id] = r
	}
	return out
}

func TestInjectionRuleMetadata(t *testing.T) {
	rules := InjectionRules()
	if len(rules) != 47 {
		t.Fatalf("InjectionRules() = %d rules, want 47", len(rules))
	}
	idRe := regexp.MustCompile(`^VGL-INJ-\d{3}$`)
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		m := r.Meta()
		if !idRe.MatchString(m.ID) {
			t.Errorf("rule id %q does not match VGL-INJ-NNN", m.ID)
		}
		if seen[m.ID] {
			t.Errorf("duplicate rule id %q", m.ID)
		}
		seen[m.ID] = true
		if m.Title == "" {
			t.Errorf("%s: empty title", m.ID)
		}
		if m.Description == "" {
			t.Errorf("%s: empty description", m.ID)
		}
		if m.Severity == "" {
			t.Errorf("%s: empty severity", m.ID)
		}
		if m.Category != model.CategoryInjection {
			t.Errorf("%s: category = %q, want %q", m.ID, m.Category, model.CategoryInjection)
		}
		if len(m.Languages) == 0 {
			t.Errorf("%s: no language gate", m.ID)
		}
		if len(m.CWE) == 0 {
			t.Errorf("%s: no CWE", m.ID)
		}
		if len(m.OWASP) == 0 {
			t.Errorf("%s: no OWASP mapping", m.ID)
		}
		if len(m.References) == 0 {
			t.Errorf("%s: no references", m.ID)
		}
	}
	for i := 1; i <= 36; i++ {
		id := fmt.Sprintf("VGL-INJ-%03d", i)
		if !seen[id] {
			t.Errorf("missing rule id %q", id)
		}
	}
}

func TestInjectionRulesPositive(t *testing.T) {
	byID := injRulesByID(t)
	cases := []struct {
		name      string
		ruleID    string
		path      string
		content   string
		wantLines []int
	}{
		{
			name:      "js eval",
			ruleID:    "VGL-INJ-001",
			path:      "src/app.js",
			content:   `const result = eval(req.query.expr);`,
			wantLines: []int{1},
		},
		{
			name:      "js new function",
			ruleID:    "VGL-INJ-001",
			path:      "src/app.js",
			content:   `new Function("return " + code)();`,
			wantLines: []int{1},
		},
		{
			name:      "js vm",
			ruleID:    "VGL-INJ-001",
			path:      "src/app.ts",
			content:   `vm.runInNewContext(userCode, {});`,
			wantLines: []int{1},
		},
		{
			name:   "js exec concat",
			ruleID: "VGL-INJ-002",
			path:   "src/deploy.js",
			content: `const { exec } = require("child_process");
exec("ls " + req.query.dir);`,
			wantLines: []int{2},
		},
		{
			name:      "js execsync template",
			ruleID:    "VGL-INJ-002",
			path:      "src/deploy.js",
			content:   "child_process.execSync(`git checkout ${branch}`);",
			wantLines: []int{1},
		},
		{
			name:      "js innerhtml",
			ruleID:    "VGL-INJ-003",
			path:      "src/view.js",
			content:   `el.innerHTML = req.query.html;`,
			wantLines: []int{1},
		},
		{
			name:      "js dangerouslysetinnerhtml",
			ruleID:    "VGL-INJ-003",
			path:      "src/View.tsx",
			content:   `return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;`,
			wantLines: []int{1},
		},
		{
			name:      "js sql template",
			ruleID:    "VGL-INJ-004",
			path:      "src/db.js",
			content:   "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);",
			wantLines: []int{1},
		},
		{
			name:      "js sql concat",
			ruleID:    "VGL-INJ-004",
			path:      "src/db.js",
			content:   `db.execute("DELETE FROM users WHERE id = " + id);`,
			wantLines: []int{1},
		},
		{
			name:      "js dynamic require",
			ruleID:    "VGL-INJ-005",
			path:      "src/loader.js",
			content:   `const plugin = require(req.query.plugin);`,
			wantLines: []int{1},
		},
		{
			name:      "js dynamic import",
			ruleID:    "VGL-INJ-005",
			path:      "src/loader.ts",
			content:   `await import(userModule);`,
			wantLines: []int{1},
		},
		{
			name:      "js proto assignment",
			ruleID:    "VGL-INJ-006",
			path:      "src/merge.js",
			content:   `target.__proto__ = req.body;`,
			wantLines: []int{1},
		},
		{
			name:      "js merge request body",
			ruleID:    "VGL-INJ-006",
			path:      "src/merge.js",
			content:   `Object.assign(config, req.body);`,
			wantLines: []int{1},
		},
		{
			name:      "js href request value",
			ruleID:    "VGL-INJ-007",
			path:      "src/Redirect.tsx",
			content:   `return <a href={req.query.next}>Continue</a>;`,
			wantLines: []int{1},
		},
		{
			name:      "js javascript url",
			ruleID:    "VGL-INJ-007",
			path:      "src/Link.tsx",
			content:   `return <a href={"javascript:" + code}>x</a>;`,
			wantLines: []int{1},
		},
		{
			name:      "python eval",
			ruleID:    "VGL-INJ-008",
			path:      "src/app.py",
			content:   `result = eval(request.args["expr"])`,
			wantLines: []int{1},
		},
		{
			name:      "python exec",
			ruleID:    "VGL-INJ-008",
			path:      "src/app.py",
			content:   `exec(user_code)`,
			wantLines: []int{1},
		},
		{
			name:      "python os system",
			ruleID:    "VGL-INJ-009",
			path:      "src/app.py",
			content:   `os.system("rm -rf " + path)`,
			wantLines: []int{1},
		},
		{
			name:   "python subprocess shell true",
			ruleID: "VGL-INJ-009",
			path:   "src/app.py",
			content: `subprocess.run(cmd,
    shell=True)`,
			wantLines: []int{1},
		},
		{
			name:      "python pickle",
			ruleID:    "VGL-INJ-010",
			path:      "src/cache.py",
			content:   `data = pickle.loads(payload)`,
			wantLines: []int{1},
		},
		{
			name:      "python yaml load",
			ruleID:    "VGL-INJ-010",
			path:      "src/config.py",
			content:   `obj = yaml.load(stream)`,
			wantLines: []int{1},
		},
		{
			name:      "python marshal",
			ruleID:    "VGL-INJ-010",
			path:      "src/cache.py",
			content:   `blob = marshal.loads(raw)`,
			wantLines: []int{1},
		},
		{
			name:      "python template",
			ruleID:    "VGL-INJ-011",
			path:      "src/render.py",
			content:   `t = Template(request.args["t"])`,
			wantLines: []int{1},
		},
		{
			name:      "python render template string",
			ruleID:    "VGL-INJ-011",
			path:      "src/views.py",
			content:   `return render_template_string(user_input)`,
			wantLines: []int{1},
		},
		{
			name:      "python mark safe",
			ruleID:    "VGL-INJ-012",
			path:      "src/views.py",
			content:   `return mark_safe(user_html)`,
			wantLines: []int{1},
		},
		{
			name:      "django template safe filter",
			ruleID:    "VGL-INJ-012",
			path:      "templates/profile.html",
			content:   `{{ user.bio|safe }}`,
			wantLines: []int{1},
		},
		{
			name:   "flask multiline debug",
			ruleID: "VGL-INJ-013",
			path:   "src/app.py",
			content: `app.run(
    host="0.0.0.0",
    debug=True,
)`,
			wantLines: []int{3},
		},
		{
			name:      "flask app debug attribute",
			ruleID:    "VGL-INJ-013",
			path:      "src/app.py",
			content:   `app.debug = True`,
			wantLines: []int{1},
		},
		{
			name:      "python sql fstring",
			ruleID:    "VGL-INJ-014",
			path:      "src/db.py",
			content:   `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
			wantLines: []int{1},
		},
		{
			name:      "python sql percent",
			ruleID:    "VGL-INJ-014",
			path:      "src/db.py",
			content:   `cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)`,
			wantLines: []int{1},
		},
		{
			name:      "go exec concat",
			ruleID:    "VGL-INJ-015",
			path:      "cmd/run.go",
			content:   `cmd := exec.Command("sh", "-c", "ls " + dir)`,
			wantLines: []int{1},
		},
		{
			name:      "go exec variable",
			ruleID:    "VGL-INJ-015",
			path:      "cmd/run.go",
			content:   `cmd := exec.Command(name, args...)`,
			wantLines: []int{1},
		},
		{
			name:   "go text template for html",
			ruleID: "VGL-INJ-016",
			path:   "cmd/web.go",
			content: `package main

import "text/template"
import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("page").Parse(page))
	t.Execute(w, data)
}`,
			wantLines: []int{7, 8},
		},
		{
			name:      "go template html",
			ruleID:    "VGL-INJ-016",
			path:      "cmd/render.go",
			content:   `var safe = template.HTML(userInput)`,
			wantLines: []int{1},
		},
		{
			name:      "go unsafe pointer",
			ruleID:    "VGL-INJ-017",
			path:      "cmd/parse.go",
			content:   `p := unsafe.Pointer(uintptr(0x1234))`,
			wantLines: []int{1},
		},
		{
			name:      "java runtime exec",
			ruleID:    "VGL-INJ-018",
			path:      "src/main/java/Run.java",
			content:   `Runtime.getRuntime().exec("sh -c " + userInput);`,
			wantLines: []int{1},
		},
		{
			name:      "java processbuilder request",
			ruleID:    "VGL-INJ-018",
			path:      "src/main/java/Run.java",
			content:   `new ProcessBuilder(request.getParameter("cmd")).start();`,
			wantLines: []int{1},
		},
		{
			name:      "java processbuilder camelcase input",
			ruleID:    "VGL-INJ-018",
			path:      "src/main/java/Run.java",
			content:   `new ProcessBuilder(userInput).start();`,
			wantLines: []int{1},
		},
		{
			name:      "java objectinputstream",
			ruleID:    "VGL-INJ-019",
			path:      "src/main/java/Load.java",
			content:   `Object obj = new ObjectInputStream(input).readObject();`,
			wantLines: []int{1},
		},
		{
			name:      "java xmldecoder",
			ruleID:    "VGL-INJ-019",
			path:      "src/main/java/Load.java",
			content:   `XMLDecoder d = new XMLDecoder(input);`,
			wantLines: []int{1},
		},
		{
			name:      "java sql concat",
			ruleID:    "VGL-INJ-020",
			path:      "src/main/java/Dao.java",
			content:   `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);`,
			wantLines: []int{1},
		},
		{
			name:      "php eval",
			ruleID:    "VGL-INJ-021",
			path:      "public/index.php",
			content:   `eval($_GET['code']);`,
			wantLines: []int{1},
		},
		{
			name:      "php system get",
			ruleID:    "VGL-INJ-022",
			path:      "public/index.php",
			content:   `system($_GET['cmd']);`,
			wantLines: []int{1},
		},
		{
			name:      "php shell exec post",
			ruleID:    "VGL-INJ-022",
			path:      "public/index.php",
			content:   `shell_exec($_POST['cmd']);`,
			wantLines: []int{1},
		},
		{
			name:      "php include variable",
			ruleID:    "VGL-INJ-023",
			path:      "public/index.php",
			content:   `include $_GET['page'];`,
			wantLines: []int{1},
		},
		{
			name:      "php unserialize",
			ruleID:    "VGL-INJ-024",
			path:      "public/session.php",
			content:   `$obj = unserialize($_COOKIE['data']);`,
			wantLines: []int{1},
		},
		{
			name:      "php sql concat",
			ruleID:    "VGL-INJ-025",
			path:      "public/db.php",
			content:   `$res = $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);`,
			wantLines: []int{1},
		},
		{
			name:      "ruby eval",
			ruleID:    "VGL-INJ-026",
			path:      "app/controllers/run.rb",
			content:   `eval(params[:code])`,
			wantLines: []int{1},
		},
		{
			name:      "ruby backticks",
			ruleID:    "VGL-INJ-026",
			path:      "app/controllers/run.rb",
			content:   "output = `ls #{params[:dir]}`",
			wantLines: []int{1},
		},
		{
			name:      "ruby send params",
			ruleID:    "VGL-INJ-027",
			path:      "app/controllers/users.rb",
			content:   `User.send(params[:method])`,
			wantLines: []int{1},
		},
		{
			name:      "ruby constantize",
			ruleID:    "VGL-INJ-027",
			path:      "app/controllers/users.rb",
			content:   `klass = params[:type].constantize`,
			wantLines: []int{1},
		},
		{
			name:      "ruby yaml load",
			ruleID:    "VGL-INJ-028",
			path:      "app/models/config.rb",
			content:   `data = YAML.load(payload)`,
			wantLines: []int{1},
		},
		{
			name:   "csharp binaryformatter",
			ruleID: "VGL-INJ-029",
			path:   "src/Loader.cs",
			content: `var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);`,
			wantLines: []int{2},
		},
		{
			name:      "csharp process start",
			ruleID:    "VGL-INJ-030",
			path:      "src/Controller.cs",
			content:   `Process.Start(Request.Query["cmd"]);`,
			wantLines: []int{1},
		},
		{
			name:      "csharp process start camelcase input",
			ruleID:    "VGL-INJ-030",
			path:      "src/Controller.cs",
			content:   `Process.Start(userInput);`,
			wantLines: []int{1},
		},
		{
			name:      "csharp sql concat",
			ruleID:    "VGL-INJ-031",
			path:      "src/Dao.cs",
			content:   `var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + Request.Query["id"]);`,
			wantLines: []int{1},
		},
		{
			name:      "rust command variable",
			ruleID:    "VGL-INJ-032",
			path:      "src/main.rs",
			content:   `let mut c = Command::new(user_cmd);`,
			wantLines: []int{1},
		},
		{
			name:      "rust shell command",
			ruleID:    "VGL-INJ-032",
			path:      "src/main.rs",
			content:   `Command::new("sh").arg("-c").arg(user_input);`,
			wantLines: []int{1},
		},
		{
			name:   "rust arg from user input",
			ruleID: "VGL-INJ-032",
			path:   "src/main.rs",
			content: `let mut c = Command::new("ls");
c.arg(user_input);`,
			wantLines: []int{2},
		},
		{
			name:      "rust transmute",
			ruleID:    "VGL-INJ-033",
			path:      "src/main.rs",
			content:   `let x: u64 = unsafe { std::mem::transmute(ptr) };`,
			wantLines: []int{1},
		},
		{
			name:      "rust transmute turbofish",
			ruleID:    "VGL-INJ-033",
			path:      "src/main.rs",
			content:   `let x: u64 = unsafe { std::mem::transmute::<Vec<u8>, u64>(buf) };`,
			wantLines: []int{1},
		},
		{
			name:      "sql exec concat",
			ruleID:    "VGL-INJ-034",
			path:      "db/proc.sql",
			content:   `EXEC('SELECT * FROM users WHERE id = ' + @id);`,
			wantLines: []int{1},
		},
		{
			name:      "shell curl pipe bash",
			ruleID:    "VGL-INJ-035",
			path:      "scripts/install.sh",
			content:   `curl -fsSL https://get.example.com/install.sh | bash`,
			wantLines: []int{1},
		},
		{
			name:      "shell eval variable",
			ruleID:    "VGL-INJ-036",
			path:      "scripts/run.sh",
			content:   `eval "$COMMAND"`,
			wantLines: []int{1},
		},
		{
			name:      "shell eval substitution",
			ruleID:    "VGL-INJ-036",
			path:      "scripts/run.sh",
			content:   `eval $(curl -s https://example.com/x)`,
			wantLines: []int{1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := byID[tc.ruleID]
			if rule == nil {
				t.Fatalf("rule %s not registered", tc.ruleID)
			}
			f := injTestFile(tc.path, tc.content)
			got := rule.Check(f)
			lines := make([]int, 0, len(got))
			for _, fd := range got {
				lines = append(lines, fd.Location.StartLine)
			}
			if !slices.Equal(lines, tc.wantLines) {
				t.Fatalf("lines = %v, want %v (findings: %+v)", lines, tc.wantLines, got)
			}
			for _, fd := range got {
				if fd.RuleID != tc.ruleID {
					t.Errorf("RuleID = %q, want %q", fd.RuleID, tc.ruleID)
				}
				if fd.Severity != rule.Meta().Severity {
					t.Errorf("Severity = %q, want meta severity %q", fd.Severity, rule.Meta().Severity)
				}
				if len(fd.References) == 0 {
					t.Error("empty references")
				}
				if fd.Category != model.CategoryInjection {
					t.Errorf("Category = %q, want %q", fd.Category, model.CategoryInjection)
				}
				if fd.Source != model.SourceRule {
					t.Errorf("Source = %q, want %q", fd.Source, model.SourceRule)
				}
				if fd.Confidence == "" {
					t.Error("empty confidence")
				}
				if fd.Remediation == "" {
					t.Error("empty remediation")
				}
				if fd.Evidence == "" {
					t.Error("empty evidence")
				}
				if fd.Location.Snippet == "" {
					t.Error("empty snippet")
				}
				if fd.ID == "" {
					t.Error("empty finding id")
				}
				if fd.Location.EndLine != fd.Location.StartLine {
					t.Errorf("EndLine = %d, want %d", fd.Location.EndLine, fd.Location.StartLine)
				}
			}
		})
	}
}

func TestInjectionNegatives(t *testing.T) {
	byID := injRulesByID(t)
	cases := []struct {
		name    string
		ruleID  string
		path    string
		content string
	}{
		{
			name:    "js evaluate function",
			ruleID:  "VGL-INJ-001",
			path:    "src/app.js",
			content: `const result = evaluateExpression(ast);`,
		},
		{
			name:   "js exec literal",
			ruleID: "VGL-INJ-002",
			path:   "src/deploy.js",
			content: `const { exec } = require("child_process");
exec("ls -la");`,
		},
		{
			name:    "js innerhtml literal",
			ruleID:  "VGL-INJ-003",
			path:    "src/view.js",
			content: `el.innerHTML = "<b>static</b>";`,
		},
		{
			name:    "js document write literal",
			ruleID:  "VGL-INJ-003",
			path:    "src/view.js",
			content: `document.write("<p>hello</p>");`,
		},
		{
			name:    "js parameterized query",
			ruleID:  "VGL-INJ-004",
			path:    "src/db.js",
			content: `db.query("SELECT * FROM users WHERE id = ?", [id]);`,
		},
		{
			name:    "js require literal",
			ruleID:  "VGL-INJ-005",
			path:    "src/loader.js",
			content: `const cfg = require("./config");`,
		},
		{
			name:    "js object assign defaults",
			ruleID:  "VGL-INJ-006",
			path:    "src/merge.js",
			content: `Object.assign({}, defaults);`,
		},
		{
			name:    "js static href",
			ruleID:  "VGL-INJ-007",
			path:    "src/Link.tsx",
			content: `return <a href="/profile">Profile</a>;`,
		},
		{
			name:    "python model eval",
			ruleID:  "VGL-INJ-008",
			path:    "src/model.py",
			content: `model.eval()`,
		},
		{
			name:    "python literal eval",
			ruleID:  "VGL-INJ-008",
			path:    "src/model.py",
			content: `value = ast.literal_eval(raw)`,
		},
		{
			name:    "python subprocess argv",
			ruleID:  "VGL-INJ-009",
			path:    "src/app.py",
			content: `subprocess.run(["ls", "-l"])`,
		},
		{
			name:    "python yaml safe load",
			ruleID:  "VGL-INJ-010",
			path:    "src/config.py",
			content: `obj = yaml.safe_load(stream)`,
		},
		{
			name:    "python pickle dumps",
			ruleID:  "VGL-INJ-010",
			path:    "src/cache.py",
			content: `pickle.dumps(obj)`,
		},
		{
			name:    "python yaml safe loader",
			ruleID:  "VGL-INJ-010",
			path:    "src/config.py",
			content: `obj = yaml.load(stream, Loader=yaml.SafeLoader)`,
		},
		{
			name:    "python static template",
			ruleID:  "VGL-INJ-011",
			path:    "src/render.py",
			content: `t = Template("index.html")`,
		},
		{
			name:    "python mark safe literal",
			ruleID:  "VGL-INJ-012",
			path:    "src/views.py",
			content: `return mark_safe("<b>static</b>")`,
		},
		{
			name:    "python debug disabled",
			ruleID:  "VGL-INJ-013",
			path:    "src/app.py",
			content: `app.run(debug=False)`,
		},
		{
			name:    "python parameterized execute",
			ruleID:  "VGL-INJ-014",
			path:    "src/db.py",
			content: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
		},
		{
			name:    "go literal command",
			ruleID:  "VGL-INJ-015",
			path:    "cmd/run.go",
			content: `cmd := exec.Command("git", "status")`,
		},
		{
			name:    "go template html literal",
			ruleID:  "VGL-INJ-016",
			path:    "cmd/render.go",
			content: `var safe = template.HTML("<b>static</b>")`,
		},
		{
			name:   "go html template escaping",
			ruleID: "VGL-INJ-016",
			path:   "cmd/web.go",
			content: `package main

import "html/template"
import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("page").Parse(page))
	t.Execute(w, data)
}`,
		},
		{
			name:    "go plain uintptr",
			ruleID:  "VGL-INJ-017",
			path:    "cmd/parse.go",
			content: `p := uintptr(0x1234)`,
		},
		{
			name:    "java literal processbuilder",
			ruleID:  "VGL-INJ-018",
			path:    "src/main/java/Run.java",
			content: `new ProcessBuilder("ls", "-l").start();`,
		},
		{
			name:    "java jackson deserialize",
			ruleID:  "VGL-INJ-019",
			path:    "src/main/java/Load.java",
			content: `Object obj = mapper.readValue(json, User.class);`,
		},
		{
			name:    "java parameterized query",
			ruleID:  "VGL-INJ-020",
			path:    "src/main/java/Dao.java",
			content: `stmt.executeQuery("SELECT * FROM users WHERE id = ?");`,
		},
		{
			name:    "php eval string",
			ruleID:  "VGL-INJ-021",
			path:    "public/index.php",
			content: `$x = "eval";`,
		},
		{
			name:    "php system literal",
			ruleID:  "VGL-INJ-022",
			path:    "public/index.php",
			content: `system("ls -l");`,
		},
		{
			name:    "php pdo exec is not a shell command",
			ruleID:  "VGL-INJ-022",
			path:    "public/db.php",
			content: `$pdo->exec("DELETE FROM t WHERE id = " . $_GET['id']);`,
		},
		{
			name:    "php include literal",
			ruleID:  "VGL-INJ-023",
			path:    "public/index.php",
			content: `include "config.php";`,
		},
		{
			name:    "php json decode",
			ruleID:  "VGL-INJ-024",
			path:    "public/session.php",
			content: `$obj = json_decode($data, true);`,
		},
		{
			name:    "php prepared statement",
			ruleID:  "VGL-INJ-025",
			path:    "public/db.php",
			content: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");`,
		},
		{
			name:    "ruby safe output",
			ruleID:  "VGL-INJ-026",
			path:    "app/controllers/run.rb",
			content: `puts "hello"`,
		},
		{
			name:    "ruby symbol send",
			ruleID:  "VGL-INJ-027",
			path:    "app/controllers/users.rb",
			content: `user.send(:name)`,
		},
		{
			name:    "ruby yaml safe load",
			ruleID:  "VGL-INJ-028",
			path:    "app/models/config.rb",
			content: `data = YAML.safe_load(payload)`,
		},
		{
			name:    "csharp json deserialize",
			ruleID:  "VGL-INJ-029",
			path:    "src/Loader.cs",
			content: `var obj = JsonSerializer.Deserialize<User>(json);`,
		},
		{
			name:    "csharp literal process",
			ruleID:  "VGL-INJ-030",
			path:    "src/Controller.cs",
			content: `Process.Start("notepad.exe");`,
		},
		{
			name:    "csharp parameterized command",
			ruleID:  "VGL-INJ-031",
			path:    "src/Dao.cs",
			content: `var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);`,
		},
		{
			name:    "rust literal command",
			ruleID:  "VGL-INJ-032",
			path:    "src/main.rs",
			content: `Command::new("ls").arg("-la").status();`,
		},
		{
			name:    "rust cast",
			ruleID:  "VGL-INJ-033",
			path:    "src/main.rs",
			content: `let x = ptr as u64;`,
		},
		{
			name:    "sql static exec",
			ruleID:  "VGL-INJ-034",
			path:    "db/proc.sql",
			content: `EXEC dbo.usp_GetUser @id = 1;`,
		},
		{
			name:    "shell curl download",
			ruleID:  "VGL-INJ-035",
			path:    "scripts/install.sh",
			content: `curl -fsSL https://example.com/file.tar.gz -o file.tar.gz`,
		},
		{
			name:    "shell eval literal",
			ruleID:  "VGL-INJ-036",
			path:    "scripts/run.sh",
			content: `eval "echo static"`,
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

func TestInjectionLanguageGating(t *testing.T) {
	byID := injRulesByID(t)
	rule := byID["VGL-INJ-008"]
	if rule == nil {
		t.Fatal("VGL-INJ-008 not registered")
	}
	snippet := `result = eval(request.args["expr"])`
	if got := rule.Check(injTestFile("src/main.go", snippet)); len(got) != 0 {
		t.Fatalf("python rule fired on Go file: %+v", got)
	}
	if got := rule.Check(injTestFile("src/main.py", snippet)); len(got) != 1 {
		t.Fatalf("python rule missed Python file: %+v", got)
	}
}

func TestInjectionCommentLinesIgnored(t *testing.T) {
	byID := injRulesByID(t)
	if got := byID["VGL-INJ-001"].Check(injTestFile("src/app.js", `// eval(userInput)`)); len(got) != 0 {
		t.Fatalf("js comment fired: %+v", got)
	}
	if got := byID["VGL-INJ-035"].Check(injTestFile("scripts/install.sh", `# curl https://x | bash`)); len(got) != 0 {
		t.Fatalf("shell comment fired: %+v", got)
	}
}

func TestInjectionSeverityDowngrade(t *testing.T) {
	byID := injRulesByID(t)
	rule := byID["VGL-INJ-008"]
	if rule == nil {
		t.Fatal("VGL-INJ-008 not registered")
	}
	src := rule.Check(injTestFile("src/app.py", `eval(user_code)`))
	if len(src) != 1 || src[0].Severity != model.SeverityHigh {
		t.Fatalf("source findings = %+v, want one high finding", src)
	}
	fixture := rule.Check(injTestFile("pkg/tests/test_app.py", `eval(user_code)`))
	if len(fixture) != 1 {
		t.Fatalf("fixture findings = %+v, want one finding", fixture)
	}
	if fixture[0].Severity != model.SeverityMedium {
		t.Errorf("fixture severity = %q, want %q", fixture[0].Severity, model.SeverityMedium)
	}
}

func TestInjectionRulesHandleNilFile(t *testing.T) {
	for _, r := range InjectionRules() {
		if got := r.Check(nil); len(got) != 0 {
			t.Errorf("%s: nil file produced %d findings", r.Meta().ID, len(got))
		}
	}
}

func TestInjectionJSSQLThroughVariable(t *testing.T) {
	rule := injRulesByID(t)["VGL-INJ-004"]
	src := `const express = require("express");
app.get("/user", (req, res) => {
  const q = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(q);
  res.send("<div>" + req.query.name + "</div>");
});
`
	findings := rule.Check(injTestFile("db.js", src))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Location.StartLine != 4 {
		t.Fatalf("line = %d, want 4", findings[0].Location.StartLine)
	}
}

func TestInjectionJSSQLNegative(t *testing.T) {
	rule := injRulesByID(t)["VGL-INJ-004"]
	src := `const q = "SELECT * FROM users WHERE id = ?";
db.query(q, [req.query.id]);
db.query("SELECT * FROM users");
`
	if findings := rule.Check(injTestFile("db.js", src)); len(findings) != 0 {
		t.Fatalf("parameterized queries flagged: %+v", findings)
	}
}

func TestInjectionHTMLResponse(t *testing.T) {
	rule := injRulesByID(t)["VGL-INJ-037"]
	src := `app.get("/x", (req, res) => {
  res.send("<div>" + req.query.name + "</div>");
  res.send("<p>static</p>");
});
`
	findings := rule.Check(injTestFile("db.js", src))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Location.StartLine != 2 {
		t.Fatalf("line = %d, want 2", findings[0].Location.StartLine)
	}
}
