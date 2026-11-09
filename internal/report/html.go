package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type htmlView struct {
	ScanID         string
	Started        string
	Finished       string
	Root           string
	Mode           string
	Model          string
	Engine         string
	Version        string
	Cards          []htmlCard
	Findings       []htmlFinding
	HasFindings    bool
	Suppressed     []htmlFinding
	HasSuppressed  bool
	Stats          []htmlStat
	Categories     []htmlStat
	ThreatModel    string
	HasThreatModel bool
	Errors         []string
	HasErrors      bool
}

type htmlCard struct {
	Label string
	Value int
	Class string
}

type htmlStat struct {
	Label string
	Value string
}

type htmlFinding struct {
	Severity       string
	SeverityClass  string
	Title          string
	ID             string
	PathLine       string
	RuleID         string
	Category       string
	Confidence     string
	CWE            string
	OWASP          string
	Source         string
	Description    string
	HasDescription bool
	Evidence       string
	HasEvidence    bool
	Remediation    string
	HasRemediation bool
	LLM            *htmlLLM
	HasLLM         bool
	Fix            *htmlFix
	HasFix         bool
	Suppressed     bool
	SuppressWhy    string
	HasSuppressWhy bool
}

type htmlLLM struct {
	Verdict     string
	Severity    string
	Confidence  string
	Reasoning   string
	Exploit     string
	Remediation string
	Model       string
}

type htmlFix struct {
	Description string
	Diff        string
	Files       string
	Applied     bool
}

func renderHTML(res *model.ScanResult, opts Options) ([]byte, error) {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("report: parse html template: %w", err)
	}

	active := activeFindings(res)
	suppressed := suppressedFindings(res)
	counts := severityCounts(active)

	cards := []htmlCard{
		{Label: "Total", Value: len(active), Class: "total"},
		{Label: "Critical", Value: counts[model.SeverityCritical], Class: "critical"},
		{Label: "High", Value: counts[model.SeverityHigh], Class: "high"},
		{Label: "Medium", Value: counts[model.SeverityMedium], Class: "medium"},
		{Label: "Low", Value: counts[model.SeverityLow], Class: "low"},
		{Label: "Info", Value: counts[model.SeverityInfo], Class: "info"},
	}
	if len(suppressed) > 0 {
		cards = append(cards, htmlCard{Label: "Suppressed", Value: len(suppressed), Class: "suppressed"})
	}

	engine := strings.TrimSpace(res.Engine)
	if engine == "" {
		engine = "vigil"
	}
	if v := strings.TrimSpace(res.Version); v != "" {
		engine += " " + v
	}

	view := htmlView{
		ScanID:         res.ID,
		Started:        formatTime(res.StartedAt),
		Finished:       formatTime(res.FinishedAt),
		Root:           res.Root,
		Mode:           res.Mode,
		Model:          formatModel(res.Model),
		Engine:         engine,
		Version:        strings.TrimSpace(res.Version),
		Cards:          cards,
		Findings:       buildHTMLFindings(active, opts, false),
		HasFindings:    len(active) > 0,
		Suppressed:     buildHTMLFindings(suppressed, opts, true),
		HasSuppressed:  len(suppressed) > 0,
		Stats:          buildHTMLStats(res),
		Categories:     buildHTMLCategories(res),
		ThreatModel:    res.ThreatModel,
		HasThreatModel: strings.TrimSpace(res.ThreatModel) != "",
		Errors:         res.Errors,
		HasErrors:      len(res.Errors) > 0,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("report: render html: %w", err)
	}
	return buf.Bytes(), nil
}

func buildHTMLFindings(findings []model.Finding, opts Options, suppressed bool) []htmlFinding {
	out := make([]htmlFinding, 0, len(findings))
	for _, f := range findings {
		title := oneLine(f.Title)
		if title == "" {
			title = "Security finding"
		}

		rule := oneLine(f.RuleID)
		if rule == "" {
			rule = "unknown"
		}
		category := oneLine(string(f.Category))
		if category == "" {
			category = "unknown"
		}
		confidence := oneLine(string(f.Confidence))
		if confidence == "" {
			confidence = "unknown"
		}

		evidence := f.Evidence
		if strings.TrimSpace(evidence) == "" {
			evidence = f.Location.Snippet
		}
		description := strings.TrimSpace(f.Description)
		remediation := strings.TrimSpace(f.Remediation)
		why := strings.TrimSpace(f.SuppressWhy)

		v := htmlFinding{
			Severity:       displaySeverity(f.Severity),
			SeverityClass:  severityClass(f.Severity),
			Title:          title,
			ID:             findingID(f),
			PathLine:       pathLine(f.Location),
			RuleID:         rule,
			Category:       category,
			Confidence:     confidence,
			CWE:            strings.Join(f.CWE, ", "),
			OWASP:          strings.Join(f.OWASP, ", "),
			Source:         oneLine(string(f.Source)),
			Description:    description,
			HasDescription: description != "",
			Evidence:       evidence,
			HasEvidence:    strings.TrimSpace(evidence) != "",
			Remediation:    remediation,
			HasRemediation: remediation != "",
			Suppressed:     f.Suppressed || suppressed,
			SuppressWhy:    why,
			HasSuppressWhy: why != "",
		}

		if f.LLM != nil {
			llm := &htmlLLM{
				Verdict:     oneLine(f.LLM.Verdict),
				Severity:    oneLine(string(f.LLM.Severity)),
				Reasoning:   strings.TrimSpace(f.LLM.Reasoning),
				Exploit:     strings.TrimSpace(f.LLM.Exploit),
				Remediation: strings.TrimSpace(f.LLM.Remediation),
				Model:       oneLine(f.LLM.Model),
			}
			if f.LLM.Confidence > 0 {
				llm.Confidence = fmt.Sprintf("%.2f", f.LLM.Confidence)
			}
			if llm.Verdict != "" || llm.Severity != "" || llm.Confidence != "" ||
				llm.Reasoning != "" || llm.Exploit != "" || llm.Remediation != "" || llm.Model != "" {
				v.HasLLM = true
				v.LLM = llm
			}
		}

		if opts.ShowFix && f.Fix != nil {
			fix := &htmlFix{
				Description: strings.TrimSpace(f.Fix.Description),
				Diff:        strings.TrimSpace(f.Fix.Diff),
				Applied:     f.Fix.Applied,
			}
			if len(f.Fix.Files) > 0 {
				fix.Files = strings.Join(f.Fix.Files, ", ")
			}
			if fix.Description != "" || fix.Diff != "" || fix.Files != "" || fix.Applied {
				v.HasFix = true
				v.Fix = fix
			}
		}

		out = append(out, v)
	}
	return out
}

func buildHTMLStats(res *model.ScanResult) []htmlStat {
	stats := []htmlStat{
		{Label: "Files scanned", Value: fmt.Sprintf("%d", res.Stats.FilesScanned)},
		{Label: "Files skipped", Value: fmt.Sprintf("%d", res.Stats.FilesSkipped)},
		{Label: "Bytes scanned", Value: fmt.Sprintf("%d", res.Stats.BytesScanned)},
		{Label: "Duration", Value: fmt.Sprintf("%d ms", res.Stats.DurationMS)},
		{Label: "Rules run", Value: fmt.Sprintf("%d", res.Stats.RulesRun)},
		{Label: "LLM calls", Value: fmt.Sprintf("%d", res.Stats.LLMCalls)},
		{Label: "Findings", Value: fmt.Sprintf("%d active, %d suppressed", len(res.Findings), len(res.Suppressed))},
	}
	if res.Stats.LLMTokens > 0 {
		stats = append(stats, htmlStat{Label: "LLM tokens", Value: fmt.Sprintf("%d", res.Stats.LLMTokens)})
	}
	return stats
}

func buildHTMLCategories(res *model.ScanResult) []htmlStat {
	if len(res.Stats.ByCategory) == 0 {
		return nil
	}
	out := make([]htmlStat, 0, len(res.Stats.ByCategory))
	for _, category := range sortedCategories(res.Stats.ByCategory) {
		out = append(out, htmlStat{
			Label: string(category),
			Value: fmt.Sprintf("%d", res.Stats.ByCategory[category]),
		})
	}
	return out
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Vigil {{.Version}}">
<title>Vigil security report{{if .ScanID}} — {{.ScanID}}{{end}}</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #f5f6f8;
  --panel: #ffffff;
  --panel-2: #eef1f5;
  --text: #171a21;
  --muted: #5b6270;
  --border: #dfe3e8;
  --accent: #3b5bdb;
  --code-bg: #eef1f4;
  --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 1px 3px rgba(16, 24, 40, .1);
  --critical: #b42318;
  --high: #c2410c;
  --medium: #a16207;
  --low: #1d4ed8;
  --info: #475467;
  --suppressed: #6b7280;
  --badge-text: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1116;
    --panel: #161b22;
    --panel-2: #1c232c;
    --text: #e6edf3;
    --muted: #9aa4b2;
    --border: #2b3440;
    --accent: #7c9cff;
    --code-bg: #0b0f14;
    --shadow: none;
    --critical: #ff7b72;
    --high: #ffa657;
    --medium: #e3b341;
    --low: #79c0ff;
    --info: #a5b0bf;
    --suppressed: #8b949e;
    --badge-text: #0e1116;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.page-header, main, footer { max-width: 1080px; margin: 0 auto; padding: 0 20px; }
.page-header { padding-top: 40px; }
.eyebrow {
  margin: 0 0 6px;
  color: var(--accent);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: .08em;
  text-transform: uppercase;
}
h1 { margin: 0 0 18px; font-size: clamp(26px, 4vw, 38px); line-height: 1.15; }
h2 { margin: 36px 0 14px; font-size: 22px; }
h3 { margin: 0; font-size: 18px; line-height: 1.3; }
h4 { margin: 0 0 8px; font-size: 14px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
.stats h3 { margin: 24px 0 10px; }
.mono, code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
.scan-meta, .finding-meta, .stats-list {
  display: grid;
  gap: 10px 22px;
  margin: 0;
  padding: 18px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  box-shadow: var(--shadow);
}
.scan-meta { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
.finding-meta { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); margin: 14px 0; padding: 14px; box-shadow: none; }
.stats-list { grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }
.scan-meta div, .finding-meta div, .stats-list div { min-width: 0; }
dt {
  color: var(--muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
}
dd { margin: 2px 0 0; overflow-wrap: anywhere; }
code {
  padding: .12em .35em;
  background: var(--code-bg);
  border-radius: 4px;
  font-size: .9em;
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
  gap: 12px;
}
.card {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 16px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-top: 4px solid var(--border);
  border-radius: 10px;
  box-shadow: var(--shadow);
}
.card-value { font-size: 30px; font-weight: 750; line-height: 1; }
.card-label { color: var(--muted); font-size: 12px; font-weight: 650; text-transform: uppercase; letter-spacing: .05em; }
.card-total { border-top-color: var(--accent); }
.card-critical { border-top-color: var(--critical); }
.card-high { border-top-color: var(--high); }
.card-medium { border-top-color: var(--medium); }
.card-low { border-top-color: var(--low); }
.card-info { border-top-color: var(--info); }
.card-suppressed { border-top-color: var(--suppressed); }
.muted, .empty { color: var(--muted); }
.empty {
  padding: 26px;
  background: var(--panel);
  border: 1px dashed var(--border);
  border-radius: 10px;
  text-align: center;
}
.finding {
  margin: 16px 0;
  padding: 20px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 5px solid var(--border);
  border-radius: 10px;
  box-shadow: var(--shadow);
}
.finding-critical { border-left-color: var(--critical); }
.finding-high { border-left-color: var(--high); }
.finding-medium { border-left-color: var(--medium); }
.finding-low { border-left-color: var(--low); }
.finding-info { border-left-color: var(--info); }
.finding-unknown { border-left-color: var(--suppressed); }
.finding-suppressed { opacity: .82; border-left-style: dashed; }
.finding-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.finding-header h3 { flex: 1 1 320px; }
.finding-id { color: var(--muted); font-size: 13px; }
.badge {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 999px;
  background: var(--suppressed);
  color: var(--badge-text);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: .07em;
  text-transform: uppercase;
}
.badge-critical { background: var(--critical); }
.badge-high { background: var(--high); }
.badge-medium { background: var(--medium); }
.badge-low { background: var(--low); }
.badge-info { background: var(--info); }
.description, .remediation, .threat-model { white-space: pre-wrap; }
.remediation { padding: 12px 14px; background: var(--panel-2); border-radius: 8px; }
details {
  margin: 14px 0;
  padding: 12px 14px;
  background: var(--panel-2);
  border: 1px solid var(--border);
  border-radius: 8px;
}
summary { cursor: pointer; font-weight: 700; }
summary::marker { color: var(--accent); }
pre {
  margin: 12px 0 0;
  padding: 14px;
  overflow: auto;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.5;
  tab-size: 4;
}
pre code { padding: 0; background: none; border-radius: 0; font-size: inherit; }
pre.diff { border-left: 4px solid var(--accent); }
.llm {
  margin: 14px 0;
  padding: 14px;
  background: var(--panel-2);
  border: 1px solid var(--border);
  border-radius: 8px;
}
.llm p { margin: 8px 0 0; white-space: pre-wrap; }
.llm p:first-of-type { margin-top: 0; }
.suppressed-note { margin: 14px 0 0; color: var(--muted); font-style: italic; }
.section-note { color: var(--muted); }
.errors ul { margin: 0; padding-left: 22px; }
.errors li { margin: 4px 0; }
footer {
  margin-top: 52px;
  padding-top: 18px;
  padding-bottom: 40px;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: 13px;
  text-align: center;
}
@media (max-width: 560px) {
  .page-header, main, footer { padding-left: 14px; padding-right: 14px; }
  .finding { padding: 16px; }
}
</style>
</head>
<body>
{{define "finding"}}
<article class="finding finding-{{.SeverityClass}}{{if .Suppressed}} finding-suppressed{{end}}">
  <header class="finding-header">
    <span class="badge badge-{{.SeverityClass}}">{{.Severity}}</span>
    <h3>{{.Title}}</h3>
    <span class="finding-id mono">{{.ID}}</span>
  </header>
  <dl class="finding-meta">
    <div><dt>Path</dt><dd><code>{{.PathLine}}</code></dd></div>
    <div><dt>Rule</dt><dd><code>{{.RuleID}}</code></dd></div>
    <div><dt>Category</dt><dd>{{.Category}}</dd></div>
    <div><dt>Confidence</dt><dd>{{.Confidence}}</dd></div>
    {{if .CWE}}<div><dt>CWE</dt><dd>{{.CWE}}</dd></div>{{end}}
    {{if .OWASP}}<div><dt>OWASP</dt><dd>{{.OWASP}}</dd></div>{{end}}
    {{if .Source}}<div><dt>Source</dt><dd>{{.Source}}</dd></div>{{end}}
  </dl>
  {{if .HasDescription}}<p class="description">{{.Description}}</p>{{end}}
  {{if .HasEvidence}}
  <details class="evidence" open>
    <summary>Evidence</summary>
    <pre><code>{{.Evidence}}</code></pre>
  </details>
  {{end}}
  {{if .HasRemediation}}<p class="remediation"><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
  {{if .HasLLM}}
  <div class="llm">
    <h4>LLM verdict</h4>
    <p><strong>{{.LLM.Verdict}}</strong>{{if .LLM.Severity}} · severity {{.LLM.Severity}}{{end}}{{if .LLM.Confidence}} · confidence {{.LLM.Confidence}}{{end}}{{if .LLM.Model}} · {{.LLM.Model}}{{end}}</p>
    {{if .LLM.Reasoning}}<p>{{.LLM.Reasoning}}</p>{{end}}
    {{if .LLM.Exploit}}<p><strong>Exploit scenario:</strong> {{.LLM.Exploit}}</p>{{end}}
    {{if .LLM.Remediation}}<p><strong>Suggested remediation:</strong> {{.LLM.Remediation}}</p>{{end}}
  </div>
  {{end}}
  {{if .HasFix}}
  <details class="fix">
    <summary>Proposed fix</summary>
    {{if .Fix.Description}}<p>{{.Fix.Description}}</p>{{end}}
    {{if .Fix.Diff}}<pre class="diff"><code>{{.Fix.Diff}}</code></pre>{{end}}
    {{if .Fix.Files}}<p class="muted">Files: {{.Fix.Files}}</p>{{end}}
    {{if .Fix.Applied}}<p class="muted">Fix applied.</p>{{end}}
  </details>
  {{end}}
  {{if .Suppressed}}<p class="suppressed-note">Suppressed{{if .HasSuppressWhy}}: {{.SuppressWhy}}{{end}}</p>{{end}}
</article>
{{end}}
<header class="page-header">
  <p class="eyebrow">Vigil security report</p>
  <h1>Security scan{{if .ScanID}} <span class="mono">{{.ScanID}}</span>{{end}}</h1>
  <dl class="scan-meta">
    <div><dt>Scan ID</dt><dd class="mono">{{.ScanID}}</dd></div>
    <div><dt>Started</dt><dd>{{.Started}}</dd></div>
    <div><dt>Finished</dt><dd>{{.Finished}}</dd></div>
    <div><dt>Root</dt><dd class="mono">{{.Root}}</dd></div>
    <div><dt>Mode</dt><dd>{{.Mode}}</dd></div>
    <div><dt>Model</dt><dd>{{.Model}}</dd></div>
    <div><dt>Engine</dt><dd>{{.Engine}}</dd></div>
  </dl>
</header>
<main>
  <section class="summary" aria-labelledby="summary-heading">
    <h2 id="summary-heading">Summary</h2>
    <div class="cards">
      {{range .Cards}}
      <div class="card card-{{.Class}}">
        <span class="card-value">{{.Value}}</span>
        <span class="card-label">{{.Label}}</span>
      </div>
      {{end}}
    </div>
    {{if .HasSuppressed}}<p class="section-note">{{len .Suppressed}} suppressed finding(s) are listed separately below.</p>{{end}}
  </section>

  <section class="findings" aria-labelledby="findings-heading">
    <h2 id="findings-heading">Findings</h2>
    {{if .HasFindings}}
      {{range .Findings}}{{template "finding" .}}{{end}}
    {{else}}
      <p class="empty">No active findings.</p>
    {{end}}
  </section>

  {{if .HasSuppressed}}
  <section class="suppressed" aria-labelledby="suppressed-heading">
    <h2 id="suppressed-heading">Suppressed findings</h2>
    {{range .Suppressed}}{{template "finding" .}}{{end}}
  </section>
  {{end}}

  {{if .HasThreatModel}}
  <section class="threat-model-section" aria-labelledby="threat-model-heading">
    <h2 id="threat-model-heading">Threat model</h2>
    <pre class="threat-model">{{.ThreatModel}}</pre>
  </section>
  {{end}}

  {{if .HasErrors}}
  <section class="errors" aria-labelledby="errors-heading">
    <h2 id="errors-heading">Scan errors</h2>
    <ul>
      {{range .Errors}}<li>{{.}}</li>{{end}}
    </ul>
  </section>
  {{end}}

  <section class="stats" aria-labelledby="stats-heading">
    <h2 id="stats-heading">Scan statistics</h2>
    <dl class="stats-list">
      {{range .Stats}}<div><dt>{{.Label}}</dt><dd>{{.Value}}</dd></div>{{end}}
    </dl>
    {{if .Categories}}
    <h3>Findings by category</h3>
    <dl class="stats-list">
      {{range .Categories}}<div><dt>{{.Label}}</dt><dd>{{.Value}}</dd></div>{{end}}
    </dl>
    {{end}}
  </section>
</main>
<footer>Generated by Vigil{{if .Version}} {{.Version}}{{end}}</footer>
</body>
</html>
`
