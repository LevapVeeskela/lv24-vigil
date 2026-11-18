package tools

import (
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// pageInfo is the pagination envelope every bounded list result carries. A
// client can page without guessing whether the response was truncated:
// NextOffset is set only when another window exists.
type pageInfo struct {
	Offset     int  `json:"offset"`
	Limit      int  `json:"limit"`
	Total      int  `json:"total"`
	HasMore    bool `json:"hasMore"`
	NextOffset *int `json:"nextOffset,omitempty"`
}

// coverageInfo states what a scan actually inspected. It carries no code and no
// secrets: the errors are the warnings already stored on the scan result.
type coverageInfo struct {
	FilesScanned int      `json:"filesScanned"`
	FilesSkipped int      `json:"filesSkipped"`
	BytesScanned int64    `json:"bytesScanned"`
	Errors       []string `json:"errors"`
	LLMUsed      bool     `json:"llmUsed"`
}

// scanPayload keeps the model.ScanResult shape at the top level of
// structuredContent and adds the pagination and coverage blocks. The embedded
// pointer is inlined by encoding/json, so existing clients that decode the
// result as a model.ScanResult keep working.
type scanPayload struct {
	*model.ScanResult
	Page     *pageInfo     `json:"page,omitempty"`
	Coverage *coverageInfo `json:"coverage,omitempty"`
}

// window clamps a requested page to a total and describes it. Offset is kept
// as requested (so a client can see that it overshot) while start/end are
// clamped to the list.
func window(total, offset, limit int) (start, end int, p pageInfo) {
	if total < 0 {
		total = 0
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		// "No limit requested" means the whole list. A caller that wants a
		// window always passes a positive size.
		limit = total
		if limit <= 0 {
			limit = 1
		}
	}

	start = offset
	if start > total {
		start = total
	}
	end = start + limit
	if end > total {
		end = total
	}

	p = pageInfo{Offset: offset, Limit: limit, Total: total, HasMore: end < total}
	if p.HasMore {
		next := end
		p.NextOffset = &next
	}
	return start, end, p
}

// pageNote is the one-line human form of a page. It always states the bound and
// how to resume.
func pageNote(p pageInfo) string {
	if p.Total == 0 {
		return "Showing 0 of 0."
	}
	if p.Offset >= p.Total {
		return fmt.Sprintf("Showing 0 of %d: offset %d is past the end.", p.Total, p.Offset)
	}
	end := p.Offset + p.Limit
	if end > p.Total {
		end = p.Total
	}
	if p.HasMore && p.NextOffset != nil {
		return fmt.Sprintf("Showing %d-%d of %d; pass offset=%d to continue.",
			p.Offset+1, end, p.Total, *p.NextOffset)
	}
	if p.Offset == 0 {
		return fmt.Sprintf("Showing all %d.", p.Total)
	}
	return fmt.Sprintf("Showing %d-%d of %d.", p.Offset+1, end, p.Total)
}

// checkOffset rejects a negative page offset as an argument error.
func checkOffset(offset int) error {
	if offset < 0 {
		return toolErrorf(CodeArgs, "offset must be 0 or greater (got %d)", offset)
	}
	return nil
}

// checkScanOffset also rejects an offset a scan result cannot reach. Without
// this, offset+limit can overflow into a negative maxFindings, which the model
// filter treats as "no cap".
func checkScanOffset(offset int) error {
	if err := checkOffset(offset); err != nil {
		return err
	}
	if offset > maxFindingsCap {
		return toolErrorf(CodeArgs, "offset %d is above the %d-finding paging cap; narrow the scan instead", offset, maxFindingsCap)
	}
	return nil
}

// scanTotal is the finding pool a scan reported before the page cap. Older
// results carry no FindingsTotal, so the visible findings are the floor.
func scanTotal(res *model.ScanResult) int {
	if res == nil {
		return 0
	}
	total := res.Stats.FindingsTotal
	if total < len(res.Findings) {
		total = len(res.Findings)
	}
	return total
}

// scanWindow returns a shallow copy of res whose findings are the requested
// window. The stored scan and the caller's result are never mutated.
func scanWindow(res *model.ScanResult, total, offset, limit int) (*model.ScanResult, pageInfo) {
	start, end, p := window(total, offset, limit)
	view := *res
	visible := len(res.Findings)
	if start > visible {
		start = visible
	}
	if end > visible {
		end = visible
	}
	if start > end {
		start = end
	}
	view.Findings = append([]model.Finding{}, res.Findings[start:end]...)
	return &view, p
}

// scanPage pages a finished scan. The page total is the number of findings this
// tool can reach (the 500-finding cap); reported is the scan's honest pre-cap
// count and drives pageCapNote.
func scanPage(res *model.ScanResult, offset, limit int, llmUsed bool) (view *model.ScanResult, page pageInfo, cov *coverageInfo, reported int) {
	reported = scanTotal(res)
	total := reported
	if total > maxFindingsCap {
		total = maxFindingsCap
	}
	view, page = scanWindow(res, total, offset, limit)
	cov = coverageFor(res, llmUsed)
	return view, page, cov, reported
}

// llmContributed reports whether model output is present in the result. A
// configured model that was never consulted must not claim egress.
func llmContributed(res *model.ScanResult) bool {
	if res == nil {
		return false
	}
	if res.Stats.LLMCalls > 0 || strings.TrimSpace(res.ThreatModel) != "" {
		return true
	}
	for _, f := range res.Findings {
		if f.Source != "" && f.Source != model.SourceRule {
			return true
		}
	}
	return false
}

// coverageFor describes the scan behind a result. llmUsed is passed by the
// caller because a configured model is not necessarily a consulted one.
func coverageFor(res *model.ScanResult, llmUsed bool) *coverageInfo {
	if res == nil {
		return nil
	}
	return &coverageInfo{
		FilesScanned: res.Stats.FilesScanned,
		FilesSkipped: res.Stats.FilesSkipped,
		BytesScanned: res.Stats.BytesScanned,
		Errors:       append([]string{}, res.Errors...),
		LLMUsed:      llmUsed,
	}
}

// coverageNote is the human form of coverageInfo. It names what was read, what
// was skipped and whether a model contributed.
func coverageNote(c *coverageInfo) string {
	if c == nil {
		return ""
	}
	parts := []string{
		fmt.Sprintf("%d file(s) scanned", c.FilesScanned),
		fmt.Sprintf("%d skipped", c.FilesSkipped),
	}
	if c.BytesScanned > 0 {
		parts = append(parts, humanBytes(c.BytesScanned)+" read")
	}
	parts = append(parts, fmt.Sprintf("%d error(s)", len(c.Errors)))
	if c.LLMUsed {
		parts = append(parts, "model used")
	} else {
		parts = append(parts, "model not used")
	}
	return "Coverage: " + strings.Join(parts, ", ") + "."
}

// pageCapNote explains an honest total that is larger than what one tool can
// page through (500 findings). It is empty when the whole pool is reachable.
func pageCapNote(reported, total int) string {
	if reported <= total {
		return ""
	}
	return fmt.Sprintf("Note: the scan reported %d findings; this tool pages through at most %d. "+
		"Raise minSeverity or narrow the path to keep the pool inside the cap.\n", reported, total)
}
