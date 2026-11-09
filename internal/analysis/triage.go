package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/llm"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// triageItem is one model judgement. Confidence is any because models return
// numbers, numeric strings and qualitative labels interchangeably.
type triageItem struct {
	ID           string `json:"id"`
	Verdict      string `json:"verdict"`
	Severity     string `json:"severity"`
	Confidence   any    `json:"confidence"`
	Reasoning    string `json:"reasoning"`
	Exploit      string `json:"exploitScenario"`
	ExploitAlt   string `json:"exploit_scenario"`
	Remediation  string `json:"remediation"`
	ReasoningAlt string `json:"reason"`
}

// TriageStats summarises one Triage run. It is diagnostic only: the returned
// findings are complete without it and callers may ignore it.
//
// Judged and Missing are counted over distinct finding ids, so they always add
// up to the number of distinct ids supplied to the run. A failed batch leaves
// its findings unjudged, which is why they are reported in Missing as well.
type TriageStats struct {
	// Batches is the number of first-attempt batch requests.
	Batches int
	// Retries is the number of follow-up requests issued because a successful
	// batch response omitted some ids.
	Retries int
	// Judged is the number of distinct findings that received a judgement.
	Judged int
	// Missing is the number of distinct findings left without a judgement.
	Missing int
	// Failed is the number of batches whose request or response failed. A
	// failed batch is not retried.
	Failed int
}

// Triage asks the model to confirm or reject deterministic findings. The
// deterministic evidence is never removed: a false positive only lowers the
// finding confidence and records the judgement.
//
// A failed batch keeps its original findings and the next batch continues. An
// error is returned only when every batch failed.
func (a *Analyzer) Triage(ctx context.Context, fs []model.Finding, root string) ([]model.Finding, error) {
	out, _, err := a.TriageWithStats(ctx, fs, root)
	return out, err
}

// TriageWithStats is Triage plus a summary of the run. The returned findings and
// error have exactly the same contract as Triage.
//
// When a batch request and its response both succeed but the model omits some
// ids, the omitted findings are retried once with a prompt that lists only those
// ids and their evidence. If the retry omits ids too, the findings keep their
// deterministic evidence and are counted in TriageStats.Missing.
func (a *Analyzer) TriageWithStats(ctx context.Context, fs []model.Finding, root string) ([]model.Finding, TriageStats, error) {
	_ = root
	var stats TriageStats
	if len(fs) == 0 {
		return fs, stats, nil
	}
	if !a.enabled() {
		return fs, stats, nil
	}

	out := append([]model.Finding(nil), fs...)
	index := make(map[string]int, len(out))
	for i := range out {
		if strings.TrimSpace(out[i].ID) == "" {
			out[i].ID = out[i].ComputeID()
		}
		if _, exists := index[out[i].ID]; !exists {
			index[out[i].ID] = i
		}
	}

	judged := make(map[string]bool, len(out))
	var errs []string
	failed := 0

	for start := 0; start < len(out); start += triageBatchSize {
		stats.Batches++
		end := start + triageBatchSize
		if end > len(out) {
			end = len(out)
		}
		if err := ctx.Err(); err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}

		batch := out[start:end]
		items, err := a.requestTriage(ctx, buildTriagePrompt(batch))
		if err != nil {
			failed++
			errs = append(errs, fmt.Sprintf("batch %d: %v", stats.Batches, err))
			continue
		}
		a.applyTriage(out, index, items, judged)

		missing := missingFindings(batch, judged)
		if len(missing) == 0 || ctx.Err() != nil {
			continue
		}
		stats.Retries++
		retryItems, retryErr := a.requestTriage(ctx, buildTriageRetryPrompt(missing))
		if retryErr != nil {
			// The batch itself succeeded; the retry is best effort. The
			// omitted findings keep their deterministic evidence.
			a.logger.Debug("triage retry failed",
				"missing", len(missing),
				"error", llm.TruncateText(retryErr.Error(), 300))
			continue
		}
		a.applyTriage(out, index, retryItems, judged)
	}

	stats.Failed = failed
	stats.Judged, stats.Missing = countJudged(out, judged)

	if stats.Batches > 0 && failed == stats.Batches {
		return out, stats, fmt.Errorf("triage: all %d batches failed: %s",
			stats.Batches, truncateBytes(strings.Join(errs, "; "), 1000))
	}
	if failed > 0 {
		a.logger.Warn("triage partially failed", "failedBatches", failed, "batches", stats.Batches)
	}
	if stats.Missing > 0 {
		// Counts only: prompts and code never reach the log.
		a.logger.Warn("triage left findings without a judgement",
			"missing", stats.Missing,
			"judged", stats.Judged,
			"batches", stats.Batches,
			"retries", stats.Retries)
	}
	return out, stats, nil
}

// requestTriage performs one triage completion and parses its judgements.
func (a *Analyzer) requestTriage(ctx context.Context, prompt string) ([]triageItem, error) {
	resp, err := a.complete(ctx, llm.Request{
		System:   systemTriage,
		Messages: []llm.Message{{Role: llm.RoleUser, Content: prompt}},
		JSON:     true,
	})
	if err != nil {
		return nil, err
	}
	return parseTriageResponse(resp.Text)
}

// missingFindings returns the batch members that still have no judgement.
func missingFindings(batch []model.Finding, judged map[string]bool) []model.Finding {
	var missing []model.Finding
	for i := range batch {
		if !judged[batch[i].ID] {
			missing = append(missing, batch[i])
		}
	}
	return missing
}

// countJudged reports how many distinct ids were judged and how many were not.
func countJudged(out []model.Finding, judged map[string]bool) (int, int) {
	seen := make(map[string]struct{}, len(out))
	got, missing := 0, 0
	for i := range out {
		id := out[i].ID
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if judged[id] {
			got++
		} else {
			missing++
		}
	}
	return got, missing
}

// buildTriageRetryPrompt renders a focused follow-up for the ids a previous
// response omitted. It contains only the missing findings, never the whole
// batch, and keeps the untrusted-data wrapper of the first request.
func buildTriageRetryPrompt(missing []model.Finding) string {
	var b strings.Builder
	b.WriteString("A previous triage response did not cover every finding. Return exactly one object for each of these IDs, inside a single JSON array, and no extra ids:\n")
	for i := range missing {
		fmt.Fprintf(&b, "- %s\n", oneLine(missing[i].ID, 200))
	}
	b.WriteString("\n")
	b.WriteString(buildTriagePrompt(missing))
	return b.String()
}

func parseTriageResponse(text string) ([]triageItem, error) {
	raw, err := extractJSONArray(text)
	if err == nil {
		var items []triageItem
		if unmarshalErr := json.Unmarshal(raw, &items); unmarshalErr == nil {
			return items, nil
		} else {
			err = fmt.Errorf("parse triage JSON: %w", unmarshalErr)
		}
	}
	// Some models return a single judgement object instead of a one-element
	// array. Accept it rather than failing the whole batch.
	if obj, objErr := llm.ExtractJSONObject(text); objErr == nil {
		var single triageItem
		if json.Unmarshal(obj, &single) == nil && strings.TrimSpace(single.ID) != "" {
			return []triageItem{single}, nil
		}
	}
	return nil, err
}

// applyTriage records judgements on the findings and marks the applied ids in
// judged. Unknown and empty ids are ignored.
func (a *Analyzer) applyTriage(out []model.Finding, index map[string]int, items []triageItem, judged map[string]bool) {
	modelName := a.modelName()
	for _, item := range items {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		i, ok := index[id]
		if !ok {
			// Unknown ids are ignored: the model may hallucinate or reorder.
			continue
		}

		verdict := normalizeVerdict(item.Verdict)
		severity := model.Severity("")
		if strings.TrimSpace(item.Severity) != "" {
			if parsed, ok := model.ParseSeverity(item.Severity); ok {
				severity = parsed
			} else {
				// A provided but unknown severity is clamped back to the
				// deterministic value instead of leaking a non-canonical label.
				severity = out[i].Severity
			}
		}
		confidence := clamp01(coerceFloat(item.Confidence))
		exploit := item.Exploit
		if strings.TrimSpace(exploit) == "" {
			exploit = item.ExploitAlt
		}
		reasoning := item.Reasoning
		if strings.TrimSpace(reasoning) == "" {
			reasoning = item.ReasoningAlt
		}

		out[i].LLM = &model.LLMJudgement{
			Verdict:     verdict,
			Severity:    severity,
			Confidence:  confidence,
			Reasoning:   truncateBytes(stripControls(reasoning), maxReasoningBytes),
			Exploit:     truncateBytes(stripControls(exploit), maxReasoningBytes),
			Remediation: truncateBytes(stripControls(item.Remediation), maxReasoningBytes),
			Model:       modelName,
		}
		judged[id] = true

		if verdict == verdictFalsePositive {
			// Advisory only: keep the deterministic finding and its evidence,
			// but make it obvious to a human that the model disagrees.
			out[i].Confidence = model.ConfidenceLow
		}
	}
}
