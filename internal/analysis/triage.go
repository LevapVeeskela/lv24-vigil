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

// Triage asks the model to confirm or reject deterministic findings. The
// deterministic evidence is never removed: a false positive only lowers the
// finding confidence and records the judgement.
//
// A failed batch keeps its original findings and the next batch continues. An
// error is returned only when every batch failed.
func (a *Analyzer) Triage(ctx context.Context, fs []model.Finding, root string) ([]model.Finding, error) {
	_ = root
	if len(fs) == 0 {
		return fs, nil
	}
	if !a.enabled() {
		return fs, nil
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

	var errs []string
	batches, failed := 0, 0
	for start := 0; start < len(out); start += triageBatchSize {
		batches++
		if err := ctx.Err(); err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}
		end := start + triageBatchSize
		if end > len(out) {
			end = len(out)
		}

		resp, err := a.complete(ctx, llm.Request{
			System:   systemTriage,
			Messages: []llm.Message{{Role: llm.RoleUser, Content: buildTriagePrompt(out[start:end])}},
			JSON:     true,
		})
		if err != nil {
			failed++
			errs = append(errs, fmt.Sprintf("batch %d: %v", start/triageBatchSize+1, err))
			continue
		}

		items, err := parseTriageResponse(resp.Text)
		if err != nil {
			failed++
			errs = append(errs, fmt.Sprintf("batch %d: %v", start/triageBatchSize+1, err))
			continue
		}
		a.applyTriage(out, index, items)
	}

	if batches > 0 && failed == batches {
		return out, fmt.Errorf("triage: all %d batches failed: %s", batches, truncateBytes(strings.Join(errs, "; "), 1000))
	}
	if failed > 0 {
		a.logger.Warn("triage partially failed", "failedBatches", failed, "batches", batches)
	}
	return out, nil
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

func (a *Analyzer) applyTriage(out []model.Finding, index map[string]int, items []triageItem) {
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

		if verdict == verdictFalsePositive {
			// Advisory only: keep the deterministic finding and its evidence,
			// but make it obvious to a human that the model disagrees.
			out[i].Confidence = model.ConfidenceLow
		}
	}
}
