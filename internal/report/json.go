package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// schemaVersion identifies the machine-readable report envelope. It is kept
// separate from the scan result so consumers can evolve independently.
const schemaVersion = "1"

// jsonScanResult mirrors model.ScanResult with a versioned envelope and with
// findings/suppressed/errors always present as arrays.
type jsonScanResult struct {
	SchemaVersion string           `json:"schemaVersion"`
	ID            string           `json:"id"`
	StartedAt     time.Time        `json:"startedAt"`
	FinishedAt    time.Time        `json:"finishedAt"`
	Root          string           `json:"root"`
	Mode          string           `json:"mode"`
	Findings      []model.Finding  `json:"findings"`
	Suppressed    []model.Finding  `json:"suppressed"`
	Stats         model.Stats      `json:"stats"`
	Model         *model.ModelInfo `json:"model,omitempty"`
	ThreatModel   string           `json:"threatModel,omitempty"`
	Errors        []string         `json:"errors"`
	Engine        string           `json:"engine"`
	Version       string           `json:"version"`
}

func renderJSON(res *model.ScanResult) ([]byte, error) {
	stats := res.Stats
	if stats.BySeverity == nil {
		stats.BySeverity = map[model.Severity]int{}
	}
	if stats.ByCategory == nil {
		stats.ByCategory = map[model.Category]int{}
	}

	suppressed := append([]model.Finding{}, res.Suppressed...)
	for i := range suppressed {
		suppressed[i].Suppressed = true
	}

	out := jsonScanResult{
		SchemaVersion: schemaVersion,
		ID:            res.ID,
		StartedAt:     res.StartedAt,
		FinishedAt:    res.FinishedAt,
		Root:          res.Root,
		Mode:          res.Mode,
		Findings:      append([]model.Finding{}, res.Findings...),
		Suppressed:    suppressed,
		Stats:         stats,
		Model:         res.Model,
		ThreatModel:   res.ThreatModel,
		Errors:        append([]string{}, res.Errors...),
		Engine:        res.Engine,
		Version:       res.Version,
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: marshal json: %w", err)
	}
	return append(b, '\n'), nil
}
