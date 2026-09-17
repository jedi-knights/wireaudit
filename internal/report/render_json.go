package report

import (
	"encoding/json"
	"io"
)

// jsonFinding is the JSON wire shape for one Finding — Bucket is rendered as
// its canonical string label rather than the internal int, so downstream CI
// consumers never depend on enum ordering.
type jsonFinding struct {
	CheckID string `json:"check_id"`
	Locator string `json:"locator"`
	Bucket  string `json:"bucket"`
	What    string `json:"what"`
	Why     string `json:"why"`
	Fix     string `json:"fix"`
}

// jsonReport is the JSON wire shape for a Report, preserving bucket ordering.
type jsonReport struct {
	MustFix   []jsonFinding `json:"must_fix"`
	ShouldFix []jsonFinding `json:"should_fix"`
	Consider  []jsonFinding `json:"consider"`
}

func toJSONFindings(findings []Finding) []jsonFinding {
	out := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, jsonFinding{
			CheckID: f.CheckID,
			Locator: f.Locator,
			Bucket:  f.Bucket.String(),
			What:    f.What,
			Why:     f.Why,
			Fix:     f.Fix,
		})
	}
	return out
}

// RenderJSON writes r as JSON, preserving Must Fix / Should Fix / Consider
// ordering for CI consumers that render further downstream.
func RenderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		MustFix:   toJSONFindings(r.MustFix),
		ShouldFix: toJSONFindings(r.ShouldFix),
		Consider:  toJSONFindings(r.Consider),
	})
}
