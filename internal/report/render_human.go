package report

import (
	"fmt"
	"io"
)

// RenderHuman writes r as grouped Markdown-ish text: Must Fix, then Should
// Fix, then Consider, omitting any bucket with no findings.
func RenderHuman(w io.Writer, r *Report) error {
	sections := []struct {
		title    string
		findings []Finding
	}{
		{"Must Fix", r.MustFix},
		{"Should Fix", r.ShouldFix},
		{"Consider", r.Consider},
	}

	wrote := false
	for _, s := range sections {
		if len(s.findings) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "### %s\n", s.title); err != nil {
			return err
		}
		for _, f := range s.findings {
			if _, err := fmt.Fprintf(w, "- `%s` — %s. **Why:** %s. **Fix:** %s.\n", f.Location(), f.What, f.Why, f.Fix); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		wrote = true
	}
	if !wrote {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	return nil
}
