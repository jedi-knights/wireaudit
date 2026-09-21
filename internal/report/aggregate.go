package report

// Report is the fully aggregated, bucket-ordered set of findings produced by
// one analyzer run.
type Report struct {
	MustFix   []Finding
	ShouldFix []Finding
	Consider  []Finding
}

// NewReport groups an unordered slice of findings into their buckets,
// preserving each bucket's relative discovery order.
func NewReport(findings []Finding) *Report {
	r := &Report{}
	for _, f := range findings {
		switch f.Bucket {
		case MustFix:
			r.MustFix = append(r.MustFix, f)
		case ShouldFix:
			r.ShouldFix = append(r.ShouldFix, f)
		case Consider:
			r.Consider = append(r.Consider, f)
		}
	}
	return r
}

// HasMustFix reports whether any Must Fix finding was recorded — the CLI's
// exit-code decision depends on exactly this.
func (r *Report) HasMustFix() bool {
	return len(r.MustFix) > 0
}
