// Package report renders analyzer findings using the three-bucket severity
// format: Must Fix, Should Fix, Consider.
package report

import "fmt"

// Bucket is a closed severity classification for a Finding.
type Bucket int

const (
	// MustFix indicates a correctness failure — the target violates a MUST-level
	// protocol requirement.
	MustFix Bucket = iota
	// ShouldFix indicates a SHOULD-level deviation that drifts from the spec
	// without breaking interoperability outright.
	ShouldFix
	// Consider indicates an improvement opportunity with no normative violation.
	Consider
)

// String renders the canonical bucket label used in reports.
func (b Bucket) String() string {
	switch b {
	case MustFix:
		return "Must Fix"
	case ShouldFix:
		return "Should Fix"
	case Consider:
		return "Consider"
	default:
		panic(fmt.Sprintf("report: unknown bucket %d", int(b)))
	}
}

// Finding is a single reported protocol-conformance violation.
type Finding struct {
	// CheckID is the stable rule identifier, e.g. "CACHE-002".
	CheckID string
	// Locator identifies where the finding applies, e.g. "GET /v1/users/42".
	Locator string
	// Bucket is the severity classification.
	Bucket Bucket
	// What is a one-sentence description of the observed defect.
	What string
	// Why is a one-sentence description of the consequence.
	Why string
	// Fix is a one- or two-sentence description of the remediation.
	Fix string
}

// Location renders the report locator line: "METHOD path — CHECK-ID".
func (f Finding) Location() string {
	return fmt.Sprintf("%s — %s", f.Locator, f.CheckID)
}
