// Package rules implements the v1 conformance rule catalog as a Strategy:
// each RFC-level check is a self-contained Rule registered in a shared
// Registry, so adding a new check never requires editing existing dispatch
// code.
package rules

import (
	"context"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

// Rule is one self-contained protocol-conformance check.
type Rule interface {
	// ID returns the stable check identifier, e.g. "CACHE-002".
	ID() string
	// Category returns the check's category name, e.g. "caching".
	Category() string
	// Check runs the rule against ep through sess and returns zero or more
	// findings. Single-shot rules call sess.Do once; sequenced rules call it
	// multiple times, bounded by probe.MaxRequestsPerRule.
	Check(ctx context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding
	// RequiresRawSocket reports whether this rule must bypass net/http's
	// request validation (true for the HDR-* checks only).
	RequiresRawSocket() bool
}

// Registry holds every registered Rule, in registration order.
type Registry struct {
	rules []Rule
}

// globalRegistry accumulates rules registered via Register at package
// init() time, one call per category file.
var globalRegistry = &Registry{}

// Register adds r to the global registry. Called from each category file's
// init() function — never from application code — so the set of active
// rules is fixed at compile time and requires no central switch statement.
func Register(r Rule) {
	globalRegistry.rules = append(globalRegistry.rules, r)
}

// All returns every registered rule.
func All() []Rule {
	return globalRegistry.rules
}
