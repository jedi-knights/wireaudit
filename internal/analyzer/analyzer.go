// Package analyzer wires the probe transports and the rule registry
// together into one public entry point, Run, that every caller (the CLI, or
// a black-box test) goes through — no test or command reaches into
// internal/rules or internal/probe directly.
package analyzer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
	"github.com/jedi-knights/wireaudit/internal/rules"
)

// Config drives one analyzer run.
type Config struct {
	// Endpoints is the set of method+URL pairs to probe. Must be non-empty.
	Endpoints []probe.Endpoint
	// Headers are added to every outgoing request across every endpoint
	// (e.g. Authorization).
	Headers map[string][]string
	// Categories, when non-empty, restricts checks to these category names.
	// Empty means every registered category runs.
	Categories map[string]bool
	// ExcludeRules skips any rule whose ID is a key here.
	ExcludeRules map[string]bool
	// Timeout bounds every individual request.
	Timeout time.Duration
	// InsecureSkipVerify disables TLS verification — must only ever be set
	// from an explicit CLI opt-in flag, never a default.
	InsecureSkipVerify bool
	// AllowUnsafeWrites permits CACHE-005 to send a real PUT/PATCH/DELETE
	// against the target — must only ever be set from an explicit CLI
	// opt-in flag, never a default.
	AllowUnsafeWrites bool
	// Concurrency bounds how many endpoints are probed in parallel. Values
	// less than 1 are treated as 1.
	Concurrency int
}

// Run probes every endpoint in cfg against every enabled rule and returns
// the aggregated, bucket-ordered Report.
func Run(ctx context.Context, cfg Config) (*report.Report, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("analyzer: no endpoints to probe")
	}

	httpClient := probe.NewHTTPClient(cfg.Timeout, cfg.InsecureSkipVerify)
	rawClient := probe.NewRawClient(cfg.Timeout)
	ctx = rules.WithAllowUnsafeWrites(ctx, cfg.AllowUnsafeWrites)

	activeRules := selectRules(cfg)

	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	var (
		mu       sync.Mutex
		findings []report.Finding
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for _, ep := range cfg.Endpoints {
		ep := ep
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			epFindings := runRules(ctx, activeRules, httpClient, rawClient, cfg.Headers, ep)

			mu.Lock()
			findings = append(findings, epFindings...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	r := report.NewReport(findings)
	assertBucketed(r)
	return r, nil
}

// runRules executes every rule in activeRules against ep, in registration
// order. Each rule gets its own Session — and therefore its own fresh
// probe.MaxRequestsPerRule budget — rather than sharing one counter across
// every rule for the endpoint, which would silently starve every rule after
// the first few once the shared budget ran out.
func runRules(ctx context.Context, activeRules []rules.Rule, httpClient *probe.HTTPClient, rawClient *probe.RawClient, headers map[string][]string, ep probe.Endpoint) []report.Finding {
	var findings []report.Finding
	for _, rule := range activeRules {
		sess := probe.NewSession(ep, httpClient, rawClient, headers)
		findings = append(findings, rule.Check(ctx, sess, ep)...)
	}
	return findings
}

// selectRules filters the global registry by cfg's category/exclude
// settings, evaluated once per Run rather than per endpoint.
func selectRules(cfg Config) []rules.Rule {
	all := rules.All()
	if len(cfg.Categories) == 0 && len(cfg.ExcludeRules) == 0 {
		return all
	}
	selected := make([]rules.Rule, 0, len(all))
	for _, rule := range all {
		if len(cfg.Categories) > 0 && !cfg.Categories[rule.Category()] {
			continue
		}
		if cfg.ExcludeRules[rule.ID()] {
			continue
		}
		selected = append(selected, rule)
	}
	return selected
}

// assertBucketed enforces the postcondition every caller relies on: a
// Report's three slices only ever contain findings whose Bucket matches the
// slice they're stored in.
func assertBucketed(r *report.Report) {
	for _, f := range r.MustFix {
		if f.Bucket != report.MustFix {
			panic(fmt.Sprintf("analyzer: finding %s misfiled in MustFix bucket", f.CheckID))
		}
	}
	for _, f := range r.ShouldFix {
		if f.Bucket != report.ShouldFix {
			panic(fmt.Sprintf("analyzer: finding %s misfiled in ShouldFix bucket", f.CheckID))
		}
	}
	for _, f := range r.Consider {
		if f.Bucket != report.Consider {
			panic(fmt.Sprintf("analyzer: finding %s misfiled in Consider bucket", f.CheckID))
		}
	}
}
