// Package analyzer wires the probe transports and the rule registry
// together into one public entry point, Run, that every caller (the CLI, or
// a black-box test) goes through — no test or command reaches into
// internal/rules or internal/probe directly.
package analyzer

import (
	"context"
	"fmt"
	"net/url"
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

	// perEndpoint is indexed by endpoint position so the flattened order, and
	// therefore which endpoint a deduplicated finding is attributed to, is
	// deterministic regardless of goroutine scheduling.
	var (
		perEndpoint = make([][]report.Finding, len(cfg.Endpoints))
		wg          sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for i, ep := range cfg.Endpoints {
		i, ep := i, ep
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			epFindings := runRules(ctx, activeRules, httpClient, rawClient, cfg.Headers, ep, cfg.AllowUnsafeWrites)

			perEndpoint[i] = epFindings // distinct index per goroutine: no lock needed
		}()
	}
	wg.Wait()

	r := report.NewReport(dedupeHostScoped(perEndpoint, cfg.Endpoints, hostScopedIDs(activeRules)))
	assertBucketed(r)
	return r, nil
}

// runRules executes every rule in activeRules against ep, in registration
// order. Each rule gets its own Session — and therefore its own fresh
// probe.MaxRequestsPerRule budget — rather than sharing one counter across
// every rule for the endpoint, which would silently starve every rule after
// the first few once the shared budget ran out.
func runRules(ctx context.Context, activeRules []rules.Rule, httpClient *probe.HTTPClient, rawClient *probe.RawClient, headers map[string][]string, ep probe.Endpoint, allowUnsafeWrites bool) []report.Finding {
	var findings []report.Finding
	for _, rule := range activeRules {
		sess := probe.NewSession(ep, httpClient, rawClient, headers, allowUnsafeWrites)
		findings = append(findings, rule.Check(ctx, sess, ep)...)
	}
	return findings
}

// hostScopedIDs returns the IDs of active rules that describe a whole host.
func hostScopedIDs(activeRules []rules.Rule) map[string]bool {
	ids := make(map[string]bool)
	for _, rule := range activeRules {
		if _, ok := rule.(rules.HostScoped); ok {
			ids[rule.ID()] = true
		}
	}
	return ids
}

// dedupeHostScoped flattens per-endpoint findings in endpoint order and keeps
// only the first finding per (host, check) for host-scoped rules, annotating
// it with how many other endpoints on the host had the same finding.
// Findings from all other rules pass through untouched. O(total findings).
func dedupeHostScoped(perEndpoint [][]report.Finding, eps []probe.Endpoint, hostScoped map[string]bool) []report.Finding {
	if len(perEndpoint) != len(eps) {
		panic(fmt.Sprintf("analyzer: %d finding sets for %d endpoints", len(perEndpoint), len(eps)))
	}
	var out []report.Finding
	firstIdx := make(map[string]int) // host|checkID -> index in out
	extra := make(map[string]int)    // host|checkID -> endpoints collapsed into it
	for i, findings := range perEndpoint {
		host := hostOf(eps[i].URL)
		for _, f := range findings {
			if !hostScoped[f.CheckID] {
				out = append(out, f)
				continue
			}
			key := host + "|" + f.CheckID
			if _, seen := firstIdx[key]; seen {
				extra[key]++
				continue
			}
			firstIdx[key] = len(out)
			out = append(out, f)
		}
	}
	for key, n := range extra {
		out[firstIdx[key]].What += fmt.Sprintf(" (host-wide: same on %d other probed endpoint(s))", n)
	}
	return out
}

// hostOf returns the host:port of rawURL, or rawURL itself if unparsable so
// distinct unparsable URLs never collapse together.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
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
