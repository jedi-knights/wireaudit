package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(validatorPresentRule{})
	Register(conditionalGetNotModifiedRule{})
	Register(cacheControlConsistentRule{})
	Register(conditionalGetModifiedRule{})
	Register(preconditionForUnsafeWriteRule{})
}

// --- CACHE-001: validator-present ---

type validatorPresentRule struct{}

func (validatorPresentRule) ID() string              { return "CACHE-001" }
func (validatorPresentRule) Category() string        { return "caching" }
func (validatorPresentRule) RequiresRawSocket() bool { return false }

func (r validatorPresentRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil || res.Response.StatusCode != 200 {
		return nil
	}
	_, hasETag := res.Response.HeaderValue("ETag")
	_, hasLastMod := res.Response.HeaderValue("Last-Modified")
	if !hasETag && !hasLastMod {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			"cacheable GET response has neither ETag nor Last-Modified",
			"RFC 9110 §8.8.2/8.8.3 relies on a validator for conditional requests; without one, clients can only cache by heuristic freshness, never revalidate cheaply",
			"set ETag (preferred) or Last-Modified on responses that represent a stable resource")}
	}
	return nil
}

// --- CACHE-002: conditional-get-not-modified ---

type conditionalGetNotModifiedRule struct{}

func (conditionalGetNotModifiedRule) ID() string              { return "CACHE-002" }
func (conditionalGetNotModifiedRule) Category() string        { return "caching" }
func (conditionalGetNotModifiedRule) RequiresRawSocket() bool { return false }

func (r conditionalGetNotModifiedRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	baseline, err := getBaseline(sess, ep)
	if err != nil || baseline.Err != nil || baseline.Response.StatusCode != 200 {
		return nil
	}

	header, value, ok := conditionalValidatorHeader(baseline.Response, false)
	if !ok {
		return nil // no validator to test against — CACHE-001 already covers this gap
	}

	res, err := sess.Do(probe.RequestSpec{
		Method: ep.Method,
		URL:    ep.URL,
		Header: map[string][]string{header: {value}},
	}, false)
	if err != nil || res.Err != nil {
		return nil
	}

	if res.Response.StatusCode != 304 {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("a conditional GET with a matching %s returned %d instead of 304", header, res.Response.StatusCode),
			"RFC 9110 §13.1.1/§15.4.5 requires 304 with an empty body when the validator matches; serving a full body wastes bandwidth and breaks cache revalidation",
			"compare the request validator against the current resource state and return 304 with no body when it matches")}
	}
	if len(res.Response.Body) != 0 {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("a 304 response carried a %d-byte body", len(res.Response.Body)),
			"RFC 9110 §15.4.5 requires 304 responses to have no body",
			"omit the body entirely when returning 304")}
	}
	return nil
}

// --- CACHE-003: cache-control-consistent ---

type cacheControlConsistentRule struct{}

func (cacheControlConsistentRule) ID() string              { return "CACHE-003" }
func (cacheControlConsistentRule) Category() string        { return "caching" }
func (cacheControlConsistentRule) RequiresRawSocket() bool { return false }

func (r cacheControlConsistentRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil || res.Response.StatusCode != 200 {
		return nil
	}
	cc, present := res.Response.HeaderValue("Cache-Control")
	if !present {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			"response has no Cache-Control header",
			"RFC 9111 §5.2 governs cache behavior via Cache-Control; without it, shared caches fall back to ambiguous heuristics",
			"set an explicit Cache-Control directive (even \"no-store\" is more explicit than omission)")}
	}
	lower := strings.ToLower(cc)
	if strings.Contains(lower, "no-store") && strings.Contains(lower, "max-age") {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			fmt.Sprintf("Cache-Control combines contradictory directives: %q", cc),
			"no-store forbids any storage while max-age instructs caches how long to store a response — combining them signals confused caching intent",
			"choose one caching intent per response: no-store for sensitive/dynamic data, or max-age (with public/private) for cacheable data")}
	}
	return nil
}

// --- CACHE-004: conditional-get-modified (false-negative complement to CACHE-002) ---

type conditionalGetModifiedRule struct{}

func (conditionalGetModifiedRule) ID() string              { return "CACHE-004" }
func (conditionalGetModifiedRule) Category() string        { return "caching" }
func (conditionalGetModifiedRule) RequiresRawSocket() bool { return false }

func (r conditionalGetModifiedRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	baseline, err := getBaseline(sess, ep)
	if err != nil || baseline.Err != nil || baseline.Response.StatusCode != 200 {
		return nil
	}

	header, value, ok := conditionalValidatorHeader(baseline.Response, true)
	if !ok {
		return nil
	}

	res, err := sess.Do(probe.RequestSpec{
		Method: ep.Method,
		URL:    ep.URL,
		Header: map[string][]string{header: {value}},
	}, false)
	if err != nil || res.Err != nil {
		return nil
	}

	if res.Response.StatusCode == 304 {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("a conditional GET with a deliberately non-matching %s still returned 304", header),
			"a server that returns 304 regardless of whether the validator actually matches will serve stale or wrong cached content to every client",
			"compare the request validator against the resource's current validator value and only return 304 on an actual match (RFC 9110 §13.1.1/§13.1.3)")}
	}
	return nil
}

// conditionalValidatorHeader builds the conditional-request header+value
// pair from a baseline response's validator. When mismatch is true, it
// deliberately returns a non-matching value (for CACHE-004); otherwise the
// exact matching value (for CACHE-002). Returns ok=false when the baseline
// carried no validator at all.
func conditionalValidatorHeader(resp *probe.Response, mismatch bool) (header, value string, ok bool) {
	if etag, present := resp.HeaderValue("ETag"); present {
		if mismatch {
			return "If-None-Match", `"wireaudit-deliberately-non-matching-etag"`, true
		}
		return "If-None-Match", etag, true
	}
	if lastMod, present := resp.HeaderValue("Last-Modified"); present {
		if mismatch {
			return "If-Modified-Since", "Mon, 01 Jan 1990 00:00:00 GMT", true
		}
		return "If-Modified-Since", lastMod, true
	}
	return "", "", false
}

// --- CACHE-005: precondition-for-unsafe-write ---

type preconditionForUnsafeWriteRule struct{}

func (preconditionForUnsafeWriteRule) ID() string              { return "CACHE-005" }
func (preconditionForUnsafeWriteRule) Category() string        { return "caching" }
func (preconditionForUnsafeWriteRule) RequiresRawSocket() bool { return false }

func (r preconditionForUnsafeWriteRule) Check(ctx context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	if !allowUnsafeWrites(ctx) {
		return nil // never send a real write unless the caller explicitly opted in
	}

	optRes, err := sess.Do(probe.RequestSpec{Method: "OPTIONS", URL: ep.URL}, false)
	if err != nil || optRes.Err != nil {
		return nil
	}
	writeMethod, ok := firstSupportedWriteMethod(optRes.Response)
	if !ok {
		return nil // no PUT/PATCH/DELETE on this route — precondition doesn't apply
	}

	baseline, err := getBaseline(sess, ep)
	if err != nil || baseline.Err != nil || baseline.Response.StatusCode != 200 {
		return nil
	}
	if _, hasETag := baseline.Response.HeaderValue("ETag"); !hasETag {
		return nil // no validator to enforce a precondition against
	}

	res, err := sess.Do(probe.RequestSpec{
		Method: writeMethod,
		URL:    ep.URL,
		Header: map[string][]string{"If-Match": {`"wireaudit-deliberately-stale-etag"`}},
	}, false)
	if err != nil || res.Err != nil {
		return nil
	}

	if res.Response.StatusCode != 412 {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			fmt.Sprintf("a %s sent with a stale If-Match returned %d instead of 412", writeMethod, res.Response.StatusCode),
			"RFC 9110 §13.1.4 expects 412 Precondition Failed when If-Match does not match — without this, concurrent writers can silently clobber each other's changes",
			"validate If-Match against the resource's current ETag before applying a write, and return 412 on mismatch")}
	}
	return nil
}

func firstSupportedWriteMethod(resp *probe.Response) (string, bool) {
	allow, present := resp.HeaderValue("Allow")
	if !present {
		return "", false
	}
	for _, candidate := range []string{"PATCH", "PUT", "DELETE"} {
		if strings.Contains(allow, candidate) {
			return candidate, true
		}
	}
	return "", false
}
