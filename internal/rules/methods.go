package rules

import (
	"context"
	"fmt"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(headMatchesGetRule{})
	Register(optionsReturnsAllowRule{})
	Register(unsupportedMethod405Rule{})
	Register(safeMethodNoBodyRule{})
}

// --- METH-001: head-matches-get ---

type headMatchesGetRule struct{}

func (headMatchesGetRule) ID() string              { return "METH-001" }
func (headMatchesGetRule) Category() string        { return "methods" }
func (headMatchesGetRule) RequiresRawSocket() bool { return true }

// Check uses the raw socket layer for both requests, not net/http: per RFC
// 9110 §9.3.2 a HEAD response body doesn't exist, and net/http's own client
// enforces that by discarding whatever bytes follow the headers — which
// would silently hide exactly the violation this rule exists to catch.
func (r headMatchesGetRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	getRes, err := sess.Do(probe.RequestSpec{Method: "GET", URL: ep.URL}, true)
	if err != nil || getRes.Err != nil {
		return nil
	}
	headRes, err := sess.Do(probe.RequestSpec{Method: "HEAD", URL: ep.URL}, true)
	if err != nil || headRes.Err != nil {
		return nil
	}

	var findings []report.Finding
	if len(headRes.Response.Body) != 0 {
		findings = append(findings, finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("HEAD returned a %d-byte body", len(headRes.Response.Body)),
			"RFC 9110 §9.3.2 requires HEAD responses to have no body — clients that trust Content-Length without discarding the body will misbehave",
			"send identical headers to GET but omit the response body entirely on HEAD"))
	}
	if headRes.Response.StatusCode != getRes.Response.StatusCode {
		findings = append(findings, finding(r.ID(), ep, report.ShouldFix,
			fmt.Sprintf("HEAD returned status %d but GET returned %d for the same resource", headRes.Response.StatusCode, getRes.Response.StatusCode),
			"HEAD is defined to be identical to GET minus the body; a differing status code means clients cannot rely on HEAD to predict GET",
			"ensure HEAD computes the same status and headers GET would return, without serializing the body"))
	}
	return findings
}

// --- METH-002: options-returns-allow ---

type optionsReturnsAllowRule struct{}

func (optionsReturnsAllowRule) ID() string              { return "METH-002" }
func (optionsReturnsAllowRule) Category() string        { return "methods" }
func (optionsReturnsAllowRule) RequiresRawSocket() bool { return false }

func (r optionsReturnsAllowRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := sess.Do(probe.RequestSpec{Method: "OPTIONS", URL: ep.URL}, false)
	if err != nil || res.Err != nil {
		return nil
	}
	if _, present := res.Response.HeaderValue("Allow"); !present {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			"OPTIONS response has no Allow header",
			"RFC 9110 §9.3.7 expects OPTIONS to advertise the methods this resource supports via Allow",
			"set Allow to the list of methods this route accepts when responding to OPTIONS")}
	}
	return nil
}

// --- METH-003: unsupported-method-405 ---

type unsupportedMethod405Rule struct{}

func (unsupportedMethod405Rule) ID() string              { return "METH-003" }
func (unsupportedMethod405Rule) Category() string        { return "methods" }
func (unsupportedMethod405Rule) RequiresRawSocket() bool { return false }

// probeMethod is an unusual-but-valid method unlikely to be intentionally
// supported by any tested endpoint, used to probe 405 handling.
const probeMethod = "PROPFIND"

func (r unsupportedMethod405Rule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := sess.Do(probe.RequestSpec{Method: probeMethod, URL: ep.URL}, false)
	if err != nil || res.Err != nil {
		return nil
	}
	if res.Response.StatusCode == 404 || res.Response.StatusCode >= 500 {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("an unsupported method on an existing route returned %d instead of 405", res.Response.StatusCode),
			"RFC 9110 §15.5.6 reserves 405 specifically for method-not-supported on a resource that exists; 404/5xx here mislead clients about resource existence",
			"return 405 with an Allow header listing the supported methods when a recognized route receives an unsupported method")}
	}
	if res.Response.StatusCode == 405 {
		if _, present := res.Response.HeaderValue("Allow"); !present {
			return []report.Finding{finding(r.ID(), ep, report.MustFix,
				"405 response has no Allow header",
				"RFC 9110 §15.5.6 requires Allow on a 405 so the client can discover which methods are actually supported",
				"include an Allow header listing supported methods on every 405 response")}
		}
	}
	return nil
}

// --- METH-004: safe-method-no-required-body ---

type safeMethodNoBodyRule struct{}

func (safeMethodNoBodyRule) ID() string              { return "METH-004" }
func (safeMethodNoBodyRule) Category() string        { return "methods" }
func (safeMethodNoBodyRule) RequiresRawSocket() bool { return false }

func (r safeMethodNoBodyRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := sess.Do(probe.RequestSpec{Method: "GET", URL: ep.URL}, false)
	if err != nil || res.Err != nil {
		return nil
	}
	if res.Response.StatusCode == 411 || res.Response.StatusCode == 400 {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			fmt.Sprintf("GET without a request body returned %d", res.Response.StatusCode),
			"RFC 9110 §9.3.1 does not require a body on GET; rejecting a bodyless GET breaks ordinary clients",
			"accept GET requests with no request body")}
	}
	return nil
}
