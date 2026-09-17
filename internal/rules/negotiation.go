package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(acceptHandledGracefullyRule{})
	Register(varyPresentRule{})
	Register(contentTypeMatchesAcceptRule{})
}

// --- NEG-001: accept-handled-gracefully ---

type acceptHandledGracefullyRule struct{}

func (acceptHandledGracefullyRule) ID() string              { return "NEG-001" }
func (acceptHandledGracefullyRule) Category() string        { return "negotiation" }
func (acceptHandledGracefullyRule) RequiresRawSocket() bool { return false }

func (r acceptHandledGracefullyRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := sess.Do(probe.RequestSpec{
		Method: ep.Method,
		URL:    ep.URL,
		Header: map[string][]string{"Accept": {"application/x-wireaudit-bogus-media-type"}},
	}, false)
	if err != nil || res.Err != nil {
		return nil
	}
	if isServerError(res.Response.StatusCode) {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("an unrecognized Accept value produced a %d server error", res.Response.StatusCode),
			"RFC 9110 §12.5.1/§15.5.7 expects a 406 or a graceful default representation for unsatisfiable Accept, never a server error",
			"return 406 Not Acceptable or fall back to a default representation when Accept cannot be satisfied")}
	}
	return nil
}

// --- NEG-002: vary-present ---

type varyPresentRule struct{}

func (varyPresentRule) ID() string              { return "NEG-002" }
func (varyPresentRule) Category() string        { return "negotiation" }
func (varyPresentRule) RequiresRawSocket() bool { return false }

func (r varyPresentRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	jsonRes, err := sess.Do(probe.RequestSpec{
		Method: ep.Method,
		URL:    ep.URL,
		Header: map[string][]string{"Accept": {"application/json"}},
	}, false)
	if err != nil || jsonRes.Err != nil || jsonRes.Response.StatusCode != 200 {
		return nil
	}
	xmlRes, err := sess.Do(probe.RequestSpec{
		Method: ep.Method,
		URL:    ep.URL,
		Header: map[string][]string{"Accept": {"application/xml"}},
	}, false)
	if err != nil || xmlRes.Err != nil {
		return nil
	}

	jsonType, _ := jsonRes.Response.HeaderValue("Content-Type")
	xmlType, _ := xmlRes.Response.HeaderValue("Content-Type")
	if jsonType == xmlType {
		return nil // response doesn't actually vary by Accept — Vary isn't required
	}

	if _, present := jsonRes.Response.HeaderValue("Vary"); !present {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			"response content type varies by Accept but no Vary header is set",
			"RFC 9110 §12.5.5 requires Vary so shared caches key on the same request headers the origin used to select a representation",
			"set Vary: Accept (and any other headers used for negotiation) whenever the response varies by request headers")}
	}
	return nil
}

// --- NEG-003: content-type-matches-accept ---

type contentTypeMatchesAcceptRule struct{}

func (contentTypeMatchesAcceptRule) ID() string              { return "NEG-003" }
func (contentTypeMatchesAcceptRule) Category() string        { return "negotiation" }
func (contentTypeMatchesAcceptRule) RequiresRawSocket() bool { return false }

func (r contentTypeMatchesAcceptRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	jsonRes, err := sess.Do(probe.RequestSpec{
		Method: ep.Method,
		URL:    ep.URL,
		Header: map[string][]string{"Accept": {"application/json"}},
	}, false)
	if err != nil || jsonRes.Err != nil {
		return nil
	}
	var findings []report.Finding
	if jsonRes.Response.StatusCode == 200 {
		ct, _ := jsonRes.Response.HeaderValue("Content-Type")
		if !strings.Contains(ct, "json") {
			findings = append(findings, finding(r.ID(), ep, report.MustFix,
				fmt.Sprintf("requested Accept: application/json but received Content-Type: %q", ct),
				"RFC 9110 §12.5.1 negotiates the representation via Accept; returning a mismatched Content-Type breaks clients that parse the body based on what they asked for",
				"return a representation whose Content-Type actually matches the negotiated Accept value"))
		}
	}

	bogusRes, err := sess.Do(probe.RequestSpec{
		Method: ep.Method,
		URL:    ep.URL,
		Header: map[string][]string{"Accept": {"application/x-wireaudit-bogus-media-type"}},
	}, false)
	if err == nil && bogusRes.Err == nil && bogusRes.Response.StatusCode == 200 {
		ct, _ := bogusRes.Response.HeaderValue("Content-Type")
		if ct == "application/x-wireaudit-bogus-media-type" {
			findings = append(findings, finding(r.ID(), ep, report.MustFix,
				"an unsupported Accept media type was echoed back as the response Content-Type",
				"RFC 9110 §8.3 requires Content-Type to describe the actual body sent; echoing an unsatisfiable Accept value verbatim means the declared type doesn't describe the real representation",
				"return 406, or fall back to a real supported representation with a Content-Type that matches what was actually sent"))
		}
	}
	return findings
}
