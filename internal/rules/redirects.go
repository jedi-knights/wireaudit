package rules

import (
	"context"
	"fmt"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(redirectHasLocationRule{})
	Register(redirectBodyPreservationRule{})
}

func isRedirectStatus(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// --- REDIR-001: 3xx-has-location ---

type redirectHasLocationRule struct{}

func (redirectHasLocationRule) ID() string              { return "REDIR-001" }
func (redirectHasLocationRule) Category() string        { return "redirects" }
func (redirectHasLocationRule) RequiresRawSocket() bool { return false }

func (r redirectHasLocationRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil {
		return nil
	}
	if !isRedirectStatus(res.Response.StatusCode) {
		return nil
	}
	if _, present := res.Response.HeaderValue("Location"); !present {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("a %d response has no Location header", res.Response.StatusCode),
			"RFC 9110 §10.2.2 requires Location on 3xx redirects; without it, clients have no target to follow",
			"set Location to the redirect target on every 3xx response")}
	}
	return nil
}

// --- REDIR-002: redirect-body-preservation ---

type redirectBodyPreservationRule struct{}

func (redirectBodyPreservationRule) ID() string              { return "REDIR-002" }
func (redirectBodyPreservationRule) Category() string        { return "redirects" }
func (redirectBodyPreservationRule) RequiresRawSocket() bool { return false }

func (r redirectBodyPreservationRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil {
		return nil
	}
	status := res.Response.StatusCode
	if !isRedirectStatus(status) {
		return nil
	}
	loc, present := res.Response.HeaderValue("Location")
	if !present {
		return nil // REDIR-001 already covers the missing-Location case
	}

	// 303 must be followed with GET regardless of the original method;
	// 307/308 must preserve the original method and body. This is only
	// checkable when the original request itself was not already GET.
	if ep.Method == "GET" {
		return nil
	}

	followRes, err := sess.Do(probe.RequestSpec{Method: ep.Method, URL: loc, Body: []byte("{}")}, false)
	if err != nil || followRes.Err != nil {
		return nil
	}

	if status == 307 || status == 308 {
		if followRes.Response.StatusCode == 405 {
			return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
				fmt.Sprintf("following a %d redirect with the original %s method returned 405 at the target", status, ep.Method),
				"RFC 9110 §15.4.8/§15.4.9 requires 307/308 to preserve the original method and body on redirect — the target must accept the same method",
				"ensure the redirect target accepts the same method the client used to reach the redirect")}
		}
	}
	return nil
}
