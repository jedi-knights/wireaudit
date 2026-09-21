package rules

import (
	"context"
	"fmt"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(dateHeaderPresentRule{})
	Register(contentTypePresentRule{})
	Register(contentLengthMatchesBodyRule{})
}

func getBaseline(sess *probe.Session, ep probe.Endpoint) (probe.Result, error) {
	return sess.Do(probe.RequestSpec{Method: ep.Method, URL: ep.URL}, false)
}

// --- RESP-001: date-header-present ---

type dateHeaderPresentRule struct{}

func (dateHeaderPresentRule) ID() string              { return "RESP-001" }
func (dateHeaderPresentRule) Category() string        { return "response-headers" }
func (dateHeaderPresentRule) RequiresRawSocket() bool { return false }

func (r dateHeaderPresentRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil {
		return nil
	}
	if res.Response.StatusCode >= 100 && res.Response.StatusCode < 200 {
		return nil
	}
	if res.Response.StatusCode >= 500 {
		return nil
	}
	if _, present := res.Response.HeaderValue("Date"); !present {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			"response has no Date header",
			"RFC 9110 §6.6.1 expects a Date header on origin-server responses; its absence breaks age calculation for shared caches",
			"set the Date header to the current time on every response")}
	}
	return nil
}

// --- RESP-002: content-type-present-matches-body ---

type contentTypePresentRule struct{}

func (contentTypePresentRule) ID() string              { return "RESP-002" }
func (contentTypePresentRule) Category() string        { return "response-headers" }
func (contentTypePresentRule) RequiresRawSocket() bool { return false }

func (r contentTypePresentRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil {
		return nil
	}
	if len(res.Response.Body) == 0 {
		return nil
	}
	if _, present := res.Response.HeaderValue("Content-Type"); !present {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			"response has a body but no Content-Type header",
			"RFC 9110 §8.3 requires Content-Type when a representation is returned; without it, clients must guess the media type",
			"set Content-Type to the actual media type of the response body")}
	}
	return nil
}

// --- RESP-003: content-length-matches-body ---

type contentLengthMatchesBodyRule struct{}

func (contentLengthMatchesBodyRule) ID() string              { return "RESP-003" }
func (contentLengthMatchesBodyRule) Category() string        { return "response-headers" }
func (contentLengthMatchesBodyRule) RequiresRawSocket() bool { return false }

func (r contentLengthMatchesBodyRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil {
		return nil
	}
	declared, present := res.Response.HeaderValue("Content-Length")
	if !present {
		return nil
	}
	actual := len(res.Response.Body)
	if declared != fmt.Sprintf("%d", actual) {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("Content-Length declared %s but the received body was %d bytes", declared, actual),
			"a mismatched Content-Length causes clients and intermediaries to truncate or hang waiting for bytes that never arrive",
			"ensure Content-Length always equals the exact byte length of the response body actually written")}
	}
	return nil
}
