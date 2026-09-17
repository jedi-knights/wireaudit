package rules

import (
	"context"
	"fmt"
	"net/url"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(duplicateContentLengthRule{})
	Register(contentLengthTEConflictRule{})
	Register(obsFoldRule{})
	Register(crlfInjectionRule{})
}

// requestLine renders the request-line + Host header shared by every raw
// HDR-* payload below.
func requestLine(ep probe.Endpoint, extraHeaders string) (string, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return "", fmt.Errorf("headersyntax: parsing endpoint URL: %w", err)
	}
	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n%s", ep.Method, u.RequestURI(), u.Host, extraHeaders), nil
}

// doRaw sends payload verbatim through sess and returns the resulting
// probe.Result, or a synthetic zero-value result if the send itself failed
// (e.g. connection refused) — a refused connection is not itself a finding,
// so callers treat res.Err != nil as "inconclusive," not "violation."
func doRaw(sess *probe.Session, ep probe.Endpoint, payload string) (probe.Result, error) {
	return sess.Do(probe.RequestSpec{
		Method:      ep.Method,
		URL:         ep.URL,
		RawOverride: []byte(payload),
	}, true)
}

// --- HDR-001: duplicate-content-length ---

type duplicateContentLengthRule struct{}

func (duplicateContentLengthRule) ID() string              { return "HDR-001" }
func (duplicateContentLengthRule) Category() string        { return "header-syntax" }
func (duplicateContentLengthRule) RequiresRawSocket() bool { return true }

func (r duplicateContentLengthRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	body := "a=1"
	headers, err := requestLine(ep, fmt.Sprintf("Content-Length: %d\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), len(body)+7, body))
	if err != nil {
		return nil
	}

	res, sendErr := doRaw(sess, ep, headers)
	if sendErr != nil || res.Err != nil {
		return nil
	}

	if !isClientError(res.Response.StatusCode) {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("sent two differing Content-Length header lines and received %d instead of a 4xx rejection", res.Response.StatusCode),
			"a server that silently picks one of two conflicting Content-Length values enables request/response smuggling in front-end/back-end deployments that disagree on which one to trust",
			"reject requests carrying multiple Content-Length header lines with differing values (RFC 9112 §6.3)")}
	}
	return nil
}

// --- HDR-002: content-length-te-conflict ---

type contentLengthTEConflictRule struct{}

func (contentLengthTEConflictRule) ID() string              { return "HDR-002" }
func (contentLengthTEConflictRule) Category() string        { return "header-syntax" }
func (contentLengthTEConflictRule) RequiresRawSocket() bool { return true }

func (r contentLengthTEConflictRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	chunkedBody := "3\r\nabc\r\n0\r\n\r\n"
	headers, err := requestLine(ep, fmt.Sprintf("Content-Length: 3\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%s", chunkedBody))
	if err != nil {
		return nil
	}

	res, sendErr := doRaw(sess, ep, headers)
	if sendErr != nil || res.Err != nil {
		return nil
	}

	if !isClientError(res.Response.StatusCode) {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("sent both Content-Length and Transfer-Encoding: chunked and received %d instead of a 4xx rejection", res.Response.StatusCode),
			"accepting both framing headers on one request is the classic HTTP request-smuggling vector when a proxy and origin disagree on which one governs body length",
			"reject requests that carry both Content-Length and Transfer-Encoding: chunked (RFC 9112 §6.3)")}
	}
	return nil
}

// --- HDR-003: obs-fold-rejection ---

type obsFoldRule struct{}

func (obsFoldRule) ID() string              { return "HDR-003" }
func (obsFoldRule) Category() string        { return "header-syntax" }
func (obsFoldRule) RequiresRawSocket() bool { return true }

func (r obsFoldRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	// "X-Wireaudit-Fold: foo" continued via an obsolete line-fold onto a
	// second physical line, which RFC 9112 §5.2 forbids generating and
	// requires recipients to either reject or correctly unfold.
	headers, err := requestLine(ep, "X-Wireaudit-Fold: foo\r\n bar\r\nConnection: close\r\n\r\n")
	if err != nil {
		return nil
	}

	res, sendErr := doRaw(sess, ep, headers)
	if sendErr != nil {
		return nil
	}
	if res.Err != nil {
		// The connection was refused or reset outright — a parser crash on
		// malformed framing, which is worse than a clean rejection.
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			fmt.Sprintf("connection failed while sending an obsolete line-folded header: %v", res.Err),
			"a parser that crashes or drops the connection on obs-fold, rather than cleanly rejecting or unfolding it, is fragile input handling",
			"reject obs-folded header lines with a 400, or correctly unfold them per RFC 9112 §5.2")}
	}

	if isServerError(res.Response.StatusCode) {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			fmt.Sprintf("an obsolete line-folded header produced a %d server error instead of a clean 4xx rejection or correct unfolding", res.Response.StatusCode),
			"a 5xx on malformed-but-recognizable input suggests the header parser is not defensively handling obs-fold",
			"reject obs-folded header lines with a 400, or correctly unfold them per RFC 9112 §5.2")}
	}
	return nil
}

// --- HDR-004: crlf-injection-resistance ---

type crlfInjectionRule struct{}

func (crlfInjectionRule) ID() string              { return "HDR-004" }
func (crlfInjectionRule) Category() string        { return "header-syntax" }
func (crlfInjectionRule) RequiresRawSocket() bool { return true }

const crlfInjectionMarker = "X-Wireaudit-Injected"

func (r crlfInjectionRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil
	}
	// Common reflection sinks (redirect targets, callback URLs) sometimes
	// echo a query parameter into a response header verbatim. Probe with a
	// CRLF-encoded attempt to inject a marker header via each candidate
	// parameter name; net/http would refuse to send this raw, so this check
	// always uses the raw socket layer.
	injected := "http://example.invalid%0d%0a" + crlfInjectionMarker + ":pwned"
	q := u.Query()
	for _, param := range []string{"redirect", "next", "url", "callback"} {
		q.Set(param, injected)
	}
	u.RawQuery = q.Encode()

	probeEP := probe.Endpoint{Method: ep.Method, URL: u.String()}
	headers, err := requestLine(probeEP, "Connection: close\r\n\r\n")
	if err != nil {
		return nil
	}

	res, sendErr := doRaw(sess, probeEP, headers)
	if sendErr != nil || res.Err != nil {
		return nil
	}

	if _, present := res.Response.HeaderValue(crlfInjectionMarker); present {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			"a CRLF sequence embedded in a query parameter was reflected into the response as a new header",
			"this is HTTP response splitting / header injection — an attacker can forge additional headers or a full second response",
			"URL-encode or reject CRLF and other control characters in any user-supplied value before it reaches a response header (RFC 9110 §5.5)")}
	}
	return nil
}
