package rules

import (
	"context"
	"mime"
	"net/url"
	"strings"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(errorUsesProblemDetailsRule{})
}

// unknownPathSegment is a path no real API is expected to serve; requesting
// it elicits the target's own "not found" error body without touching any
// real resource.
const unknownPathSegment = "/wireaudit-probe-nonexistent-resource"

// problemJSONType is the RFC 9457 media type for machine-readable errors.
const problemJSONType = "application/problem+json"

// --- ERR-001: error-uses-problem-details ---

type errorUsesProblemDetailsRule struct{}

func (errorUsesProblemDetailsRule) ID() string              { return "ERR-001" }
func (errorUsesProblemDetailsRule) Category() string        { return "errors" }
func (errorUsesProblemDetailsRule) RequiresRawSocket() bool { return false }

func (r errorUsesProblemDetailsRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	probeURL, ok := unknownResourceURL(ep.URL)
	if !ok {
		return nil
	}
	res, err := sess.Do(probe.RequestSpec{Method: "GET", URL: probeURL}, false)
	if err != nil || res.Err != nil {
		return nil
	}
	resp := res.Response
	// Skip catch-all targets (SPA fallbacks return 200) and error responses
	// with no body: there is no error representation to judge.
	if !isClientError(resp.StatusCode) || len(resp.Body) == 0 {
		return nil
	}
	contentType, _ := resp.HeaderValue("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(contentType)
	if parseErr == nil && strings.EqualFold(mediaType, problemJSONType) {
		return nil
	}
	return []report.Finding{finding(r.ID(), ep, report.Consider,
		"error response to an unknown resource is not application/problem+json (got \""+mediaType+"\")",
		"RFC 9457 defines application/problem+json as the standard machine-readable error format; a bespoke error shape forces every client to special-case this API",
		"return errors as application/problem+json with type, title, status and detail members, including for framework-generated errors such as 404 and 405")}
}

// unknownResourceURL derives, from a target URL, a same-origin URL for a
// path that should not exist. Query and fragment are dropped so no
// caller-supplied parameters leak into the probe.
func unknownResourceURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	u.Path = unknownPathSegment
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), true
}
