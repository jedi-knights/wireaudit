// Package probe sends HTTP/HTTPS requests to a target and captures the raw
// response envelope that rules inspect. It has two transport layers: a
// net/http-based layer for well-formed requests, and a raw net.Conn layer for
// requests that deliberately violate HTTP framing (net/http's Transport
// normalizes or rejects that malformation before it reaches the wire).
package probe

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"time"
)

// Endpoint identifies one method+URL pair a Rule probes. Rules receive an
// Endpoint rather than a bare locator string so they can build follow-up
// RequestSpecs (e.g. a conditional GET reusing the baseline GET's URL)
// without re-parsing a display string.
type Endpoint struct {
	Method string
	URL    string
}

// Locator renders the report locator: "METHOD path" (query/fragment
// stripped for readability).
func (e Endpoint) Locator() string {
	if u, err := url.Parse(e.URL); err == nil {
		return fmt.Sprintf("%s %s", e.Method, u.Path)
	}
	return fmt.Sprintf("%s %s", e.Method, e.URL)
}

// RequestSpec describes one request a Rule wants to send.
type RequestSpec struct {
	// Method is the HTTP method, e.g. "GET".
	Method string
	// URL is the absolute target URL.
	URL string
	// Header is the set of headers to send, in addition to any the transport
	// adds automatically (e.g. Host).
	Header map[string][]string
	// Body is the raw request body, or nil for no body.
	Body []byte
	// RawOverride, when non-empty, is sent verbatim over the wire instead of
	// a request built from Method/URL/Header/Body. Only honored by the raw
	// transport layer — used by header-syntax checks (HDR-001..004) that need
	// to emit deliberately malformed framing.
	RawOverride []byte
}

// Response captures a received HTTP response without further normalization
// beyond what the originating transport layer performed.
type Response struct {
	// StatusCode is the parsed status code.
	StatusCode int
	// Header is every header line as received, preserving duplicates and
	// original casing — callers needing case-insensitive lookup use
	// Response.HeaderValues.
	Header []HeaderField
	// Body is the received response body.
	Body []byte
	// Raw is the complete raw response bytes, when captured by the raw
	// transport layer; nil for net/http-layer responses.
	Raw []byte
}

// HeaderField is one header line exactly as received.
type HeaderField struct {
	Name  string
	Value string
}

// HeaderValues returns every value for a header name, matched
// case-insensitively per RFC 9110 §5.1.
func (r *Response) HeaderValues(name string) []string {
	var out []string
	for _, h := range r.Header {
		if equalFoldASCII(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

// HeaderValue returns the first value for a header name, and whether it was
// present at all.
func (r *Response) HeaderValue(name string) (string, bool) {
	vals := r.HeaderValues(name)
	if len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Result is the envelope every transport layer produces, regardless of
// whether it used the net/http or raw-socket path. Rules consume only this
// type and never know which layer produced it.
type Result struct {
	Request  RequestSpec
	Response *Response
	TLS      *tls.ConnectionState
	Timing   time.Duration
	Err      error
}

// NewResult builds a Result, enforcing the invariant that exactly one of
// Response or Err is set — a probe never silently produces neither, and
// never produces both.
func NewResult(req RequestSpec, resp *Response, tlsState *tls.ConnectionState, timing time.Duration, err error) Result {
	if (resp == nil) == (err == nil) {
		panic(fmt.Sprintf("probe: invariant violated for %s %s: exactly one of Response/Err must be set", req.Method, req.URL))
	}
	return Result{Request: req, Response: resp, TLS: tlsState, Timing: timing, Err: err}
}
