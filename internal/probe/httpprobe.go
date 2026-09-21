package probe

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"
)

// HTTPClient sends well-formed requests via net/http and captures the
// negotiated TLS state alongside the response. Requests that need
// deliberately malformed framing must use Client (the raw-socket layer)
// instead — net/http's Transport normalizes or rejects that malformation
// before it reaches the wire. Safe for concurrent use: TLS state is captured
// per-request via httptrace rather than a shared struct field, since
// multiple Sessions probing different endpoints may share one HTTPClient.
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient builds an HTTPClient with a fixed timeout. CheckRedirect
// returns http.ErrUseLastResponse so each redirect hop is captured
// individually rather than silently followed, which also prevents a
// redirect-after-allowlist pivot to an internal host. insecureSkipVerify must
// only ever be true when the caller passed an explicit opt-in flag.
func NewHTTPClient(timeout time.Duration, insecureSkipVerify bool) *HTTPClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec — explicit opt-in flag only, never the default; see NewHTTPClient doc comment.
		},
	}
	return &HTTPClient{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Do sends spec and returns the captured Result. RawOverride is not honored
// here — callers needing raw framing must use the raw-socket layer.
func (c *HTTPClient) Do(spec RequestSpec) Result {
	var body io.Reader
	if len(spec.Body) > 0 {
		body = bytes.NewReader(spec.Body)
	}

	req, err := http.NewRequest(spec.Method, spec.URL, body)
	if err != nil {
		return NewResult(spec, nil, nil, 0, fmt.Errorf("probe: building request: %w", err))
	}
	for name, values := range spec.Header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	var tlsState *tls.ConnectionState
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			tlsState = &state
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	start := time.Now()
	resp, err := c.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return NewResult(spec, nil, nil, elapsed, fmt.Errorf("probe: sending request: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	// io.ReadAll returns whatever bytes it read even when it also returns an
	// error — a body shorter than a declared Content-Length surfaces exactly
	// this way (io.ErrUnexpectedEOF). That truncation is itself the
	// violation RESP-003 exists to catch, so it must reach the rule as a
	// Response with a short body, not be swallowed here as a probe failure.
	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil && len(respBody) == 0 {
		return NewResult(spec, nil, nil, elapsed, fmt.Errorf("probe: reading response body: %w", readErr))
	}

	return NewResult(spec, toProbeResponse(resp, respBody), tlsState, elapsed, nil)
}

func toProbeResponse(resp *http.Response, body []byte) *Response {
	fields := make([]HeaderField, 0, len(resp.Header))
	for name, values := range resp.Header {
		for _, v := range values {
			fields = append(fields, HeaderField{Name: name, Value: v})
		}
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     fields,
		Body:       body,
	}
}
