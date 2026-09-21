package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RawClient sends requests over a raw net.Conn, bypassing net/http's request
// validation entirely. It is used exclusively by the header-syntax checks
// (HDR-001..004), which need to emit framing net/http would normalize or
// refuse to send: duplicate Content-Length lines, obsolete line-folding, or
// raw CRLF inside a header value.
type RawClient struct {
	timeout time.Duration
}

// NewRawClient builds a RawClient with a fixed dial/read timeout.
func NewRawClient(timeout time.Duration) *RawClient {
	return &RawClient{timeout: timeout}
}

// Do sends spec and returns the captured Result. If spec.RawOverride is set,
// those bytes are written to the wire verbatim; otherwise a request is
// assembled from Method/URL/Header/Body using unvalidated string
// concatenation (deliberately — this layer's entire purpose is to bypass
// validation).
func (c *RawClient) Do(spec RequestSpec) Result {
	u, err := url.Parse(spec.URL)
	if err != nil {
		return NewResult(spec, nil, nil, 0, fmt.Errorf("probe: parsing target URL: %w", err))
	}

	start := time.Now()
	conn, tlsState, err := c.dial(u)
	if err != nil {
		return NewResult(spec, nil, nil, time.Since(start), fmt.Errorf("probe: dialing: %w", err))
	}
	defer func() { _ = conn.Close() }()

	payload := spec.RawOverride
	if len(payload) == 0 {
		payload = buildRawRequest(spec, u)
	}

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return NewResult(spec, nil, nil, time.Since(start), fmt.Errorf("probe: setting deadline: %w", err))
	}
	if _, err := conn.Write(payload); err != nil {
		return NewResult(spec, nil, nil, time.Since(start), fmt.Errorf("probe: writing request: %w", err))
	}

	resp, raw, err := readRawResponse(conn)
	elapsed := time.Since(start)
	if err != nil {
		return NewResult(spec, nil, tlsState, elapsed, fmt.Errorf("probe: reading response: %w", err))
	}
	resp.Raw = raw
	return NewResult(spec, resp, tlsState, elapsed, nil)
}

func (c *RawClient) dial(u *url.URL) (net.Conn, *tls.ConnectionState, error) {
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}

	dialer := net.Dialer{Timeout: c.timeout}
	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, nil, err
	}

	if u.Scheme != "https" {
		return conn, nil, nil
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname()}) //nolint:gosec — no InsecureSkipVerify override here; raw layer always verifies.
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	state := tlsConn.ConnectionState()
	return tlsConn, &state, nil
}

// buildRawRequest hand-assembles request bytes without validation, so a
// caller can populate spec.Header with values net/http would reject.
func buildRawRequest(spec RequestSpec, u *url.URL) []byte {
	var b strings.Builder
	path := u.RequestURI()
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", spec.Method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	for name, values := range spec.Header {
		for _, v := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(spec.Body))
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.Write(spec.Body)
	return []byte(b.String())
}

// readRawResponse parses a response with no normalization: header order,
// duplicates, and raw casing are all preserved exactly as received.
func readRawResponse(conn net.Conn) (*Response, []byte, error) {
	r := bufio.NewReader(conn)
	var raw strings.Builder

	statusLine, err := readLine(r, &raw)
	if err != nil {
		return nil, nil, fmt.Errorf("reading status line: %w", err)
	}
	statusCode, err := parseStatusCode(statusLine)
	if err != nil {
		return nil, nil, err
	}

	var headers []HeaderField
	contentLength := -1
	for {
		line, err := readLine(r, &raw)
		if err != nil {
			return nil, nil, fmt.Errorf("reading headers: %w", err)
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		headers = append(headers, HeaderField{Name: name, Value: value})
		if equalFoldASCII(name, "Content-Length") {
			if n, err := strconv.Atoi(value); err == nil {
				contentLength = n
			}
		}
	}

	var body []byte
	if contentLength > 0 {
		body = make([]byte, contentLength)
		if _, err := readFull(r, body, &raw); err != nil {
			return nil, nil, fmt.Errorf("reading body: %w", err)
		}
	}

	return &Response{StatusCode: statusCode, Header: headers, Body: body}, []byte(raw.String()), nil
}

func readLine(r *bufio.Reader, raw *strings.Builder) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	raw.WriteString(line)
	return strings.TrimRight(line, "\r\n"), nil
}

func readFull(r *bufio.Reader, buf []byte, raw *strings.Builder) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		raw.Write(buf[n-m : n])
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func parseStatusCode(statusLine string) (int, error) {
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed status line %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("malformed status code in %q: %w", statusLine, err)
	}
	return code, nil
}
