package probe

import "fmt"

// MaxRequestsPerRule bounds how many requests a single Rule may issue
// through one Session. Sequenced rules (e.g. a conditional GET that depends
// on a baseline GET's ETag) drive this loop from the target's own responses,
// which are external input — per the project's bounded-loop convention, the
// cap must be a named constant a reader can point to, not an unbounded
// while-loop trusting the target to behave.
const MaxRequestsPerRule = 5

// Session wraps the two transport layers behind one bounded, sequential
// request API so a Rule can issue a chain of dependent requests (baseline
// GET, then a conditional follow-up) without knowing which transport
// serviced any individual call.
type Session struct {
	http           *HTTPClient
	raw            *RawClient
	sent           int
	endpoint       Endpoint
	defaultHeaders map[string][]string
}

// NewSession builds a Session for one target Endpoint. defaultHeaders (e.g.
// a caller-supplied Authorization header) are merged into every RequestSpec
// sent through Do, alongside — not replacing — any header the spec itself
// sets for that name.
func NewSession(endpoint Endpoint, httpClient *HTTPClient, rawClient *RawClient, defaultHeaders map[string][]string) *Session {
	return &Session{endpoint: endpoint, http: httpClient, raw: rawClient, defaultHeaders: defaultHeaders}
}

// Do sends spec through whichever transport layer the request needs —
// RawOverride or a spec targeting deliberately malformed framing goes
// through the raw socket layer; everything else goes through net/http. It
// returns an error, rather than sending, once MaxRequestsPerRule has been
// reached.
func (s *Session) Do(spec RequestSpec, requiresRaw bool) (Result, error) {
	if s.sent >= MaxRequestsPerRule {
		return Result{}, fmt.Errorf("probe: session for %s exceeded MaxRequestsPerRule (%d)", s.endpoint.Locator(), MaxRequestsPerRule)
	}
	s.sent++
	spec.Header = mergeHeaders(s.defaultHeaders, spec.Header)

	if requiresRaw || len(spec.RawOverride) > 0 {
		return s.raw.Do(spec), nil
	}
	return s.http.Do(spec), nil
}

// mergeHeaders combines defaults with overrides, letting overrides add to
// (not silently replace) any default value for the same header name.
func mergeHeaders(defaults, overrides map[string][]string) map[string][]string {
	if len(defaults) == 0 {
		return overrides
	}
	merged := make(map[string][]string, len(defaults)+len(overrides))
	for name, values := range defaults {
		merged[name] = append(merged[name], values...)
	}
	for name, values := range overrides {
		merged[name] = append(merged[name], values...)
	}
	return merged
}
