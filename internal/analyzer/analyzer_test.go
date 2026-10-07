package analyzer_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jedi-knights/wireaudit/internal/analyzer"
	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

// rawFixture serves a fixed raw HTTP response over a plain TCP listener, for
// tests that need response bytes net/http's own Server would never produce
// (e.g. a response with genuinely no Date header — net/http.Server always
// injects one, so httptest.Server can't be used for that case).
func rawFixture(t *testing.T, rawResponse string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("rawFixture: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = conn.Write([]byte(rawResponse))
			}()
		}
	}()
	return fmt.Sprintf("http://%s", ln.Addr().String())
}

// rawFixtureByMethod serves a response chosen by respond based on the
// request's HTTP method — used for cases like "HEAD must have no body"
// where net/http.Server itself enforces the correct behavior and so cannot
// be coerced into producing the violating response via httptest.Server.
func rawFixtureByMethod(t *testing.T, respond func(method string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("rawFixtureByMethod: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				requestLine, _ := bufio.NewReader(conn).ReadString('\n')
				method, _, _ := strings.Cut(requestLine, " ")
				_, _ = conn.Write([]byte(respond(method)))
			}()
		}
	}()
	return fmt.Sprintf("http://%s", ln.Addr().String())
}

// findingIDs collects every Finding.CheckID present in rpt, across all
// three buckets, for simple membership assertions.
func findingIDs(rpt *report.Report) map[string]report.Bucket {
	out := make(map[string]report.Bucket)
	for _, f := range rpt.MustFix {
		out[f.CheckID] = f.Bucket
	}
	for _, f := range rpt.ShouldFix {
		out[f.CheckID] = f.Bucket
	}
	for _, f := range rpt.Consider {
		out[f.CheckID] = f.Bucket
	}
	return out
}

func runAgainst(t *testing.T, srv *httptest.Server, opts ...func(*analyzer.Config)) *report.Report {
	t.Helper()
	cfg := analyzer.Config{
		Endpoints: []probe.Endpoint{{Method: "GET", URL: srv.URL + "/"}},
		Timeout:   5 * time.Second,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	rpt, err := analyzer.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("analyzer.Run: %v", err)
	}
	return rpt
}

func TestDateHeaderMissing_FlagsRESP001(t *testing.T) {
	// net/http.Server always injects its own Date header, so this fixture
	// must bypass it entirely and hand-write a response with none.
	target := rawFixture(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	cfg := analyzer.Config{
		Endpoints: []probe.Endpoint{{Method: "GET", URL: target + "/"}},
		Timeout:   5 * time.Second,
	}
	rpt, err := analyzer.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("analyzer.Run: %v", err)
	}

	ids := findingIDs(rpt)
	if bucket, ok := ids["RESP-001"]; !ok || bucket != report.ShouldFix {
		t.Errorf("expected RESP-001 in ShouldFix, got %v (present=%v)", bucket, ok)
	}
}

func TestContentLengthMismatch_FlagsRESP003(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short body"))
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["RESP-003"]; !ok || bucket != report.MustFix {
		t.Errorf("expected RESP-003 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

func TestHeadReturnsBody_FlagsMETH001(t *testing.T) {
	// net/http.Server itself suppresses any body a handler writes for a HEAD
	// request, so the violation must be produced via a raw fixture instead.
	target := rawFixtureByMethod(t, func(method string) string {
		if method == http.MethodHead {
			return "HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\nthis should not be here!"
		}
		return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	})

	cfg := analyzer.Config{
		Endpoints: []probe.Endpoint{{Method: "GET", URL: target + "/"}},
		Timeout:   5 * time.Second,
	}
	rpt, err := analyzer.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("analyzer.Run: %v", err)
	}

	ids := findingIDs(rpt)
	if bucket, ok := ids["METH-001"]; !ok || bucket != report.MustFix {
		t.Errorf("expected METH-001 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

func TestUnsupportedMethodReturns404_FlagsMETH003(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["METH-003"]; !ok || bucket != report.MustFix {
		t.Errorf("expected METH-003 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

// etagFixture is a stateful handler used to prove both CACHE-002 (true
// positive: a matching validator gets 304) and CACHE-004 (false-negative
// avoidance: a non-matching validator does NOT get 304) against the same
// resource, per the plan's shared-fixture testing strategy.
func etagFixture(t *testing.T, alwaysNotModified bool) *httptest.Server {
	t.Helper()
	const etag = `"fixture-etag-v1"`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		inm := r.Header.Get("If-None-Match")
		if inm != "" {
			if alwaysNotModified || inm == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("resource body"))
	}))
}

func TestConditionalGetMatchingValidator_FlagsCACHE002IfNotHonored(t *testing.T) {
	// A fixture that NEVER honors If-None-Match — CACHE-002's true-positive
	// case must fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"fixture-etag-v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("resource body"))
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["CACHE-002"]; !ok || bucket != report.MustFix {
		t.Errorf("expected CACHE-002 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

func TestConditionalGetMatchingValidator_CACHE002ClearWhenHonored(t *testing.T) {
	srv := etagFixture(t, false)
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if _, ok := ids["CACHE-002"]; ok {
		t.Errorf("expected no CACHE-002 finding when the fixture correctly honors If-None-Match")
	}
}

func TestConditionalGetNonMatchingValidator_FlagsCACHE004(t *testing.T) {
	// A fixture that ALWAYS returns 304 regardless of validator match —
	// CACHE-004's false-negative-avoidance case must fire.
	srv := etagFixture(t, true)
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["CACHE-004"]; !ok || bucket != report.MustFix {
		t.Errorf("expected CACHE-004 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

func TestRedirectMissingLocation_FlagsREDIR001(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["REDIR-001"]; !ok || bucket != report.MustFix {
		t.Errorf("expected REDIR-001 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

func TestUnacceptableAcceptCauses500_FlagsNEG001(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "application/x-wireaudit-bogus-media-type" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["NEG-001"]; !ok || bucket != report.MustFix {
		t.Errorf("expected NEG-001 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

func TestBogusAcceptEchoedAsContentType_FlagsNEG003(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		w.Header().Set("Content-Type", accept)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["NEG-003"]; !ok || bucket != report.MustFix {
		t.Errorf("expected NEG-003 in MustFix, got %v (present=%v)", bucket, ok)
	}
}

func TestCacheControlContradiction_FlagsCACHE003(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=3600")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv)
	ids := findingIDs(rpt)
	if bucket, ok := ids["CACHE-003"]; !ok || bucket != report.ShouldFix {
		t.Errorf("expected CACHE-003 in ShouldFix, got %v (present=%v)", bucket, ok)
	}
}

// TestUnsafeWriteFixture proves CACHE-005 only evaluates when
// AllowUnsafeWrites is explicitly set, and only when the endpoint both
// supports a write method and returns a validator (the "skipped, not
// failed" precondition from the plan).
func TestUnsafeWriteFixture(t *testing.T) {
	newFixture := func(honorsIfMatch bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodOptions:
				w.Header().Set("Allow", "GET, PUT, OPTIONS")
				w.WriteHeader(http.StatusNoContent)
			case http.MethodGet:
				w.Header().Set("ETag", `"fixture-etag-v1"`)
				w.WriteHeader(http.StatusOK)
			case http.MethodPut:
				if honorsIfMatch && r.Header.Get("If-Match") != `"fixture-etag-v1"` {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
				w.WriteHeader(http.StatusOK)
			}
		}))
	}

	t.Run("disabled by default", func(t *testing.T) {
		srv := newFixture(false)
		defer srv.Close()
		rpt := runAgainst(t, srv) // AllowUnsafeWrites left false
		if _, ok := findingIDs(rpt)["CACHE-005"]; ok {
			t.Errorf("CACHE-005 must not run unless AllowUnsafeWrites is explicitly true")
		}
	})

	t.Run("flags a server that ignores If-Match", func(t *testing.T) {
		srv := newFixture(false)
		defer srv.Close()
		rpt := runAgainst(t, srv, func(c *analyzer.Config) { c.AllowUnsafeWrites = true })
		if bucket, ok := findingIDs(rpt)["CACHE-005"]; !ok || bucket != report.ShouldFix {
			t.Errorf("expected CACHE-005 in ShouldFix, got %v (present=%v)", bucket, ok)
		}
	})

	t.Run("clean when the server honors If-Match", func(t *testing.T) {
		srv := newFixture(true)
		defer srv.Close()
		rpt := runAgainst(t, srv, func(c *analyzer.Config) { c.AllowUnsafeWrites = true })
		if _, ok := findingIDs(rpt)["CACHE-005"]; ok {
			t.Errorf("expected no CACHE-005 finding when the fixture honors If-Match")
		}
	})
}

func TestCategoryFilter_ExcludesOtherCategories(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusFound) // would normally trigger REDIR-001
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv, func(c *analyzer.Config) {
		c.Categories = map[string]bool{"caching": true}
	})
	if _, ok := findingIDs(rpt)["REDIR-001"]; ok {
		t.Errorf("REDIR-001 should have been excluded by the category filter")
	}
}

func TestExcludeRule_SkipsSpecificCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=3600")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rpt := runAgainst(t, srv, func(c *analyzer.Config) {
		c.ExcludeRules = map[string]bool{"CACHE-003": true}
	})
	if _, ok := findingIDs(rpt)["CACHE-003"]; ok {
		t.Errorf("CACHE-003 should have been excluded via ExcludeRules")
	}
}

func TestUnauthorizedWithoutChallenge_FlagsAUTH001(t *testing.T) {
	t.Run("401 with no WWW-Authenticate is Must Fix", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		rpt := runAgainst(t, srv)
		if bucket, ok := findingIDs(rpt)["AUTH-001"]; !ok || bucket != report.MustFix {
			t.Errorf("expected AUTH-001 in MustFix, got %v (present=%v)", bucket, ok)
		}
	})

	t.Run("401 with a challenge is clean", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		rpt := runAgainst(t, srv)
		if _, ok := findingIDs(rpt)["AUTH-001"]; ok {
			t.Errorf("expected no AUTH-001 finding when WWW-Authenticate is present")
		}
	})

	t.Run("non-401 responses are not judged", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		rpt := runAgainst(t, srv)
		if _, ok := findingIDs(rpt)["AUTH-001"]; ok {
			t.Errorf("expected no AUTH-001 finding for a 403")
		}
	})
}

func TestErrorBodyFormat_FlagsERR001(t *testing.T) {
	notFound := func(contentType, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(body))
		}))
	}

	t.Run("plain-text 404 body is Consider", func(t *testing.T) {
		srv := notFound("text/plain", "not found")
		defer srv.Close()

		rpt := runAgainst(t, srv)
		if bucket, ok := findingIDs(rpt)["ERR-001"]; !ok || bucket != report.Consider {
			t.Errorf("expected ERR-001 in Consider, got %v (present=%v)", bucket, ok)
		}
	})

	t.Run("problem+json 404 body is clean", func(t *testing.T) {
		srv := notFound("application/problem+json; charset=utf-8", `{"type":"about:blank","title":"Not Found","status":404}`)
		defer srv.Close()

		rpt := runAgainst(t, srv)
		if _, ok := findingIDs(rpt)["ERR-001"]; ok {
			t.Errorf("expected no ERR-001 finding for application/problem+json")
		}
	})

	t.Run("empty 404 body is not judged", func(t *testing.T) {
		srv := notFound("", "")
		defer srv.Close()

		rpt := runAgainst(t, srv)
		if _, ok := findingIDs(rpt)["ERR-001"]; ok {
			t.Errorf("expected no ERR-001 finding when the error has no body")
		}
	})

	t.Run("catch-all 200 is not judged", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("spa shell"))
		}))
		defer srv.Close()

		rpt := runAgainst(t, srv)
		if _, ok := findingIDs(rpt)["ERR-001"]; ok {
			t.Errorf("expected no ERR-001 finding when unknown paths return 200")
		}
	})
}

// runAtPath probes path (which may include a query string) on a trivially
// healthy server, for the static URI checks that judge the endpoint URL
// itself rather than the response.
func runAtPath(t *testing.T, path string, rewrite func(base string) string) *report.Report {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	base := srv.URL
	if rewrite != nil {
		base = rewrite(base)
	}
	rpt, err := analyzer.Run(context.Background(), analyzer.Config{
		Endpoints: []probe.Endpoint{{Method: "GET", URL: base + path}},
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("analyzer.Run: %v", err)
	}
	return rpt
}

func TestURINaming_FlagsURI001(t *testing.T) {
	flagged := []string{
		"/users/",          // trailing slash
		"/Users",           // uppercase
		"/user_profiles",   // underscore
		"/users.json",      // file extension
		"/get-users",       // leading verb
		"/v1/delete",       // verb as whole segment
		"/v1/users/getAll", // camelCase verb
	}
	for _, path := range flagged {
		t.Run("flags "+path, func(t *testing.T) {
			if bucket, ok := findingIDs(runAtPath(t, path, nil))["URI-001"]; !ok || bucket != report.Consider {
				t.Errorf("expected URI-001 in Consider for %q, got %v (present=%v)", path, bucket, ok)
			}
		})
	}

	clean := []string{
		"/",
		"/v1/users",
		"/v1/users/42",
		"/v1/users/usr_9F2", // identifier-like segment is exempt
		"/v1/user-profiles/42/orders",
		"/v1.2/users", // version, not an extension
		"/.well-known/security.txt",
		"/v1/targets", // "get" inside a word, not a leading verb
	}
	for _, path := range clean {
		t.Run("clean "+path, func(t *testing.T) {
			if _, ok := findingIDs(runAtPath(t, path, nil))["URI-001"]; ok {
				t.Errorf("expected no URI-001 finding for %q", path)
			}
		})
	}
}

func TestURICredentials_FlagsURI002(t *testing.T) {
	t.Run("userinfo is Must Fix", func(t *testing.T) {
		rpt := runAtPath(t, "/v1/users", func(base string) string {
			return strings.Replace(base, "http://", "http://user:pass@", 1)
		})
		if bucket, ok := findingIDs(rpt)["URI-002"]; !ok || bucket != report.MustFix {
			t.Errorf("expected URI-002 in MustFix, got %v (present=%v)", bucket, ok)
		}
	})

	t.Run("secret query parameter is Should Fix and the value is not reported", func(t *testing.T) {
		rpt := runAtPath(t, "/v1/users?API_KEY=hunter2&page=1", nil)
		if bucket, ok := findingIDs(rpt)["URI-002"]; !ok || bucket != report.ShouldFix {
			t.Fatalf("expected URI-002 in ShouldFix, got %v (present=%v)", bucket, ok)
		}
		for _, f := range rpt.ShouldFix {
			if strings.Contains(f.What, "hunter2") {
				t.Errorf("finding must not echo the secret value: %q", f.What)
			}
		}
	})

	t.Run("ordinary query parameters are clean", func(t *testing.T) {
		if _, ok := findingIDs(runAtPath(t, "/v1/users?page=1&sort=name", nil))["URI-002"]; ok {
			t.Errorf("expected no URI-002 finding for non-credential parameters")
		}
	})
}

// mutationRecorder is a well-behaved read-only resource that counts every
// request using a mutating method, so tests can prove the probe never sent one.
func mutationRecorder(t *testing.T) (*httptest.Server, func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			w.Header().Set("ETag", `"v1"`)
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte("ok"))
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			mu.Lock()
			seen[r.Method]++
			mu.Unlock()
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed) // e.g. METH-003's read-only PROPFIND
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string]int, len(seen))
		for k, v := range seen {
			out[k] = v
		}
		return out
	}
}

func TestMutatingEndpoint_NeverSendsWriteWithoutOptIn(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			srv, mutations := mutationRecorder(t)
			rpt, err := analyzer.Run(context.Background(), analyzer.Config{
				Endpoints: []probe.Endpoint{{Method: method, URL: srv.URL + "/v1/things/1"}},
				Timeout:   5 * time.Second,
			})
			if err != nil {
				t.Fatalf("analyzer.Run: %v", err)
			}
			if got := mutations(); len(got) != 0 {
				t.Errorf("%s endpoint without --allow-unsafe-writes sent mutating requests: %v", method, got)
			}
			// A read-only probe of a healthy resource must not blame it for
			// the write method's own behavior (the old bug: a PUT carrying
			// If-None-Match reported "conditional GET returned 200").
			if _, ok := findingIDs(rpt)["CACHE-002"]; ok {
				t.Errorf("CACHE-002 must not fire for a %s endpoint whose GET handles If-None-Match correctly", method)
			}
		})
	}
}

func TestMutatingEndpoint_WithOptInSendsAtMostTheRedirectBaseline(t *testing.T) {
	srv, mutations := mutationRecorder(t)
	_, err := analyzer.Run(context.Background(), analyzer.Config{
		Endpoints:         []probe.Endpoint{{Method: "POST", URL: srv.URL + "/v1/things"}},
		Timeout:           5 * time.Second,
		AllowUnsafeWrites: true,
	})
	if err != nil {
		t.Fatalf("analyzer.Run: %v", err)
	}
	// Only REDIR-002 issues the endpoint's real method (one baseline
	// request); every other rule keeps probing with GET.
	if got := mutations()["POST"]; got > 1 {
		t.Errorf("expected at most 1 POST (REDIR-002 baseline) with opt-in, got %d", got)
	}
}

func TestMissingEndpoint_IsNotBlamedForMethodBehavior(t *testing.T) {
	t.Run("404 endpoint: no METH-002 or METH-003", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		ids := findingIDs(runAgainst(t, srv))
		for _, id := range []string{"METH-002", "METH-003"} {
			if _, ok := ids[id]; ok {
				t.Errorf("%s must not fire on an endpoint that itself returns 404", id)
			}
		}
	})

	t.Run("existing endpoint: 404 for an unsupported method is still Must Fix", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		ids := findingIDs(runAgainst(t, srv))
		if bucket, ok := ids["METH-003"]; !ok || bucket != report.MustFix {
			t.Errorf("expected METH-003 in MustFix for a 200 route that 404s PROPFIND, got %v (present=%v)", bucket, ok)
		}
		if bucket, ok := ids["METH-002"]; !ok || bucket != report.ShouldFix {
			t.Errorf("expected METH-002 in ShouldFix for a 200 route whose OPTIONS lacks Allow, got %v (present=%v)", bucket, ok)
		}
	})
}
