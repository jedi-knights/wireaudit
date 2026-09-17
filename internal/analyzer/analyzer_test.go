package analyzer_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
