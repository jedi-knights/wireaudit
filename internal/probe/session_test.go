package probe_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jedi-knights/wireaudit/internal/probe"
)

func TestSession_RefusesMutatingMethodsWithoutOptIn(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
	}))
	defer srv.Close()

	ep := probe.Endpoint{Method: "GET", URL: srv.URL + "/"}
	newSession := func(allow bool) *probe.Session {
		return probe.NewSession(ep, probe.NewHTTPClient(5*time.Second, false), nil, nil, allow)
	}

	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "MKCOL", "post"} {
		if _, err := newSession(false).Do(probe.RequestSpec{Method: method, URL: ep.URL}, false); err == nil {
			t.Errorf("%s: expected refusal without opt-in, got nil error", method)
		}
	}
	if n := received.Load(); n != 0 {
		t.Fatalf("server received %d request(s); refused methods must never reach the wire", n)
	}

	for _, method := range []string{"GET", "HEAD", "OPTIONS", "PROPFIND", "get"} {
		if _, err := newSession(false).Do(probe.RequestSpec{Method: method, URL: ep.URL}, false); err != nil {
			t.Errorf("%s: read-only method refused: %v", method, err)
		}
	}

	if _, err := newSession(true).Do(probe.RequestSpec{Method: "PUT", URL: ep.URL}, false); err != nil {
		t.Errorf("PUT with opt-in refused: %v", err)
	}
}
