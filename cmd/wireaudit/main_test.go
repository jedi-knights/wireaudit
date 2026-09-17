package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// buildBinary compiles the wireaudit binary once per test run and returns
// its path, so this black-box test exercises the actual process boundary
// (argv → stdout/exit code) rather than calling internal/cli functions
// directly.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := t.TempDir() + "/wireaudit"
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building wireaudit: %v\n%s", err, out)
	}
	return bin
}

// conformantHandler implements every check in the methods, response-headers,
// caching, redirects, and negotiation categories correctly. It deliberately
// does NOT attempt to satisfy header-syntax (HDR-*) or TLS checks: HDR-*
// depends on the underlying net/http server's own wire-level framing
// parser, which this test does not control and which varies by Go version,
// and TLS-* is naturally inapplicable to a plaintext httptest.Server.
func conformantHandler(w http.ResponseWriter, r *http.Request) {
	const etag = `"v1"`

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		accept := r.Header.Get("Accept")
		contentType := "text/plain; charset=utf-8"
		switch {
		case strings.Contains(accept, "json"):
			contentType = "application/json"
		case strings.Contains(accept, "xml"):
			contentType = "application/xml"
		}
		w.Header().Set("Vary", "Accept")
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Type", contentType)

		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	case http.MethodOptions:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestMain_CleanTargetExitsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(conformantHandler))
	defer srv.Close()

	bin := buildBinary(t)
	cmd := exec.Command(bin, "--target", srv.URL, "--format", "json",
		"--categories", "methods,response-headers,caching,redirects,negotiation")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			t.Fatalf("running wireaudit: %v", err)
		}
	}
	if cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("expected exit code 0, got %d; stdout=%s", cmd.ProcessState.ExitCode(), stdout.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if _, ok := payload["must_fix"]; !ok {
		t.Errorf("expected a must_fix key in the JSON report, got: %s", stdout.String())
	}
}

func TestMain_ViolatingTargetExitsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusFound) // 302 with no Location — REDIR-001 Must Fix
	}))
	defer srv.Close()

	bin := buildBinary(t)
	cmd := exec.Command(bin, "--target", srv.URL, "--format", "json")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()

	if cmd.ProcessState.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d; stdout=%s", cmd.ProcessState.ExitCode(), stdout.String())
	}

	var payload struct {
		MustFix []struct {
			CheckID string `json:"check_id"`
		} `json:"must_fix"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	found := false
	for _, f := range payload.MustFix {
		if f.CheckID == "REDIR-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected REDIR-001 in must_fix, got: %s", stdout.String())
	}
}

func TestMain_MissingTargetExitsTwo(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	_ = cmd.Run()

	if cmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for missing --target, got %d", cmd.ProcessState.ExitCode())
	}
}
