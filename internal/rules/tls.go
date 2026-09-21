package rules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(certificateValidRule{})
	Register(minTLSVersionRule{})
	Register(httpToHTTPSRedirectRule{})
	Register(hstsPresentRule{})
}

// --- TLS-001: certificate-valid ---

type certificateValidRule struct{}

func (certificateValidRule) ID() string              { return "TLS-001" }
func (certificateValidRule) Category() string        { return "tls" }
func (certificateValidRule) RequiresRawSocket() bool { return false }

func (r certificateValidRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	if !strings.HasPrefix(ep.URL, "https://") {
		return nil
	}
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil || res.TLS == nil {
		return nil
	}
	if len(res.TLS.VerifiedChains) == 0 && len(res.TLS.PeerCertificates) == 0 {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			"TLS handshake completed but presented no verifiable certificate chain",
			"RFC 5280 chain validation is what lets clients trust the server's identity; without it, connections are vulnerable to interception",
			"serve a valid certificate chain issued by a trusted CA and keep it current")}
	}
	for _, cert := range res.TLS.PeerCertificates {
		if time.Now().After(cert.NotAfter) {
			return []report.Finding{finding(r.ID(), ep, report.MustFix,
				fmt.Sprintf("certificate for %s expired on %s", cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)),
				"an expired certificate causes every conformant client to refuse the connection",
				"renew the certificate before expiry and automate rotation")}
		}
	}
	return nil
}

// --- TLS-002: min-tls-version ---

type minTLSVersionRule struct{}

func (minTLSVersionRule) ID() string              { return "TLS-002" }
func (minTLSVersionRule) Category() string        { return "tls" }
func (minTLSVersionRule) RequiresRawSocket() bool { return false }

func (r minTLSVersionRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	if !strings.HasPrefix(ep.URL, "https://") {
		return nil
	}
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil || res.TLS == nil {
		return nil
	}
	if res.TLS.Version < tls.VersionTLS12 {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("negotiated TLS version %s is below TLS 1.2", tlsVersionName(res.TLS.Version)),
			"RFC 8996 deprecates TLS 1.0/1.1 due to known cryptographic weaknesses",
			"configure the server to negotiate TLS 1.2 or higher only")}
	}
	return nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// --- TLS-003: http-to-https-redirect ---

type httpToHTTPSRedirectRule struct{}

func (httpToHTTPSRedirectRule) ID() string              { return "TLS-003" }
func (httpToHTTPSRedirectRule) Category() string        { return "tls" }
func (httpToHTTPSRedirectRule) RequiresRawSocket() bool { return false }

func (r httpToHTTPSRedirectRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	if !strings.HasPrefix(ep.URL, "https://") {
		return nil
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil
	}
	httpURL := "http://" + u.Host + u.RequestURI()

	res, err := sess.Do(probe.RequestSpec{Method: ep.Method, URL: httpURL}, false)
	if err != nil || res.Err != nil {
		return nil // plaintext port likely closed entirely, which is at least as safe
	}

	if !isRedirectStatus(res.Response.StatusCode) {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("plaintext HTTP on the same host served a %d instead of redirecting to HTTPS", res.Response.StatusCode),
			"serving content over plaintext HTTP exposes every header and body to on-path interception and modification",
			"redirect all plaintext HTTP traffic to the HTTPS equivalent (301/308) rather than serving it directly")}
	}
	loc, _ := res.Response.HeaderValue("Location")
	if loc != "" && !strings.HasPrefix(loc, "https://") {
		return []report.Finding{finding(r.ID(), ep, report.MustFix,
			fmt.Sprintf("HTTP redirected to a non-HTTPS Location: %q", loc),
			"redirecting HTTP to HTTP defeats the purpose of the redirect and leaves the request unencrypted",
			"redirect Location must point at the https:// equivalent of the request")}
	}
	return nil
}

// --- TLS-004: hsts-present ---

type hstsPresentRule struct{}

func (hstsPresentRule) ID() string              { return "TLS-004" }
func (hstsPresentRule) Category() string        { return "tls" }
func (hstsPresentRule) RequiresRawSocket() bool { return false }

func (r hstsPresentRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	if !strings.HasPrefix(ep.URL, "https://") {
		return nil
	}
	res, err := getBaseline(sess, ep)
	if err != nil || res.Err != nil {
		return nil
	}
	if _, present := res.Response.HeaderValue("Strict-Transport-Security"); !present {
		return []report.Finding{finding(r.ID(), ep, report.ShouldFix,
			"HTTPS response has no Strict-Transport-Security header",
			"RFC 6797 HSTS tells browsers to refuse plaintext HTTP for this host on future visits, closing the window for downgrade attacks",
			"set Strict-Transport-Security with a meaningful max-age on every HTTPS response")}
	}
	return nil
}
