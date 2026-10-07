package rules

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(uriNamingRule{})
	Register(uriNoCredentialsRule{})
}

// crudVerbs are action words that REST resource names should not start
// with: the HTTP method already carries the action.
var crudVerbs = []string{"get", "create", "update", "delete", "add", "remove", "edit", "fetch", "set"}

// secretParamNames are query parameter names (lowercase) that conventionally
// carry credentials. URLs are logged by proxies, browsers and servers, so a
// secret in the query string leaks into every one of those logs.
var secretParamNames = map[string]bool{
	"password": true, "passwd": true, "pwd": true,
	"secret": true, "client_secret": true,
	"token": true, "access_token": true, "refresh_token": true, "auth_token": true,
	"api_key": true, "apikey": true, "api-key": true,
	"authorization": true, "sessionid": true,
}

// fileExtension matches a trailing ".json"/".xml"-style suffix. It must
// start with a letter so version-like segments ("v1.2") are not flagged.
var fileExtension = regexp.MustCompile(`[^/.]\.[A-Za-z][A-Za-z0-9]{0,4}$`)

// --- URI-001: uri-naming ---

type uriNamingRule struct{}

func (uriNamingRule) ID() string              { return "URI-001" }
func (uriNamingRule) Category() string        { return "uri" }
func (uriNamingRule) RequiresRawSocket() bool { return false }

// Check is static: it lints the endpoint's path and sends no request. A
// segment containing a digit is treated as an identifier (42, usr_9F2,
// v1) and exempted from the case, underscore and verb checks, because
// identifiers legitimately use those characters. Plural-vs-singular naming
// is not checked: it cannot be decided from the URI alone.
func (r uriNamingRule) Check(_ context.Context, _ *probe.Session, ep probe.Endpoint) []report.Finding {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil
	}
	path := u.EscapedPath()
	if strings.HasPrefix(path, "/.well-known/") {
		return nil // RFC 8615 fixes these names (e.g. security.txt); not ours to lint
	}
	var problems []string

	if len(path) > 1 && strings.HasSuffix(path, "/") {
		problems = append(problems, "trailing slash")
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for _, seg := range segments {
		if seg == "" || strings.HasPrefix(seg, ".") {
			continue // empty or a dot-segment such as /.well-known/
		}
		if fileExtension.MatchString(seg) {
			problems = append(problems, fmt.Sprintf("file extension in %q", seg))
		}
		if strings.ContainsAny(seg, "0123456789") {
			continue // identifier-like segment
		}
		if seg != strings.ToLower(seg) {
			problems = append(problems, fmt.Sprintf("uppercase letters in %q", seg))
		}
		if strings.Contains(seg, "_") {
			problems = append(problems, fmt.Sprintf("underscore in %q (use hyphens)", seg))
		}
		if verb, ok := leadingVerb(strings.ToLower(seg)); ok {
			problems = append(problems, fmt.Sprintf("action verb %q in %q (the HTTP method is the action)", verb, seg))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return []report.Finding{finding(r.ID(), ep, report.Consider,
		"URI path deviates from REST resource-naming conventions: "+strings.Join(problems, "; "),
		"RFC 3986 §6.2.2.1 treats path case as significant and consistent, lowercase hyphenated noun paths keep URIs predictable; verbs and extensions duplicate what the HTTP method and Accept header already express",
		"use lowercase, hyphen-separated nouns, no trailing slash, no file extension, and no CRUD verbs in the path")}
}

// leadingVerb reports whether seg is a CRUD verb or starts with one followed
// by a hyphen ("get-users").
func leadingVerb(seg string) (string, bool) {
	for _, v := range crudVerbs {
		if seg == v || strings.HasPrefix(seg, v+"-") {
			return v, true
		}
	}
	return "", false
}

// --- URI-002: uri-no-credentials ---

type uriNoCredentialsRule struct{}

func (uriNoCredentialsRule) ID() string              { return "URI-002" }
func (uriNoCredentialsRule) Category() string        { return "uri" }
func (uriNoCredentialsRule) RequiresRawSocket() bool { return false }

// Check is static: it inspects the endpoint URL and sends no request. Only
// parameter names are reported, never values, so a real secret passed on the
// command line is not echoed into reports or CI logs.
func (r uriNoCredentialsRule) Check(_ context.Context, _ *probe.Session, ep probe.Endpoint) []report.Finding {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil
	}
	var findings []report.Finding
	if u.User != nil {
		findings = append(findings, finding(r.ID(), ep, report.MustFix,
			"URL carries userinfo (user:password@host)",
			"RFC 9110 §4.2.4 forbids generating userinfo in http(s) URIs; it exposes credentials in logs, referrers and history",
			"remove the userinfo and send credentials in an Authorization header (--header)"))
	}
	var leaked []string
	for name := range u.Query() { // bounded by the caller-supplied endpoint URL
		if secretParamNames[strings.ToLower(name)] {
			leaked = append(leaked, name)
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		findings = append(findings, finding(r.ID(), ep, report.ShouldFix,
			"query string carries credential-like parameter(s): "+strings.Join(leaked, ", "),
			"URLs are recorded by proxies, access logs, browser history and Referer headers, so a secret in the query string leaks to all of them",
			"move the credential to an Authorization header or request body"))
	}
	return findings
}
