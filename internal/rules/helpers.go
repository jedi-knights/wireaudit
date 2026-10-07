package rules

import (
	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

// finding builds a report.Finding for checkID against ep.
func finding(checkID string, ep probe.Endpoint, bucket report.Bucket, what, why, fix string) report.Finding {
	return report.Finding{
		CheckID: checkID,
		Locator: ep.Locator(),
		Bucket:  bucket,
		What:    what,
		Why:     why,
		Fix:     fix,
	}
}

// isClientError reports whether status is a 4xx code — the expected outcome
// when a target correctly rejects a malformed or invalid request.
func isClientError(status int) bool {
	return status >= 400 && status < 500
}

// isServerError reports whether status is a 5xx code.
func isServerError(status int) bool {
	return status >= 500 && status < 600
}

// readOnlyMethod returns the method rules use for their read-only probes of ep:
// the endpoint's own method when it is on the read-only allowlist, otherwise
// GET. A rule that merely inspects headers, caching or negotiation on a
// "PUT /x" endpoint must never send a PUT — only CACHE-005 and REDIR-002
// issue the endpoint's real method, and only after --allow-unsafe-writes.
func readOnlyMethod(ep probe.Endpoint) string {
	if probe.IsSafeMethod(ep.Method) {
		return ep.Method
	}
	return "GET"
}
