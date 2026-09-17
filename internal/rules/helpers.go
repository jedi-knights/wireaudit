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
