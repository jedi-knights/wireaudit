package rules

import (
	"context"
	"strings"

	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

func init() {
	Register(unauthorizedHasChallengeRule{})
}

// --- AUTH-001: 401-has-www-authenticate ---

type unauthorizedHasChallengeRule struct{}

func (unauthorizedHasChallengeRule) ID() string              { return "AUTH-001" }
func (unauthorizedHasChallengeRule) Category() string        { return "authentication" }
func (unauthorizedHasChallengeRule) RequiresRawSocket() bool { return false }

// Check is passive: it only inspects the response to a plain request on the
// endpoint, so it never sends credentials-guessing or otherwise unusual
// traffic. It fires only when the target itself answers 401.
func (r unauthorizedHasChallengeRule) Check(_ context.Context, sess *probe.Session, ep probe.Endpoint) []report.Finding {
	res, err := sess.Do(probe.RequestSpec{Method: readOnlyMethod(ep), URL: ep.URL}, false)
	if err != nil || res.Err != nil || res.Response.StatusCode != 401 {
		return nil
	}
	for _, challenge := range res.Response.HeaderValues("WWW-Authenticate") {
		if strings.TrimSpace(challenge) != "" {
			return nil
		}
	}
	return []report.Finding{finding(r.ID(), ep, report.MustFix,
		"401 response has no WWW-Authenticate challenge",
		"RFC 9110 §15.5.2 requires a 401 to carry WWW-Authenticate so the client knows which authentication scheme to use; without it the client cannot recover",
		"send at least one WWW-Authenticate challenge (e.g. Bearer realm=\"api\") on every 401, or use 403 if no authentication scheme applies")}
}
