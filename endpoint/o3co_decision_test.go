// Copyright 2026 1o1 Co. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

const testDigest = "sha256:9f2c1e0b7a4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b"

// serve answers every request with status and body.
func serve(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestEndpoint(t *testing.T, url string, opts ...O3coOption) *o3coEndpoint {
	t.Helper()
	ep, err := NewO3coEndpoint(url, opts...)
	if err != nil {
		t.Fatalf("NewO3coEndpoint: %v", err)
	}
	return ep.(*o3coEndpoint)
}

// captureLogs points the endpoint's logger at a buffer, at the default level.
func captureLogs(e *o3coEndpoint) *bytes.Buffer {
	var buf bytes.Buffer
	e.logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	return &buf
}

const allowWithEvaluation = `{
  "decision": "allow", "resource": "posts:1", "action": "read",
  "reason": { "groups": [ {
    "ruleType": "cedar", "passed": true,
    "evaluated": [ { "code": "cedar_permit", "message": "Permitted", "passed": true,
      "evaluation": { "status": "completed", "revision": "` + testDigest + `", "determiningPolicies": ["10-permit-read"] } } ],
    "satisfiedBy": { "code": "cedar_permit", "message": "Permitted", "passed": true,
      "evaluation": { "status": "completed", "revision": "` + testDigest + `", "determiningPolicies": ["10-permit-read"] } }
  } ] }
}`

const allowWithoutEvaluation = `{
  "decision": "allow", "resource": "posts:1", "action": "read",
  "reason": { "groups": [ {
    "ruleType": "rbac", "passed": true,
    "evaluated": [ { "code": "role_granted", "message": "Granted", "passed": true } ],
    "satisfiedBy": { "code": "role_granted", "message": "Granted", "passed": true }
  } ] }
}`

const denyWithEvaluation = `{
  "decision": "deny", "code": "cedar_deny", "message": "Denied by Cedar policy",
  "resource": "posts:1", "action": "write",
  "reason": { "groups": [ {
    "ruleType": "cedar", "passed": false,
    "evaluated": [ { "code": "cedar_deny", "message": "Denied by Cedar policy", "passed": false,
      "evaluation": { "status": "completed", "revision": "` + testDigest + `", "determiningPolicies": ["20-forbid-secret"] } } ]
  } ] }
}`

// allowWithARestrictingGroup is an allow a policy granted and a delegation
// range narrowed: the range's group restricts, and has no policy source.
const allowWithARestrictingGroup = `{
  "decision": "allow", "resource": "project:p1.report", "action": "run",
  "reason": { "groups": [ {
    "ruleType": "cedar", "passed": true,
    "evaluated": [ { "code": "cedar_permit", "message": "Permitted", "passed": true,
      "evaluation": { "status": "completed", "revision": "` + testDigest + `" } } ],
    "satisfiedBy": { "code": "cedar_permit", "message": "Permitted", "passed": true,
      "evaluation": { "status": "completed", "revision": "` + testDigest + `" } }
  }, {
    "ruleType": "delegation_range", "passed": true, "restricts": true,
    "evaluated": [ { "code": "within_delegation_range", "message": "Within the delegation range", "passed": true } ],
    "satisfiedBy": { "code": "within_delegation_range", "message": "Within the delegation range", "passed": true }
  } ] }
}`

func TestO3coVerifyDecision_RestrictingGroup_IsMarked(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, allowWithARestrictingGroup).URL)
	d, err := e.VerifyDecision(ctxWithToken("tok"), "project:p1.report", "run")
	if err != nil || d == nil || len(d.Groups) != 2 {
		t.Fatalf("VerifyDecision = (%+v, %v)", d, err)
	}
	if d.Groups[0].Restricts {
		t.Error("a group without restricts decoded as restricting")
	}
	if !d.Groups[1].Restricts {
		t.Error("a group with restricts: true decoded as granting")
	}
}

// A delegated token outside its range is denied by its restricting group,
// which the denial reports as restricting.
func TestO3coVerifyDecision_DenyWithAFailingRestrictingGroup_IsMarked(t *testing.T) {
	const body = `{
  "decision": "deny", "code": "outside_delegation_range", "message": "Outside the delegation range",
  "resource": "project:p2.report", "action": "run",
  "reason": { "groups": [ {
    "ruleType": "cedar", "passed": true,
    "evaluated": [ { "code": "cedar_permit", "message": "Permitted", "passed": true } ],
    "satisfiedBy": { "code": "cedar_permit", "message": "Permitted", "passed": true }
  }, {
    "ruleType": "delegation_range", "passed": false, "restricts": true,
    "evaluated": [ { "code": "outside_delegation_range", "message": "Outside the delegation range", "passed": false } ]
  } ] }
}`
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, body).URL)
	_, err := e.VerifyDecision(ctxWithToken("tok"), "project:p2.report", "run")
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) || denied.Decision == nil || len(denied.Decision.Groups) != 2 {
		t.Fatalf("VerifyDecision error = %T: %v", err, err)
	}
	if g := denied.Decision.Groups; g[0].Restricts || !g[1].Restricts || g[1].Passed {
		t.Errorf("Groups = %+v, want a granting group and a failing restricting one", g)
	}
}

// The delegation range's group has no policy source; the allow is confirmed by
// the policy that granted it.
func TestO3coRequireConfirmedRevision_AcceptsAnAllowARestrictingGroupNarrowed(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, allowWithARestrictingGroup).URL, WithO3coRequireConfirmedRevision())
	if err := e.Verify(ctxWithToken("tok"), "project:p1.report", "run"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestO3coEndpoint_IsADecisionVerifier(t *testing.T) {
	ep, err := NewO3coEndpoint("http://localhost:3000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := ep.(DecisionVerifier); !ok {
		t.Fatalf("%T does not implement DecisionVerifier", ep)
	}
}

func TestO3coVerifyDecision_Allow_ReturnsTheDecision(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, allowWithEvaluation).URL)

	d, err := e.VerifyDecision(ctxWithTokenAndRequestID("tok", "req-1"), "posts:1", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d == nil {
		t.Fatal("expected a decision")
	}
	if d.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want %q", d.RequestID, "req-1")
	}
	if d.Code != "" || d.Message != "" {
		t.Errorf("an allow carries no code or message, got (%q, %q)", d.Code, d.Message)
	}
	if len(d.Groups) != 1 || d.Groups[0].SatisfiedBy == nil {
		t.Fatalf("Groups = %+v, want one passing group with its satisfying rule", d.Groups)
	}
	g := d.Groups[0]
	if g.RuleType != "cedar" || !g.Passed || len(g.Evaluated) != 1 {
		t.Errorf("group = %+v", g)
	}
	rev, ok := g.SatisfiedBy.Evaluation.ConfirmedRevision()
	if !ok || rev != testDigest {
		t.Errorf("ConfirmedRevision() = (%q, %v), want (%q, true)", rev, ok, testDigest)
	}
	if got := g.SatisfiedBy.Evaluation.DeterminingPolicies; len(got) != 1 || got[0] != "10-permit-read" {
		t.Errorf("DeterminingPolicies = %v", got)
	}
	if !d.RevisionConfirmed() {
		t.Error("RevisionConfirmed() = false, want true")
	}
}

func TestO3coVerifyDecision_Deny_CarriesTheCodeBesideTheDeniedError(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, denyWithEvaluation).URL)

	d, err := e.VerifyDecision(ctxWithToken("tok"), "posts:1", "write")
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
	// The RPC caller is told only "access denied"; the deny code travels on
	// the Decision.
	if denied.Reason != "access denied" {
		t.Errorf("Reason = %q, want %q", denied.Reason, "access denied")
	}
	if denied.Decision == nil || denied.Decision != d {
		t.Fatalf("DeniedError.Decision = %v, want the returned decision %v", denied.Decision, d)
	}
	if d.Code != "cedar_deny" || d.Message != "Denied by Cedar policy" {
		t.Errorf("(Code, Message) = (%q, %q)", d.Code, d.Message)
	}
	if len(d.Groups) != 1 || d.Groups[0].Passed || d.Groups[0].SatisfiedBy != nil {
		t.Errorf("Groups = %+v, want one failing group", d.Groups)
	}
}

// not_invoked, failed, revision: null and absent must each be told apart, and
// none may read as an evaluated revision.
func TestO3coVerifyDecision_EvaluationShapesAreDistinguishable(t *testing.T) {
	body := `{
	  "decision": "deny", "code": "cedar_error", "message": "Cedar failed", "resource": "r", "action": "a",
	  "reason": { "groups": [ { "ruleType": "cedar", "passed": false, "evaluated": [
	    { "code": "c1", "message": "m", "passed": false, "evaluation": { "status": "not_invoked" } },
	    { "code": "c2", "message": "m", "passed": false, "evaluation": { "status": "failed", "revision": "` + testDigest + `" } },
	    { "code": "c3", "message": "m", "passed": false, "evaluation": { "status": "completed", "revision": null, "loadedRevision": "` + testDigest + `" } },
	    { "code": "c4", "message": "m", "passed": false }
	  ] } ] }
	}`
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, body).URL)

	d, _ := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if d == nil || len(d.Groups) != 1 || len(d.Groups[0].Evaluated) != 4 {
		t.Fatalf("decision = %+v", d)
	}
	ev := d.Groups[0].Evaluated

	if got := ev[0].Evaluation; got == nil || got.Status != interceptors.EvaluationNotInvoked {
		t.Errorf("not_invoked decoded as %+v", got)
	}
	if got := ev[1].Evaluation; got == nil || got.Status != interceptors.EvaluationFailed || got.Revision != testDigest {
		t.Errorf("failed decoded as %+v", got)
	}
	if got := ev[2].Evaluation; got == nil || got.Status != interceptors.EvaluationCompleted || got.Revision != "" || got.LoadedRevision != testDigest {
		t.Errorf("revision: null decoded as %+v", got)
	}
	if got := ev[3].Evaluation; got != nil {
		t.Errorf("absent decoded as %+v, want nil", got)
	}
	for i, o := range ev {
		if rev, ok := o.Evaluation.ConfirmedRevision(); ok {
			t.Errorf("outcome %d reads as evaluated revision %q", i, rev)
		}
	}
}

// A client must ignore keys it does not know — above all inside evaluation,
// which the verifier extends in minor releases.
func TestO3coVerifyDecision_IgnoresUnknownKeys(t *testing.T) {
	body := `{
	  "decision": "allow", "resource": "r", "action": "a", "subject": { "sub": "u1" }, "future": 1,
	  "reason": { "future": true, "groups": [ { "ruleType": "cedar", "passed": true, "future": [],
	    "evaluated": [ { "code": "c", "message": "m", "passed": true, "future": "x",
	      "evaluation": { "status": "completed", "revision": "` + testDigest + `", "future": { "nested": 1 } } } ],
	    "satisfiedBy": { "code": "c", "message": "m", "passed": true,
	      "evaluation": { "status": "completed", "revision": "` + testDigest + `", "future": { "nested": 1 } } }
	  } ] }
	}`
	e := newTestEndpoint(t, serve(t, http.StatusOK, body).URL)

	d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.RevisionConfirmed() {
		t.Errorf("RevisionConfirmed() = false for %+v", d)
	}
}

// Without evaluation — a verifier that does not report one, or has not opted
// in — an allow is still an allow, and the satisfying rule's Evaluation is nil
// (unknown).
func TestO3coVerify_ResponseWithoutEvaluation_BehavesAsBefore(t *testing.T) {
	allow := newTestEndpoint(t, serve(t, http.StatusOK, allowWithoutEvaluation).URL)
	if err := allow.Verify(ctxWithToken("tok"), "r", "a"); err != nil {
		t.Errorf("allow: unexpected error: %v", err)
	}
	d, err := allow.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err != nil || d == nil || d.Groups[0].SatisfiedBy.Evaluation != nil {
		t.Errorf("VerifyDecision = (%+v, %v), want a decision with no evaluation", d, err)
	}
}

// An allow is a 200 carrying a whole allow. A 200 whose body is anything
// less is not one, and is not a deny either: the verifier did not say what it
// decided. A 403 stays a deny whatever its body holds.
func TestO3coVerify_BodyThatIsNotAWholeDecision(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"empty allow", http.StatusOK, ""},
		{"allow that is not JSON", http.StatusOK, "<html>ok</html>"},
		{"allow with no decision key", http.StatusOK, `{"ok": true}`},
		{"allow whose reason is malformed", http.StatusOK, `{"decision": "allow", "reason": {"groups": "nope"}}`},
		{"empty deny", http.StatusForbidden, ""},
		{"deny that is not JSON", http.StatusForbidden, "<html>forbidden</html>"},
		{"deny whose revision is a number", http.StatusForbidden, `{"decision": "deny", "code": "x", "message": "m", "reason": {"groups": [{"ruleType": "cedar", "passed": false, "evaluated": [{"code": "x", "message": "m", "passed": false, "evaluation": {"status": "completed", "revision": 7}}]}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEndpoint(t, serve(t, tc.status, tc.body).URL)
			d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
			if d != nil {
				t.Errorf("decision = %+v, want nil for a body that is not a decision", d)
			}
			var denied *interceptors.DeniedError
			switch tc.status {
			case http.StatusOK:
				if err == nil || errors.As(err, &denied) {
					t.Errorf("got %T: %v, want an error that is not a denial", err, err)
				}
			case http.StatusForbidden:
				if !errors.As(err, &denied) {
					t.Errorf("expected *DeniedError, got %T: %v", err, err)
				}
			}
		})
	}
}

// Only 200 is the allow status: any other 2xx is an error, even with a whole
// allow in its body.
func TestO3coVerify_2xxOtherThan200_IsAnError(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusNonAuthoritativeInfo, http.StatusNoContent, http.StatusPartialContent, 299} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := newTestEndpoint(t, serve(t, status, allowWithEvaluation).URL)
			_, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
			var denied *interceptors.DeniedError
			if err == nil || errors.As(err, &denied) {
				t.Errorf("status %d: got %T: %v, want an error that is not a denial", status, err, err)
			}
		})
	}
}

// A 200 whose body breaks off is not an allow, even when what arrived is one.
func TestO3coVerify_200WhoseBodyFailsToRead_IsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(allowWithEvaluation)+100))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(allowWithEvaluation))
	}))
	t.Cleanup(srv.Close)

	e := newTestEndpoint(t, srv.URL)
	d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err == nil || d != nil {
		t.Errorf("VerifyDecision = (%+v, %v), want (nil, an error)", d, err)
	}
}

// A 200 that is not an allow is logged at the default level, by status and
// request ID, and without its body.
func TestO3coVerify_200ThatIsNotAWholeAllow_IsLoggedWithoutTheBody(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, `{"decision": "allow", "secret": "leak-me"}`).URL)
	logs := captureLogs(e)

	_ = e.Verify(ctxWithTokenAndRequestID("tok", "req-1"), "r", "a")
	out := logs.String()
	if strings.Contains(out, "leak-me") {
		t.Errorf("default-level log carries the body:\n%s", out)
	}
	for _, want := range []string{"level=ERROR", "status=200", "req-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("default-level log lacks %q:\n%s", want, out)
		}
	}
}

// Past the size bound the body is not read as a decision at all — a deny
// stays a deny, and an allow is not one.
func TestO3coVerify_OversizedBody_IsNotADecision(t *testing.T) {
	limit := WithO3coMaxResponseBodySize(64)

	deny := newTestEndpoint(t, serve(t, http.StatusForbidden, denyWithEvaluation).URL, limit)
	d, err := deny.VerifyDecision(ctxWithToken("tok"), "r", "a")
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) || d != nil {
		t.Errorf("oversized deny = (%+v, %v), want (nil, *DeniedError)", d, err)
	}

	allow := newTestEndpoint(t, serve(t, http.StatusOK, allowWithEvaluation).URL, limit)
	d, err = allow.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err == nil || errors.As(err, &denied) || d != nil {
		t.Errorf("oversized allow = (%+v, %v), want (nil, an error that is not a denial)", d, err)
	}
}

// The body may not grant, but it may refuse: a 2xx that says anything but
// allow is a verifier contradicting itself, and fails closed. The decision it
// did send is still reported, so an observer can record what it said.
func TestO3coVerify_2xxWhoseBodySaysDeny_FailsClosedAndReportsTheDecision(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, denyWithEvaluation).URL)
	d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err == nil {
		t.Fatal("expected an error for a 200 whose decision is deny")
	}
	if d == nil || d.Code != "cedar_deny" || len(d.Groups) != 1 {
		t.Errorf("decision = %+v, want the deny the verifier sent", d)
	}
}

// Whatever else is wrong with the body, a decision member that is not allow
// refuses — an envelope too malformed to report must not be one that grants.
func TestO3coVerify_2xxWhoseDecisionIsNotAllow_FailsClosed(t *testing.T) {
	for name, body := range map[string]string{
		"an unknown verdict":          `{"decision": "maybe"}`,
		"a null verdict":              `{"decision": null}`,
		"a verdict of the wrong type": `{"decision": true}`,
		"a malformed deny":            `{"decision": "deny"}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEndpoint(t, serve(t, http.StatusOK, body).URL)
			d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
			if err == nil {
				t.Fatalf("expected an error for %s", body)
			}
			if d != nil {
				t.Errorf("decision = %+v, want nil for an envelope that is not whole", d)
			}
		})
	}
}

// Every key the wire contract requires must be there, and not null, or the
// body reports nothing — never part of a decision — and a 200 carrying it is
// not an allow.
func TestO3coVerifyDecision_EnvelopeMissingARequiredKey_IsNotADecision(t *testing.T) {
	const ev = `"evaluation": {"status": "completed", "revision": "` + testDigest + `"}`
	const outcome = `{"code": "c", "message": "m", "passed": true, ` + ev + `}`
	const group = `{"ruleType": "cedar", "passed": true, "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}`
	cases := map[string]string{
		"no resource":                                 `{"action": "a", "decision": "allow", "reason": {"groups": []}}`,
		"no action":                                   `{"resource": "r", "decision": "allow", "reason": {"groups": []}}`,
		"no reason":                                   `{"resource": "r", "action": "a", "decision": "allow"}`,
		"a null reason":                               `{"resource": "r", "action": "a", "decision": "allow", "reason": null}`,
		"no groups":                                   `{"resource": "r", "action": "a", "decision": "allow", "reason": {}}`,
		"null groups":                                 `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": null}}`,
		"a null resource":                             `{"resource": null, "action": "a", "decision": "allow", "reason": {"groups": []}}`,
		"a group with no ruleType":                    `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"passed": true, "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}]}}`,
		"a passing group with no satisfiedBy":         `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [` + outcome + `]}]}}`,
		"a failing group with a satisfiedBy":          `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": false, "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}]}}`,
		"an outcome with no passed":                   `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [{"code": "c", "message": "m"}], "satisfiedBy": {"code": "c", "message": "m"}}]}}`,
		"an outcome with a null code":                 `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [{"code": null, "message": "m", "passed": true}], "satisfiedBy": {"code": null, "message": "m", "passed": true}}]}}`,
		"a null evaluation":                           `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [{"code": "c", "message": "m", "passed": true, "evaluation": null}], "satisfiedBy": {"code": "c", "message": "m", "passed": true, "evaluation": null}}]}}`,
		"an evaluation with no status":                `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [{"code": "c", "message": "m", "passed": true, "evaluation": {"revision": "` + testDigest + `"}}], "satisfiedBy": {"code": "c", "message": "m", "passed": true, "evaluation": {"revision": "` + testDigest + `"}}}]}}`,
		"a completed evaluation with no revision key": `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [{"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed"}}], "satisfiedBy": {"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed"}}}]}}`,
		"null determiningPolicies":                    `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [{"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed", "revision": null, "determiningPolicies": null}}], "satisfiedBy": {"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed", "revision": null, "determiningPolicies": null}}}]}}`,
		"a passed of the wrong type":                  `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": "yes", "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}]}}`,
		"a restricts of false":                        `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "restricts": false, "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}]}}`,
		"a null restricts":                            `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "restricts": null, "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}]}}`,
		"a restricts of the wrong type":               `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "restricts": "true", "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}]}}`,
		"a restricts spelled in another case":         `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "Restricts": true, "evaluated": [` + outcome + `], "satisfiedBy": ` + outcome + `}]}}`,
		"a fractional determiningPoliciesOmitted":     `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [], "satisfiedBy": {"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed", "revision": null, "determiningPolicies": ["p"], "determiningPoliciesOmitted": 1.5}}}]}}`,
		"an out-of-range determiningPoliciesOmitted":  `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [], "satisfiedBy": {"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed", "revision": null, "determiningPolicies": ["p"], "determiningPoliciesOmitted": 1e19}}}]}}`,
		"a determiningPolicies that is not strings":   `{"resource": "r", "action": "a", "decision": "allow", "reason": {"groups": [{"ruleType": "cedar", "passed": true, "evaluated": [], "satisfiedBy": {"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed", "revision": null, "determiningPolicies": [7]}}}]}}`,
		"a resource of the wrong type":                `{"resource": 1, "action": "a", "decision": "allow", "reason": {"groups": []}}`,
		"an allow whose code is of the wrong type":    `{"resource": "r", "action": "a", "decision": "allow", "code": 1, "reason": {"groups": []}}`,
		"a JSON array":                                `[` + group + `]`,
		"JSON null":                                   `null`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEndpoint(t, serve(t, http.StatusOK, body).URL)
			d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
			if err == nil {
				t.Error("expected an error: a 200 without a whole allow is not an allow")
			}
			if d != nil {
				t.Errorf("decision = %+v, want nil", d)
			}
		})
	}
}

// A deny made without a policy evaluation carries an empty reason: it is a
// whole decision, whose Groups are empty rather than unknown.
func TestO3coVerifyDecision_DenyWithNoGroups_IsADecision(t *testing.T) {
	body := `{"resource": "r", "action": "a", "decision": "deny", "code": "collector_timeout", "message": "m", "reason": {"groups": []}}`
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, body).URL)
	d, _ := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if d == nil || d.Code != "collector_timeout" || d.Groups == nil || len(d.Groups) != 0 {
		t.Errorf("decision = %+v, want a deny with an empty, non-nil reason", d)
	}
}

// The largest bound there is still reads the body.
func TestO3coVerify_MaximalBodySizeBound_StillReadsTheBody(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, allowWithEvaluation).URL, WithO3coMaxResponseBodySize(math.MaxInt64))
	d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err != nil || d == nil {
		t.Errorf("VerifyDecision = (%+v, %v), want the decision", d, err)
	}
}

func TestO3coVerify_403WhoseBodySaysAllow_StaysDenied(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, allowWithEvaluation).URL)
	var denied *interceptors.DeniedError
	if err := e.Verify(ctxWithToken("tok"), "r", "a"); !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

// --- 401: subject token or caller credential ---------------------------------
//
// The verifier answers 401 for two different failures: the subject's bearer
// token (invalid_token, missing_token, ...) and, under http.callerAuth, this
// service's own caller credential (caller_unauthenticated). Only the first is
// the RPC caller's to fix.

func TestO3coVerify_401CallerUnauthenticated_IsNotTheSubjectsFault(t *testing.T) {
	body := `{"decision": "deny", "code": "caller_unauthenticated", "message": "Caller credential required"}`
	e := newTestEndpoint(t, serve(t, http.StatusUnauthorized, body).URL)

	err := e.Verify(ctxWithToken("tok"), "r", "a")
	if !errors.Is(err, ErrCallerUnauthenticated) {
		t.Fatalf("expected ErrCallerUnauthenticated, got %T: %v", err, err)
	}
	var unauth *interceptors.UnauthenticatedError
	if errors.As(err, &unauth) {
		t.Fatal("a refused caller credential must not tell the RPC caller its token is invalid")
	}
}

func TestO3coVerify_401InvalidToken_IsUnauthenticated(t *testing.T) {
	body := `{"decision": "deny", "code": "invalid_token", "message": "Token is invalid"}`
	e := newTestEndpoint(t, serve(t, http.StatusUnauthorized, body).URL)

	var unauth *interceptors.UnauthenticatedError
	if err := e.Verify(ctxWithToken("tok"), "r", "a"); !errors.As(err, &unauth) {
		t.Fatalf("expected *UnauthenticatedError, got %T: %v", err, err)
	}
}

// --- Strict mode ---------------------------------------------------------------

func TestO3coRequireConfirmedRevision_AcceptsAConfirmedAllow(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, allowWithEvaluation).URL, WithO3coRequireConfirmedRevision())
	if err := e.Verify(ctxWithToken("tok"), "r", "a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestO3coRequireConfirmedRevision_RefusesAnUnconfirmedAllow(t *testing.T) {
	cases := map[string]string{
		"no evaluation": allowWithoutEvaluation,
		"null revision": strings.ReplaceAll(allowWithEvaluation, `"revision": "`+testDigest+`"`, `"revision": null`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEndpoint(t, serve(t, http.StatusOK, body).URL, WithO3coRequireConfirmedRevision())
			d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
			var unconfirmed *interceptors.UnconfirmedRevisionError
			if !errors.As(err, &unconfirmed) {
				t.Fatalf("expected *UnconfirmedRevisionError, got %T: %v", err, err)
			}
			if unconfirmed.Decision != d {
				t.Errorf("UnconfirmedRevisionError.Decision = %v, want the returned decision %v", unconfirmed.Decision, d)
			}
			var denied *interceptors.DeniedError
			if errors.As(err, &denied) {
				t.Error("an unconfirmed allow is not a denial")
			}
		})
	}
}

func TestO3coRequireConfirmedRevision_LeavesADenyADeny(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, denyWithEvaluation).URL, WithO3coRequireConfirmedRevision())
	var denied *interceptors.DeniedError
	if err := e.Verify(ctxWithToken("tok"), "r", "a"); !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

// Against a verifier that has not opted in, strict mode refuses every allow.
// That cannot be detected at construction, so the first such refusal says so
// once, at the default level.
func TestO3coRequireConfirmedRevision_SaysOnceWhenTheVerifierSendsNoEvaluation(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, allowWithoutEvaluation).URL, WithO3coRequireConfirmedRevision())
	logs := captureLogs(e)

	for range 3 {
		_ = e.Verify(ctxWithToken("tok"), "r", "a")
	}
	if n := strings.Count(logs.String(), "evaluationInResponse"); n != 1 {
		t.Errorf("the evaluationInResponse hint was logged %d times, want once:\n%s", n, logs.String())
	}
}

// --- Logging -------------------------------------------------------------------

func TestO3coVerify_DoesNotLogTheDecisionBodyAtTheDefaultLevel(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, denyWithEvaluation).URL)
	logs := captureLogs(e)

	_ = e.Verify(ctxWithTokenAndRequestID("tok", "req-1"), "r", "a")
	out := logs.String()
	for _, leak := range []string{"sha256", "20-forbid-secret", "Denied by Cedar policy"} {
		if strings.Contains(out, leak) {
			t.Errorf("default-level log carries %q from the decision body:\n%s", leak, out)
		}
	}
	for _, want := range []string{"status=403", "code=cedar_deny", "req-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("default-level log lacks %q:\n%s", want, out)
		}
	}
}

// --- VerifyWithDecision ----------------------------------------------------------

type plainVerifier struct{ err error }

func (p plainVerifier) Verify(context.Context, string, string) error { return p.err }

func TestVerifyWithDecision_PlainEndpointReportsNothing(t *testing.T) {
	want := &interceptors.DeniedError{Reason: "no"}
	d, err := VerifyWithDecision(context.Background(), plainVerifier{err: want}, "r", "a")
	if d != nil || err != want {
		t.Errorf("VerifyWithDecision = (%v, %v), want (nil, %v)", d, err, want)
	}
}

func TestVerifyWithDecision_DecisionVerifierReportsItsDecision(t *testing.T) {
	e := newTestEndpoint(t, serve(t, http.StatusOK, allowWithEvaluation).URL)
	d, err := VerifyWithDecision(ctxWithToken("tok"), e, "r", "a")
	if err != nil || !d.RevisionConfirmed() {
		t.Errorf("VerifyWithDecision = (%+v, %v)", d, err)
	}
}

// --- Key case ---------------------------------------------------------------------
//
// The wire contract's keys are case-sensitive. A key in another case is one
// the contract does not define, which a client ignores: it must not stand in
// for the key it resembles.

func TestO3coVerify_ADecisionKeyInAnotherCase_DoesNotGrant(t *testing.T) {
	body := strings.Replace(denyWithEvaluation, `"decision": "deny",`, `"decision": "deny", "Decision": "allow",`, 1)
	e := newTestEndpoint(t, serve(t, http.StatusOK, body).URL)
	d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err == nil {
		t.Fatal("expected an error: a 200 whose decision is deny is not an allow")
	}
	if d == nil || d.Code != "cedar_deny" {
		t.Errorf("decision = %+v, want the deny", d)
	}
}

func TestO3coRequireConfirmedRevision_KeysInAnotherCase_DoNotConfirm(t *testing.T) {
	const confirmed = `{"code": "c", "message": "m", "passed": true, "evaluation": {"status": "completed", "revision": "` + testDigest + `"}}`
	envelope := func(group string) string {
		return `{"decision": "allow", "resource": "r", "action": "a", "reason": {"groups": [` + group + `]}}`
	}
	cases := map[string]string{
		"a failing group that says Passed and SatisfiedBy": envelope(`{"ruleType": "cedar", "passed": false, "evaluated": [` + confirmed + `],
			"Passed": true, "SatisfiedBy": ` + confirmed + `}`),
		"a null revision beside a Revision": envelope(`{"ruleType": "cedar", "passed": true, "evaluated": [],
			"satisfiedBy": {"code": "c", "message": "m", "passed": true,
				"evaluation": {"status": "completed", "revision": null, "Revision": "` + testDigest + `"}}}`),
		"a failed status beside a Status": envelope(`{"ruleType": "cedar", "passed": true, "evaluated": [],
			"satisfiedBy": {"code": "c", "message": "m", "passed": true,
				"evaluation": {"status": "failed", "revision": "` + testDigest + `", "Status": "completed"}}}`),
		"a satisfying rule without an evaluation beside an Evaluation": envelope(`{"ruleType": "cedar", "passed": true, "evaluated": [],
			"satisfiedBy": {"code": "c", "message": "m", "passed": true,
				"Evaluation": {"status": "completed", "revision": "` + testDigest + `"}}}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEndpoint(t, serve(t, http.StatusOK, body).URL, WithO3coRequireConfirmedRevision())
			d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
			var unconfirmed *interceptors.UnconfirmedRevisionError
			if !errors.As(err, &unconfirmed) {
				t.Fatalf("expected *UnconfirmedRevisionError, got %T: %v (decision %+v)", err, err, d)
			}
		})
	}
}

// The group reads as the exact keys say: failing, with no satisfying rule.
func TestO3coVerifyDecision_PassedAndSatisfiedByInAnotherCase_AreIgnored(t *testing.T) {
	body := `{"decision": "deny", "code": "c", "message": "m", "resource": "r", "action": "a", "reason": {"groups": [
		{"ruleType": "cedar", "passed": false, "evaluated": [{"code": "c", "message": "m", "passed": false}],
		 "Passed": true, "SatisfiedBy": {"code": "c", "message": "m", "passed": true}}]}}`
	e := newTestEndpoint(t, serve(t, http.StatusForbidden, body).URL)
	d, _ := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if d == nil || len(d.Groups) != 1 {
		t.Fatalf("decision = %+v", d)
	}
	if g := d.Groups[0]; g.Passed || g.SatisfiedBy != nil {
		t.Errorf("group = %+v, want failing with no satisfying rule", g)
	}
}
