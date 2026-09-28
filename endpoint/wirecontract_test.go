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
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/internal/wirecontract"
)

// These tests build every envelope from the key sets auth.policy-verifier's
// wire contract lists, so a key the verifier starts to require, or a status or
// code it renames, fails here instead of in production. A key the contract
// lists that fill() does not know fails too: the envelope cannot be built
// without deciding what this endpoint does with it.

// fill returns an object holding exactly keys, each set from values.
func fill(t *testing.T, what string, keys []string, values map[string]any) map[string]any {
	t.Helper()
	obj := make(map[string]any, len(keys))
	for _, k := range keys {
		v, ok := values[k]
		if !ok {
			t.Fatalf("the wire contract lists %q on %s, which this test does not know how to fill", k, what)
		}
		obj[k] = v
	}
	return obj
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestWireContract_StatusesMeanWhatTheVerifierMeans(t *testing.T) {
	c := wirecontract.Load(t)

	errorEnvelope := func(code string) string {
		return mustJSON(t, fill(t, "an error envelope", c.Error.Keys, map[string]any{
			"decision": c.Error.Decision, "code": code, "message": "m",
		}))
	}

	check := func(name string, status int, body string, want func(error) bool) {
		t.Run(name, func(t *testing.T) {
			e := newTestEndpoint(t, serve(t, status, body).URL)
			if err := e.Verify(ctxWithToken("tok"), "r", "a"); !want(err) {
				t.Errorf("status %d: got %T: %v", status, err, err)
			}
		})
	}
	isDenied := func(err error) bool { var d *interceptors.DeniedError; return errors.As(err, &d) }
	isUnauth := func(err error) bool { var u *interceptors.UnauthenticatedError; return errors.As(err, &u) }

	check("allow", c.Status["allow"], "", func(err error) bool { return err == nil })
	check("deny", c.Status["deny"], "", isDenied)
	for _, code := range []string{c.Codes["missingToken"], c.Codes["invalidToken"], c.Codes["unsupportedScheme"]} {
		check("unauthenticated/"+code, c.Status["unauthenticated"], errorEnvelope(code), isUnauth)
	}
	check("callerUnauthenticated", c.Status["callerUnauthenticated"], errorEnvelope(c.Codes["callerUnauthenticated"]), func(err error) bool {
		return errors.Is(err, ErrCallerUnauthenticated) && !isUnauth(err)
	})
	for _, key := range []string{"invalidRequest", "payloadTooLarge", "unsupportedMediaType", "internalError"} {
		check(key, c.Status[key], errorEnvelope(c.Codes[key]), func(err error) bool {
			return err != nil && !isDenied(err) && !isUnauth(err)
		})
	}
}

func TestWireContract_CallerUnauthenticatedCode(t *testing.T) {
	c := wirecontract.Load(t)
	if got := c.Codes["callerUnauthenticated"]; got != codeCallerUnauthenticated {
		t.Errorf("codeCallerUnauthenticated = %q, the wire contract says %q", codeCallerUnauthenticated, got)
	}
}

func TestWireContract_RequestIDHeader(t *testing.T) {
	c := wirecontract.Load(t)
	if !strings.EqualFold(c.RequestID.Header, defaultRequestIDHeaderKey) {
		t.Errorf("default request-ID header = %q, the wire contract says %q", defaultRequestIDHeaderKey, c.RequestID.Header)
	}
}

func TestWireContract_EvaluationShapesDecode(t *testing.T) {
	c := wirecontract.Load(t)

	revision := testDigest
	if !regexp.MustCompile(c.Evaluation.Revision.Pattern).MatchString(revision) {
		t.Fatalf("the test revision %q does not match the contract's pattern", revision)
	}
	values := map[string]any{
		"revision":                   revision,
		"loadedRevision":             revision,
		"determiningPolicies":        []string{"10-permit-read"},
		"determiningPoliciesOmitted": 2,
	}
	evaluation := func(status string, keys []string, nullRevision bool) map[string]any {
		v := map[string]any{"status": status}
		for k, x := range values {
			v[k] = x
		}
		if nullRevision {
			v["revision"] = nil
		}
		return fill(t, "an evaluation", keys, v)
	}
	ev := c.Evaluation.Evaluated
	shapes := map[string]map[string]any{
		"not_invoked":         fill(t, "a not_invoked evaluation", c.Evaluation.NotInvoked.Keys, map[string]any{"status": "not_invoked"}),
		"failed":              evaluation("failed", ev.Required, false),
		"failed/null":         evaluation("failed", append(append([]string{}, ev.Required...), ev.OnlyWhenRevisionIsNull...), true),
		"completed":           evaluation("completed", append(append([]string{}, ev.Required...), ev.OnlyWhenCompleted...), false),
		"completed/null":      evaluation("completed", append(append(append([]string{}, ev.Required...), ev.OnlyWhenRevisionIsNull...), ev.OnlyWhenCompleted...), true),
		"completed/minimal":   evaluation("completed", ev.Required, false),
		"completed/null/bare": evaluation("completed", ev.Required, true),
	}

	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			outcomeValues := map[string]any{"code": "c", "message": "m", "passed": true, "evaluation": shape}
			outcome := fill(t, "a rule outcome", append(append([]string{}, c.RuleOutcome.Required...), c.RuleOutcome.Optional...), outcomeValues)
			group := fill(t, "a passing rule group", append(append([]string{}, c.RuleGroup.Required...), c.RuleGroup.OnlyOnAPassingGroup...), map[string]any{
				"ruleType": "cedar", "passed": true, "evaluated": []any{outcome}, "satisfiedBy": outcome,
			})
			decision := fill(t, "an allow", c.Decision.Required, map[string]any{
				"resource": "r", "action": "a", "decision": "allow", "reason": map[string]any{"groups": []any{group}},
			})

			e := newTestEndpoint(t, serve(t, c.Status["allow"], mustJSON(t, decision)).URL)
			d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
			if err != nil || d == nil || len(d.Groups) != 1 || d.Groups[0].SatisfiedBy == nil {
				t.Fatalf("VerifyDecision = (%+v, %v)", d, err)
			}
			got := d.Groups[0].SatisfiedBy.Evaluation
			if got == nil || string(got.Status) != shape["status"] {
				t.Fatalf("evaluation decoded as %+v", got)
			}
			_, confirmed := got.ConfirmedRevision()
			wantConfirmed := shape["status"] == "completed" && shape["revision"] != nil
			if confirmed != wantConfirmed {
				t.Errorf("ConfirmedRevision ok = %v, want %v for %v", confirmed, wantConfirmed, shape)
			}
			if _, ok := shape["loadedRevision"]; ok && got.LoadedRevision != revision {
				t.Errorf("LoadedRevision = %q", got.LoadedRevision)
			}
			if _, ok := shape["determiningPolicies"]; ok && (len(got.DeterminingPolicies) != 1 || got.DeterminingPoliciesOmitted != 2) {
				t.Errorf("determining policies = (%v, %d)", got.DeterminingPolicies, got.DeterminingPoliciesOmitted)
			}
		})
	}
}

func TestWireContract_DenyCarriesItsCode(t *testing.T) {
	c := wirecontract.Load(t)
	values := map[string]any{
		"resource": "r", "action": "a", "decision": "deny", "reason": map[string]any{"groups": []any{}},
		"code": "cedar_deny", "message": "Denied",
	}
	deny := fill(t, "a deny", append(append([]string{}, c.Decision.Required...), c.Decision.DenyAlsoCarries...), values)

	e := newTestEndpoint(t, serve(t, c.Status["deny"], mustJSON(t, deny)).URL)
	d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) || d == nil || d.Code != "cedar_deny" || d.Message != "Denied" {
		t.Errorf("VerifyDecision = (%+v, %v)", d, err)
	}
	if status := c.Status["deny"]; status != http.StatusForbidden {
		t.Errorf("the contract's deny status is %d; this endpoint reads a denial from 403", status)
	}
}
