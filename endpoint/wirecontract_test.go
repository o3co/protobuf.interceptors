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
	"maps"
	"net/http"
	"regexp"
	"slices"
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

	allow := mustJSON(t, fill(t, "an allow", c.Decision.Required, map[string]any{
		"resource": "r", "action": "a", "decision": "allow", "reason": map[string]any{"groups": []any{}},
	}))
	check("allow", c.Status["allow"], allow, func(err error) bool { return err == nil })
	check("allow status without a decision", c.Status["allow"], "", func(err error) bool {
		return err != nil && !isDenied(err) && !isUnauth(err)
	})
	check("deny", c.Status["deny"], "", isDenied)
	if status := c.Status["allow"]; status != http.StatusOK {
		t.Errorf("the contract's allow status is %d; this endpoint reads an allow only from 200", status)
	}
	for _, code := range []string{c.Codes["missingToken"], c.Codes["invalidToken"], c.Codes["unsupportedScheme"]} {
		check("unauthenticated/"+code, c.Status["unauthenticated"], errorEnvelope(code), isUnauth)
	}
	check("callerUnauthenticated", c.Status["callerUnauthenticated"], errorEnvelope(c.Codes["callerUnauthenticated"]), func(err error) bool {
		return errors.Is(err, ErrCallerUnauthenticated) && !isUnauth(err)
	})
	for _, key := range []string{"invalidRequest", "payloadTooLarge", "unsupportedMediaType", "internalError", "verificationUnavailable"} {
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

// A group carrying every key the contract allows a passing group decodes, and
// the optional ones mean what the verifier means by them.
func TestWireContract_EveryRuleGroupKeyDecodes(t *testing.T) {
	c := wirecontract.Load(t)
	outcome := fill(t, "a rule outcome", c.RuleOutcome.Required, map[string]any{"code": "c", "message": "m", "passed": true})
	keys := append(append(append([]string{}, c.RuleGroup.Required...), c.RuleGroup.Optional...), c.RuleGroup.OnlyOnAPassingGroup...)
	group := fill(t, "a passing rule group", keys, map[string]any{
		"ruleType": "delegation_range", "passed": true, "evaluated": []any{outcome}, "satisfiedBy": outcome, "restricts": true,
	})
	decision := fill(t, "an allow", c.Decision.Required, map[string]any{
		"resource": "r", "action": "a", "decision": "allow", "reason": map[string]any{"groups": []any{group}},
	})

	e := newTestEndpoint(t, serve(t, c.Status["allow"], mustJSON(t, decision)).URL)
	d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
	if err != nil || d == nil || len(d.Groups) != 1 {
		t.Fatalf("VerifyDecision = (%+v, %v)", d, err)
	}
	if !slices.Contains(c.RuleGroup.Optional, "restricts") {
		t.Fatalf("the wire contract no longer lists restricts on a rule group: %v", c.RuleGroup.Optional)
	}
	if !d.Groups[0].Restricts {
		t.Error("restricts: true decoded as a granting group")
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

// An envelope missing any key the contract requires — or holding null where
// the contract types a value — is not a decision, at every level. Only a
// revision may be null: that is the explicit unknown.
func TestWireContract_AnEnvelopeMissingARequiredKeyIsNotADecision(t *testing.T) {
	c := wirecontract.Load(t)
	ev := c.Evaluation.Evaluated

	build := func(verdict string) map[string]any {
		evaluation := fill(t, "an evaluation", ev.Required, map[string]any{"status": "completed", "revision": testDigest})
		outcome := func() map[string]any {
			o := fill(t, "a rule outcome", c.RuleOutcome.Required, map[string]any{"code": "c", "message": "m", "passed": verdict == "allow"})
			o["evaluation"] = maps.Clone(evaluation)
			return o
		}
		groupKeys := c.RuleGroup.Required
		if verdict == "allow" {
			groupKeys = append(append([]string{}, groupKeys...), c.RuleGroup.OnlyOnAPassingGroup...)
		}
		group := fill(t, "a rule group", groupKeys, map[string]any{
			"ruleType": "cedar", "passed": verdict == "allow", "evaluated": []any{outcome()}, "satisfiedBy": outcome(),
		})
		keys := c.Decision.Required
		if verdict == "deny" {
			keys = append(append([]string{}, keys...), c.Decision.DenyAlsoCarries...)
		}
		return fill(t, "a decision", keys, map[string]any{
			"resource": "r", "action": "a", "decision": verdict, "code": "c", "message": "m",
			"reason": map[string]any{"groups": []any{group}},
		})
	}
	group := func(env map[string]any) map[string]any {
		return env["reason"].(map[string]any)["groups"].([]any)[0].(map[string]any)
	}
	outcome := func(env map[string]any) map[string]any {
		return group(env)["evaluated"].([]any)[0].(map[string]any)
	}
	evaluation := func(env map[string]any) map[string]any {
		return outcome(env)["evaluation"].(map[string]any)
	}

	type level struct {
		name string
		at   func(map[string]any) map[string]any
		keys []string
	}
	for _, verdict := range []string{"allow", "deny"} {
		status := c.Status[verdict]
		topKeys := c.Decision.Required
		if verdict == "deny" {
			topKeys = append(append([]string{}, topKeys...), c.Decision.DenyAlsoCarries...)
		}
		levels := []level{
			{"decision", func(env map[string]any) map[string]any { return env }, topKeys},
			{"rule group", group, c.RuleGroup.Required},
			{"rule outcome", outcome, c.RuleOutcome.Required},
			{"evaluation", evaluation, ev.Required},
		}

		// The unmutated envelope is a decision, or the cases below prove nothing.
		e := newTestEndpoint(t, serve(t, status, mustJSON(t, build(verdict))).URL)
		if d, _ := e.VerifyDecision(ctxWithToken("tok"), "r", "a"); d == nil {
			t.Fatalf("%s: the whole envelope did not decode", verdict)
		}

		for _, l := range levels {
			for _, key := range l.keys {
				for _, mutation := range []string{"missing", "null"} {
					if mutation == "null" && key == "revision" {
						continue
					}
					t.Run(verdict+"/"+l.name+"/"+key+"/"+mutation, func(t *testing.T) {
						env := build(verdict)
						target := l.at(env)
						if mutation == "missing" {
							delete(target, key)
						} else {
							target[key] = nil
						}
						e := newTestEndpoint(t, serve(t, status, mustJSON(t, env)).URL)
						d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
						if d != nil {
							t.Errorf("decision = %+v, want nil", d)
						}
						if err == nil {
							t.Error("expected an error: an envelope that is not whole neither allows nor is silent")
						}
					})
				}
			}
		}
	}
}

// An allow never carries the keys the contract keeps for a deny, not even as
// null: an allow that does is not a whole one, and a 200 carrying it does not
// allow.
func TestWireContract_AnAllowCarryingADenyKeyIsNotADecision(t *testing.T) {
	c := wirecontract.Load(t)
	if len(c.Decision.AllowNeverCarries) == 0 {
		t.Fatal("the wire contract lists nothing an allow never carries")
	}
	for _, key := range c.Decision.AllowNeverCarries {
		for name, value := range map[string]any{"a string": "x", "null": nil} {
			t.Run(key+"/"+name, func(t *testing.T) {
				allow := fill(t, "an allow", c.Decision.Required, map[string]any{
					"resource": "r", "action": "a", "decision": "allow", "reason": map[string]any{"groups": []any{}},
				})
				allow[key] = value
				e := newTestEndpoint(t, serve(t, c.Status["allow"], mustJSON(t, allow)).URL)
				d, err := e.VerifyDecision(ctxWithToken("tok"), "r", "a")
				if err == nil || d != nil {
					t.Errorf("VerifyDecision = (%+v, %v), want (nil, an error)", d, err)
				}
			})
		}
	}
}
