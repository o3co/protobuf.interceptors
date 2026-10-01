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
	"math"
	"strings"

	interceptors "github.com/o3co/protobuf.interceptors"
)

// codeCallerUnauthenticated is the code auth.policy-verifier's http.callerAuth
// gate refuses a request with, under the same 401 as a bad subject token.
const codeCallerUnauthenticated = "caller_unauthenticated"

// ErrCallerUnauthenticated reports that the verifier refused this service's
// own caller credential (see WithO3coHeaders), not the subject's bearer
// token. It is a deployment fault the RPC caller cannot fix, so it is not an
// UnauthenticatedError and the framework interceptors map it to Internal.
var ErrCallerUnauthenticated = errors.New("authorization service refused this service's caller credential")

// wireDecision is the body of a POST /verify answer: the decision envelope on
// 200 and 403, the error envelope — decision, code and message only —
// otherwise. It is read from the body decoded as a map, whose keys match the
// contract's exactly: the one walk over it both checks the envelope and
// builds what is returned, so no key it did not check can reach a decision.
// Keys this library does not know, a key in another case among them, are
// ignored, as the verifier's wire contract requires of a client.
type wireDecision struct {
	Decision string
	Code     string
	Message  string
	// Groups are the reason's rule groups, nil in an error envelope.
	Groups []interceptors.RuleGroup
}

// envelopeKind is which envelope a status answers with.
type envelopeKind int

const (
	// decisionEnvelope is a 2xx or 403: the verdict and the reason behind it.
	decisionEnvelope envelopeKind = iota
	// errorEnvelope is any other status: decision, code and message.
	errorEnvelope
)

// decodeObject decodes body as a JSON object, and reports whether it is one.
func decodeObject(body []byte) (map[string]any, bool) {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// parseEnvelope reads obj as an envelope of kind. It returns nil unless every
// key the wire contract requires of that kind is there, none is null where the
// contract types a value, and each has the right type — so that a body that
// is not a whole envelope reports nothing rather than part of one.
func parseEnvelope(obj map[string]any, kind envelopeKind) *wireDecision {
	var (
		w  *wireDecision
		ok bool
	)
	switch kind {
	case decisionEnvelope:
		w, ok = readDecision(obj)
	case errorEnvelope:
		w, ok = readError(obj)
	}
	if !ok {
		return nil
	}
	return w
}

// present reports whether obj holds each of keys, none of them null.
func present(obj map[string]any, keys ...string) bool {
	for _, k := range keys {
		if v, ok := obj[k]; !ok || v == nil {
			return false
		}
	}
	return true
}

// optionalString reads obj[key] where the contract may leave it out: absent
// or null is "", and anything but a string is not the contract's.
func optionalString(obj map[string]any, key string) (string, bool) {
	v, has := obj[key]
	if !has || v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

func readError(obj map[string]any) (*wireDecision, bool) {
	decision, ok1 := obj["decision"].(string)
	code, ok2 := obj["code"].(string)
	message, ok3 := obj["message"].(string)
	if !ok1 || !ok2 || !ok3 {
		return nil, false
	}
	return &wireDecision{Decision: decision, Code: code, Message: message}, true
}

func readDecision(obj map[string]any) (*wireDecision, bool) {
	if !present(obj, "resource", "action", "decision", "reason") {
		return nil, false
	}
	_, okResource := obj["resource"].(string)
	_, okAction := obj["action"].(string)
	if !okResource || !okAction {
		return nil, false
	}
	w := &wireDecision{}
	w.Decision, _ = obj["decision"].(string)
	switch w.Decision {
	case "allow":
	case "deny":
		if !present(obj, "code", "message") {
			return nil, false
		}
	default:
		return nil, false
	}
	var okCode, okMessage bool
	w.Code, okCode = optionalString(obj, "code")
	w.Message, okMessage = optionalString(obj, "message")
	if !okCode || !okMessage {
		return nil, false
	}
	reason, ok := obj["reason"].(map[string]any)
	if !ok {
		return nil, false
	}
	groups, ok := reason["groups"].([]any)
	if !ok {
		return nil, false
	}
	w.Groups = make([]interceptors.RuleGroup, 0, len(groups))
	for _, g := range groups {
		group, ok := readGroup(g)
		if !ok {
			return nil, false
		}
		w.Groups = append(w.Groups, group)
	}
	return w, true
}

func readGroup(v any) (interceptors.RuleGroup, bool) {
	g, ok := v.(map[string]any)
	if !ok || !present(g, "ruleType", "passed", "evaluated") {
		return interceptors.RuleGroup{}, false
	}
	ruleType, okRuleType := g["ruleType"].(string)
	passed, okPassed := g["passed"].(bool)
	evaluated, okEvaluated := g["evaluated"].([]any)
	if !okRuleType || !okPassed || !okEvaluated {
		return interceptors.RuleGroup{}, false
	}
	group := interceptors.RuleGroup{RuleType: ruleType, Passed: passed}
	for _, o := range evaluated {
		outcome, ok := readOutcome(o)
		if !ok {
			return interceptors.RuleGroup{}, false
		}
		group.Evaluated = append(group.Evaluated, outcome)
	}
	// restricts is optional and, when sent, true: a group of restricting
	// rules. Any other value is not the contract's. Unlike other unknown keys,
	// the key in another case is refused rather than ignored: a group marked
	// restricting is left out of what must be confirmed, and a client that
	// matched keys case-insensitively would mark this one.
	for k, v := range g {
		if strings.EqualFold(k, "restricts") && (k != "restricts" || v != true) {
			return interceptors.RuleGroup{}, false
		}
	}
	group.Restricts = g["restricts"] == true
	// satisfiedBy marks a pass: a passing group names the rule that satisfied
	// it, and a failing one, where every alternative refused, names none.
	satisfiedBy, has := g["satisfiedBy"]
	if passed != has {
		return interceptors.RuleGroup{}, false
	}
	if has {
		outcome, ok := readOutcome(satisfiedBy)
		if !ok {
			return interceptors.RuleGroup{}, false
		}
		group.SatisfiedBy = &outcome
	}
	return group, true
}

func readOutcome(v any) (interceptors.RuleOutcome, bool) {
	o, ok := v.(map[string]any)
	if !ok || !present(o, "code", "message", "passed") {
		return interceptors.RuleOutcome{}, false
	}
	code, okCode := o["code"].(string)
	message, okMessage := o["message"].(string)
	passed, okPassed := o["passed"].(bool)
	if !okCode || !okMessage || !okPassed {
		return interceptors.RuleOutcome{}, false
	}
	outcome := interceptors.RuleOutcome{Code: code, Message: message, Passed: passed}
	if evaluation, has := o["evaluation"]; has {
		e, ok := readEvaluation(evaluation)
		if !ok {
			return interceptors.RuleOutcome{}, false
		}
		outcome.Evaluation = e
	}
	return outcome, true
}

func readEvaluation(v any) (*interceptors.Evaluation, bool) {
	e, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	status, ok := e["status"].(string)
	if !ok {
		return nil, false
	}
	out := &interceptors.Evaluation{Status: interceptors.EvaluationStatus(status)}
	// Optional keys: absent is unknown, null is not the contract's.
	if x, has := e["loadedRevision"]; has {
		if out.LoadedRevision, ok = x.(string); !ok {
			return nil, false
		}
	}
	if x, has := e["determiningPolicies"]; has {
		if out.DeterminingPolicies, ok = readStrings(x); !ok {
			return nil, false
		}
	}
	if x, has := e["determiningPoliciesOmitted"]; has {
		if out.DeterminingPoliciesOmitted, ok = readInt(x); !ok {
			return nil, false
		}
	}
	// revision is a string, or null: the explicit unknown.
	revision, has := e["revision"]
	if has && revision != nil {
		if out.Revision, ok = revision.(string); !ok {
			return nil, false
		}
	}
	switch out.Status {
	case interceptors.EvaluationCompleted, interceptors.EvaluationFailed:
		// An evaluated answer always names its revision, and null is one.
		if !has {
			return nil, false
		}
	}
	// not_invoked carries nothing else, and a status added after this library
	// was written is passed through as it came.
	return out, true
}

func readStrings(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// readInt reads a JSON number that is an integer within int's range.
func readInt(v any) (int, bool) {
	f, ok := v.(float64)
	// float64(math.MaxInt) is 2^63, one past the largest int.
	if !ok || f != math.Trunc(f) || f < math.MinInt || f >= math.MaxInt {
		return 0, false
	}
	return int(f), true
}

// toDecision converts w, sent with requestID, to the library's decision. A
// nil w converts to nil.
func (w *wireDecision) toDecision(requestID string) *interceptors.Decision {
	if w == nil {
		return nil
	}
	return &interceptors.Decision{Code: w.Code, Message: w.Message, Groups: w.Groups, RequestID: requestID}
}
