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
// otherwise. Keys this library does not know are ignored, as the verifier's
// wire contract requires of a client.
type wireDecision struct {
	Decision string      `json:"decision"`
	Code     string      `json:"code"`
	Message  string      `json:"message"`
	Reason   *wireReason `json:"reason"`
}

type wireReason struct {
	Groups []wireGroup `json:"groups"`
}

type wireGroup struct {
	RuleType    string        `json:"ruleType"`
	Passed      bool          `json:"passed"`
	Restricts   bool          `json:"restricts"`
	Evaluated   []wireOutcome `json:"evaluated"`
	SatisfiedBy *wireOutcome  `json:"satisfiedBy"`
}

type wireOutcome struct {
	Code       string          `json:"code"`
	Message    string          `json:"message"`
	Passed     bool            `json:"passed"`
	Evaluation *wireEvaluation `json:"evaluation"`
}

type wireEvaluation struct {
	Status                     string   `json:"status"`
	Revision                   *string  `json:"revision"`
	LoadedRevision             string   `json:"loadedRevision"`
	DeterminingPolicies        []string `json:"determiningPolicies"`
	DeterminingPoliciesOmitted int      `json:"determiningPoliciesOmitted"`
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

// parseEnvelope reads body, decoded as obj, as an envelope of kind. It returns
// nil unless every key the wire contract requires of that kind is there, none
// is null where the contract types a value, and each has the right type — so
// that a body that is not a whole envelope reports nothing rather than part of
// one.
func parseEnvelope(body []byte, obj map[string]any, kind envelopeKind) *wireDecision {
	valid := false
	switch kind {
	case decisionEnvelope:
		valid = validDecision(obj)
	case errorEnvelope:
		valid = present(obj, "decision", "code", "message")
	}
	if !valid {
		return nil
	}
	// Presence is checked above; the typed decode checks every value's type.
	var w wireDecision
	if err := json.Unmarshal(body, &w); err != nil {
		return nil
	}
	return &w
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

func validDecision(obj map[string]any) bool {
	if !present(obj, "resource", "action", "decision", "reason") {
		return false
	}
	switch obj["decision"] {
	case "allow":
	case "deny":
		if !present(obj, "code", "message") {
			return false
		}
	default:
		return false
	}
	reason, ok := obj["reason"].(map[string]any)
	if !ok {
		return false
	}
	groups, ok := reason["groups"].([]any)
	if !ok {
		return false
	}
	for _, g := range groups {
		if !validGroup(g) {
			return false
		}
	}
	return true
}

func validGroup(v any) bool {
	g, ok := v.(map[string]any)
	if !ok || !present(g, "ruleType", "passed", "evaluated") {
		return false
	}
	evaluated, ok := g["evaluated"].([]any)
	if !ok {
		return false
	}
	for _, o := range evaluated {
		if !validOutcome(o) {
			return false
		}
	}
	// restricts is optional and, when sent, true: a group of restricting
	// rules. Any other value is not the contract's.
	if r, has := g["restricts"]; has && r != true {
		return false
	}
	// satisfiedBy marks a pass: a passing group names the rule that satisfied
	// it, and a failing one, where every alternative refused, names none.
	satisfiedBy, has := g["satisfiedBy"]
	if g["passed"] == true {
		return has && validOutcome(satisfiedBy)
	}
	return !has
}

func validOutcome(v any) bool {
	o, ok := v.(map[string]any)
	if !ok || !present(o, "code", "message", "passed") {
		return false
	}
	evaluation, has := o["evaluation"]
	return !has || validEvaluation(evaluation)
}

func validEvaluation(v any) bool {
	e, ok := v.(map[string]any)
	if !ok || !present(e, "status") {
		return false
	}
	for _, k := range []string{"loadedRevision", "determiningPolicies", "determiningPoliciesOmitted"} {
		if x, has := e[k]; has && x == nil {
			return false
		}
	}
	switch e["status"] {
	case string(interceptors.EvaluationCompleted), string(interceptors.EvaluationFailed):
		// An evaluated answer always names its revision, and null is one: the
		// explicit unknown.
		_, has := e["revision"]
		return has
	}
	// not_invoked carries nothing else, and a status added after this library
	// was written is passed through as it came.
	return true
}

// toDecision converts w, sent with requestID, to the library's decision. A
// nil w converts to nil.
func (w *wireDecision) toDecision(requestID string) *interceptors.Decision {
	if w == nil {
		return nil
	}
	d := &interceptors.Decision{Code: w.Code, Message: w.Message, RequestID: requestID}
	if w.Reason != nil {
		d.Groups = make([]interceptors.RuleGroup, 0, len(w.Reason.Groups))
		for _, g := range w.Reason.Groups {
			group := interceptors.RuleGroup{RuleType: g.RuleType, Passed: g.Passed, Restricts: g.Restricts}
			for _, o := range g.Evaluated {
				group.Evaluated = append(group.Evaluated, o.toOutcome())
			}
			if g.SatisfiedBy != nil {
				s := g.SatisfiedBy.toOutcome()
				group.SatisfiedBy = &s
			}
			d.Groups = append(d.Groups, group)
		}
	}
	return d
}

func (o wireOutcome) toOutcome() interceptors.RuleOutcome {
	out := interceptors.RuleOutcome{Code: o.Code, Message: o.Message, Passed: o.Passed}
	if e := o.Evaluation; e != nil {
		out.Evaluation = &interceptors.Evaluation{
			Status:                     interceptors.EvaluationStatus(e.Status),
			LoadedRevision:             e.LoadedRevision,
			DeterminingPolicies:        e.DeterminingPolicies,
			DeterminingPoliciesOmitted: e.DeterminingPoliciesOmitted,
		}
		if e.Revision != nil {
			out.Evaluation.Revision = *e.Revision
		}
	}
	return out
}
