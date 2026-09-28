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

// parseDecision reads body as a decision or error envelope. It returns nil for
// anything else — empty, not JSON, a value of the wrong type anywhere, or no
// decision at all — so that a body that is not a decision reports nothing
// rather than part of one.
func parseDecision(body []byte) *wireDecision {
	if len(body) == 0 {
		return nil
	}
	var w wireDecision
	if err := json.Unmarshal(body, &w); err != nil || w.Decision == "" {
		return nil
	}
	return &w
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
			group := interceptors.RuleGroup{RuleType: g.RuleType, Passed: g.Passed}
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
