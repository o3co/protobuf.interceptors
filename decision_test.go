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

package interceptors_test

import (
	"context"
	"strings"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

const digest = "sha256:9f2c1e0b7a4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b"

func completed(revision string) *interceptors.Evaluation {
	return &interceptors.Evaluation{Status: interceptors.EvaluationCompleted, Revision: revision}
}

func TestEvaluation_ConfirmedRevision(t *testing.T) {
	cases := []struct {
		name string
		eval *interceptors.Evaluation
		want string
		ok   bool
	}{
		{"completed with a digest", completed(digest), digest, true},
		{"completed under a scheme of its own", completed("git:0a1b2c3d"), "git:0a1b2c3d", true},
		// revision: null — the evaluator ran and what it evaluated is not established.
		{"completed with a null revision", &interceptors.Evaluation{Status: interceptors.EvaluationCompleted, LoadedRevision: digest}, "", false},
		// A failed evaluation is the rule failing closed; its revision decided nothing.
		{"failed", &interceptors.Evaluation{Status: interceptors.EvaluationFailed, Revision: digest}, "", false},
		{"not invoked", &interceptors.Evaluation{Status: interceptors.EvaluationNotInvoked}, "", false},
		{"a status this library does not know", &interceptors.Evaluation{Status: "partial", Revision: digest}, "", false},
		{"a path is not a revision", completed("/etc/policies/main.cedar"), "", false},
		{"a label with spaces is not a revision", completed("release 12"), "", false},
		{"no scheme", completed("9f2c1e0b"), "", false},
		{"longer than 256 characters", completed("sha256:" + strings.Repeat("a", 250)), "", false},
		{"absent", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.eval.ConfirmedRevision()
			if got != tc.want || ok != tc.ok {
				t.Errorf("ConfirmedRevision() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func passingGroup(ruleType string, satisfiedBy interceptors.RuleOutcome, triedBefore ...interceptors.RuleOutcome) interceptors.RuleGroup {
	return interceptors.RuleGroup{
		RuleType:    ruleType,
		Passed:      true,
		Evaluated:   append(triedBefore, satisfiedBy),
		SatisfiedBy: &satisfiedBy,
	}
}

func outcome(passed bool, eval *interceptors.Evaluation) interceptors.RuleOutcome {
	return interceptors.RuleOutcome{Code: "rule", Message: "rule", Passed: passed, Evaluation: eval}
}

func TestDecision_RevisionConfirmed(t *testing.T) {
	cases := []struct {
		name     string
		decision *interceptors.Decision
		want     bool
	}{
		{
			name:     "every satisfying outcome carries a confirmed revision",
			decision: &interceptors.Decision{Groups: []interceptors.RuleGroup{passingGroup("cedar", outcome(true, completed(digest)))}},
			want:     true,
		},
		{
			// Only what satisfied a group counts; an alternative tried before it decided nothing.
			name: "an alternative tried first carries none",
			decision: &interceptors.Decision{Groups: []interceptors.RuleGroup{
				passingGroup("cedar", outcome(true, completed(digest)), outcome(false, nil)),
			}},
			want: true,
		},
		{
			name: "one group is satisfied by a rule with no policy source",
			decision: &interceptors.Decision{Groups: []interceptors.RuleGroup{
				passingGroup("cedar", outcome(true, completed(digest))),
				passingGroup("rbac", outcome(true, nil)),
			}},
			want: false,
		},
		{
			name:     "the revision is null",
			decision: &interceptors.Decision{Groups: []interceptors.RuleGroup{passingGroup("cedar", outcome(true, completed("")))}},
			want:     false,
		},
		{
			name: "a group did not pass",
			decision: &interceptors.Decision{Groups: []interceptors.RuleGroup{
				{RuleType: "cedar", Passed: false, Evaluated: []interceptors.RuleOutcome{outcome(false, completed(digest))}},
			}},
			want: false,
		},
		{
			name: "a passing group names nothing that satisfied it",
			decision: &interceptors.Decision{Groups: []interceptors.RuleGroup{
				{RuleType: "cedar", Passed: true, Evaluated: []interceptors.RuleOutcome{outcome(true, completed(digest))}},
			}},
			want: false,
		},
		{name: "no groups", decision: &interceptors.Decision{}, want: false},
		{name: "no decision", decision: nil, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.decision.RevisionConfirmed(); got != tc.want {
				t.Errorf("RevisionConfirmed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDecisionFromContext(t *testing.T) {
	if d, ok := interceptors.DecisionFromContext(context.Background()); ok || d != nil {
		t.Fatalf("DecisionFromContext(empty) = (%v, %v), want (nil, false)", d, ok)
	}

	want := &interceptors.Decision{RequestID: "req-1"}
	got, ok := interceptors.DecisionFromContext(interceptors.WithDecision(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("DecisionFromContext = (%v, %v), want (%v, true)", got, ok, want)
	}
}

// The decision is the service's: nothing of it may reach an error message,
// which the framework interceptors hand to the RPC caller.
func TestDecisionErrors_DoNotCarryTheDecisionInTheirMessage(t *testing.T) {
	decision := &interceptors.Decision{
		Code:      "cedar_deny",
		Message:   "Denied by Cedar policy",
		RequestID: "req-1",
		Groups:    []interceptors.RuleGroup{passingGroup("cedar", outcome(true, completed(digest)))},
	}
	errs := []error{
		&interceptors.DeniedError{Reason: "access denied", Decision: decision},
		&interceptors.UnconfirmedRevisionError{Decision: decision},
	}
	for _, err := range errs {
		msg := err.Error()
		for _, leak := range []string{"cedar_deny", "Denied by Cedar policy", "req-1", "sha256", "9f2c"} {
			if strings.Contains(msg, leak) {
				t.Errorf("%T.Error() = %q, which carries %q from the decision", err, msg, leak)
			}
		}
	}
}
