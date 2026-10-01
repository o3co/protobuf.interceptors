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

package interceptors

import (
	"context"
	"regexp"
)

// Decision is what an authorization backend reported behind one verdict: the
// deny code and message, and the reason — every rule group it evaluated, how
// each rule came out, and, where a rule reported one, the evaluation behind
// that answer.
//
// It is for the service, never for the RPC caller. Policy revisions and
// evaluation statuses say when a policy set changed and whether a denial was
// the engine failing, so no error this library returns carries any of it in
// its message, and the framework interceptors hand the caller nothing else.
//
// Only an endpoint that implements endpoint.DecisionVerifier reports one (in
// package endpoint, only the o3co endpoint). A nil *Decision means the backend
// reported nothing, or no backend was asked (a refused placeholder value, or a
// method with no policy): it is unknown, not "no policy decided".
type Decision struct {
	// Code and Message are the backend's deny code and message. Both are
	// empty on an allow.
	Code    string
	Message string
	// Groups is the reason: every rule group the backend evaluated, in
	// evaluation order. A deny made without a policy evaluation — a collector
	// timeout, or no applicable rule — has none.
	Groups []RuleGroup
	// RequestID is the request ID sent with the verify request, empty when
	// none was. The backend's own record of the decision carries the same ID,
	// so the service's record joins it on this.
	RequestID string
}

// RuleGroup is how one rule group came out. Groups are ANDed; the rules in a
// group are alternatives, tried in order until one passes.
type RuleGroup struct {
	// RuleType names the group: the backend groups its rules by type, and a
	// group is all the rules of one type.
	RuleType string
	// Passed reports whether one of the group's rules passed.
	Passed bool
	// Restricts marks a group of restricting rules — a delegated token's
	// range, for one. Such a group narrows what the granting groups allow and
	// is never a reason to allow on its own, so a group that passed and
	// restricts granted nothing. False is a granting group, or a backend that
	// does not mark groups.
	Restricts bool
	// Evaluated is every rule that actually ran, in order. A passing group
	// stops at its first passing rule, so alternatives after it are absent.
	Evaluated []RuleOutcome
	// SatisfiedBy is the rule that satisfied a passing group — the last of
	// Evaluated — and nil on a failing one, where every alternative refused.
	SatisfiedBy *RuleOutcome
}

// RuleOutcome is how one rule came out.
type RuleOutcome struct {
	// Code names the rule, as the backend declared it.
	Code string
	// Message is the rule's own account of its answer.
	Message string
	// Passed reports whether the rule passed.
	Passed bool
	// Evaluation is nil when the rule reported none. That is every rule with
	// no policy source, and also every rule of a backend that does not report
	// evaluations or was not configured to: absence means unknown.
	Evaluation *Evaluation
}

// EvaluationStatus says whether a rule's policy evaluator ran.
type EvaluationStatus string

const (
	// EvaluationCompleted: the evaluator ran to an answer.
	EvaluationCompleted EvaluationStatus = "completed"
	// EvaluationFailed: the evaluator was invoked and did not produce a clean
	// answer. The rule failed closed; no policy produced its answer.
	EvaluationFailed EvaluationStatus = "failed"
	// EvaluationNotInvoked: the rule failed before asking its evaluator.
	// Nothing was evaluated.
	EvaluationNotInvoked EvaluationStatus = "not_invoked"
)

// Evaluation is what a policy-backed rule reported about the evaluation
// behind its answer.
type Evaluation struct {
	// Status is as the backend sent it, so a status added after this library
	// was written is visible rather than dropped.
	Status EvaluationStatus
	// Revision is the policy revision the backend sent, empty when it sent
	// null: the evaluator ran and what it evaluated cannot be established.
	// Read it through ConfirmedRevision, which also checks that it is one.
	Revision string
	// LoadedRevision is what the backend loaded, sent only beside a null
	// Revision. It is worth recording and is not proof of what ran.
	LoadedRevision string
	// DeterminingPolicies names the policies that determined a completed
	// answer — the permits that applied to an allow, the forbids that applied
	// to a deny — and is empty, not nil, when none applied. nil means the rule
	// did not say. Beside an unconfirmed revision the ids are as unconfirmed.
	DeterminingPolicies []string
	// DeterminingPoliciesOmitted counts ids the backend could not list.
	DeterminingPoliciesOmitted int
}

// revisionPattern and revisionMaxLength are the policy revision grammar of
// auth.policy-verifier's wire contract: scheme:encoded, the OCI digest
// grammar. TestRevisionGrammar_MatchesTheWireContract holds them to it.
const (
	revisionPattern   = `^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]+$`
	revisionMaxLength = 256
)

var revisionRE = regexp.MustCompile(revisionPattern)

// ConfirmedRevision returns the policy revision the evaluator vouches it
// evaluated, and whether there is one. Only a completed evaluation carries
// one, and only when its revision is well-formed: a failed evaluation decided
// nothing, and a null revision is unknown.
func (e *Evaluation) ConfirmedRevision() (string, bool) {
	if e == nil || e.Status != EvaluationCompleted {
		return "", false
	}
	if len(e.Revision) > revisionMaxLength || !revisionRE.MatchString(e.Revision) {
		return "", false
	}
	return e.Revision, true
}

// RevisionConfirmed reports whether d is an allow established against
// confirmed policy revisions: every group passed, at least one of them
// grants, and the rule that satisfied each granting group carries a
// ConfirmedRevision. Alternatives tried before a satisfying rule decided
// nothing and are not consulted.
//
// A restricting group granted nothing, so what satisfied it is not
// consulted, and an allow whose groups all restrict is never confirmed. A
// granting rule with no policy source never carries a revision, so a
// decision any of whose granting groups such a rule satisfies is never
// confirmed.
func (d *Decision) RevisionConfirmed() bool {
	if d == nil {
		return false
	}
	granted := false
	for _, g := range d.Groups {
		if !g.Passed || g.SatisfiedBy == nil {
			return false
		}
		if g.Restricts {
			continue
		}
		if _, ok := g.SatisfiedBy.Evaluation.ConfirmedRevision(); !ok {
			return false
		}
		granted = true
	}
	return granted
}

// WithDecision stores the decision that allowed an RPC, for its handler.
func WithDecision(ctx context.Context, d *Decision) context.Context {
	return context.WithValue(ctx, ctxKeyDecision, d)
}

// DecisionFromContext returns the decision that allowed the RPC, and whether
// there is one. The verification interceptors set it before the handler runs
// when the endpoint reported one; for a stream it is the decision that opened
// the stream, not a later re-check.
func DecisionFromContext(ctx context.Context) (*Decision, bool) {
	d, ok := ctx.Value(ctxKeyDecision).(*Decision)
	return d, ok && d != nil
}

// DecisionEvent is one authorization check a verification interceptor made.
type DecisionEvent struct {
	// Resource and Action are what the backend was asked about.
	Resource string
	Action   string
	// Decision is what the backend reported, nil when it reported nothing.
	Decision *Decision
	// Err is the check's error, nil when the RPC was allowed. It is the
	// endpoint's error, before the interceptor maps it for the caller, so
	// errors.As finds a *DeniedError or *UnconfirmedRevisionError on it.
	Err error
}

// DecisionObserver receives every authorization check a verification
// interceptor makes — allowed, denied or failed — before the interceptor acts
// on it: for a stream, the check that opens it and each re-check after. It is
// where a service records what authorized or refused an operation, since a
// denied RPC's handler never runs. It runs on the RPC's goroutine, so it
// should not block.
type DecisionObserver func(ctx context.Context, ev DecisionEvent)
