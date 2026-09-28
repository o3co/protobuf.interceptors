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

package grpc_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const digest = "sha256:9f2c1e0b7a4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b"

func confirmedDecision(code string) *interceptors.Decision {
	satisfied := interceptors.RuleOutcome{
		Code: code, Message: "Permitted", Passed: true,
		Evaluation: &interceptors.Evaluation{Status: interceptors.EvaluationCompleted, Revision: digest},
	}
	return &interceptors.Decision{
		RequestID: "req-1",
		Groups: []interceptors.RuleGroup{{
			RuleType: "cedar", Passed: true,
			Evaluated:   []interceptors.RuleOutcome{satisfied},
			SatisfiedBy: &satisfied,
		}},
	}
}

func deniedDecision() *interceptors.Decision {
	return &interceptors.Decision{
		Code: "cedar_deny", Message: "Denied by Cedar policy", RequestID: "req-1",
		Groups: []interceptors.RuleGroup{{
			RuleType: "cedar",
			Evaluated: []interceptors.RuleOutcome{{
				Code: "cedar_deny", Message: "Denied by Cedar policy",
				Evaluation: &interceptors.Evaluation{Status: interceptors.EvaluationCompleted, Revision: digest, DeterminingPolicies: []string{"20-forbid-secret"}},
			}},
		}},
	}
}

// decisionServer records the decision its handler finds on its context.
type decisionServer struct {
	testpb.UnimplementedTestServiceServer
	seen    atomic.Pointer[interceptors.Decision]
	present atomic.Bool
}

func (s *decisionServer) GetResource(ctx context.Context, req *testpb.GetResourceRequest) (*testpb.GetResourceResponse, error) {
	d, ok := interceptors.DecisionFromContext(ctx)
	s.seen.Store(d)
	s.present.Store(ok)
	return &testpb.GetResourceResponse{Id: req.Id}, nil
}

// recorder is a DecisionObserver that keeps every event.
type recorder struct {
	mu     sync.Mutex
	events []interceptors.DecisionEvent
}

func (r *recorder) observe(_ context.Context, ev interceptors.DecisionEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) all() []interceptors.DecisionEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]interceptors.DecisionEvent(nil), r.events...)
}

func TestChain_Allow_TheHandlerSeesTheDecision(t *testing.T) {
	want := confirmedDecision("cedar_permit")
	impl := &decisionServer{}
	client, cleanup := startServerWithImpl(t, impl,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Decide(
			func(context.Context, string, string) (*interceptors.Decision, error) { return want, nil },
		)),
	)
	defer cleanup()

	if _, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !impl.present.Load() || impl.seen.Load() != want {
		t.Errorf("DecisionFromContext in the handler = (%v, %v), want (%v, true)", impl.seen.Load(), impl.present.Load(), want)
	}
}

// An endpoint that reports nothing leaves nothing on the context.
func TestChain_PlainEndpoint_NoDecisionForTheHandler(t *testing.T) {
	impl := &decisionServer{}
	client, cleanup := startServerWithImpl(t, impl,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	if _, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if impl.present.Load() {
		t.Errorf("DecisionFromContext = %v, want none", impl.seen.Load())
	}
}

func TestChain_DecisionObserver_SeesAllowAndDeny(t *testing.T) {
	allowed := confirmedDecision("cedar_permit")
	denied := deniedDecision()
	deniedErr := &interceptors.DeniedError{Reason: "access denied", Decision: denied}

	cases := []struct {
		name     string
		decision *interceptors.Decision
		err      error
	}{
		{"allow", allowed, nil},
		{"deny", denied, deniedErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			client, cleanup := startServer(t,
				policygrpc.PolicyOptionInterceptor(),
				policygrpc.VerificationInterceptor(endpointtest.Decide(
					func(context.Context, string, string) (*interceptors.Decision, error) { return tc.decision, tc.err },
				), policygrpc.WithDecisionObserver(rec.observe)),
			)
			defer cleanup()

			_, _ = client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "42"})
			events := rec.all()
			if len(events) != 1 {
				t.Fatalf("observer saw %d events, want 1", len(events))
			}
			ev := events[0]
			if ev.Decision != tc.decision || ev.Err != tc.err {
				t.Errorf("event = %+v, want decision %v and error %v", ev, tc.decision, tc.err)
			}
			if ev.Resource == "" || ev.Action == "" {
				t.Errorf("event names no resource or action: %+v", ev)
			}
		})
	}
}

// Nothing of the decision may reach the RPC caller.
func TestChain_DecisionDoesNotReachTheCaller(t *testing.T) {
	denied := deniedDecision()
	cases := []struct {
		name string
		err  error
		code codes.Code
	}{
		{"deny", &interceptors.DeniedError{Reason: "access denied", Decision: denied}, codes.PermissionDenied},
		{"unconfirmed allow", &interceptors.UnconfirmedRevisionError{Decision: confirmedDecision("rbac")}, codes.Internal},
		// A refused caller credential is this service's fault, not the caller's token.
		{"caller credential refused", endpoint.ErrCallerUnauthenticated, codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := startServer(t,
				policygrpc.PolicyOptionInterceptor(),
				policygrpc.VerificationInterceptor(endpointtest.Decide(
					func(context.Context, string, string) (*interceptors.Decision, error) { return denied, tc.err },
				)),
			)
			defer cleanup()

			_, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"})
			st, _ := status.FromError(err)
			if st.Code() != tc.code {
				t.Errorf("code = %v, want %v", st.Code(), tc.code)
			}
			for _, leak := range []string{"cedar_deny", "Denied by Cedar policy", "20-forbid-secret", "sha256", "req-1"} {
				if strings.Contains(st.Message(), leak) {
					t.Errorf("the caller's status message %q carries %q from the decision", st.Message(), leak)
				}
			}
		})
	}
}

// A stream is checked when it opens and again on every RecvMsg; the observer
// sees each check, and the handler's context carries the one that opened it.
func TestVerificationStreamInterceptor_DecisionObserver_SeesEveryCheck(t *testing.T) {
	opening := confirmedDecision("open")
	recheck := confirmedDecision("recheck")
	calls := 0
	rec := &recorder{}
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Decide(
		func(context.Context, string, string) (*interceptors.Decision, error) {
			calls++
			if calls == 1 {
				return opening, nil
			}
			return recheck, nil
		},
	), policygrpc.WithDecisionObserver(rec.observe))

	var onContext *interceptors.Decision
	err := interceptor(nil, &fakeServerStream{ctx: policyStreamCtx()}, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		onContext, _ = interceptors.DecisionFromContext(ss.Context())
		return ss.RecvMsg(new(string))
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if onContext != opening {
		t.Errorf("DecisionFromContext in the handler = %v, want the opening decision", onContext)
	}
	events := rec.all()
	if len(events) != 2 || events[0].Decision != opening || events[1].Decision != recheck {
		t.Errorf("observer events = %+v, want the opening check then the re-check", events)
	}
}

func TestVerificationStreamInterceptor_DecisionObserver_SeesADenialBeforeTheHandler(t *testing.T) {
	denied := deniedDecision()
	rec := &recorder{}
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Decide(
		func(context.Context, string, string) (*interceptors.Decision, error) {
			return denied, &interceptors.DeniedError{Reason: "access denied", Decision: denied}
		},
	), policygrpc.WithDecisionObserver(rec.observe))

	err := interceptor(nil, &fakeServerStream{ctx: policyStreamCtx()}, streamInfo(), func(any, grpc.ServerStream) error {
		t.Fatal("the handler must not run")
		return nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	if events := rec.all(); len(events) != 1 || events[0].Decision != denied {
		t.Errorf("observer events = %+v", events)
	}
}
