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

package connectrpc_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
)

const digest = "sha256:9f2c1e0b7a4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b"

func confirmedDecision() *interceptors.Decision {
	satisfied := interceptors.RuleOutcome{
		Code: "cedar_permit", Message: "Permitted", Passed: true,
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

func decide(d *interceptors.Decision, err error) endpoint.DecisionVerifier {
	return endpointtest.Decide(func(context.Context, string, string) (*interceptors.Decision, error) { return d, err })
}

// decisionHandler records the decision its handler finds on its context.
type decisionHandler struct {
	testServiceHandler
	seen    atomic.Pointer[interceptors.Decision]
	present atomic.Bool
}

func (h *decisionHandler) GetResource(ctx context.Context, req *connect.Request[testpb.GetResourceRequest]) (*connect.Response[testpb.GetResourceResponse], error) {
	d, ok := interceptors.DecisionFromContext(ctx)
	h.seen.Store(d)
	h.present.Store(ok)
	return connect.NewResponse(&testpb.GetResourceResponse{Id: req.Msg.Id}), nil
}

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

func getResource(t *testing.T, client interface {
	GetResource(context.Context, *connect.Request[testpb.GetResourceRequest]) (*connect.Response[testpb.GetResourceResponse], error)
}) error {
	t.Helper()
	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Bearer tok")
	_, err := client.GetResource(context.Background(), req)
	return err
}

func TestConnectChain_Allow_TheHandlerSeesTheDecision(t *testing.T) {
	want := confirmedDecision()
	impl := &decisionHandler{}
	client, cleanup := startConnectServerWithImpl(t, impl,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(decide(want, nil)),
	)
	defer cleanup()

	if err := getResource(t, client); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !impl.present.Load() || impl.seen.Load() != want {
		t.Errorf("DecisionFromContext in the handler = (%v, %v), want (%v, true)", impl.seen.Load(), impl.present.Load(), want)
	}
}

func TestConnectChain_PlainEndpoint_NoDecisionForTheHandler(t *testing.T) {
	impl := &decisionHandler{}
	client, cleanup := startConnectServerWithImpl(t, impl,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	if err := getResource(t, client); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if impl.present.Load() {
		t.Errorf("DecisionFromContext = %v, want none", impl.seen.Load())
	}
}

func TestConnectChain_DecisionObserver_SeesAllowAndDeny(t *testing.T) {
	allowed := confirmedDecision()
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
			client, cleanup := startConnectServer(t,
				policyconnect.PolicyOptionInterceptor(),
				policyconnect.VerificationInterceptor(decide(tc.decision, tc.err), policyconnect.WithDecisionObserver(rec.observe)),
			)
			defer cleanup()

			_ = getResource(t, client)
			events := rec.all()
			if len(events) != 1 {
				t.Fatalf("observer saw %d events, want 1", len(events))
			}
			if ev := events[0]; ev.Decision != tc.decision || ev.Err != tc.err || ev.Resource == "" || ev.Action == "" {
				t.Errorf("event = %+v, want decision %v and error %v", ev, tc.decision, tc.err)
			}
		})
	}
}

func TestConnectChain_DecisionDoesNotReachTheCaller(t *testing.T) {
	denied := deniedDecision()
	cases := []struct {
		name string
		err  error
		code connect.Code
	}{
		{"deny", &interceptors.DeniedError{Reason: "access denied", Decision: denied}, connect.CodePermissionDenied},
		{"unconfirmed allow", &interceptors.UnconfirmedRevisionError{Decision: confirmedDecision()}, connect.CodeInternal},
		{"caller credential refused", endpoint.ErrCallerUnauthenticated, connect.CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := startConnectServer(t,
				policyconnect.PolicyOptionInterceptor(),
				policyconnect.VerificationInterceptor(decide(denied, tc.err)),
			)
			defer cleanup()

			err := getResource(t, client)
			if connect.CodeOf(err) != tc.code {
				t.Errorf("code = %v, want %v", connect.CodeOf(err), tc.code)
			}
			var ce *connect.Error
			if !errors.As(err, &ce) {
				t.Fatalf("expected *connect.Error, got %T", err)
			}
			for _, leak := range []string{"cedar_deny", "Denied by Cedar policy", "20-forbid-secret", "sha256", "req-1"} {
				if strings.Contains(ce.Message(), leak) {
					t.Errorf("the caller's error message %q carries %q from the decision", ce.Message(), leak)
				}
			}
		})
	}
}

// fakeStreamingConn is the handler side of a stream. Only the methods the
// interceptors touch are implemented.
type fakeStreamingConn struct {
	connect.StreamingHandlerConn
	header http.Header
	// recv, when set, is what the transport does on Receive.
	recv func(msg any) error
}

func (c *fakeStreamingConn) RequestHeader() http.Header { return c.header }

func (c *fakeStreamingConn) Receive(msg any) error {
	if c.recv != nil {
		return c.recv(msg)
	}
	return nil
}

func TestConnectVerification_Streaming_DecisionReachesTheHandlerAndTheObserver(t *testing.T) {
	want := confirmedDecision()
	rec := &recorder{}
	wrapped := policyconnect.VerificationInterceptor(decide(want, nil), policyconnect.WithDecisionObserver(rec.observe)).
		WrapStreamingHandler(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
			if got, ok := interceptors.DecisionFromContext(ctx); !ok || got != want {
				t.Errorf("DecisionFromContext in the handler = (%v, %v), want (%v, true)", got, ok, want)
			}
			return nil
		})

	ctx := interceptors.WithPolicy(interceptors.MarkInterceptorRan(context.Background()), "resource", "read")
	conn := &fakeStreamingConn{header: http.Header{"Authorization": []string{"Bearer tok"}}}
	if err := wrapped(ctx, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events := rec.all(); len(events) != 1 || events[0].Decision != want {
		t.Errorf("observer events = %+v", events)
	}
}
