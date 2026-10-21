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
	"testing"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// panicsOnRecheck is an observer that panics on the first check after the one
// that opened the stream, as one that dereferences a nil ev.Decision would.
func panicsOnRecheck() interceptors.DecisionObserver {
	seen := 0
	return func(context.Context, interceptors.DecisionEvent) {
		seen++
		if seen == 2 {
			panic("observer failed")
		}
	}
}

// recovered calls f and reports whether it panicked.
func recovered(f func()) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	f()
	return false
}

// A re-check whose observer panics did not complete. The message it was
// checking is cleared, even if the handler recovers the panic, and the stream
// is over: later sends and receives fail without asking the verifier, and the
// interceptor returns Internal whatever the handler returns.
func TestVerificationStreamInterceptor_ObserverPanicsOnRecvRecheck_ClosesTheStream(t *testing.T) {
	for name, verdict := range map[string]error{
		"denied":  &interceptors.DeniedError{Reason: "grant revoked"},
		"allowed": nil,
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			verifier := endpointtest.Func(func(context.Context, string, string) error {
				calls++
				if calls == 1 {
					return nil
				}
				return verdict
			})
			interceptor := policygrpc.VerificationStreamInterceptor(verifier, policygrpc.WithDecisionObserver(panicsOnRecheck()))
			stream := &fakeServerStream{ctx: policyStreamCtx(), recv: func(m any) error {
				*m.(*string) = "checked by a re-check that did not complete"
				return nil
			}}

			msg := new(string)
			var recvPanicked bool
			var laterRecv, laterSend error
			err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
				recvPanicked = recovered(func() { _ = ss.RecvMsg(msg) })
				laterRecv = ss.RecvMsg(new(string))
				laterSend = ss.SendMsg("reply")
				return nil
			})

			if !recvPanicked {
				t.Fatal("the observer's panic did not reach the handler")
			}
			if *msg != "" {
				t.Errorf("the message reached the handler: %q", *msg)
			}
			if status.Code(err) != codes.Internal {
				t.Errorf("interceptor code = %v, want %v", status.Code(err), codes.Internal)
			}
			if status.Code(laterRecv) != codes.Internal || status.Code(laterSend) != codes.Internal {
				t.Errorf("later RecvMsg / SendMsg codes = %v / %v, want %v", status.Code(laterRecv), status.Code(laterSend), codes.Internal)
			}
			if stream.recvCalls != 1 || stream.sendCalls != 0 {
				t.Errorf("transport receives / sends = %d / %d, want 1 / 0", stream.recvCalls, stream.sendCalls)
			}
			if calls != 2 {
				t.Errorf("verifier calls = %d, want 2: nothing is asked after the re-check that did not complete", calls)
			}
		})
	}
}

// A send whose re-check's observer panics is not sent, and closes the stream.
func TestVerificationStreamInterceptor_ObserverPanicsOnSendRecheck_ClosesTheStream(t *testing.T) {
	calls := 0
	verifier := endpointtest.Func(func(context.Context, string, string) error { calls++; return nil })
	interceptor := policygrpc.VerificationStreamInterceptor(verifier, policygrpc.WithDecisionObserver(panicsOnRecheck()))
	stream := &fakeServerStream{ctx: policyStreamCtx()}

	var sendPanicked bool
	var laterSend error
	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		sendPanicked = recovered(func() { _ = ss.SendMsg("first") })
		laterSend = ss.SendMsg("second")
		return nil
	})

	if !sendPanicked {
		t.Fatal("the observer's panic did not reach the handler")
	}
	if stream.sendCalls != 0 {
		t.Errorf("transport sends = %d, want 0", stream.sendCalls)
	}
	if status.Code(laterSend) != codes.Internal {
		t.Errorf("later SendMsg code = %v, want %v", status.Code(laterSend), codes.Internal)
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("interceptor code = %v, want %v", status.Code(err), codes.Internal)
	}
	if calls != 2 {
		t.Errorf("verifier calls = %d, want 2", calls)
	}
}

// An endpoint that panics on a re-check made after the interval has passed
// closes the stream the same way, and the interval does not reopen it.
func TestVerificationStreamInterceptor_EndpointPanicsOnRecheck_WithInterval_ClosesTheStream(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	verifier := endpointtest.Func(func(context.Context, string, string) error {
		calls++
		if calls == 2 {
			panic("endpoint failed")
		}
		return nil
	})
	interceptor := policygrpc.VerificationStreamInterceptor(verifier,
		policygrpc.WithStreamRecheckInterval(time.Minute),
		policygrpc.WithClock(func() time.Time { return now }))
	stream := &fakeServerStream{ctx: policyStreamCtx(), recv: func(m any) error {
		*m.(*string) = "checked by a re-check that did not complete"
		return nil
	}}

	msg := new(string)
	var recvPanicked bool
	var laterSend error
	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		now = now.Add(time.Minute)
		recvPanicked = recovered(func() { _ = ss.RecvMsg(msg) })
		laterSend = ss.SendMsg("within the interval of nothing")
		return nil
	})

	if !recvPanicked {
		t.Fatal("the endpoint's panic did not reach the handler")
	}
	if *msg != "" {
		t.Errorf("the message reached the handler: %q", *msg)
	}
	if status.Code(laterSend) != codes.Internal || stream.sendCalls != 0 {
		t.Errorf("later SendMsg code = %v with %d transport sends, want %v and 0", status.Code(laterSend), stream.sendCalls, codes.Internal)
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("interceptor code = %v, want %v", status.Code(err), codes.Internal)
	}
}
