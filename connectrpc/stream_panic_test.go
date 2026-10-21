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
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpointtest"
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
func TestConnectVerification_ObserverPanicsOnReceiveRecheck_ClosesTheStream(t *testing.T) {
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
			msg := new(string)
			var recvPanicked bool
			var laterRecv, laterSend error
			handler := policyconnect.VerificationInterceptor(verifier, policyconnect.WithDecisionObserver(panicsOnRecheck())).
				WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
					recvPanicked = recovered(func() { _ = conn.Receive(msg) })
					laterRecv = conn.Receive(new(string))
					laterSend = conn.Send("reply")
					return nil
				})
			conn := &sendingConn{fakeStreamingConn: fakeStreamingConn{header: http.Header{}, recv: func(m any) error {
				*m.(*string) = "checked by a re-check that did not complete"
				return nil
			}}}

			err := handler(policyStreamCtx(), conn)

			if !recvPanicked {
				t.Fatal("the observer's panic did not reach the handler")
			}
			if *msg != "" {
				t.Errorf("the message reached the handler: %q", *msg)
			}
			if connect.CodeOf(err) != connect.CodeInternal {
				t.Errorf("interceptor code = %v, want %v", connect.CodeOf(err), connect.CodeInternal)
			}
			if connect.CodeOf(laterRecv) != connect.CodeInternal || connect.CodeOf(laterSend) != connect.CodeInternal {
				t.Errorf("later Receive / Send codes = %v / %v, want %v", connect.CodeOf(laterRecv), connect.CodeOf(laterSend), connect.CodeInternal)
			}
			if conn.recvCalls != 1 || conn.sendCalls != 0 {
				t.Errorf("transport receives / sends = %d / %d, want 1 / 0", conn.recvCalls, conn.sendCalls)
			}
			if calls != 2 {
				t.Errorf("verifier calls = %d, want 2: nothing is asked after the re-check that did not complete", calls)
			}
		})
	}
}

// A send whose re-check's observer panics is not sent, and closes the stream.
func TestConnectVerification_ObserverPanicsOnSendRecheck_ClosesTheStream(t *testing.T) {
	calls := 0
	verifier := endpointtest.Func(func(context.Context, string, string) error { calls++; return nil })
	var sendPanicked bool
	var laterSend error
	handler := policyconnect.VerificationInterceptor(verifier, policyconnect.WithDecisionObserver(panicsOnRecheck())).
		WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
			sendPanicked = recovered(func() { _ = conn.Send("first") })
			laterSend = conn.Send("second")
			return nil
		})
	conn := &sendingConn{fakeStreamingConn: fakeStreamingConn{header: http.Header{}}}

	err := handler(policyStreamCtx(), conn)

	if !sendPanicked {
		t.Fatal("the observer's panic did not reach the handler")
	}
	if conn.sendCalls != 0 {
		t.Errorf("transport sends = %d, want 0", conn.sendCalls)
	}
	if connect.CodeOf(laterSend) != connect.CodeInternal {
		t.Errorf("later Send code = %v, want %v", connect.CodeOf(laterSend), connect.CodeInternal)
	}
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("interceptor code = %v, want %v", connect.CodeOf(err), connect.CodeInternal)
	}
	if calls != 2 {
		t.Errorf("verifier calls = %d, want 2", calls)
	}
}

// An endpoint that panics on a re-check made after the interval has passed
// closes the stream the same way, and the interval does not reopen it.
func TestConnectVerification_EndpointPanicsOnRecheck_WithInterval_ClosesTheStream(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	verifier := endpointtest.Func(func(context.Context, string, string) error {
		calls++
		if calls == 2 {
			panic("endpoint failed")
		}
		return nil
	})
	msg := new(string)
	var recvPanicked bool
	var laterSend error
	handler := policyconnect.VerificationInterceptor(verifier,
		policyconnect.WithStreamRecheckInterval(time.Minute),
		policyconnect.WithClock(func() time.Time { return now })).
		WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
			now = now.Add(time.Minute)
			recvPanicked = recovered(func() { _ = conn.Receive(msg) })
			laterSend = conn.Send("within the interval of nothing")
			return nil
		})
	conn := &sendingConn{fakeStreamingConn: fakeStreamingConn{header: http.Header{}, recv: func(m any) error {
		*m.(*string) = "checked by a re-check that did not complete"
		return nil
	}}}

	err := handler(policyStreamCtx(), conn)

	if !recvPanicked {
		t.Fatal("the endpoint's panic did not reach the handler")
	}
	if *msg != "" {
		t.Errorf("the message reached the handler: %q", *msg)
	}
	if connect.CodeOf(laterSend) != connect.CodeInternal || conn.sendCalls != 0 {
		t.Errorf("later Send code = %v with %d transport sends, want %v and 0", connect.CodeOf(laterSend), conn.sendCalls, connect.CodeInternal)
	}
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("interceptor code = %v, want %v", connect.CodeOf(err), connect.CodeInternal)
	}
}
