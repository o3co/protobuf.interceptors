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
	"io"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
)

// revokedAfter allows the first n checks and denies every one after.
func revokedAfter(n int) endpoint.VerifierEndpoint {
	var calls atomic.Int32
	return endpointtest.Func(func(context.Context, string, string) error {
		if int(calls.Add(1)) <= n {
			return nil
		}
		return &interceptors.DeniedError{Reason: "grant revoked"}
	})
}

func policyStreamCtx() context.Context {
	return interceptors.WithPolicy(interceptors.MarkInterceptorRan(context.Background()), "resource", "write")
}

// On a real stream: the grant is revoked after the stream opened and its first
// message was delivered, so the next message the client sends never reaches
// the handler.
func TestConnectStreamChain_RevokedAfterOpen_NextMessageIsNotDelivered(t *testing.T) {
	impl := &uploadHandler{}
	rec := &recorder{}
	client, cleanup := startConnectServerWithImpl(t, impl,
		policyconnect.PolicyOptionInterceptor(),
		// The opening check and the re-check of the first message are allowed.
		policyconnect.VerificationInterceptor(revokedAfter(2), policyconnect.WithDecisionObserver(rec.observe)),
	)
	defer cleanup()

	err := upload(client, "first", "second")

	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want %v (%v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	if got := impl.all(); len(got) != 1 || got[0] != "first" {
		t.Errorf("handler received %q, want only the message sent before revocation", got)
	}
	if events := rec.all(); len(events) != 3 {
		t.Errorf("observer saw %d checks, want the opening one and one per message", len(events))
	}
}

// The re-check follows the receive, so a message that arrives after
// revocation is cleared, never handed over.
func TestConnectVerification_Receive_RechecksAfterTheMessage(t *testing.T) {
	var order []string
	calls := 0
	wrapped := policyconnect.VerificationInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			order = append(order, "verify")
			if calls == 1 {
				return nil
			}
			return &interceptors.DeniedError{Reason: "grant revoked mid-stream"}
		},
	))
	msg := &testpb.CreateResourceRequest{}
	var recvErr error
	handler := wrapped.WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
		recvErr = conn.Receive(msg)
		return recvErr
	})
	conn := &fakeStreamingConn{header: http.Header{}, recv: func(m any) error {
		order = append(order, "recv")
		m.(*testpb.CreateResourceRequest).Name = "arrived after revocation"
		return nil
	}}

	if err := handler(policyStreamCtx(), conn); err == nil {
		t.Fatal("expected the revoked stream to fail")
	}
	if connect.CodeOf(recvErr) != connect.CodePermissionDenied {
		t.Errorf("Receive code = %v, want %v", connect.CodeOf(recvErr), connect.CodePermissionDenied)
	}
	if want := []string{"verify", "recv", "verify"}; !slices.Equal(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	if msg.Name != "" {
		t.Errorf("the refused message reached the handler: %q", msg.Name)
	}
}

// A receive that fails has no message to authorize, so it is not re-checked
// and its error is returned as is.
func TestConnectVerification_ReceiveError_IsNotRechecked(t *testing.T) {
	calls := 0
	wrapped := policyconnect.VerificationInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			return nil
		},
	))
	var recvErr error
	handler := wrapped.WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
		recvErr = conn.Receive(&testpb.CreateResourceRequest{})
		return nil
	})
	conn := &fakeStreamingConn{header: http.Header{}, recv: func(any) error { return io.EOF }}

	if err := handler(policyStreamCtx(), conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recvErr != io.EOF {
		t.Errorf("Receive error = %v, want io.EOF", recvErr)
	}
	if calls != 1 {
		t.Errorf("verify calls = %d, want only the opening check", calls)
	}
}
