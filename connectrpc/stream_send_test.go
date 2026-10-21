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
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
)

// sendingConn is a fakeStreamingConn that records its sends and receives,
// logging sends into order when it is set.
type sendingConn struct {
	fakeStreamingConn
	order     *[]string
	sendCalls int
	recvCalls int
}

func (c *sendingConn) Send(any) error {
	c.sendCalls++
	if c.order != nil {
		*c.order = append(*c.order, "send")
	}
	return nil
}

func (c *sendingConn) Receive(msg any) error {
	c.recvCalls++
	return c.fakeStreamingConn.Receive(msg)
}

// A stream that only sends — the long-lived server stream — is re-checked
// before each message it sends, and a refused message is never sent.
func TestConnectVerification_Send_RechecksBeforeSending(t *testing.T) {
	var order []string
	calls := 0
	wrapped := policyconnect.VerificationInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			order = append(order, "verify")
			if calls <= 2 {
				return nil // the opening check and the first send
			}
			return &interceptors.DeniedError{Reason: "grant revoked mid-stream"}
		},
	))
	conn := &sendingConn{fakeStreamingConn: fakeStreamingConn{header: http.Header{}}, order: &order}
	var secondErr error
	handler := wrapped.WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
		if err := conn.Send("first"); err != nil {
			return err
		}
		secondErr = conn.Send("second, after revocation")
		return secondErr
	})

	err := handler(policyStreamCtx(), conn)

	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodePermissionDenied)
	}
	if connect.CodeOf(secondErr) != connect.CodePermissionDenied {
		t.Errorf("Send code = %v, want %v", connect.CodeOf(secondErr), connect.CodePermissionDenied)
	}
	if want := []string{"verify", "verify", "send", "verify"}; !slices.Equal(order, want) {
		t.Errorf("order = %v, want %v: each send is checked before it goes out", order, want)
	}
	if conn.sendCalls != 1 {
		t.Errorf("sendCalls = %d, want 1: the refused message must not be sent", conn.sendCalls)
	}
}

// A failed re-check ends the stream: every later send or receive returns the
// same error without asking the verifier or touching the transport, and the
// caller is told the refusal even when the handler drops it.
func TestConnectVerification_FailedRecheck_EndsTheStream(t *testing.T) {
	calls := 0
	wrapped := policyconnect.VerificationInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			if calls == 1 {
				return nil
			}
			return &interceptors.DeniedError{Reason: "grant revoked mid-stream"}
		},
	))
	conn := &sendingConn{fakeStreamingConn: fakeStreamingConn{header: http.Header{}}}
	var sendErr, laterSendErr, laterRecvErr error
	handler := wrapped.WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
		sendErr = conn.Send("refused")
		laterSendErr = conn.Send("after the refusal")
		laterRecvErr = conn.Receive(new(string))
		return nil // a handler that ignores the error
	})

	err := handler(policyStreamCtx(), conn)

	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want %v: the refusal ends the RPC", connect.CodeOf(err), connect.CodePermissionDenied)
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Errorf("error %v does not unwrap to the refusal", err)
	}
	for name, got := range map[string]error{"later Send": laterSendErr, "later Receive": laterRecvErr} {
		if got != sendErr {
			t.Errorf("%s = %v, want the refusal %v", name, got, sendErr)
		}
	}
	if calls != 2 {
		t.Errorf("verify calls = %d, want 2: nothing is asked after a refusal", calls)
	}
	if conn.sendCalls != 0 || conn.recvCalls != 0 {
		t.Errorf("transport used after the refusal: sendCalls = %d, recvCalls = %d", conn.sendCalls, conn.recvCalls)
	}
}

// With an interval, a stream is re-checked at most once per interval, on the
// first message, sent or received, after the interval has passed.
func TestConnectVerification_RecheckInterval(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	wrapped := policyconnect.VerificationInterceptor(
		endpointtest.Func(func(context.Context, string, string) error {
			calls++
			return nil
		}),
		policyconnect.WithStreamRecheckInterval(time.Minute),
		policyconnect.WithClock(func() time.Time { return now }),
	)
	conn := &sendingConn{fakeStreamingConn: fakeStreamingConn{header: http.Header{}}}
	var after []int
	handler := wrapped.WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
		_ = conn.Send("within the interval")
		_ = conn.Receive(new(string))
		after = append(after, calls)
		now = now.Add(time.Minute)
		_ = conn.Receive(new(string))
		after = append(after, calls)
		_ = conn.Send("within the next interval")
		after = append(after, calls)
		now = now.Add(time.Minute)
		_ = conn.Send("after the next interval")
		after = append(after, calls)
		return nil
	})

	if err := handler(policyStreamCtx(), conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []int{1, 2, 2, 3}; !slices.Equal(after, want) {
		t.Errorf("verify calls after each step = %v, want %v", after, want)
	}
	if conn.sendCalls != 3 || conn.recvCalls != 2 {
		t.Errorf("sendCalls = %d, recvCalls = %d; want 3 and 2", conn.sendCalls, conn.recvCalls)
	}
}

func TestConnectWithStreamRecheckInterval_Negative_Panics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a negative interval")
		}
	}()
	policyconnect.WithStreamRecheckInterval(-time.Second)
}

// On a real server-streaming RPC: the grant is revoked while the server is
// sending, so the next message never leaves and the client is told why.
func TestConnectStreamChain_RevokedWhileSending_NextMessageIsNotSent(t *testing.T) {
	const procedure = "/test.v1.TestService/UploadResources"
	var sent []string
	rec := &recorder{}
	mux := http.NewServeMux()
	// UploadResources served as a stream that sends up to ten messages,
	// stopping at the first send that fails. Its policy is the one the test
	// service declares for UploadResources.
	mux.Handle(procedure, connect.NewServerStreamHandler(procedure,
		func(_ context.Context, _ *connect.Request[testpb.CreateResourceRequest], stream *connect.ServerStream[testpb.GetResourceResponse]) error {
			for i := range 10 {
				name := fmt.Sprintf("m%d", i+1)
				if err := stream.Send(&testpb.GetResourceResponse{Name: name}); err != nil {
					return err
				}
				sent = append(sent, name)
			}
			return nil
		},
		connect.WithSchema(methodDescriptor("UploadResources")),
		connect.WithInterceptors(
			policyconnect.PolicyOptionInterceptor(),
			// Allowed: the opening check, the request, and the first two sends.
			policyconnect.VerificationInterceptor(revokedAfter(4), policyconnect.WithDecisionObserver(rec.observe)),
		),
	))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[testpb.CreateResourceRequest, testpb.GetResourceResponse](srv.Client(), srv.URL+procedure)
	req := connect.NewRequest(&testpb.CreateResourceRequest{Name: "watch"})
	req.Header().Set("Authorization", "Bearer tok")
	stream, err := client.CallServerStream(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []string
	for stream.Receive() {
		got = append(got, stream.Msg().Name)
	}
	err = stream.Err()
	_ = stream.Close()

	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("stream ended with %v, want %v", err, connect.CodePermissionDenied)
	}
	if want := []string{"m1", "m2"}; !slices.Equal(got, want) {
		t.Errorf("client received %q, want %q: only messages sent before revocation", got, want)
	}
	if want := []string{"m1", "m2"}; !slices.Equal(sent, want) {
		t.Errorf("server sent %q, want %q", sent, want)
	}
	if events := rec.all(); len(events) != 5 {
		t.Errorf("observer saw %d checks, want the opening one, the request's and one per send", len(events))
	}
}
