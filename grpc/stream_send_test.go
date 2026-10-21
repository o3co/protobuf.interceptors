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
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// orderedStream is a fakeServerStream whose sends are logged into order.
type orderedStream struct {
	fakeServerStream
	order *[]string
}

func (s *orderedStream) SendMsg(m any) error {
	*s.order = append(*s.order, "send")
	return s.fakeServerStream.SendMsg(m)
}

// A stream that only sends — the long-lived server stream — is re-checked
// before each message it sends, and a refused message is never sent.
func TestVerificationStreamInterceptor_SendMsg_RechecksBeforeSending(t *testing.T) {
	var order []string
	calls := 0
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			order = append(order, "verify")
			if calls <= 2 {
				return nil // the opening check and the first send
			}
			return &interceptors.DeniedError{Reason: "grant revoked mid-stream"}
		},
	))
	stream := &orderedStream{fakeServerStream: fakeServerStream{ctx: policyStreamCtx()}, order: &order}

	var secondErr error
	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		if err := ss.SendMsg("first"); err != nil {
			return err
		}
		secondErr = ss.SendMsg("second, after revocation")
		return secondErr
	})

	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	if status.Code(secondErr) != codes.PermissionDenied {
		t.Errorf("SendMsg code = %v, want %v", status.Code(secondErr), codes.PermissionDenied)
	}
	if want := []string{"verify", "verify", "send", "verify"}; !slices.Equal(order, want) {
		t.Errorf("order = %v, want %v: each send is checked before it goes out", order, want)
	}
	if stream.sendCalls != 1 {
		t.Errorf("sendCalls = %d, want 1: the refused message must not be sent", stream.sendCalls)
	}
}

// A failed re-check ends the stream: every later send or receive returns the
// same error without asking the verifier or touching the transport, and the
// caller is told the refusal even when the handler drops it.
func TestVerificationStreamInterceptor_FailedRecheck_EndsTheStream(t *testing.T) {
	calls := 0
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			if calls == 1 {
				return nil
			}
			return &interceptors.DeniedError{Reason: "grant revoked mid-stream"}
		},
	))
	stream := &fakeServerStream{ctx: policyStreamCtx()}

	var sendErr, laterSendErr, laterRecvErr error
	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		sendErr = ss.SendMsg("refused")
		laterSendErr = ss.SendMsg("after the refusal")
		laterRecvErr = ss.RecvMsg(new(string))
		return nil // a handler that ignores the error
	})

	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v: the refusal ends the RPC", status.Code(err), codes.PermissionDenied)
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Errorf("error %v does not unwrap to the refusal", err)
	}
	for name, got := range map[string]error{"later SendMsg": laterSendErr, "later RecvMsg": laterRecvErr} {
		if got != sendErr {
			t.Errorf("%s = %v, want the refusal %v", name, got, sendErr)
		}
	}
	if calls != 2 {
		t.Errorf("verify calls = %d, want 2: nothing is asked after a refusal", calls)
	}
	if stream.sendCalls != 0 || stream.recvCalls != 0 {
		t.Errorf("transport used after the refusal: sendCalls = %d, recvCalls = %d", stream.sendCalls, stream.recvCalls)
	}
}

// With an interval, a stream is re-checked at most once per interval, on the
// first message, sent or received, after the interval has passed.
func TestVerificationStreamInterceptor_RecheckInterval(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	interceptor := policygrpc.VerificationStreamInterceptor(
		endpointtest.Func(func(context.Context, string, string) error {
			calls++
			return nil
		}),
		policygrpc.WithStreamRecheckInterval(time.Minute),
		policygrpc.WithClock(func() time.Time { return now }),
	)
	stream := &fakeServerStream{ctx: policyStreamCtx()}

	var after []int
	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		_ = ss.SendMsg("within the interval")
		_ = ss.RecvMsg(new(string))
		after = append(after, calls)
		now = now.Add(time.Minute)
		_ = ss.RecvMsg(new(string))
		after = append(after, calls)
		_ = ss.SendMsg("within the next interval")
		after = append(after, calls)
		now = now.Add(time.Minute)
		_ = ss.SendMsg("after the next interval")
		after = append(after, calls)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []int{1, 2, 2, 3}; !slices.Equal(after, want) {
		t.Errorf("verify calls after each step = %v, want %v", after, want)
	}
	if stream.sendCalls != 3 || stream.recvCalls != 2 {
		t.Errorf("sendCalls = %d, recvCalls = %d; want 3 and 2", stream.sendCalls, stream.recvCalls)
	}
}

func TestWithStreamRecheckInterval_Negative_Panics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a negative interval")
		}
	}()
	policygrpc.WithStreamRecheckInterval(-time.Second)
}

// pushDesc serves UploadResources as a stream that, given one request, sends
// up to ten GetResourceResponse messages, stopping at the first send that
// fails. Its policy is the one the
// test service declares for UploadResources.
func pushDesc(sent *[]string) grpc.ServiceDesc {
	return grpc.ServiceDesc{
		ServiceName: "test.v1.TestService",
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "UploadResources",
			ServerStreams: true,
			ClientStreams: true,
			Handler: func(_ any, ss grpc.ServerStream) error {
				if err := ss.RecvMsg(&testpb.CreateResourceRequest{}); err != nil {
					return err
				}
				for i := range 10 {
					name := fmt.Sprintf("m%d", i+1)
					if err := ss.SendMsg(&testpb.GetResourceResponse{Name: name}); err != nil {
						return err
					}
					*sent = append(*sent, name)
				}
				return nil
			},
		}},
	}
}

// On a real server-streaming RPC: the grant is revoked while the server is
// sending, so the next message never leaves and the client is told why.
func TestStreamChain_RevokedWhileSending_NextMessageIsNotSent(t *testing.T) {
	var sent []string
	rec := &recorder{}
	srv := grpc.NewServer(grpc.ChainStreamInterceptor(
		policygrpc.PolicyOptionStreamInterceptor(),
		// Allowed: the opening check, the request, and the first two sends.
		policygrpc.VerificationStreamInterceptor(revokedAfter(4), policygrpc.WithDecisionObserver(rec.observe)),
	))
	desc := pushDesc(&sent)
	srv.RegisterService(&desc, struct{}{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	stream, err := conn.NewStream(bearerCtx("tok"), &desc.Streams[0], "/test.v1.TestService/UploadResources")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := stream.SendMsg(&testpb.CreateResourceRequest{Name: "watch"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []string
	for {
		msg := &testpb.GetResourceResponse{}
		if err = stream.RecvMsg(msg); err != nil {
			break
		}
		got = append(got, msg.Name)
	}

	if err == io.EOF || status.Code(err) != codes.PermissionDenied {
		t.Errorf("stream ended with %v, want %v", err, codes.PermissionDenied)
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
