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
	"io"
	"net"
	"slices"
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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// fakeServerStream is the transport a stream interceptor wraps. Only the
// methods the interceptors touch are implemented; anything else would panic on
// the nil embedded interface, which is what we want from a test double.
type fakeServerStream struct {
	grpc.ServerStream
	ctx       context.Context
	sendCalls int
	recvCalls int
	// recv, when set, is what the transport does on RecvMsg.
	recv func(m any) error
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func (s *fakeServerStream) SendMsg(any) error {
	s.sendCalls++
	return nil
}

func (s *fakeServerStream) RecvMsg(m any) error {
	s.recvCalls++
	if s.recv != nil {
		return s.recv(m)
	}
	return nil
}

// policyStreamCtx is the context PolicyOptionStreamInterceptor leaves behind
// for a method that declares a policy.
func policyStreamCtx() context.Context {
	ctx := interceptors.MarkInterceptorRan(context.Background())
	return interceptors.WithPolicy(ctx, "resource", "read")
}

func streamInfo() *grpc.StreamServerInfo {
	return &grpc.StreamServerInfo{
		FullMethod:     "/test.v1.TestService/Stream",
		IsServerStream: true,
		IsClientStream: true,
	}
}

func TestPolicyOptionStreamInterceptor_NotNil(t *testing.T) {
	interceptor := policygrpc.PolicyOptionStreamInterceptor()
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}
}

func TestVerificationStreamInterceptor_NilVerifier_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil verifier")
		}
	}()
	policygrpc.VerificationStreamInterceptor(nil)
}

func TestVerificationStreamInterceptor_NotNil(t *testing.T) {
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Allow())
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}
}

// TestVerificationStreamInterceptor_SendBeforeRecv_IsDenied: a bidirectional or
// client-streaming handler may send before it ever receives, so a denied stream
// is refused before the handler runs, not at its first RecvMsg.
func TestVerificationStreamInterceptor_SendBeforeRecv_IsDenied(t *testing.T) {
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Deny())
	stream := &fakeServerStream{ctx: policyStreamCtx()}
	handlerCalled := false

	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		handlerCalled = true
		return ss.SendMsg("first message, before any RecvMsg")
	})

	if err == nil {
		t.Fatal("expected the stream to be denied")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	if handlerCalled {
		t.Error("handler ran for a denied stream")
	}
	if stream.sendCalls != 0 {
		t.Errorf("sendCalls = %d, want 0: a denied stream must not send", stream.sendCalls)
	}
}

// TestVerificationStreamInterceptor_NeverReceives_IsStillChecked covers a
// handler that only ever sends and never calls RecvMsg, so only the check
// before the handler authorizes it.
func TestVerificationStreamInterceptor_NeverReceives_IsStillChecked(t *testing.T) {
	verifyCalls := 0
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			verifyCalls++
			return nil
		},
	))
	stream := &fakeServerStream{ctx: policyStreamCtx()}

	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		return ss.SendMsg("only ever sends")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifyCalls != 1 {
		t.Errorf("verifyCalls = %d, want 1: a stream that never receives must still be authorized", verifyCalls)
	}
}

func TestVerificationStreamInterceptor_AuthorizesBeforeHandler(t *testing.T) {
	var order []string
	var capturedResource, capturedAction string
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
		func(_ context.Context, resource, action string) error {
			order = append(order, "verify")
			capturedResource, capturedAction = resource, action
			return nil
		},
	))
	stream := &fakeServerStream{ctx: policyStreamCtx()}

	err := interceptor(nil, stream, streamInfo(), func(_ any, _ grpc.ServerStream) error {
		order = append(order, "handler")
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(order) != 2 || order[0] != "verify" || order[1] != "handler" {
		t.Errorf("order = %v, want [verify handler]", order)
	}
	if capturedResource != "resource" || capturedAction != "read" {
		t.Errorf("verified (%q, %q), want (%q, %q)", capturedResource, capturedAction, "resource", "read")
	}
}

func TestVerificationStreamInterceptor_Allowed_StreamStillWorks(t *testing.T) {
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Allow())
	stream := &fakeServerStream{ctx: policyStreamCtx()}

	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		if err := ss.SendMsg("out"); err != nil {
			return err
		}
		return ss.RecvMsg(new(string))
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stream.sendCalls != 1 {
		t.Errorf("sendCalls = %d, want 1", stream.sendCalls)
	}
	if stream.recvCalls != 1 {
		t.Errorf("recvCalls = %d, want 1", stream.recvCalls)
	}
}

// TestVerificationStreamInterceptor_RecvMsg_RechecksAuthorization pins the
// per-message check made after the up-front one. The resource and action are
// fixed for the life of a stream, so the re-check exists to refuse a message
// that arrives once authorization is withdrawn: it runs after the transport
// returns the message, and a refused message is cleared, never handed over.
func TestVerificationStreamInterceptor_RecvMsg_RechecksAuthorization(t *testing.T) {
	calls := 0
	var order []string
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			order = append(order, "verify")
			if calls == 1 {
				return nil // opening the stream is allowed
			}
			return &interceptors.DeniedError{Reason: "grant revoked mid-stream"}
		},
	))
	stream := &fakeServerStream{ctx: policyStreamCtx(), recv: func(m any) error {
		order = append(order, "recv")
		m.(*testpb.CreateResourceRequest).Name = "arrived after revocation"
		return nil
	}}

	var recvErr error
	msg := &testpb.CreateResourceRequest{}
	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		recvErr = ss.RecvMsg(msg)
		return recvErr
	})
	if err == nil {
		t.Fatal("expected the revoked stream to fail")
	}
	if status.Code(recvErr) != codes.PermissionDenied {
		t.Errorf("RecvMsg code = %v, want %v", status.Code(recvErr), codes.PermissionDenied)
	}
	if calls != 2 {
		t.Errorf("verify calls = %d, want the opening check and one re-check", calls)
	}
	if want := []string{"verify", "recv", "verify"}; !slices.Equal(order, want) {
		t.Errorf("order = %v, want %v: the re-check follows the message it authorizes", order, want)
	}
	if msg.Name != "" {
		t.Errorf("the refused message reached the handler: %q", msg.Name)
	}
}

// A receive that fails — the client closed its side, the stream broke — has
// no message to authorize, so it is not re-checked and its error is returned
// as is.
func TestVerificationStreamInterceptor_RecvMsgError_IsNotRechecked(t *testing.T) {
	calls := 0
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			if calls == 1 {
				return nil
			}
			return &interceptors.DeniedError{Reason: "must not be asked"}
		},
	))
	stream := &fakeServerStream{ctx: policyStreamCtx(), recv: func(any) error { return io.EOF }}

	var recvErr error
	_ = interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		recvErr = ss.RecvMsg(&testpb.CreateResourceRequest{})
		return nil
	})
	if recvErr != io.EOF {
		t.Errorf("RecvMsg error = %v, want io.EOF", recvErr)
	}
	if calls != 1 {
		t.Errorf("verify calls = %d, want only the opening check", calls)
	}
}

func TestVerificationStreamInterceptor_NoPolicy_PassesThrough(t *testing.T) {
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Deny())
	// PolicyOptionStreamInterceptor ran but the method declares no policy.
	stream := &fakeServerStream{ctx: interceptors.MarkInterceptorRan(context.Background())}
	handlerCalled := false

	err := interceptor(nil, stream, streamInfo(), func(_ any, _ grpc.ServerStream) error {
		handlerCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler must run for a method with no policy")
	}
}

func TestVerificationStreamInterceptor_WithoutPolicyOptionInterceptor_IsInternal(t *testing.T) {
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Allow())
	stream := &fakeServerStream{ctx: context.Background()}

	err := interceptor(nil, stream, streamInfo(), func(_ any, _ grpc.ServerStream) error {
		t.Error("handler must not run when the policy interceptor did not")
		return nil
	})
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v, want %v", status.Code(err), codes.Internal)
	}
}

// TestPolicyOptionStreamInterceptor_FieldMappings_IsInternal pins the stream
// interceptor's outright refusal of a policy carrying field_mappings: the
// interceptor runs before any request message is read, and a client or
// bidirectional stream has no single one, so it fails closed rather than
// guess. The mapping's presence is what is refused, so
// moving its placeholder out of the resource template does not make a
// streaming method reachable (README, "Streaming").
func TestPolicyOptionStreamInterceptor_FieldMappings_IsInternal(t *testing.T) {
	interceptor := policygrpc.PolicyOptionStreamInterceptor()
	stream := &fakeServerStream{ctx: context.Background()}
	handlerCalled := false

	// GetResourceById is the method whose policy declares field_mappings. The
	// policy lookup is by full method name against the proto registry and does
	// not care that the method is not declared streaming, which is exactly the
	// case being pinned: it is the option, not the cardinality, that is refused.
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.v1.TestService/GetResourceById",
		IsServerStream: true,
	}

	err := interceptor(nil, stream, info, func(any, grpc.ServerStream) error {
		handlerCalled = true
		return nil
	})

	if err == nil {
		t.Fatal("expected a policy with field_mappings to be refused on a stream")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v, want %v", status.Code(err), codes.Internal)
	}
	if handlerCalled {
		t.Error("handler ran for a policy the interceptor refused")
	}
}

// TestPolicyOptionStreamInterceptor_NoFieldMappings_ResolvesPolicy is the
// counterpart: the same interceptor resolves a policy without field_mappings and
// leaves it on the stream context, so the refusal above is specific to
// field_mappings and not a blanket failure of the streaming path.
func TestPolicyOptionStreamInterceptor_NoFieldMappings_ResolvesPolicy(t *testing.T) {
	interceptor := policygrpc.PolicyOptionStreamInterceptor()
	stream := &fakeServerStream{ctx: context.Background()}
	var captured *interceptors.PolicyData

	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.v1.TestService/GetResource",
		IsServerStream: true,
	}

	err := interceptor(nil, stream, info, func(_ any, ss grpc.ServerStream) error {
		captured, _ = interceptors.PolicyFromContext(ss.Context())
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured == nil {
		t.Fatal("expected a resolved policy on the stream context")
	}
	if captured.Resource != "resource" || captured.Action != "read" {
		t.Errorf("policy = %+v, want {Resource:resource Action:read}", captured)
	}
}

// uploadServer is the handler of the client-streaming UploadResources RPC. It
// records every message it is handed.
type uploadServer struct {
	testServer
	mu       sync.Mutex
	received []string
}

func (s *uploadServer) UploadResources(stream grpc.ClientStreamingServer[testpb.CreateResourceRequest, testpb.CreateResourceResponse]) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&testpb.CreateResourceResponse{Id: "done"})
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.received = append(s.received, msg.Name)
		s.mu.Unlock()
	}
}

func (s *uploadServer) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.received...)
}

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

// On a real stream: the grant is revoked after the stream opened and its first
// message was delivered, so the next message the client sends never reaches
// the handler.
func TestStreamChain_RevokedAfterOpen_NextMessageIsNotDelivered(t *testing.T) {
	impl := &uploadServer{}
	rec := &recorder{}
	srv := grpc.NewServer(grpc.ChainStreamInterceptor(
		policygrpc.PolicyOptionStreamInterceptor(),
		// The opening check and the re-check of the first message are allowed.
		policygrpc.VerificationStreamInterceptor(revokedAfter(2), policygrpc.WithDecisionObserver(rec.observe)),
	))
	testpb.RegisterTestServiceServer(srv, impl)
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

	stream, err := testpb.NewTestServiceClient(conn).UploadResources(bearerCtx("tok"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"first", "second"} {
		// A send may fail once the server has ended the stream; the status
		// comes from CloseAndRecv.
		if err := stream.Send(&testpb.CreateResourceRequest{Name: name}); err != nil {
			break
		}
	}
	_, err = stream.CloseAndRecv()

	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	if got := impl.all(); len(got) != 1 || got[0] != "first" {
		t.Errorf("handler received %q, want only the message sent before revocation", got)
	}
	if events := rec.all(); len(events) != 3 {
		t.Errorf("observer saw %d checks, want the opening one and one per message", len(events))
	}
}
