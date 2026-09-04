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

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func (s *fakeServerStream) SendMsg(any) error {
	s.sendCalls++
	return nil
}

func (s *fakeServerStream) RecvMsg(any) error {
	s.recvCalls++
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

// TestVerificationStreamInterceptor_SendBeforeRecv_IsDenied is the regression:
// a bidirectional or client-streaming handler may send before it ever receives,
// so an authorization check that lived only in RecvMsg let the whole handler
// run unauthorized.
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

// TestVerificationStreamInterceptor_NeverReceives_IsStillChecked covers the
// server-streaming handler that only ever sends: it used to be authorized by
// nothing at all, because no RecvMsg was ever called.
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
// per-message check that survives the up-front one: the resource and action are
// fixed for the life of a stream, so the re-check exists to stop delivery on a
// long-lived stream whose authorization has since been withdrawn.
func TestVerificationStreamInterceptor_RecvMsg_RechecksAuthorization(t *testing.T) {
	calls := 0
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
		func(context.Context, string, string) error {
			calls++
			if calls == 1 {
				return nil // opening the stream is allowed
			}
			return &interceptors.DeniedError{Reason: "grant revoked mid-stream"}
		},
	))
	stream := &fakeServerStream{ctx: policyStreamCtx()}

	var recvErr error
	err := interceptor(nil, stream, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		recvErr = ss.RecvMsg(new(string))
		return recvErr
	})
	if err == nil {
		t.Fatal("expected the revoked stream to fail")
	}
	if status.Code(recvErr) != codes.PermissionDenied {
		t.Errorf("RecvMsg code = %v, want %v", status.Code(recvErr), codes.PermissionDenied)
	}
	if stream.recvCalls != 0 {
		t.Errorf("recvCalls = %d, want 0: a message must not be delivered after the re-check denies", stream.recvCalls)
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
