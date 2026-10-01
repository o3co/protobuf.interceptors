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
	"regexp"
	"sync/atomic"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var generatedRequestID = regexp.MustCompile(`^[0-9]{14}_[0-9a-f]{16}$`)

// seenByEndpoint is what the verifier was handed for one RPC.
type seenByEndpoint struct {
	called    atomic.Bool
	requestID atomic.Pointer[string]
	token     atomic.Pointer[string]
}

func (s *seenByEndpoint) verifier() endpoint.VerifierEndpoint {
	return endpointtest.Func(func(ctx context.Context, _, _ string) error {
		s.called.Store(true)
		id := interceptors.RequestIDFromContext(ctx)
		s.requestID.Store(&id)
		if token, ok := interceptors.BearerTokenFromContext(ctx); ok {
			s.token.Store(&token)
		}
		return nil
	})
}

func callGetResource(t *testing.T, seen *seenByEndpoint, md metadata.MD, opts ...policygrpc.Option) error {
	t.Helper()
	client, cleanup := startServer(t,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(seen.verifier(), opts...),
	)
	defer cleanup()
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	_, err := client.GetResource(ctx, &testpb.GetResourceRequest{Id: "1"})
	return err
}

func TestChain_RequestID(t *testing.T) {
	cases := []struct {
		name string
		md   metadata.MD
		keep string // "" when a generated ID is expected
	}{
		{"absent", metadata.MD{}, ""},
		{"in the verifier's shape", metadata.Pairs("x-request-id", "req-7f3a:1"), "req-7f3a:1"},
		{"outside the verifier's shape", metadata.Pairs("x-request-id", "not an id; <b>"), ""},
		{"several values", metadata.Pairs("x-request-id", "a", "x-request-id", "b"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := &seenByEndpoint{}
			if err := callGetResource(t, seen, tc.md); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := *seen.requestID.Load()
			if tc.keep != "" && got != tc.keep {
				t.Errorf("request ID = %q, want the inbound %q kept", got, tc.keep)
			}
			if tc.keep == "" && !generatedRequestID.MatchString(got) {
				t.Errorf("request ID = %q, want a generated one", got)
			}
		})
	}
}

// RFC 9110 §11.1: the scheme is case-insensitive.
func TestChain_BearerToken_SchemeIsCaseInsensitive(t *testing.T) {
	seen := &seenByEndpoint{}
	if err := callGetResource(t, seen, metadata.Pairs("authorization", "bearer tok-1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := seen.token.Load(); got == nil || *got != "tok-1" {
		t.Errorf("token = %v, want %q", got, "tok-1")
	}
}

func TestChain_BearerToken_Absent_TheEndpointDecides(t *testing.T) {
	seen := &seenByEndpoint{}
	if err := callGetResource(t, seen, metadata.MD{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !seen.called.Load() {
		t.Error("the endpoint was not asked")
	}
	if got := seen.token.Load(); got != nil {
		t.Errorf("token = %q, want none", *got)
	}
}

// A credential that is not exactly one bearer token is refused before any
// endpoint is asked, and the observer sees the refusal.
func TestChain_BearerToken_NotOneBearerCredential_IsUnauthenticated(t *testing.T) {
	cases := map[string]metadata.MD{
		"several values": metadata.Pairs("authorization", "Bearer a", "authorization", "Bearer b"),
		"empty token":    metadata.Pairs("authorization", "Bearer "),
		"another scheme": metadata.Pairs("authorization", "Basic dXNlcjpwYXNz"),
	}
	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			seen := &seenByEndpoint{}
			rec := &recorder{}
			err := callGetResource(t, seen, md, policygrpc.WithDecisionObserver(rec.observe))
			if status.Code(err) != codes.Unauthenticated {
				t.Errorf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
			}
			if seen.called.Load() {
				t.Error("the endpoint was asked with a credential the interceptor could not read")
			}
			var unauth *interceptors.UnauthenticatedError
			if events := rec.all(); len(events) != 1 || !errors.As(events[0].Err, &unauth) {
				t.Errorf("observer events = %+v, want the refusal", events)
			}
		})
	}
}

// A method with no policy is not checked, so its credential is not read.
func TestChain_NoPolicyMethod_UnreadableCredentialPassesThrough(t *testing.T) {
	client, cleanup := startServer(t,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Deny()),
	)
	defer cleanup()

	ctx := metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer a", "authorization", "Bearer b"))
	if _, err := client.HealthCheck(ctx, &testpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerificationStreamInterceptor_InboundCredentialAndRequestID(t *testing.T) {
	t.Run("not one bearer credential", func(t *testing.T) {
		interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Allow())
		ctx := metadata.NewIncomingContext(policyStreamCtx(),
			metadata.Pairs("authorization", "Bearer a", "authorization", "Bearer b"))

		err := interceptor(nil, &fakeServerStream{ctx: ctx}, streamInfo(), func(any, grpc.ServerStream) error {
			t.Error("the handler must not run")
			return nil
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
		}
	})
	t.Run("request ID outside the verifier's shape", func(t *testing.T) {
		var got string
		interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Func(
			func(ctx context.Context, _, _ string) error {
				got = interceptors.RequestIDFromContext(ctx)
				return nil
			},
		))
		ctx := metadata.NewIncomingContext(policyStreamCtx(), metadata.Pairs("x-request-id", "not an id"))

		err := interceptor(nil, &fakeServerStream{ctx: ctx}, streamInfo(), func(any, grpc.ServerStream) error { return nil })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !generatedRequestID.MatchString(got) {
			t.Errorf("request ID = %q, want a generated one", got)
		}
	})
}
