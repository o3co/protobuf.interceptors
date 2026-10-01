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
	"net/url"
	"strings"
	"testing"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// backendFailure is an error the way an HTTP endpoint reports one: it names
// the backend and the URL it called.
func backendFailure(cause error) error {
	return fmt.Errorf("OPA request failed: %w", &url.Error{
		Op: "Post", URL: "http://opa.internal:8181/v1/data/authz", Err: cause,
	})
}

// leaks are fragments of an endpoint's error that must never reach the caller.
var leaks = []string{"http", "opa", "OPA", "8181", "Cedar", "verifier", "refused", "placeholder", "<id>", "token expired"}

func assertFixedMessage(t *testing.T, err error, code codes.Code, message string) {
	t.Helper()
	st, _ := status.FromError(err)
	if st.Code() != code {
		t.Errorf("code = %v, want %v", st.Code(), code)
	}
	if st.Message() != message {
		t.Errorf("message = %q, want %q", st.Message(), message)
	}
	for _, leak := range leaks {
		if strings.Contains(st.Message(), leak) {
			t.Errorf("the caller's message %q carries %q", st.Message(), leak)
		}
	}
}

// The caller is told the outcome in a fixed message. What the endpoint said —
// a backend name, a URL, a reason — stays in the service.
func TestChain_CallerMessageIsFixed(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		code    codes.Code
		message string
	}{
		{"denied", &interceptors.DeniedError{Reason: "denied by http://opa.internal:8181"}, codes.PermissionDenied, "access denied"},
		{"unauthenticated", &interceptors.UnauthenticatedError{Reason: "OPA says token expired"}, codes.Unauthenticated, "unauthenticated"},
		{"backend failure", backendFailure(errors.New("connection refused")), codes.Internal, "authorization check failed"},
		// The endpoint's own timeout or cancellation, while the RPC is live, is
		// the service's failure, not the caller's deadline.
		{"endpoint canceled", backendFailure(context.Canceled), codes.Internal, "authorization check failed"},
		{"endpoint timed out", backendFailure(context.DeadlineExceeded), codes.Internal, "authorization check failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := startServer(t,
				policygrpc.PolicyOptionInterceptor(),
				policygrpc.VerificationInterceptor(endpointtest.Func(
					func(context.Context, string, string) error { return tc.err },
				)),
			)
			defer cleanup()

			_, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"})
			assertFixedMessage(t, err, tc.code, tc.message)
		})
	}
}

// A refused placeholder value is a denial like any other: the caller is not
// told which placeholder or which character.
func TestChain_RefusedPlaceholderValue_CallerMessageIsFixed(t *testing.T) {
	client, cleanup := startServer(t,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	_, err := client.GetResourceById(bearerCtx("tok"), &testpb.GetResourceByIdRequest{Id: "1.member:2"})
	assertFixedMessage(t, err, codes.PermissionDenied, "access denied")
}

// The error an interceptor returns unwraps to the endpoint's, so an
// interceptor placed outside it can record what the caller is not told.
func TestVerificationInterceptor_ReturnedErrorUnwrapsToTheCause(t *testing.T) {
	cause := backendFailure(errors.New("connection refused"))
	interceptor := policygrpc.VerificationInterceptor(endpointtest.Func(
		func(context.Context, string, string) error { return cause },
	))
	ctx := interceptors.WithPolicy(interceptors.MarkInterceptorRan(context.Background()), "resource", "read")

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.v1.TestService/GetResource"},
		func(context.Context, any) (any, error) {
			t.Fatal("the handler must not run")
			return nil, nil
		})
	if !errors.Is(err, cause) {
		t.Errorf("error %v does not unwrap to the endpoint's error", err)
	}
	assertFixedMessage(t, err, codes.Internal, "authorization check failed")
}

// When the RPC's own context has ended, the caller is told so.
func TestVerificationInterceptor_RPCContextEnded(t *testing.T) {
	base := interceptors.WithPolicy(interceptors.MarkInterceptorRan(context.Background()), "resource", "read")
	canceled, cancel := context.WithCancel(base)
	cancel()
	expired, cancelExpired := context.WithDeadline(base, time.Now().Add(-time.Second))
	defer cancelExpired()

	cases := []struct {
		name    string
		ctx     context.Context
		code    codes.Code
		message string
	}{
		{"canceled", canceled, codes.Canceled, "request canceled"},
		{"deadline exceeded", expired, codes.DeadlineExceeded, "deadline exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interceptor := policygrpc.VerificationInterceptor(endpointtest.Func(
				func(ctx context.Context, _, _ string) error { return backendFailure(ctx.Err()) },
			))
			_, err := interceptor(tc.ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.v1.TestService/GetResource"},
				func(context.Context, any) (any, error) {
					t.Fatal("the handler must not run")
					return nil, nil
				})
			assertFixedMessage(t, err, tc.code, tc.message)
		})
	}
}

// A policy the interceptor cannot apply, or a chain in the wrong order, is a
// server fault: the caller is told only that the check failed, and the
// returned error unwraps to what went wrong.
func TestPolicyAndGuardErrors_CallerMessageIsFixed(t *testing.T) {
	noHandler := func(context.Context, any) (any, error) {
		t.Fatal("the handler must not run")
		return nil, nil
	}
	noStreamHandler := func(any, grpc.ServerStream) error {
		t.Fatal("the handler must not run")
		return nil
	}
	cases := []struct {
		name  string
		cause string
		run   func() error
	}{
		{"request is not a proto message", "proto.Message", func() error {
			_, err := policygrpc.PolicyOptionInterceptor()(context.Background(), "not a message",
				&grpc.UnaryServerInfo{FullMethod: "/test.v1.TestService/GetResourceById"}, noHandler)
			return err
		}},
		{"unary chain out of order", "must run before", func() error {
			_, err := policygrpc.VerificationInterceptor(endpointtest.Allow())(context.Background(), nil,
				&grpc.UnaryServerInfo{FullMethod: "/test.v1.TestService/GetResource"}, noHandler)
			return err
		}},
		{"field_mappings on a stream", "field_mappings", func() error {
			return policygrpc.PolicyOptionStreamInterceptor()(nil, &fakeServerStream{ctx: context.Background()},
				&grpc.StreamServerInfo{FullMethod: "/test.v1.TestService/GetResourceById"}, noStreamHandler)
		}},
		{"stream chain out of order", "must run before", func() error {
			return policygrpc.VerificationStreamInterceptor(endpointtest.Allow())(nil,
				&fakeServerStream{ctx: context.Background()}, streamInfo(), noStreamHandler)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			assertFixedMessage(t, err, codes.Internal, "authorization check failed")
			if cause := errors.Unwrap(err); cause == nil || !strings.Contains(cause.Error(), tc.cause) {
				t.Errorf("error %v does not unwrap to a cause naming %q", err, tc.cause)
			}
		})
	}
}
