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
	"net"
	"sync/atomic"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type testServer struct {
	testpb.UnimplementedTestServiceServer
	// getResourceByIDCalled records whether the handler was reached. Read from
	// the test goroutine while the server writes it, so it is atomic.
	getResourceByIDCalled atomic.Bool
}

func (s *testServer) GetResource(_ context.Context, req *testpb.GetResourceRequest) (*testpb.GetResourceResponse, error) {
	return &testpb.GetResourceResponse{Id: req.Id, Name: "test"}, nil
}

func (s *testServer) CreateResource(_ context.Context, req *testpb.CreateResourceRequest) (*testpb.CreateResourceResponse, error) {
	return &testpb.CreateResourceResponse{Id: "new-id"}, nil
}

func (s *testServer) GetResourceById(_ context.Context, req *testpb.GetResourceByIdRequest) (*testpb.GetResourceResponse, error) {
	s.getResourceByIDCalled.Store(true)
	return &testpb.GetResourceResponse{Id: req.Id, Name: "found"}, nil
}

func (s *testServer) HealthCheck(_ context.Context, _ *testpb.HealthCheckRequest) (*testpb.HealthCheckResponse, error) {
	return &testpb.HealthCheckResponse{Status: "ok"}, nil
}

func bearerCtx(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(context.Background(), md)
}

func startServer(t *testing.T, interceptors ...grpc.UnaryServerInterceptor) (testpb.TestServiceClient, func()) {
	t.Helper()
	return startServerWithImpl(t, &testServer{}, interceptors...)
}

func startServerWithImpl(t *testing.T, impl testpb.TestServiceServer, interceptors ...grpc.UnaryServerInterceptor) (testpb.TestServiceClient, func()) {
	t.Helper()
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(interceptors...))
	testpb.RegisterTestServiceServer(srv, impl)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	return testpb.NewTestServiceClient(conn), func() {
		_ = conn.Close()
		srv.GracefulStop()
	}
}

func TestChain_Allow(t *testing.T) {
	client, cleanup := startServer(t,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	resp, err := client.GetResource(bearerCtx("valid-token"), &testpb.GetResourceRequest{Id: "42"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Id != "42" {
		t.Errorf("Id = %q, want %q", resp.Id, "42")
	}
}

func TestChain_Deny(t *testing.T) {
	client, cleanup := startServer(t,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Deny()),
	)
	defer cleanup()

	_, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("code = %v, want %v", st.Code(), codes.PermissionDenied)
	}
}

func TestChain_NoPolicyMethod_PassThrough(t *testing.T) {
	client, cleanup := startServer(t,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Deny()),
	)
	defer cleanup()

	resp, err := client.HealthCheck(context.Background(), &testpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
}

func TestVerificationInterceptor_MissingPolicyOption_ReturnsInternal(t *testing.T) {
	client, cleanup := startServer(t,
		policygrpc.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	_, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("code = %v, want %v", st.Code(), codes.Internal)
	}
}

func TestVerificationInterceptor_NilVerifier_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	policygrpc.VerificationInterceptor(nil)
}

func TestChain_VerifiesCorrectResourceAction(t *testing.T) {
	var capturedResource, capturedAction string
	client, cleanup := startServer(t,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Func(
			func(ctx context.Context, resource, action string) error {
				capturedResource = resource
				capturedAction = action
				return nil
			},
		)),
	)
	defer cleanup()

	_, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedResource != "resource" {
		t.Errorf("resource = %q, want %q", capturedResource, "resource")
	}
	if capturedAction != "read" {
		t.Errorf("action = %q, want %q", capturedAction, "read")
	}
}

// Ensure interceptors package is used (bearer token / request ID wiring).
var _ = interceptors.BearerTokenFromContext

// TestChain_PlaceholderValueChangingResourceStructure_IsDenied pins the
// end-to-end consequence of the resolution refusal: the policy on
// GetResourceById is "resource/<id>", and an id of "1.member:2" would resolve
// to "resource/1.member:2" — a different resource type for the verifier. The
// request is denied before any backend is asked and the handler never runs.
func TestChain_PlaceholderValueChangingResourceStructure_IsDenied(t *testing.T) {
	var verified atomic.Bool
	impl := &testServer{}
	client, cleanup := startServerWithImpl(t, impl,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Func(
			func(context.Context, string, string) error {
				verified.Store(true)
				return nil
			},
		)),
	)
	defer cleanup()

	_, err := client.GetResourceById(bearerCtx("tok"), &testpb.GetResourceByIdRequest{Id: "1.member:2"})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("code = %v, want %v (an unmapped error must not read as a server fault)", st.Code(), codes.PermissionDenied)
	}
	if impl.getResourceByIDCalled.Load() {
		t.Error("handler was reached for a refused resource value")
	}
	if verified.Load() {
		t.Error("verifier was called with a resource string that should never have been built")
	}
}

func TestChain_PlaceholderValueWithinGrammar_IsResolved(t *testing.T) {
	var capturedResource string
	impl := &testServer{}
	client, cleanup := startServerWithImpl(t, impl,
		policygrpc.PolicyOptionInterceptor(),
		policygrpc.VerificationInterceptor(endpointtest.Func(
			func(_ context.Context, resource, _ string) error {
				capturedResource = resource
				return nil
			},
		)),
	)
	defer cleanup()

	resp, err := client.GetResourceById(bearerCtx("tok"), &testpb.GetResourceByIdRequest{Id: "42"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Id != "42" {
		t.Errorf("Id = %q, want %q", resp.Id, "42")
	}
	if capturedResource != "resource/42" {
		t.Errorf("resource = %q, want %q", capturedResource, "resource/42")
	}
}
