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
}

func (s *testServer) GetResource(_ context.Context, req *testpb.GetResourceRequest) (*testpb.GetResourceResponse, error) {
	return &testpb.GetResourceResponse{Id: req.Id, Name: "test"}, nil
}

func (s *testServer) CreateResource(_ context.Context, req *testpb.CreateResourceRequest) (*testpb.CreateResourceResponse, error) {
	return &testpb.CreateResourceResponse{Id: "new-id"}, nil
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
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(interceptors...))
	testpb.RegisterTestServiceServer(srv, &testServer{})
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
