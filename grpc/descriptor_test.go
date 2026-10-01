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

	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"
)

// startDenyingServer serves with both chains over a verifier that denies
// everything, so only a method with no policy can succeed.
func startDenyingServer(t *testing.T, register func(*grpc.Server), opts ...grpc.ServerOption) *grpc.ClientConn {
	t.Helper()
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			policygrpc.PolicyOptionInterceptor(),
			policygrpc.VerificationInterceptor(endpointtest.Deny()),
		),
		grpc.ChainStreamInterceptor(
			policygrpc.PolicyOptionStreamInterceptor(),
			policygrpc.VerificationStreamInterceptor(endpointtest.Deny()),
		),
	)
	srv := grpc.NewServer(opts...)
	register(srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return conn
}

// A method whose descriptor is not registered cannot say whether it has a
// policy, so it is refused rather than treated as having none.
func TestChain_MethodWithoutADescriptor_IsRefused(t *testing.T) {
	var reached atomic.Bool
	conn := startDenyingServer(t,
		func(srv *grpc.Server) { testpb.RegisterTestServiceServer(srv, &testServer{}) },
		grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
			reached.Store(true)
			return nil
		}),
	)

	for _, method := range []string{"/unknown.v1.Unknown/Do", "/test.v1.TestService/NoSuchMethod"} {
		err := conn.Invoke(context.Background(), method, &testpb.HealthCheckRequest{}, &testpb.HealthCheckResponse{})
		if status.Code(err) != codes.Internal {
			t.Errorf("%s: code = %v, want %v", method, status.Code(err), codes.Internal)
		}
	}
	if reached.Load() {
		t.Error("the unknown service handler ran for a method with no descriptor")
	}
}

// Health and reflection register descriptors without the policy option, so
// they are not checked.
func TestChain_HealthAndReflection_PassThrough(t *testing.T) {
	conn := startDenyingServer(t, func(srv *grpc.Server) {
		healthpb.RegisterHealthServer(srv, health.NewServer())
		reflection.Register(srv)
	})
	ctx := context.Background()

	t.Run("health check", func(t *testing.T) {
		resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("status = %v, want SERVING", resp.Status)
		}
	})

	t.Run("health watch, a server stream with no policy", func(t *testing.T) {
		stream, err := healthpb.NewHealthClient(conn).Watch(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("status = %v, want SERVING", resp.Status)
		}
	})

	t.Run("reflection", func(t *testing.T) {
		stream, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := stream.Send(&reflectionpb.ServerReflectionRequest{
			MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{},
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.GetListServicesResponse().GetService()) == 0 {
			t.Error("reflection listed no services")
		}
	})
}
