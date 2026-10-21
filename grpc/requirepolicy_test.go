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
	"sync/atomic"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	healthCheckMethod = "/test.v1.TestService/HealthCheck"
	testService       = "/test.v1.TestService/"
)

type healthServer struct {
	testpb.UnimplementedTestServiceServer
	called atomic.Bool
}

func (s *healthServer) HealthCheck(context.Context, *testpb.HealthCheckRequest) (*testpb.HealthCheckResponse, error) {
	s.called.Store(true)
	return &testpb.HealthCheckResponse{Status: "ok"}, nil
}

func (s *healthServer) GetResource(_ context.Context, req *testpb.GetResourceRequest) (*testpb.GetResourceResponse, error) {
	return &testpb.GetResourceResponse{Id: req.Id}, nil
}

func TestRequirePolicy_Unary(t *testing.T) {
	run := func(t *testing.T, opts ...policygrpc.Option) (*healthServer, int32, int32, error) {
		t.Helper()
		var verifies, observed atomic.Int32
		impl := &healthServer{}
		verifier := endpointtest.Func(func(context.Context, string, string) error {
			verifies.Add(1)
			return nil
		})
		opts = append(opts, policygrpc.WithDecisionObserver(func(context.Context, interceptors.DecisionEvent) {
			observed.Add(1)
		}))
		client, cleanup := startServerWithImpl(t, impl,
			policygrpc.PolicyOptionInterceptor(),
			policygrpc.VerificationInterceptor(verifier, opts...),
		)
		defer cleanup()
		_, err := client.HealthCheck(context.Background(), &testpb.HealthCheckRequest{})
		return impl, verifies.Load(), observed.Load(), err
	}

	t.Run("a method with no policy is refused before its handler", func(t *testing.T) {
		impl, verifies, observed, err := run(t, policygrpc.WithRequirePolicy())
		if status.Code(err) != codes.Internal {
			t.Fatalf("code = %v, want %v (%v)", status.Code(err), codes.Internal, err)
		}
		if msg := status.Convert(err).Message(); msg != "authorization check failed" {
			t.Errorf("message = %q, want the fixed Internal message", msg)
		}
		if impl.called.Load() {
			t.Error("the handler ran")
		}
		if verifies != 0 || observed != 0 {
			t.Errorf("verifier asked %d times, observer called %d times; want neither", verifies, observed)
		}
	})

	t.Run("without the option it passes", func(t *testing.T) {
		impl, _, _, err := run(t)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !impl.called.Load() {
			t.Error("the handler did not run")
		}
	})

	t.Run("an exempt method passes", func(t *testing.T) {
		impl, verifies, _, err := run(t, policygrpc.WithRequirePolicy("/other.Svc/", healthCheckMethod))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !impl.called.Load() || verifies != 0 {
			t.Errorf("handler ran = %v, verifier asked %d times; want ran and not asked", impl.called.Load(), verifies)
		}
	})

	t.Run("an exempt service passes", func(t *testing.T) {
		impl, _, _, err := run(t, policygrpc.WithRequirePolicy(testService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !impl.called.Load() {
			t.Error("the handler did not run")
		}
	})

	t.Run("exemptions from several calls add up", func(t *testing.T) {
		_, _, _, err := run(t, policygrpc.WithRequirePolicy(testService), policygrpc.WithRequirePolicy())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("an annotated method is unaffected", func(t *testing.T) {
		var verifies atomic.Int32
		client, cleanup := startServer(t,
			policygrpc.PolicyOptionInterceptor(),
			policygrpc.VerificationInterceptor(endpointtest.Func(func(context.Context, string, string) error {
				verifies.Add(1)
				return nil
			}), policygrpc.WithRequirePolicy()),
		)
		defer cleanup()
		if _, err := client.GetResource(bearerCtx("tok"), &testpb.GetResourceRequest{Id: "1"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if verifies.Load() != 1 {
			t.Errorf("verifier asked %d times, want 1", verifies.Load())
		}
	})
}

func TestRequirePolicy_Unary_ErrorUnwrapsToErrNoPolicy(t *testing.T) {
	interceptor := policygrpc.VerificationInterceptor(endpointtest.Allow(), policygrpc.WithRequirePolicy())
	ctx := interceptors.MarkInterceptorRan(context.Background())

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: healthCheckMethod}, func(context.Context, any) (any, error) {
		t.Error("the handler ran")
		return nil, nil
	})
	if !errors.Is(err, interceptors.ErrNoPolicy) {
		t.Errorf("err = %v, want one that unwraps to ErrNoPolicy", err)
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v, want %v", status.Code(err), codes.Internal)
	}
}

func TestRequirePolicy_Stream(t *testing.T) {
	// PolicyOptionStreamInterceptor ran and found no policy on the method.
	noPolicy := func() *fakeServerStream {
		return &fakeServerStream{ctx: interceptors.MarkInterceptorRan(context.Background())}
	}
	info := func(method string) *grpc.StreamServerInfo {
		return &grpc.StreamServerInfo{FullMethod: method, IsServerStream: true}
	}
	run := func(t *testing.T, ss *fakeServerStream, method string, opts ...policygrpc.Option) (bool, int32, int32, error) {
		t.Helper()
		var verifies, observed atomic.Int32
		verifier := endpointtest.Func(func(context.Context, string, string) error {
			verifies.Add(1)
			return nil
		})
		opts = append(opts, policygrpc.WithDecisionObserver(func(context.Context, interceptors.DecisionEvent) {
			observed.Add(1)
		}))
		ran := false
		err := policygrpc.VerificationStreamInterceptor(verifier, opts...)(nil, ss, info(method), func(any, grpc.ServerStream) error {
			ran = true
			return nil
		})
		return ran, verifies.Load(), observed.Load(), err
	}

	t.Run("a method with no policy is refused before its handler", func(t *testing.T) {
		ran, verifies, observed, err := run(t, noPolicy(), healthCheckMethod, policygrpc.WithRequirePolicy())
		if status.Code(err) != codes.Internal {
			t.Fatalf("code = %v, want %v (%v)", status.Code(err), codes.Internal, err)
		}
		if !errors.Is(err, interceptors.ErrNoPolicy) {
			t.Errorf("err = %v, want one that unwraps to ErrNoPolicy", err)
		}
		if ran {
			t.Error("the handler ran")
		}
		if verifies != 0 || observed != 0 {
			t.Errorf("verifier asked %d times, observer called %d times; want neither", verifies, observed)
		}
	})

	t.Run("without the option it passes", func(t *testing.T) {
		ran, _, _, err := run(t, noPolicy(), healthCheckMethod)
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
	})

	t.Run("an exempt method passes", func(t *testing.T) {
		ran, _, _, err := run(t, noPolicy(), healthCheckMethod, policygrpc.WithRequirePolicy(healthCheckMethod))
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
	})

	t.Run("an exempt service passes", func(t *testing.T) {
		ran, _, _, err := run(t, noPolicy(), healthCheckMethod, policygrpc.WithRequirePolicy(testService))
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
	})

	t.Run("an annotated method is unaffected", func(t *testing.T) {
		ran, verifies, _, err := run(t, &fakeServerStream{ctx: policyStreamCtx()}, "/test.v1.TestService/UploadResources", policygrpc.WithRequirePolicy())
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
		if verifies != 1 {
			t.Errorf("verifier asked %d times, want 1", verifies)
		}
	})
}

func TestWithRequirePolicy_MalformedEntry_Panics(t *testing.T) {
	for _, entry := range []string{"", "pkg.Svc/Get", "/pkg.Svc", "/pkg.Svc/Get/", "/pkg.Svc/*"} {
		t.Run(entry, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("WithRequirePolicy(%q) did not panic", entry)
				}
			}()
			policygrpc.WithRequirePolicy("/ok.Svc/", entry)
		})
	}
}
