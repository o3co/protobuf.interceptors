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
	"net/http"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"github.com/o3co/protobuf.interceptors/testproto/testpbconnect"
)

const testService = "/test.v1.TestService/"

type healthHandler struct {
	testpbconnect.UnimplementedTestServiceHandler
	called atomic.Bool
}

func (h *healthHandler) HealthCheck(context.Context, *connect.Request[testpb.HealthCheckRequest]) (*connect.Response[testpb.HealthCheckResponse], error) {
	h.called.Store(true)
	return connect.NewResponse(&testpb.HealthCheckResponse{Status: "ok"}), nil
}

func (h *healthHandler) GetResource(_ context.Context, req *connect.Request[testpb.GetResourceRequest]) (*connect.Response[testpb.GetResourceResponse], error) {
	return connect.NewResponse(&testpb.GetResourceResponse{Id: req.Msg.Id}), nil
}

// checkCounter is a verifier that allows every check, and an observer, each
// counting its calls.
type checkCounter struct {
	verifies, observed atomic.Int32
}

func (c *checkCounter) interceptor(opts ...policyconnect.Option) connect.Interceptor {
	opts = append(opts, policyconnect.WithDecisionObserver(func(context.Context, interceptors.DecisionEvent) {
		c.observed.Add(1)
	}))
	return policyconnect.VerificationInterceptor(endpointtest.Func(func(context.Context, string, string) error {
		c.verifies.Add(1)
		return nil
	}), opts...)
}

func TestConnectRequirePolicy_Unary(t *testing.T) {
	run := func(t *testing.T, opts ...policyconnect.Option) (*healthHandler, *checkCounter, error) {
		t.Helper()
		impl := &healthHandler{}
		counter := &checkCounter{}
		client, cleanup := startConnectServerWithImpl(t, impl,
			policyconnect.PolicyOptionInterceptor(),
			counter.interceptor(opts...),
		)
		defer cleanup()
		_, err := client.HealthCheck(context.Background(), connect.NewRequest(&testpb.HealthCheckRequest{}))
		return impl, counter, err
	}

	t.Run("a method with no policy is refused before its handler", func(t *testing.T) {
		impl, counter, err := run(t, policyconnect.WithRequirePolicy())
		if connect.CodeOf(err) != connect.CodeInternal {
			t.Fatalf("code = %v, want %v (%v)", connect.CodeOf(err), connect.CodeInternal, err)
		}
		var cerr *connect.Error
		if errors.As(err, &cerr) && cerr.Message() != "authorization check failed" {
			t.Errorf("message = %q, want the fixed Internal message", cerr.Message())
		}
		if impl.called.Load() {
			t.Error("the handler ran")
		}
		if counter.verifies.Load() != 0 || counter.observed.Load() != 0 {
			t.Errorf("verifier asked %d times, observer called %d times; want neither", counter.verifies.Load(), counter.observed.Load())
		}
	})

	t.Run("without the option it passes", func(t *testing.T) {
		impl, _, err := run(t)
		if err != nil || !impl.called.Load() {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, impl.called.Load())
		}
	})

	t.Run("an exempt method passes", func(t *testing.T) {
		impl, counter, err := run(t, policyconnect.WithRequirePolicy("/other.Svc/", testpbconnect.TestServiceHealthCheckProcedure))
		if err != nil || !impl.called.Load() {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, impl.called.Load())
		}
		if counter.verifies.Load() != 0 {
			t.Errorf("verifier asked %d times, want 0", counter.verifies.Load())
		}
	})

	t.Run("an exempt service passes", func(t *testing.T) {
		impl, _, err := run(t, policyconnect.WithRequirePolicy(testService))
		if err != nil || !impl.called.Load() {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, impl.called.Load())
		}
	})

	t.Run("exemptions from several calls add up", func(t *testing.T) {
		_, _, err := run(t, policyconnect.WithRequirePolicy(testService), policyconnect.WithRequirePolicy())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("an annotated method is unaffected", func(t *testing.T) {
		counter := &checkCounter{}
		client, cleanup := startConnectServerWithImpl(t, &healthHandler{},
			policyconnect.PolicyOptionInterceptor(),
			counter.interceptor(policyconnect.WithRequirePolicy()),
		)
		defer cleanup()
		req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
		req.Header().Set("Authorization", "Bearer tok")
		if _, err := client.GetResource(context.Background(), req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if counter.verifies.Load() != 1 {
			t.Errorf("verifier asked %d times, want 1", counter.verifies.Load())
		}
	})

	t.Run("the error unwraps to ErrNoPolicy", func(t *testing.T) {
		var got error
		counter := &checkCounter{}
		client, cleanup := startConnectServerWithImpl(t, &healthHandler{},
			connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
				return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
					res, err := next(ctx, req)
					got = err
					return res, err
				}
			}),
			policyconnect.PolicyOptionInterceptor(),
			counter.interceptor(policyconnect.WithRequirePolicy()),
		)
		defer cleanup()
		_, _ = client.HealthCheck(context.Background(), connect.NewRequest(&testpb.HealthCheckRequest{}))
		if !errors.Is(got, interceptors.ErrNoPolicy) {
			t.Errorf("err = %v, want one that unwraps to ErrNoPolicy", got)
		}
	})
}

// specStreamingConn is a stream whose spec names a procedure.
type specStreamingConn struct {
	fakeStreamingConn
	spec connect.Spec
}

func (c *specStreamingConn) Spec() connect.Spec { return c.spec }

func TestConnectRequirePolicy_Streaming(t *testing.T) {
	const procedure = testpbconnect.TestServiceHealthCheckProcedure
	run := func(t *testing.T, ctx context.Context, opts ...policyconnect.Option) (bool, *checkCounter, error) {
		t.Helper()
		counter := &checkCounter{}
		ran := false
		handler := counter.interceptor(opts...).WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
			ran = true
			return nil
		})
		conn := &specStreamingConn{
			fakeStreamingConn: fakeStreamingConn{header: http.Header{"Authorization": {"Bearer tok"}}},
			spec:              connect.Spec{Procedure: procedure},
		}
		err := handler(ctx, conn)
		return ran, counter, err
	}
	// PolicyOptionInterceptor ran and found no policy on the method.
	noPolicy := interceptors.MarkInterceptorRan(context.Background())

	t.Run("a method with no policy is refused before its handler", func(t *testing.T) {
		ran, counter, err := run(t, noPolicy, policyconnect.WithRequirePolicy())
		if connect.CodeOf(err) != connect.CodeInternal {
			t.Fatalf("code = %v, want %v (%v)", connect.CodeOf(err), connect.CodeInternal, err)
		}
		if !errors.Is(err, interceptors.ErrNoPolicy) {
			t.Errorf("err = %v, want one that unwraps to ErrNoPolicy", err)
		}
		if ran {
			t.Error("the handler ran")
		}
		if counter.verifies.Load() != 0 || counter.observed.Load() != 0 {
			t.Errorf("verifier asked %d times, observer called %d times; want neither", counter.verifies.Load(), counter.observed.Load())
		}
	})

	t.Run("without the option it passes", func(t *testing.T) {
		ran, _, err := run(t, noPolicy)
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
	})

	t.Run("an exempt method passes", func(t *testing.T) {
		ran, _, err := run(t, noPolicy, policyconnect.WithRequirePolicy(procedure))
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
	})

	t.Run("an exempt service passes", func(t *testing.T) {
		ran, _, err := run(t, noPolicy, policyconnect.WithRequirePolicy(testService))
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
	})

	t.Run("an annotated method is unaffected", func(t *testing.T) {
		ran, counter, err := run(t, policyStreamCtx(), policyconnect.WithRequirePolicy())
		if err != nil || !ran {
			t.Errorf("err = %v, handler ran = %v; want nil and ran", err, ran)
		}
		if counter.verifies.Load() != 1 {
			t.Errorf("verifier asked %d times, want 1", counter.verifies.Load())
		}
	})
}

func TestConnectWithRequirePolicy_MalformedEntry_Panics(t *testing.T) {
	for _, entry := range []string{"", "pkg.Svc/Get", "/pkg.Svc", "/pkg.Svc/Get/", "/pkg.Svc/*"} {
		t.Run(entry, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("WithRequirePolicy(%q) did not panic", entry)
				}
			}()
			policyconnect.WithRequirePolicy("/ok.Svc/", entry)
		})
	}
}
