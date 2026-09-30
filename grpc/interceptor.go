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

package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Option configures an interceptor.
type Option func(*config)

type config struct {
	logLevel slog.Level
	observer interceptors.DecisionObserver
}

// WithLogLevel sets the log level for the interceptor's internal logger.
func WithLogLevel(level slog.Level) Option {
	return func(c *config) {
		c.logLevel = level
	}
}

// WithDecisionObserver has a verification interceptor hand every
// authorization check it makes to fn, allowed or not (see
// interceptors.DecisionObserver). The policy option interceptors ignore it.
func WithDecisionObserver(fn interceptors.DecisionObserver) Option {
	return func(c *config) {
		c.observer = fn
	}
}

// verify runs one authorization check and hands it to the observer, if any.
func (c *config) verify(ctx context.Context, verifier endpoint.VerifierEndpoint, resource, action string) (*interceptors.Decision, error) {
	decision, err := endpoint.VerifyWithDecision(ctx, verifier, resource, action)
	if c.observer != nil {
		c.observer(ctx, interceptors.DecisionEvent{Resource: resource, Action: action, Decision: decision, Err: err})
	}
	return decision, err
}

// withDecision puts an allowing decision on the handler's context. An
// endpoint that reported nothing leaves nothing there.
func withDecision(ctx context.Context, d *interceptors.Decision) context.Context {
	if d == nil {
		return ctx
	}
	return interceptors.WithDecision(ctx, d)
}

func newConfig(opts []Option) *config {
	c := &config{logLevel: slog.LevelInfo}
	for _, o := range opts {
		o(c)
	}
	return c
}

func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// generateRequestID returns a request ID formatted as YYYYMMDDHHmmss_<16 hex
// digits>, the hex digits being the wall-clock time in Unix nanoseconds. Nothing
// in it is random: two requests in the same nanosecond get the same ID.
func generateRequestID() string {
	now := time.Now().UTC()
	nano := now.UnixNano()
	return fmt.Sprintf("%s_%016x", now.Format("20060102150405"), nano)
}

// extractBearerToken extracts the Bearer token from gRPC incoming metadata.
// Returns empty string if not present.
func extractBearerToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	for _, v := range vals {
		if strings.HasPrefix(v, "Bearer ") {
			return strings.TrimPrefix(v, "Bearer ")
		}
	}
	return ""
}

// extractOrGenerateRequestID extracts x-request-id from gRPC metadata, or generates one.
func extractOrGenerateRequestID(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if vals := md.Get("x-request-id"); len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return generateRequestID()
}

// PolicyOptionInterceptor returns a gRPC UnaryServerInterceptor that reads
// proto method options and injects the resolved Policy into context.
//
// It resolves with interceptors.ResolveResource, so extracted field_mappings
// values fill the resource template and are then discarded, unlike
// connectrpc.PolicyOptionInterceptor, which forwards them. A field mapping
// whose placeholder the template does not use therefore never reaches the
// verifier. See README, "Extracted field forwarding".
func PolicyOptionInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
	_ = newConfig(opts) // reserve for future logging use
	var cache sync.Map

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Always mark that this interceptor ran.
		ctx = interceptors.MarkInterceptorRan(ctx)

		policy, err := getMethodPolicy(&cache, info.FullMethod)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to look up method policy: %v", err)
		}

		if policy == nil {
			// No policy defined for this method — pass through without setting policy.
			return handler(ctx, req)
		}

		// Resolve resource and action, substituting field_mappings if present.
		var resource, action string
		if len(policy.FieldMappings) > 0 {
			msg, ok := req.(proto.Message)
			if !ok {
				return nil, status.Errorf(codes.Internal, "request does not implement proto.Message")
			}
			resource, action, err = interceptors.ResolveResource(policy, msg)
		} else {
			resource, action, err = interceptors.ResolveResource(policy, nil)
		}
		// Mapped, not blanket-Internal: resolution refuses a request field value
		// that would change which resource the string names, and that refusal is
		// a denial rather than a server fault. Anything else still maps to
		// Internal — an unmapped error must never let the handler run.
		if err != nil {
			return nil, toGRPCError(fmt.Errorf("failed to resolve resource: %w", err))
		}

		ctx = interceptors.WithPolicy(ctx, resource, action)
		return handler(ctx, req)
	}
}

// VerificationInterceptor returns a gRPC UnaryServerInterceptor that reads
// Policy from context and calls the verifier endpoint.
//
// When the endpoint is an endpoint.DecisionVerifier, the decision that allowed
// the RPC is on the handler's context (interceptors.DecisionFromContext), and
// WithDecisionObserver receives every check, denied ones included. Nothing of
// a decision reaches the RPC caller's error.
//
// Panics if verifier is nil.
func VerificationInterceptor(verifier endpoint.VerifierEndpoint, opts ...Option) grpc.UnaryServerInterceptor {
	if verifier == nil {
		panic("VerificationInterceptor: verifier must not be nil")
	}
	cfg := newConfig(opts)

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Extract and store bearer token from incoming metadata.
		if token := extractBearerToken(ctx); token != "" {
			ctx = interceptors.WithBearerToken(ctx, token)
		}

		// Extract or generate request ID.
		requestID := extractOrGenerateRequestID(ctx)
		ctx = interceptors.WithRequestID(ctx, requestID)

		// Guard: PolicyOptionInterceptor must have run before this interceptor.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return nil, status.Errorf(codes.Internal, "PolicyOptionInterceptor must run before VerificationInterceptor")
		}

		// Get the policy from context; if none, pass through (no policy = no enforcement).
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		// Call the verifier endpoint.
		decision, err := cfg.verify(ctx, verifier, policyData.Resource, policyData.Action)
		if err != nil {
			return nil, toGRPCError(err)
		}

		return handler(withDecision(ctx, decision), req)
	}
}
