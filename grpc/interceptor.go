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
	"errors"
	"fmt"
	"sync"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/internal/methodset"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Option configures a verification interceptor.
type Option func(*config)

type config struct {
	observer        interceptors.DecisionObserver
	recheckInterval time.Duration
	now             func() time.Time
	requirePolicy   bool
	exempt          methodset.Set
}

// WithRequirePolicy has a verification interceptor refuse an RPC whose method
// declares no policy option, except a method exempt names, instead of letting
// it through unchecked. The refusal is Internal, before the handler runs, and
// wraps interceptors.ErrNoPolicy; no backend is asked and the observer is not
// called. A method with a policy is checked as before.
//
// An exempt entry is a full method name, "/package.Service/Method", or a
// service, "/package.Service/", which exempts each of its methods. Nothing is
// exempt unless listed, the grpc-go health and reflection services included:
// "/grpc.health.v1.Health/", "/grpc.reflection.v1.ServerReflection/" and
// "/grpc.reflection.v1alpha.ServerReflection/". An exemption admits only a
// method with no policy; a method with a policy is always checked. Later
// calls add to the exemptions of earlier ones.
//
// Each interceptor applies the option to the RPCs it sees, so give it to both
// VerificationInterceptor and VerificationStreamInterceptor.
//
// Panics if an entry is not of either form.
func WithRequirePolicy(exempt ...string) Option {
	set, err := methodset.Parse(exempt)
	if err != nil {
		panic("WithRequirePolicy: " + err.Error())
	}
	return func(c *config) {
		c.requirePolicy = true
		c.exempt = c.exempt.Union(set)
	}
}

// checkUnannotated decides an RPC to fullMethod, which declares no policy: an
// error when a policy is required and the method is not exempt.
func (c *config) checkUnannotated(fullMethod string) error {
	if !c.requirePolicy || c.exempt.Contains(fullMethod) {
		return nil
	}
	return fmt.Errorf("method %s: %w", fullMethod, interceptors.ErrNoPolicy)
}

// WithStreamRecheckInterval has VerificationStreamInterceptor re-check a
// stream at most once per d instead of on every message: a message sent or
// received less than d after the last check began goes through without one.
// The default, 0, re-checks every message. VerificationInterceptor, which
// checks each unary RPC once, ignores it.
//
// Panics if d is negative.
func WithStreamRecheckInterval(d time.Duration) Option {
	if d < 0 {
		panic("WithStreamRecheckInterval: interval must not be negative")
	}
	return func(c *config) {
		c.recheckInterval = d
	}
}

// WithDecisionObserver has a verification interceptor hand every
// authorization check it makes to fn, allowed or not (see
// interceptors.DecisionObserver). A stream's re-check calls fn on the send or
// receive that made it, which waits for fn to return.
func WithDecisionObserver(fn interceptors.DecisionObserver) Option {
	return func(c *config) {
		c.observer = fn
	}
}

// verify runs one authorization check and hands it to the observer, if any.
// A credential the interceptor could not read (credErr) refuses the check
// without asking the verifier.
func (c *config) verify(ctx context.Context, verifier endpoint.VerifierEndpoint, resource, action string, credErr error) (*interceptors.Decision, error) {
	var decision *interceptors.Decision
	err := credErr
	if err == nil {
		decision, err = endpoint.VerifyWithDecision(ctx, verifier, resource, action)
	}
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
	c := &config{}
	for _, o := range opts {
		o(c)
	}
	return c
}

// withInbound puts the request's bearer token and request ID on ctx. The
// error is a credential that could not be read; it refuses only a method that
// has a policy, since a method without one is not checked.
func withInbound(ctx context.Context) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	token, err := interceptors.InboundBearerToken(md.Get("authorization"))
	if token != "" {
		ctx = interceptors.WithBearerToken(ctx, token)
	}
	return interceptors.WithRequestID(ctx, interceptors.InboundRequestID(md.Get("x-request-id"))), err
}

// PolicyOptionInterceptor returns a gRPC UnaryServerInterceptor that reads
// proto method options and injects the resolved Policy into context.
//
// It resolves with interceptors.ResolveResourceWithFields and attaches the
// extracted values with interceptors.WithExtractedFields, as
// connectrpc.PolicyOptionInterceptor does, so a field mapping whose
// placeholder is absent from the resource template still reaches an endpoint
// that reads them (in package endpoint, the o3co and OPA endpoints). See
// README, "Extracted field forwarding".
func PolicyOptionInterceptor() grpc.UnaryServerInterceptor {
	var cache sync.Map

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Always mark that this interceptor ran.
		ctx = interceptors.MarkInterceptorRan(ctx)

		policy, err := getMethodPolicy(&cache, info.FullMethod)
		if err != nil {
			return nil, toGRPCError(ctx, fmt.Errorf("failed to look up method policy: %w", err))
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
				return nil, toGRPCError(ctx, errors.New("request does not implement proto.Message"))
			}
			var fields map[string]string
			resource, action, fields, err = interceptors.ResolveResourceWithFields(policy, msg)
			if err == nil && len(fields) > 0 {
				ctx = interceptors.WithExtractedFields(ctx, fields)
			}
		} else {
			resource, action, err = interceptors.ResolveResource(policy, nil)
		}
		// Mapped, not blanket-Internal: resolution refuses a request field value
		// that would change which resource the string names, and that refusal is
		// a denial rather than a server fault. Anything else still maps to
		// Internal — an unmapped error must never let the handler run.
		if err != nil {
			return nil, toGRPCError(ctx, fmt.Errorf("failed to resolve resource: %w", err))
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
		ctx, credErr := withInbound(ctx)

		// Guard: PolicyOptionInterceptor must have run before this interceptor.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return nil, toGRPCError(ctx, errors.New("PolicyOptionInterceptor must run before VerificationInterceptor"))
		}

		// No policy in context means the method declares none: it passes
		// through unchecked, unless WithRequirePolicy refuses it.
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			if err := cfg.checkUnannotated(info.FullMethod); err != nil {
				return nil, toGRPCError(ctx, err)
			}
			return handler(ctx, req)
		}

		// Call the verifier endpoint.
		decision, err := cfg.verify(ctx, verifier, policyData.Resource, policyData.Action, credErr)
		if err != nil {
			return nil, toGRPCError(ctx, err)
		}

		return handler(withDecision(ctx, decision), req)
	}
}
