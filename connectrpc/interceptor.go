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

// Package connectrpc provides ConnectRPC interceptors that read proto method
// options and verify authorization via a VerifierEndpoint.
package connectrpc

import (
	"context"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	pb "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// getPolicyFromSpec returns the policy of the method spec describes, nil when
// its descriptor carries no policy option. A spec whose Schema is not a method
// descriptor — a handler built without connect.WithSchema — is an error, not
// "no policy": its policy cannot be known.
func getPolicyFromSpec(spec connect.Spec) (*pb.Policy, error) {
	md, ok := spec.Schema.(protoreflect.MethodDescriptor)
	if !ok {
		return nil, fmt.Errorf("no method descriptor for %q: build the handler with connect.WithSchema", spec.Procedure)
	}
	methodOptions, ok := md.Options().(*descriptorpb.MethodOptions)
	if !ok {
		return nil, fmt.Errorf("unexpected method options type %T", md.Options())
	}
	if !proto.HasExtension(methodOptions, pb.E_Policy) {
		return nil, nil
	}
	policy, ok := proto.GetExtension(methodOptions, pb.E_Policy).(*pb.Policy)
	if !ok {
		return nil, fmt.Errorf("unexpected policy option type %T", proto.GetExtension(methodOptions, pb.E_Policy))
	}
	return policy, nil
}

// withInbound puts the request's bearer token and request ID on ctx. The
// error is a credential that could not be read; it refuses only a method that
// has a policy, since a method without one is not checked.
func withInbound(ctx context.Context, header http.Header) (context.Context, error) {
	token, err := interceptors.InboundBearerToken(header.Values("Authorization"))
	if token != "" {
		ctx = interceptors.WithBearerToken(ctx, token)
	}
	return interceptors.WithRequestID(ctx, interceptors.InboundRequestID(header.Values("X-Request-Id"))), err
}

// policyOptionInterceptor implements connect.Interceptor for PolicyOptionInterceptor.
type policyOptionInterceptor struct{}

// PolicyOptionInterceptor returns a ConnectRPC Interceptor that reads the proto
// method option and injects the resolved Policy into context. It must be placed
// before VerificationInterceptor in the chain.
//
// For unary RPCs it resolves with interceptors.ResolveResourceWithFields and
// attaches the extracted values with interceptors.WithExtractedFields, so a
// field mapping whose placeholder is absent from the resource template still
// reaches an endpoint that reads them (in package endpoint, only the o3co
// endpoint does). The gRPC unary interceptor discards the fields. Streaming
// handlers refuse field_mappings outright, as gRPC's do.
func PolicyOptionInterceptor() connect.Interceptor {
	return &policyOptionInterceptor{}
}

func (p *policyOptionInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// The interceptors guard handlers; a client's call is not theirs.
		if req.Spec().IsClient {
			return next(ctx, req)
		}

		ctx = interceptors.MarkInterceptorRan(ctx)

		policy, err := getPolicyFromSpec(req.Spec())
		if err != nil {
			return nil, toConnectError(ctx, fmt.Errorf("failed to look up method policy: %w", err))
		}
		if policy == nil {
			// No policy defined — pass through.
			return next(ctx, req)
		}

		var resource, action string
		if len(policy.FieldMappings) > 0 {
			msg, ok := req.Any().(proto.Message)
			if !ok {
				return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("request does not implement proto.Message"))
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
			return nil, toConnectError(ctx, fmt.Errorf("failed to resolve resource: %w", err))
		}

		ctx = interceptors.WithPolicy(ctx, resource, action)
		return next(ctx, req)
	}
}

func (p *policyOptionInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	// The interceptors guard handlers; a client's stream is not theirs.
	return next
}

func (p *policyOptionInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx = interceptors.MarkInterceptorRan(ctx)

		policy, err := getPolicyFromSpec(conn.Spec())
		if err != nil {
			return toConnectError(ctx, fmt.Errorf("failed to look up method policy: %w", err))
		}
		if policy == nil {
			return next(ctx, conn)
		}

		if len(policy.FieldMappings) > 0 {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("field_mappings are not supported for streaming RPCs"))
		}

		resource, action, err := interceptors.ResolveResource(policy, nil)
		if err != nil {
			// See WrapUnary: a refused placeholder value is a denial,
			// everything else is Internal.
			return toConnectError(ctx, fmt.Errorf("failed to resolve resource: %w", err))
		}

		ctx = interceptors.WithPolicy(ctx, resource, action)
		return next(ctx, conn)
	}
}

// Option configures VerificationInterceptor.
type Option func(*verificationInterceptor)

// WithDecisionObserver has VerificationInterceptor hand every authorization
// check it makes to fn, allowed or not (see interceptors.DecisionObserver).
func WithDecisionObserver(fn interceptors.DecisionObserver) Option {
	return func(v *verificationInterceptor) {
		v.observer = fn
	}
}

// verificationInterceptor implements connect.Interceptor for VerificationInterceptor.
type verificationInterceptor struct {
	verifier endpoint.VerifierEndpoint
	observer interceptors.DecisionObserver
}

// VerificationInterceptor returns a ConnectRPC Interceptor that reads Policy
// from context and calls the verifier endpoint. A stream is authorized before
// its handler runs, then re-checked on each message Receive returns.
//
// When the endpoint is an endpoint.DecisionVerifier, the decision that allowed
// the RPC is on the handler's context (interceptors.DecisionFromContext), and
// WithDecisionObserver receives every check, denied ones included. Nothing of
// a decision reaches the RPC caller's error.
//
// Panics if verifier is nil.
func VerificationInterceptor(verifier endpoint.VerifierEndpoint, opts ...Option) connect.Interceptor {
	if verifier == nil {
		panic("VerificationInterceptor: verifier must not be nil")
	}
	v := &verificationInterceptor{verifier: verifier}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// verify runs one authorization check, hands it to the observer, if any, and
// returns the context the handler runs with. A credential the interceptor
// could not read (credErr) refuses the check without asking the verifier.
func (v *verificationInterceptor) verify(ctx context.Context, resource, action string, credErr error) (context.Context, error) {
	var decision *interceptors.Decision
	err := credErr
	if err == nil {
		decision, err = endpoint.VerifyWithDecision(ctx, v.verifier, resource, action)
	}
	if v.observer != nil {
		v.observer(ctx, interceptors.DecisionEvent{Resource: resource, Action: action, Decision: decision, Err: err})
	}
	if err != nil {
		return ctx, err
	}
	if decision != nil {
		ctx = interceptors.WithDecision(ctx, decision)
	}
	return ctx, nil
}

func (v *verificationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// The interceptors guard handlers; a client's call is not theirs.
		if req.Spec().IsClient {
			return next(ctx, req)
		}

		ctx, credErr := withInbound(ctx, req.Header())

		// Guard: PolicyOptionInterceptor must have run.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("PolicyOptionInterceptor must run before VerificationInterceptor"))
		}

		// No policy in context means the method has no policy — pass through.
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			return next(ctx, req)
		}

		ctx, err := v.verify(ctx, policyData.Resource, policyData.Action, credErr)
		if err != nil {
			return nil, toConnectError(ctx, err)
		}

		return next(ctx, req)
	}
}

func (v *verificationInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	// The interceptors guard handlers; a client's stream is not theirs.
	return next
}

func (v *verificationInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, credErr := withInbound(ctx, conn.RequestHeader())

		// Guard: PolicyOptionInterceptor must have run.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("PolicyOptionInterceptor must run before VerificationInterceptor"))
		}

		// No policy in context means the method has no policy — pass through.
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			return next(ctx, conn)
		}

		ctx, err := v.verify(ctx, policyData.Resource, policyData.Action, credErr)
		if err != nil {
			return toConnectError(ctx, err)
		}

		return next(ctx, &authStreamingHandlerConn{
			StreamingHandlerConn: conn,
			ctx:                  ctx,
			resource:             policyData.Resource,
			action:               policyData.Action,
			v:                    v,
		})
	}
}

// authStreamingHandlerConn re-checks authorization on each message Receive
// returns, before handing it over.
//
// The stream is already authorized before the handler is invoked. The
// resource and action are fixed, so re-asking the verifier per message is what
// stops a stream that keeps receiving once a grant is revoked or a token
// expires. The check follows the receive, so a message that arrives after
// revocation is cleared and never handed over; a receive that fails has no
// message and is not checked. Sends are not re-checked.
type authStreamingHandlerConn struct {
	connect.StreamingHandlerConn
	ctx      context.Context
	resource string
	action   string
	v        *verificationInterceptor
}

func (c *authStreamingHandlerConn) Receive(msg any) error {
	if err := c.StreamingHandlerConn.Receive(msg); err != nil {
		return err
	}
	if _, err := c.v.verify(c.ctx, c.resource, c.action, nil); err != nil {
		if m, ok := msg.(proto.Message); ok {
			proto.Reset(m)
		}
		return toConnectError(c.ctx, err)
	}
	return nil
}
