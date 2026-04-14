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
	"strings"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	pb "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// getPolicyFromSpec extracts the Policy proto option from a connect.Spec's Schema.
// Returns nil if no policy option is defined.
func getPolicyFromSpec(spec connect.Spec) *pb.Policy {
	md, ok := spec.Schema.(protoreflect.MethodDescriptor)
	if !ok {
		return nil
	}
	opts := md.Options()
	if opts == nil {
		return nil
	}
	methodOptions, ok := opts.(*descriptorpb.MethodOptions)
	if !ok {
		return nil
	}
	if !proto.HasExtension(methodOptions, pb.E_Policy) {
		return nil
	}
	ext := proto.GetExtension(methodOptions, pb.E_Policy)
	policy, ok := ext.(*pb.Policy)
	if !ok {
		return nil
	}
	return policy
}

// extractBearerTokenFromHeader extracts the Bearer token from an http.Header.
func extractBearerTokenFromHeader(header interface{ Get(string) string }) string {
	v := header.Get("Authorization")
	if strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	return ""
}

// extractRequestIDFromHeader extracts X-Request-Id from an http.Header, returning empty string if absent.
func extractRequestIDFromHeader(header interface{ Get(string) string }) string {
	return header.Get("X-Request-Id")
}

// policyOptionInterceptor implements connect.Interceptor for PolicyOptionInterceptor.
type policyOptionInterceptor struct{}

// PolicyOptionInterceptor returns a ConnectRPC Interceptor that reads the proto
// method option and injects the resolved Policy into context.
//
// This interceptor must be placed before VerificationInterceptor in the chain.
func PolicyOptionInterceptor() connect.Interceptor {
	return &policyOptionInterceptor{}
}

func (p *policyOptionInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = interceptors.MarkInterceptorRan(ctx)

		policy := getPolicyFromSpec(req.Spec())
		if policy == nil {
			// No policy defined — pass through.
			return next(ctx, req)
		}

		var resource, action string
		var err error

		if len(policy.FieldMappings) > 0 {
			msg, ok := req.Any().(proto.Message)
			if !ok {
				return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("request does not implement proto.Message"))
			}
			resource, action, err = interceptors.ResolveResource(policy, msg)
		} else {
			resource, action, err = interceptors.ResolveResource(policy, nil)
		}
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to resolve resource: %w", err))
		}

		ctx = interceptors.WithPolicy(ctx, resource, action)
		return next(ctx, req)
	}
}

func (p *policyOptionInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	// Pass-through for client-side streaming.
	return next
}

func (p *policyOptionInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx = interceptors.MarkInterceptorRan(ctx)

		policy := getPolicyFromSpec(conn.Spec())
		if policy == nil {
			return next(ctx, conn)
		}

		if len(policy.FieldMappings) > 0 {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("field_mappings are not supported for streaming RPCs"))
		}

		resource, action, err := interceptors.ResolveResource(policy, nil)
		if err != nil {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("failed to resolve resource: %w", err))
		}

		ctx = interceptors.WithPolicy(ctx, resource, action)
		return next(ctx, conn)
	}
}

// verificationInterceptor implements connect.Interceptor for VerificationInterceptor.
type verificationInterceptor struct {
	verifier endpoint.VerifierEndpoint
}

// VerificationInterceptor returns a ConnectRPC Interceptor that reads Policy
// from context and calls the verifier endpoint.
// Panics if verifier is nil.
func VerificationInterceptor(verifier endpoint.VerifierEndpoint) connect.Interceptor {
	if verifier == nil {
		panic("VerificationInterceptor: verifier must not be nil")
	}
	return &verificationInterceptor{verifier: verifier}
}

func (v *verificationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// Extract and store bearer token.
		if token := extractBearerTokenFromHeader(req.Header()); token != "" {
			ctx = interceptors.WithBearerToken(ctx, token)
		}

		// Extract or store request ID.
		if rid := extractRequestIDFromHeader(req.Header()); rid != "" {
			ctx = interceptors.WithRequestID(ctx, rid)
		}

		// Guard: PolicyOptionInterceptor must have run.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("PolicyOptionInterceptor must run before VerificationInterceptor"))
		}

		// No policy in context means the method has no policy — pass through.
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			return next(ctx, req)
		}

		if err := v.verifier.Verify(ctx, policyData.Resource, policyData.Action); err != nil {
			return nil, toConnectError(err)
		}

		return next(ctx, req)
	}
}

func (v *verificationInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	// Pass-through for client-side streaming.
	return next
}

func (v *verificationInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		// Extract and store bearer token.
		if token := extractBearerTokenFromHeader(conn.RequestHeader()); token != "" {
			ctx = interceptors.WithBearerToken(ctx, token)
		}

		// Extract or store request ID.
		if rid := extractRequestIDFromHeader(conn.RequestHeader()); rid != "" {
			ctx = interceptors.WithRequestID(ctx, rid)
		}

		// Guard: PolicyOptionInterceptor must have run.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("PolicyOptionInterceptor must run before VerificationInterceptor"))
		}

		// No policy in context means the method has no policy — pass through.
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			return next(ctx, conn)
		}

		if err := v.verifier.Verify(ctx, policyData.Resource, policyData.Action); err != nil {
			return toConnectError(err)
		}

		return next(ctx, conn)
	}
}
