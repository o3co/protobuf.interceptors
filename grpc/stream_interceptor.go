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
	"log/slog"
	"sync"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// contextServerStream wraps grpc.ServerStream and overrides Context() to
// return an enriched context.
type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextServerStream) Context() context.Context { return s.ctx }

// authServerStream wraps grpc.ServerStream and calls verifier.Verify on each
// RecvMsg before delegating to the underlying stream.
type authServerStream struct {
	grpc.ServerStream
	ctx      context.Context
	resource string
	action   string
	verifier endpoint.VerifierEndpoint
	log      *slog.Logger
}

func (s *authServerStream) Context() context.Context { return s.ctx }

func (s *authServerStream) RecvMsg(m interface{}) error {
	if err := s.verifier.Verify(s.ctx, s.resource, s.action); err != nil {
		s.log.Error("authorization check failed on RecvMsg",
			"resource", s.resource,
			"action", s.action,
			"error", err,
		)
		return toGRPCError(err)
	}
	return s.ServerStream.RecvMsg(m)
}

// PolicyOptionStreamInterceptor returns a gRPC StreamServerInterceptor that
// reads proto method options and injects the resolved Policy into the stream
// context.
//
// Note: field_mappings are not supported for streaming RPCs (no unary request
// message available). Methods with field_mappings will return codes.Internal.
func PolicyOptionStreamInterceptor(opts ...Option) grpc.StreamServerInterceptor {
	_ = newConfig(opts)
	var cache sync.Map

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		// Always mark that this interceptor ran.
		ctx = interceptors.MarkInterceptorRan(ctx)

		policy, err := getMethodPolicy(&cache, info.FullMethod)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to look up method policy: %v", err)
		}

		if policy == nil {
			// No policy defined — pass through without setting policy.
			wrapped := &contextServerStream{ServerStream: ss, ctx: ctx}
			return handler(srv, wrapped)
		}

		// field_mappings are not supported for streaming (no single request message).
		if len(policy.FieldMappings) > 0 {
			return status.Errorf(codes.Internal, "field_mappings are not supported for streaming RPCs")
		}

		resource, action, err := interceptors.ResolveResource(policy, nil)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to resolve resource: %v", err)
		}

		ctx = interceptors.WithPolicy(ctx, resource, action)
		wrapped := &contextServerStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

// VerificationStreamInterceptor returns a gRPC StreamServerInterceptor that
// reads Policy from the stream context and calls the verifier endpoint on each
// RecvMsg.
//
// Panics if verifier is nil.
func VerificationStreamInterceptor(verifier endpoint.VerifierEndpoint, opts ...Option) grpc.StreamServerInterceptor {
	if verifier == nil {
		panic("VerificationStreamInterceptor: verifier must not be nil")
	}
	cfg := newConfig(opts)
	log := newLogger(cfg.logLevel)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		// Extract and store bearer token from incoming metadata.
		if token := extractBearerToken(ctx); token != "" {
			ctx = interceptors.WithBearerToken(ctx, token)
		}

		// Extract or generate request ID.
		requestID := extractOrGenerateRequestID(ctx)
		ctx = interceptors.WithRequestID(ctx, requestID)

		// Guard: PolicyOptionStreamInterceptor must have run before this interceptor.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return status.Errorf(codes.Internal, "PolicyOptionStreamInterceptor must run before VerificationStreamInterceptor")
		}

		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			// No policy — pass through.
			wrapped := &contextServerStream{ServerStream: ss, ctx: ctx}
			return handler(srv, wrapped)
		}

		wrapped := &authServerStream{
			ServerStream: ss,
			ctx:          ctx,
			resource:     policyData.Resource,
			action:       policyData.Action,
			verifier:     verifier,
			log:          log,
		}
		return handler(srv, wrapped)
	}
}
