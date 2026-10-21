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
	"reflect"
	"sync"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/internal/streamcheck"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// contextServerStream wraps grpc.ServerStream and overrides Context() to
// return an enriched context.
type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextServerStream) Context() context.Context { return s.ctx }

// authServerStream wraps grpc.ServerStream and re-checks authorization
// before each message SendMsg sends and after each message RecvMsg returns.
//
// The stream is already authorized before the handler is invoked (see
// VerificationStreamInterceptor). The resource and action are fixed, so
// re-asking the verifier per message is what stops a stream once a grant is
// revoked or a token expires, whichever way its messages flow. A send is
// checked before the message goes out, so a refused message is never sent. A
// receive is checked after the message arrives, so a refused message is
// cleared and never handed over; a receive that fails has no message and is
// not checked. A check that does not return — the observer or the endpoint
// panicked — is a failure: a send it guarded is not sent, a message it checked
// is cleared even when the handler recovers the panic, and the stream fails
// with Internal. The gate decides which messages are checked and makes the
// first failure final: every later send or receive returns it without asking
// the verifier or using the transport.
type authServerStream struct {
	grpc.ServerStream
	ctx  context.Context
	gate *streamcheck.Gate
	// check re-checks the stream, made at phase.
	check func(phase interceptors.CheckPhase) error
}

func (s *authServerStream) Context() context.Context { return s.ctx }

func (s *authServerStream) SendMsg(m any) error {
	if err := s.gate.Check(func() error { return s.check(interceptors.CheckSend) }); err != nil {
		return gateError(s.ctx, err)
	}
	return s.ServerStream.SendMsg(m)
}

func (s *authServerStream) RecvMsg(m any) error {
	if err := s.gate.Err(); err != nil {
		return gateError(s.ctx, err)
	}
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	allowed := false
	defer func() {
		if !allowed {
			clearMessage(m)
		}
	}()
	if err := s.gate.Check(func() error { return s.check(interceptors.CheckReceive) }); err != nil {
		return gateError(s.ctx, err)
	}
	allowed = true
	return nil
}

// gateError is the stream's failure as the caller is told it. A check that
// returned an error mapped it already; one that did not return left
// streamcheck.ErrCheckIncomplete, which is mapped here.
func gateError(ctx context.Context, err error) error {
	if errors.Is(err, streamcheck.ErrCheckIncomplete) {
		return toGRPCError(ctx, err)
	}
	return err
}

// clearMessage zeroes a received message that must not be handed over: a
// proto message is reset, and any other pointer, as a non-proto codec decodes
// into, has its target set to the zero value.
func clearMessage(m any) {
	if msg, ok := m.(proto.Message); ok {
		proto.Reset(msg)
		return
	}
	if rv := reflect.ValueOf(m); rv.Kind() == reflect.Pointer && !rv.IsNil() {
		rv.Elem().SetZero()
	}
}

// PolicyOptionStreamInterceptor returns a gRPC StreamServerInterceptor that
// reads proto method options and injects the resolved Policy into the stream
// context.
//
// Note: field_mappings are not supported for streaming RPCs (no unary request
// message available). Methods with field_mappings will return codes.Internal.
func PolicyOptionStreamInterceptor() grpc.StreamServerInterceptor {
	var cache sync.Map

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		// Always mark that this interceptor ran.
		ctx = interceptors.MarkInterceptorRan(ctx)

		policy, err := getMethodPolicy(&cache, info.FullMethod)
		if err != nil {
			return toGRPCError(ctx, fmt.Errorf("failed to look up method policy: %w", err))
		}

		if policy == nil {
			// No policy defined — pass through without setting policy.
			wrapped := &contextServerStream{ServerStream: ss, ctx: ctx}
			return handler(srv, wrapped)
		}

		// field_mappings are not supported for streaming: this interceptor runs
		// before any request message is read, and a client or bidirectional
		// stream has no single one.
		if len(policy.FieldMappings) > 0 {
			return toGRPCError(ctx, errors.New("field_mappings are not supported for streaming RPCs"))
		}

		resource, action, err := interceptors.ResolveResource(policy, nil)
		if err != nil {
			// See PolicyOptionInterceptor: a refused placeholder value is a
			// denial, everything else is Internal.
			return toGRPCError(ctx, fmt.Errorf("failed to resolve resource: %w", err))
		}

		ctx = interceptors.WithPolicy(ctx, resource, action)
		wrapped := &contextServerStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

// VerificationStreamInterceptor returns a gRPC StreamServerInterceptor that
// reads Policy from the stream context and authorizes the stream before the
// handler is invoked, then re-checks it before each message SendMsg sends and
// after each message RecvMsg returns — at most once per interval when
// WithStreamRecheckInterval is given. A failed re-check ends the stream: the
// interceptor returns it, whatever the handler returns.
//
// As with VerificationInterceptor, the decision that opened the stream is on
// the handler's context, and WithDecisionObserver receives the opening check
// and every re-check that runs.
//
// Panics if verifier is nil.
func VerificationStreamInterceptor(verifier endpoint.VerifierEndpoint, opts ...Option) grpc.StreamServerInterceptor {
	if verifier == nil {
		panic("VerificationStreamInterceptor: verifier must not be nil")
	}
	cfg := newConfig(opts)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, credErr := withInbound(ss.Context())

		// Guard: PolicyOptionStreamInterceptor must have run before this interceptor.
		if !interceptors.InterceptorRanFromContext(ctx) {
			return toGRPCError(ctx, errors.New("PolicyOptionStreamInterceptor must run before VerificationStreamInterceptor"))
		}

		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			// No policy — pass through, unless WithRequirePolicy refuses it.
			if err := cfg.checkUnannotated(info.FullMethod); err != nil {
				return toGRPCError(ctx, err)
			}
			wrapped := &contextServerStream{ServerStream: ss, ctx: ctx}
			return handler(srv, wrapped)
		}

		// Copied once: the policy on the context is shared with the handler and
		// inner interceptors, and every check of the stream must ask about the
		// target it opened for.
		resource, action := policyData.Resource, policyData.Action

		// Authorize before the handler runs, as the ConnectRPC streaming
		// interceptor does: a handler may act before it sends or receives any
		// message, or never do either, so checks made only per message would
		// leave it unauthorized. The opening check is the gate's first, so an
		// interval runs from it.
		gate := streamcheck.New(cfg.recheckInterval, cfg.now)
		var decision *interceptors.Decision
		err := gate.Check(func() error {
			var err error
			decision, err = cfg.verify(ctx, verifier, info.FullMethod, interceptors.CheckOpen, resource, action, credErr)
			return err
		})
		if err != nil {
			return toGRPCError(ctx, err)
		}

		hctx := withDecision(ctx, decision)
		wrapped := &authServerStream{
			ServerStream: ss,
			ctx:          hctx,
			gate:         gate,
			check: func(phase interceptors.CheckPhase) error {
				if _, err := cfg.verify(hctx, verifier, info.FullMethod, phase, resource, action, nil); err != nil {
					return toGRPCError(hctx, err)
				}
				return nil
			},
		}
		err = handler(srv, wrapped)
		if failed := gate.Err(); failed != nil {
			return gateError(hctx, failed)
		}
		return err
	}
}
