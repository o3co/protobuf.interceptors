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

package connectrpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/internal/methodset"
	"github.com/o3co/protobuf.interceptors/internal/streamcheck"
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
// reaches an endpoint that reads them (in package endpoint, the o3co and OPA
// endpoints), as the gRPC unary interceptor does. Streaming
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
				return nil, toConnectError(ctx, errors.New("request does not implement proto.Message"))
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
			return toConnectError(ctx, errors.New("field_mappings are not supported for streaming RPCs"))
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
// check it makes to fn, allowed or not (see interceptors.DecisionObserver). A
// stream's re-check calls fn inside the Send or Receive that made it, while
// the stream's checks are serialized, so a slow fn stalls the stream in both
// directions: keep it cheap and non-blocking.
func WithDecisionObserver(fn interceptors.DecisionObserver) Option {
	return func(v *verificationInterceptor) {
		v.observer = fn
	}
}

// WithStreamRecheckInterval has VerificationInterceptor re-check a stream at
// most once per d instead of on every message: a message sent or received less
// than d after the last check began goes through without one. The default, 0,
// re-checks every message. A unary RPC is checked once, and the option does not
// apply to it.
//
// Panics if d is negative.
func WithStreamRecheckInterval(d time.Duration) Option {
	if d < 0 {
		panic("WithStreamRecheckInterval: interval must not be negative")
	}
	return func(v *verificationInterceptor) {
		v.recheckInterval = d
	}
}

// WithRequirePolicy has VerificationInterceptor refuse an RPC whose method
// declares no policy option, except a procedure exempt names, instead of
// letting it through unchecked. The refusal is Internal, before the handler
// runs, and wraps interceptors.ErrNoPolicy; no backend is asked and the
// observer is not called. A method with a policy is checked as before.
//
// An exempt entry is a procedure, "/package.Service/Method", or a service,
// "/package.Service/", which exempts each of its procedures. Nothing is exempt
// unless listed. An exemption admits only a method with no policy; a method
// with a policy is always checked. It does not admit a handler built without
// connect.WithSchema, such as those of connectrpc.com/grpchealth and
// connectrpc.com/grpcreflect: PolicyOptionInterceptor refuses it before this
// option applies, so mount those handlers without these interceptors. Later
// calls add to the exemptions of earlier ones.
//
// Panics if an entry is not of either form.
func WithRequirePolicy(exempt ...string) Option {
	set, err := methodset.Parse(exempt)
	if err != nil {
		panic("WithRequirePolicy: " + err.Error())
	}
	return func(v *verificationInterceptor) {
		v.requirePolicy = true
		v.exempt = v.exempt.Union(set)
	}
}

// verificationInterceptor implements connect.Interceptor for VerificationInterceptor.
type verificationInterceptor struct {
	verifier        endpoint.VerifierEndpoint
	observer        interceptors.DecisionObserver
	recheckInterval time.Duration
	now             func() time.Time
	requirePolicy   bool
	exempt          methodset.Set
}

// checkUnannotated decides an RPC to procedure, which declares no policy: an
// error when a policy is required and the procedure is not exempt.
func (v *verificationInterceptor) checkUnannotated(procedure string) error {
	if !v.requirePolicy || v.exempt.Contains(procedure) {
		return nil
	}
	return fmt.Errorf("procedure %s: %w", procedure, interceptors.ErrNoPolicy)
}

// VerificationInterceptor returns a ConnectRPC Interceptor that reads Policy
// from context and calls the verifier endpoint. A stream is authorized before
// its handler runs, then re-checked before each message Send sends and after
// each message Receive returns — at most once per interval when
// WithStreamRecheckInterval is given. A failed re-check ends the stream: the
// interceptor returns it, whatever the handler returns.
//
// When the endpoint is an endpoint.DecisionVerifier, the decision that allowed
// the RPC is on the handler's context (interceptors.DecisionFromContext), and
// WithDecisionObserver receives every check that runs, denied ones included.
// Nothing of a decision reaches the RPC caller's error.
//
// Panics if verifier is nil.
func VerificationInterceptor(verifier endpoint.VerifierEndpoint, opts ...Option) connect.Interceptor {
	if verifier == nil {
		panic("VerificationInterceptor: verifier must not be nil")
	}
	v := &verificationInterceptor{verifier: verifier, now: time.Now}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// verify runs one authorization check of procedure, made at phase, hands it
// to the observer, if any, and returns the context the handler runs with. A
// credential the interceptor could not read (credErr) refuses the check
// without asking the verifier.
func (v *verificationInterceptor) verify(ctx context.Context, procedure string, phase interceptors.CheckPhase, resource, action string, credErr error) (context.Context, error) {
	var (
		decision *interceptors.Decision
		took     time.Duration
	)
	err := credErr
	if err == nil {
		start := v.now()
		decision, err = endpoint.VerifyWithDecision(ctx, v.verifier, resource, action)
		took = v.now().Sub(start)
	}
	if v.observer != nil {
		v.observer(ctx, interceptors.DecisionEvent{
			Procedure: procedure, Phase: phase, Duration: took,
			Resource: resource, Action: action, Decision: decision, Err: err,
		})
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
			return nil, toConnectError(ctx, errors.New("PolicyOptionInterceptor must run before VerificationInterceptor"))
		}

		// No policy in context means the method declares none: it passes
		// through unchecked, unless WithRequirePolicy refuses it.
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			if err := v.checkUnannotated(req.Spec().Procedure); err != nil {
				return nil, toConnectError(ctx, err)
			}
			return next(ctx, req)
		}

		ctx, err := v.verify(ctx, req.Spec().Procedure, interceptors.CheckOpen, policyData.Resource, policyData.Action, credErr)
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
			return toConnectError(ctx, errors.New("PolicyOptionInterceptor must run before VerificationInterceptor"))
		}

		// No policy in context means the method declares none: it passes
		// through unchecked, unless WithRequirePolicy refuses it.
		policyData, ok := interceptors.PolicyFromContext(ctx)
		if !ok {
			if err := v.checkUnannotated(conn.Spec().Procedure); err != nil {
				return toConnectError(ctx, err)
			}
			return next(ctx, conn)
		}

		// Copied once: the policy on the context is shared with the handler and
		// inner interceptors, and every check of the stream must ask about the
		// target it opened for.
		resource, action := policyData.Resource, policyData.Action
		procedure := conn.Spec().Procedure

		// The opening check is the gate's first, so an interval runs from it.
		gate := streamcheck.New(v.recheckInterval, v.now)
		err := gate.Check(func() error {
			var err error
			ctx, err = v.verify(ctx, procedure, interceptors.CheckOpen, resource, action, credErr)
			return err
		})
		if err != nil {
			return toConnectError(ctx, err)
		}

		err = next(ctx, &authStreamingHandlerConn{
			StreamingHandlerConn: conn,
			ctx:                  ctx,
			gate:                 gate,
			check: func(phase interceptors.CheckPhase) error {
				if _, err := v.verify(ctx, procedure, phase, resource, action, nil); err != nil {
					return toConnectError(ctx, err)
				}
				return nil
			},
		})
		if failed := gate.Err(); failed != nil {
			return gateError(ctx, failed)
		}
		return err
	}
}

// authStreamingHandlerConn re-checks authorization before each message Send
// sends and after each message Receive returns.
//
// The stream is already authorized before the handler is invoked. The
// resource and action are fixed, so re-asking the verifier per message is what
// stops a stream once a grant is revoked or a token expires, whichever way its
// messages flow. A send is checked before the message goes out, so a refused
// message is never sent. A receive is checked after the message arrives, so a
// refused message is cleared and never handed over; a receive that fails has
// no message and is not checked. A check that does not return — the observer
// or the endpoint panicked — is a failure: a send it guarded is not sent, a
// message it checked is cleared even when the handler recovers the panic, and
// the stream fails with Internal. The gate decides which messages are checked and makes the
// first failure final: every later send or receive returns it without asking
// the verifier or using the transport.
type authStreamingHandlerConn struct {
	connect.StreamingHandlerConn
	ctx  context.Context
	gate *streamcheck.Gate
	// check re-checks the stream, made at phase.
	check func(phase interceptors.CheckPhase) error
}

func (c *authStreamingHandlerConn) Send(msg any) error {
	if err := c.gate.Check(func() error { return c.check(interceptors.CheckSend) }); err != nil {
		return gateError(c.ctx, err)
	}
	return c.StreamingHandlerConn.Send(msg)
}

func (c *authStreamingHandlerConn) Receive(msg any) error {
	if err := c.gate.Err(); err != nil {
		return gateError(c.ctx, err)
	}
	if err := c.StreamingHandlerConn.Receive(msg); err != nil {
		return err
	}
	allowed := false
	defer func() {
		if !allowed {
			clearMessage(msg)
		}
	}()
	if err := c.gate.Check(func() error { return c.check(interceptors.CheckReceive) }); err != nil {
		return gateError(c.ctx, err)
	}
	allowed = true
	return nil
}

// gateError is the stream's failure as the caller is told it. A check that
// returned an error mapped it already; one that did not return left
// streamcheck.ErrCheckIncomplete, which is mapped here.
func gateError(ctx context.Context, err error) error {
	if errors.Is(err, streamcheck.ErrCheckIncomplete) {
		return toConnectError(ctx, err)
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
