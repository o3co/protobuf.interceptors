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

package interceptors

import "context"

type ctxKey string

const (
	ctxKeyPolicy          ctxKey = "o3:policy"
	ctxKeyInterceptorRan  ctxKey = "o3:interceptor_ran"
	ctxKeyBearerToken     ctxKey = "o3:bearer_token"
	ctxKeyRequestID       ctxKey = "o3:request_id"
	ctxKeyExtractedFields ctxKey = "o3:extracted_fields"
	ctxKeyDecision        ctxKey = "o3:decision"
)

// The functions in this file are the plumbing between the core and the
// framework modules: the policy interceptors put what they resolved on the
// context, the verification interceptors put the inbound credentials there,
// and the endpoints read them back. A service rarely calls them itself; a
// test of an endpoint, or an interceptor of its own, may.

// PolicyData holds the resolved authorization policy for an RPC method.
type PolicyData struct {
	// Resource is the resource string resolved from the policy option, with
	// every placeholder filled.
	Resource string
	// Action is the policy option's action, as declared.
	Action string
}

// WithPolicy stores the policy resolved for an RPC. The policy interceptors
// set it; a verification interceptor finding none lets the RPC through
// unchecked, as a method without a policy option.
func WithPolicy(ctx context.Context, resource, action string) context.Context {
	return context.WithValue(ctx, ctxKeyPolicy, &PolicyData{Resource: resource, Action: action})
}

// PolicyFromContext returns the policy WithPolicy stored, and whether there is
// one.
func PolicyFromContext(ctx context.Context) (*PolicyData, bool) {
	v := ctx.Value(ctxKeyPolicy)
	if v == nil {
		return nil, false
	}
	p, ok := v.(*PolicyData)
	return p, ok
}

// MarkInterceptorRan records that a policy interceptor handled the RPC. The
// verification interceptors refuse an RPC without the mark, so that a chain
// with the policy interceptor missing or placed after them fails closed rather
// than passing every RPC as one without a policy.
func MarkInterceptorRan(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyInterceptorRan, true)
}

// InterceptorRanFromContext reports whether MarkInterceptorRan marked ctx.
func InterceptorRanFromContext(ctx context.Context) bool {
	return ctx.Value(ctxKeyInterceptorRan) != nil
}

// WithBearerToken stores the bearer token of the request, without its
// scheme. The verification interceptors set it from the inbound credential
// (see InboundBearerToken), and the endpoints send it to their backend.
func WithBearerToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxKeyBearerToken, token)
}

// BearerTokenFromContext returns the token WithBearerToken stored, and
// whether there is one.
func BearerTokenFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxKeyBearerToken)
	if v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// WithRequestID stores the request ID of the request. The verification
// interceptors set it (see InboundRequestID), and the endpoints forward it to
// their backend.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// RequestIDFromContext returns the request ID WithRequestID stored, or "" when
// there is none.
func RequestIDFromContext(ctx context.Context) string {
	v := ctx.Value(ctxKeyRequestID)
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// WithExtractedFields stores the field_mappings values resolved for an RPC, so
// an endpoint can send them alongside the resource and action.
//
// Of this module's interceptors, only connectrpc.PolicyOptionInterceptor sets
// it, on unary RPCs, and of the endpoints in package endpoint only the o3co
// endpoint reads it, as the "context" object of POST /verify. A value that must
// be part of the decision on gRPC unary, or under OPA/Cedar/static rules, has
// to be in the resource string, inside the segment grammar
// ResolveResourceWithFields enforces; a streaming RPC can map none. See README,
// "Extracted field forwarding" and "Streaming".
func WithExtractedFields(ctx context.Context, fields map[string]string) context.Context {
	return context.WithValue(ctx, ctxKeyExtractedFields, fields)
}

// ExtractedFieldsFromContext returns the values WithExtractedFields stored,
// and whether there are any.
func ExtractedFieldsFromContext(ctx context.Context) (map[string]string, bool) {
	v := ctx.Value(ctxKeyExtractedFields)
	if v == nil {
		return nil, false
	}
	m, ok := v.(map[string]string)
	return m, ok
}
