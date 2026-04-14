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
)

// PolicyData holds the resolved authorization policy for an RPC method.
type PolicyData struct {
	Resource string
	Action   string
}

func WithPolicy(ctx context.Context, resource, action string) context.Context {
	return context.WithValue(ctx, ctxKeyPolicy, &PolicyData{Resource: resource, Action: action})
}

func PolicyFromContext(ctx context.Context) (*PolicyData, bool) {
	v := ctx.Value(ctxKeyPolicy)
	if v == nil {
		return nil, false
	}
	p, ok := v.(*PolicyData)
	return p, ok
}

func MarkInterceptorRan(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyInterceptorRan, true)
}

func InterceptorRanFromContext(ctx context.Context) bool {
	return ctx.Value(ctxKeyInterceptorRan) != nil
}

func WithBearerToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxKeyBearerToken, token)
}

func BearerTokenFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxKeyBearerToken)
	if v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

func RequestIDFromContext(ctx context.Context) string {
	v := ctx.Value(ctxKeyRequestID)
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func WithExtractedFields(ctx context.Context, fields map[string]string) context.Context {
	return context.WithValue(ctx, ctxKeyExtractedFields, fields)
}

func ExtractedFieldsFromContext(ctx context.Context) (map[string]string, bool) {
	v := ctx.Value(ctxKeyExtractedFields)
	if v == nil {
		return nil, false
	}
	m, ok := v.(map[string]string)
	return m, ok
}
