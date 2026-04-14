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

package interceptors_test

import (
	"context"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

func TestWithPolicy_PolicyFromContext_RoundTrip(t *testing.T) {
	ctx := interceptors.WithPolicy(context.Background(), "posts/123", "read")
	p, ok := interceptors.PolicyFromContext(ctx)
	if !ok {
		t.Fatal("expected policy in context")
	}
	if p.Resource != "posts/123" {
		t.Errorf("Resource = %q, want %q", p.Resource, "posts/123")
	}
	if p.Action != "read" {
		t.Errorf("Action = %q, want %q", p.Action, "read")
	}
}

func TestPolicyFromContext_Empty(t *testing.T) {
	_, ok := interceptors.PolicyFromContext(context.Background())
	if ok {
		t.Fatal("expected no policy in empty context")
	}
}

func TestMarkInterceptorRan_InterceptorRanFromContext(t *testing.T) {
	ctx := context.Background()
	if interceptors.InterceptorRanFromContext(ctx) {
		t.Fatal("expected false before marking")
	}
	ctx = interceptors.MarkInterceptorRan(ctx)
	if !interceptors.InterceptorRanFromContext(ctx) {
		t.Fatal("expected true after marking")
	}
}

func TestWithBearerToken_BearerTokenFromContext_RoundTrip(t *testing.T) {
	ctx := interceptors.WithBearerToken(context.Background(), "my-token-123")
	token, ok := interceptors.BearerTokenFromContext(ctx)
	if !ok {
		t.Fatal("expected bearer token in context")
	}
	if token != "my-token-123" {
		t.Errorf("token = %q, want %q", token, "my-token-123")
	}
}

func TestBearerTokenFromContext_Empty(t *testing.T) {
	_, ok := interceptors.BearerTokenFromContext(context.Background())
	if ok {
		t.Fatal("expected no bearer token in empty context")
	}
}

func TestWithRequestID_RequestIDFromContext_RoundTrip(t *testing.T) {
	ctx := interceptors.WithRequestID(context.Background(), "req-abc-123")
	id := interceptors.RequestIDFromContext(ctx)
	if id != "req-abc-123" {
		t.Errorf("id = %q, want %q", id, "req-abc-123")
	}
}

func TestRequestIDFromContext_Empty(t *testing.T) {
	id := interceptors.RequestIDFromContext(context.Background())
	if id != "" {
		t.Errorf("id = %q, want empty string", id)
	}
}
