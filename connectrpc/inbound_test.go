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

package connectrpc_test

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
)

var generatedRequestID = regexp.MustCompile(`^[0-9]{14}_[0-9a-f]{16}$`)

// seenByEndpoint is what the verifier was handed for one RPC.
type seenByEndpoint struct {
	called    atomic.Bool
	requestID atomic.Pointer[string]
	token     atomic.Pointer[string]
}

func (s *seenByEndpoint) verifier() endpoint.VerifierEndpoint {
	return endpointtest.Func(func(ctx context.Context, _, _ string) error {
		s.called.Store(true)
		id := interceptors.RequestIDFromContext(ctx)
		s.requestID.Store(&id)
		if token, ok := interceptors.BearerTokenFromContext(ctx); ok {
			s.token.Store(&token)
		}
		return nil
	})
}

func callGetResource(t *testing.T, seen *seenByEndpoint, header http.Header, opts ...policyconnect.Option) error {
	t.Helper()
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(seen.verifier(), opts...),
	)
	defer cleanup()
	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	for k, vs := range header {
		for _, v := range vs {
			req.Header().Add(k, v)
		}
	}
	_, err := client.GetResource(context.Background(), req)
	return err
}

func TestConnectChain_RequestID(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		keep   string // "" when a generated ID is expected
	}{
		{"absent", http.Header{}, ""},
		{"in the verifier's shape", http.Header{"X-Request-Id": {"req-7f3a:1"}}, "req-7f3a:1"},
		{"outside the verifier's shape", http.Header{"X-Request-Id": {"not an id; <b>"}}, ""},
		{"several values", http.Header{"X-Request-Id": {"a", "b"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := &seenByEndpoint{}
			if err := callGetResource(t, seen, tc.header); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := *seen.requestID.Load()
			if tc.keep != "" && got != tc.keep {
				t.Errorf("request ID = %q, want the inbound %q kept", got, tc.keep)
			}
			if tc.keep == "" && !generatedRequestID.MatchString(got) {
				t.Errorf("request ID = %q, want a generated one", got)
			}
		})
	}
}

// RFC 9110 §11.1: the scheme is case-insensitive.
func TestConnectChain_BearerToken_SchemeIsCaseInsensitive(t *testing.T) {
	seen := &seenByEndpoint{}
	if err := callGetResource(t, seen, http.Header{"Authorization": {"bearer tok-1"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := seen.token.Load(); got == nil || *got != "tok-1" {
		t.Errorf("token = %v, want %q", got, "tok-1")
	}
}

func TestConnectChain_BearerToken_Absent_TheEndpointDecides(t *testing.T) {
	seen := &seenByEndpoint{}
	if err := callGetResource(t, seen, http.Header{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !seen.called.Load() {
		t.Error("the endpoint was not asked")
	}
	if got := seen.token.Load(); got != nil {
		t.Errorf("token = %q, want none", *got)
	}
}

// A credential that is not exactly one bearer token is refused before any
// endpoint is asked, and the observer sees the refusal.
func TestConnectChain_BearerToken_NotOneBearerCredential_IsUnauthenticated(t *testing.T) {
	cases := map[string]http.Header{
		"several values": {"Authorization": {"Bearer a", "Bearer b"}},
		"empty token":    {"Authorization": {"Bearer "}},
		"another scheme": {"Authorization": {"Basic dXNlcjpwYXNz"}},
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			seen := &seenByEndpoint{}
			rec := &recorder{}
			err := callGetResource(t, seen, header, policyconnect.WithDecisionObserver(rec.observe))
			if connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodeUnauthenticated)
			}
			if seen.called.Load() {
				t.Error("the endpoint was asked with a credential the interceptor could not read")
			}
			var unauth *interceptors.UnauthenticatedError
			if events := rec.all(); len(events) != 1 || !errors.As(events[0].Err, &unauth) {
				t.Errorf("observer events = %+v, want the refusal", events)
			}
		})
	}
}

// A method with no policy is not checked, so its credential is not read.
func TestConnectChain_NoPolicyMethod_UnreadableCredentialPassesThrough(t *testing.T) {
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Deny()),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.HealthCheckRequest{})
	req.Header().Add("Authorization", "Bearer a")
	req.Header().Add("Authorization", "Bearer b")
	if _, err := client.HealthCheck(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnectVerification_Streaming_InboundCredentialAndRequestID(t *testing.T) {
	policyCtx := interceptors.WithPolicy(interceptors.MarkInterceptorRan(context.Background()), "resource", "read")

	t.Run("not one bearer credential", func(t *testing.T) {
		wrapped := policyconnect.VerificationInterceptor(endpointtest.Allow()).
			WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
				t.Error("the handler must not run")
				return nil
			})
		err := wrapped(policyCtx, &fakeStreamingConn{header: http.Header{"Authorization": {"Bearer a", "Bearer b"}}})
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodeUnauthenticated)
		}
	})
	t.Run("request ID absent", func(t *testing.T) {
		var got string
		wrapped := policyconnect.VerificationInterceptor(endpointtest.Func(
			func(ctx context.Context, _, _ string) error {
				got = interceptors.RequestIDFromContext(ctx)
				return nil
			},
		)).WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error { return nil })
		if err := wrapped(policyCtx, &fakeStreamingConn{header: http.Header{}}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !generatedRequestID.MatchString(got) {
			t.Errorf("request ID = %q, want a generated one", got)
		}
	})
}
