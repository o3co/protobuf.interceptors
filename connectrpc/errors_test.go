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
	"fmt"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
)

// backendFailure is an error the way an HTTP endpoint reports one: it names
// the backend and the URL it called.
func backendFailure(cause error) error {
	return fmt.Errorf("OPA request failed: %w", &url.Error{
		Op: "Post", URL: "http://opa.internal:8181/v1/data/authz", Err: cause,
	})
}

// leaks are fragments of an endpoint's error that must never reach the caller.
var leaks = []string{"http", "opa", "OPA", "8181", "Cedar", "verifier", "refused", "placeholder", "<id>", "token expired"}

func assertFixedMessage(t *testing.T, err error, code connect.Code, message string) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Errorf("code = %v, want %v", connect.CodeOf(err), code)
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("expected *connect.Error, got %T", err)
	}
	if ce.Message() != message {
		t.Errorf("message = %q, want %q", ce.Message(), message)
	}
	for _, leak := range leaks {
		if strings.Contains(ce.Message(), leak) {
			t.Errorf("the caller's message %q carries %q", ce.Message(), leak)
		}
	}
}

// The caller is told the outcome in a fixed message. What the endpoint said —
// a backend name, a URL, a reason — stays in the service.
func TestConnectChain_CallerMessageIsFixed(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		code    connect.Code
		message string
	}{
		{"denied", &interceptors.DeniedError{Reason: "denied by http://opa.internal:8181"}, connect.CodePermissionDenied, "access denied"},
		{"unauthenticated", &interceptors.UnauthenticatedError{Reason: "OPA says token expired"}, connect.CodeUnauthenticated, "unauthenticated"},
		{"backend failure", backendFailure(errors.New("connection refused")), connect.CodeInternal, "authorization check failed"},
		{"canceled", backendFailure(context.Canceled), connect.CodeCanceled, "request canceled"},
		{"deadline exceeded", backendFailure(context.DeadlineExceeded), connect.CodeDeadlineExceeded, "deadline exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := startConnectServer(t,
				policyconnect.PolicyOptionInterceptor(),
				policyconnect.VerificationInterceptor(endpointtest.Func(
					func(context.Context, string, string) error { return tc.err },
				)),
			)
			defer cleanup()

			assertFixedMessage(t, getResource(t, client), tc.code, tc.message)
		})
	}
}

// A refused placeholder value is a denial like any other: the caller is not
// told which placeholder or which character.
func TestConnectChain_RefusedPlaceholderValue_CallerMessageIsFixed(t *testing.T) {
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceByIdRequest{Id: "1.member:2"})
	req.Header().Set("Authorization", "Bearer tok")
	_, err := client.GetResourceById(context.Background(), req)
	assertFixedMessage(t, err, connect.CodePermissionDenied, "access denied")
}

// The error an interceptor returns unwraps to the endpoint's, so an
// interceptor placed outside it can record what the caller is not told.
func TestConnectVerification_ReturnedErrorUnwrapsToTheCause(t *testing.T) {
	cause := backendFailure(errors.New("connection refused"))
	wrapped := policyconnect.VerificationInterceptor(endpointtest.Func(
		func(context.Context, string, string) error { return cause },
	)).WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
		t.Fatal("the handler must not run")
		return nil
	})

	ctx := interceptors.WithPolicy(interceptors.MarkInterceptorRan(context.Background()), "resource", "read")
	err := wrapped(ctx, &fakeStreamingConn{header: map[string][]string{"Authorization": {"Bearer tok"}}})
	if !errors.Is(err, cause) {
		t.Errorf("error %v does not unwrap to the endpoint's error", err)
	}
	assertFixedMessage(t, err, connect.CodeInternal, "authorization check failed")
}
