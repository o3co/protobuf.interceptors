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

package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

// tokenAsPrincipal resolves the bearer token to itself. It authenticates
// nothing, and is fit only for tests.
func tokenAsPrincipal(_ context.Context, token string) (string, error) { return token, nil }

func cedarServerWithDecision(decision string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"decision": decision})
	}))
}

func TestNewCedarEndpoint_EmptyURL_ReturnsError(t *testing.T) {
	_, err := NewCedarEndpoint("", WithCedarPrincipalResolver(tokenAsPrincipal))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewCedarEndpoint_ValidURL_ConstructsCorrectEndpoint(t *testing.T) {
	ep, err := NewCedarEndpoint("http://localhost:8180", WithCedarPrincipalResolver(tokenAsPrincipal))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ep.(*cedarEndpoint)
	if e.authorizeURL != "http://localhost:8180/v1/is_authorized" {
		t.Errorf("authorizeURL = %q, want %q", e.authorizeURL, "http://localhost:8180/v1/is_authorized")
	}
}

func TestCedarVerify_Allow_ReturnsNil(t *testing.T) {
	srv := cedarServerWithDecision("Allow")
	defer srv.Close()
	ep, _ := NewCedarEndpoint(srv.URL, WithCedarPrincipalResolver(tokenAsPrincipal))
	err := ep.Verify(ctxWithToken("tok"), "resource", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCedarVerify_Deny_ReturnsDeniedError(t *testing.T) {
	srv := cedarServerWithDecision("Deny")
	defer srv.Close()
	ep, _ := NewCedarEndpoint(srv.URL, WithCedarPrincipalResolver(tokenAsPrincipal))
	err := ep.Verify(ctxWithToken("tok"), "resource", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

func TestCedarVerify_NoToken_ReturnsUnauthenticatedError(t *testing.T) {
	ep, _ := NewCedarEndpoint("http://localhost:9999", WithCedarPrincipalResolver(tokenAsPrincipal))
	err := ep.Verify(context.Background(), "resource", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var unauth *interceptors.UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected *UnauthenticatedError, got %T: %v", err, err)
	}
}

func TestCedarVerify_RequestBody_ContainsCedarEntityUIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		if req["principal"] != `User::"my-token"` {
			t.Errorf("principal = %q, want %q", req["principal"], `User::"my-token"`)
		}
		if req["action"] != `Action::"read"` {
			t.Errorf("action = %q, want %q", req["action"], `Action::"read"`)
		}
		if req["resource"] != `Resource::"posts/123"` {
			t.Errorf("resource = %q, want %q", req["resource"], `Resource::"posts/123"`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"decision": "Allow"})
	}))
	defer srv.Close()
	ep, _ := NewCedarEndpoint(srv.URL, WithCedarPrincipalResolver(tokenAsPrincipal))
	_ = ep.Verify(ctxWithToken("my-token"), "posts/123", "read")
}

func TestCedarVerify_CustomPrefixes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		if req["principal"] != `Account::"my-token"` {
			t.Errorf("principal = %q, want %q", req["principal"], `Account::"my-token"`)
		}
		if req["action"] != `Operation::"read"` {
			t.Errorf("action = %q, want %q", req["action"], `Operation::"read"`)
		}
		if req["resource"] != `Document::"file.txt"` {
			t.Errorf("resource = %q, want %q", req["resource"], `Document::"file.txt"`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"decision": "Allow"})
	}))
	defer srv.Close()
	ep, _ := NewCedarEndpoint(srv.URL,
		WithCedarPrincipalResolver(tokenAsPrincipal),
		WithCedarPrincipalPrefix("Account"),
		WithCedarActionPrefix("Operation"),
		WithCedarResourcePrefix("Document"),
	)
	_ = ep.Verify(ctxWithToken("my-token"), "file.txt", "read")
}

// The endpoint authenticates nothing itself: the principal is whatever the
// resolver says, so there is no default for it to fall back on.
func TestNewCedarEndpoint_WithoutAPrincipalResolver_ReturnsErrorNamingTheOption(t *testing.T) {
	_, err := NewCedarEndpoint("http://localhost:8180")
	if err == nil {
		t.Fatal("expected an error without a principal resolver")
	}
	if !strings.Contains(err.Error(), "WithCedarPrincipalResolver") {
		t.Errorf("error %q does not name WithCedarPrincipalResolver", err)
	}
}

func TestCedarVerify_PrincipalIsWhatTheResolverReturns(t *testing.T) {
	var principal any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		principal = req["principal"]
		_ = json.NewEncoder(w).Encode(map[string]string{"decision": "Allow"})
	}))
	defer srv.Close()

	var seen string
	ep, err := NewCedarEndpoint(srv.URL, WithCedarPrincipalResolver(func(_ context.Context, token string) (string, error) {
		seen = token
		return "alice", nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ep.Verify(ctxWithToken("signed-token"), "r", "a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seen != "signed-token" {
		t.Errorf("the resolver was given %q, want the bearer token", seen)
	}
	if principal != `User::"alice"` {
		t.Errorf("principal = %v, want %q", principal, `User::"alice"`)
	}
}

// A resolver that refuses the token, or names no principal, leaves the
// request unauthenticated, and the Cedar agent is never asked.
func TestCedarVerify_ResolverRefusal_IsUnauthenticatedAndAsksNothing(t *testing.T) {
	cases := map[string]func(context.Context, string) (string, error){
		"an error":           func(context.Context, string) (string, error) { return "", errors.New("resolver detail: signature") },
		"an error and an id": func(context.Context, string) (string, error) { return "alice", errors.New("resolver detail: key") },
		"no principal":       func(context.Context, string) (string, error) { return "", nil },
	}
	for name, resolve := range cases {
		t.Run(name, func(t *testing.T) {
			var asked atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				asked.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]string{"decision": "Allow"})
			}))
			defer srv.Close()

			ep, err := NewCedarEndpoint(srv.URL, WithCedarPrincipalResolver(resolve))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			err = ep.Verify(ctxWithToken("tok"), "r", "a")
			var unauth *interceptors.UnauthenticatedError
			if !errors.As(err, &unauth) {
				t.Fatalf("expected *UnauthenticatedError, got %T: %v", err, err)
			}
			if strings.Contains(unauth.Reason, "resolver detail") {
				t.Errorf("the reason %q carries the resolver's error to the RPC caller", unauth.Reason)
			}
			if n := asked.Load(); n != 0 {
				t.Errorf("the Cedar agent was asked %d times, want never", n)
			}
		})
	}
}

// An id is a Cedar string literal: a quote or backslash in it is escaped, so
// a crafted id names one entity of the configured type and nothing else.
func TestFormatEntityUID_EscapesTheID(t *testing.T) {
	cases := map[string]string{
		"alice":                           `User::"alice"`,
		`x"`:                              `User::"x\""`,
		`x\`:                              `User::"x\\"`,
		`x" || principal == User::"admin`: `User::"x\" || principal == User::\"admin"`,
		"line\nbreak":                     `User::"line\u{a}break"`,
		"nul\x00":                         `User::"nul\u{0}"`,
		"tab\tand del\x7f":                `User::"tab\u{9}and del\u{7f}"`,
	}
	for id, want := range cases {
		if got := formatEntityUID("User", id); got != want {
			t.Errorf("formatEntityUID(%q) = %s, want %s", id, got, want)
		}
	}
}

func TestCedarVerify_PrincipalWithAQuote_IsEscapedOnTheWire(t *testing.T) {
	var principal any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		principal = req["principal"]
		_ = json.NewEncoder(w).Encode(map[string]string{"decision": "Allow"})
	}))
	defer srv.Close()

	ep, err := NewCedarEndpoint(srv.URL, WithCedarPrincipalResolver(func(context.Context, string) (string, error) { return `x"`, nil }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = ep.Verify(ctxWithToken("tok"), "r", "a")
	if principal != `User::"x\""` {
		t.Errorf("principal = %v, want %s", principal, `User::"x\""`)
	}
}

// The Cedar agent's keys are case-sensitive: a key in another case is not
// decision, and cannot allow.
func TestCedarVerify_DecisionInAnotherCase_DoesNotAllow(t *testing.T) {
	for _, body := range []string{`{"decision": "Deny", "DECISION": "Allow"}`, `{"Decision": "Allow"}`} {
		t.Run(body, func(t *testing.T) {
			ep, _ := NewCedarEndpoint(serve(t, http.StatusOK, body).URL, WithCedarPrincipalResolver(tokenAsPrincipal))
			err := ep.Verify(ctxWithToken("tok"), "resource", "read")
			var denied *interceptors.DeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("expected *DeniedError, got %T: %v", err, err)
			}
		})
	}
}
