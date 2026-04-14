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
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

func cedarServerWithDecision(decision string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"decision": decision})
	}))
}

func TestNewCedarEndpoint_EmptyURL_ReturnsError(t *testing.T) {
	_, err := NewCedarEndpoint("")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewCedarEndpoint_ValidURL_ConstructsCorrectEndpoint(t *testing.T) {
	ep, err := NewCedarEndpoint("http://localhost:8180")
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
	ep, _ := NewCedarEndpoint(srv.URL)
	err := ep.Verify(ctxWithToken("tok"), "resource", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCedarVerify_Deny_ReturnsDeniedError(t *testing.T) {
	srv := cedarServerWithDecision("Deny")
	defer srv.Close()
	ep, _ := NewCedarEndpoint(srv.URL)
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
	ep, _ := NewCedarEndpoint("http://localhost:9999")
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
	ep, _ := NewCedarEndpoint(srv.URL)
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
		WithCedarPrincipalPrefix("Account"),
		WithCedarActionPrefix("Operation"),
		WithCedarResourcePrefix("Document"),
	)
	_ = ep.Verify(ctxWithToken("my-token"), "file.txt", "read")
}
