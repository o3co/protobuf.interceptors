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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

func opaServerWithResult(result *bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{}
		if result != nil {
			resp["result"] = *result
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func boolPtr(b bool) *bool { return &b }

func TestNewOPAEndpoint_EmptyURL_ReturnsError(t *testing.T) {
	_, err := NewOPAEndpoint("", "authz/allow")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewOPAEndpoint_EmptyPolicyPath_ReturnsError(t *testing.T) {
	_, err := NewOPAEndpoint("http://localhost:8181", "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewOPAEndpoint_ValidURL_ConstructsCorrectEndpoint(t *testing.T) {
	ep, err := NewOPAEndpoint("http://localhost:8181", "authz/allow")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ep.(*opaEndpoint)
	if e.evaluateURL != "http://localhost:8181/v1/data/authz/allow" {
		t.Errorf("evaluateURL = %q, want %q", e.evaluateURL, "http://localhost:8181/v1/data/authz/allow")
	}
}

func TestOPAVerify_ResultTrue_ReturnsNil(t *testing.T) {
	srv := opaServerWithResult(boolPtr(true))
	defer srv.Close()
	ep, _ := NewOPAEndpoint(srv.URL, "authz/allow")
	err := ep.Verify(ctxWithToken("tok"), "resource", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOPAVerify_ResultFalse_ReturnsDeniedError(t *testing.T) {
	srv := opaServerWithResult(boolPtr(false))
	defer srv.Close()
	ep, _ := NewOPAEndpoint(srv.URL, "authz/allow")
	err := ep.Verify(ctxWithToken("tok"), "resource", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

func TestOPAVerify_ResultAbsent_ReturnsDeniedError(t *testing.T) {
	srv := opaServerWithResult(nil)
	defer srv.Close()
	ep, _ := NewOPAEndpoint(srv.URL, "authz/allow")
	err := ep.Verify(ctxWithToken("tok"), "resource", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

func TestOPAVerify_NoToken_ReturnsUnauthenticatedError(t *testing.T) {
	ep, _ := NewOPAEndpoint("http://localhost:9999", "authz/allow")
	err := ep.Verify(ctxWithToken(""), "resource", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var unauth *interceptors.UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected *UnauthenticatedError, got %T: %v", err, err)
	}
}

func TestOPAVerify_RequestBody_ContainsInputFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]map[string]string
		_ = json.Unmarshal(body, &req)
		input := req["input"]
		if input["resource"] != "posts" {
			t.Errorf("input.resource = %q, want %q", input["resource"], "posts")
		}
		if input["action"] != "read" {
			t.Errorf("input.action = %q, want %q", input["action"], "read")
		}
		if input["token"] != "my-tok" {
			t.Errorf("input.token = %q, want %q", input["token"], "my-tok")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": true})
	}))
	defer srv.Close()
	ep, _ := NewOPAEndpoint(srv.URL, "authz/allow")
	_ = ep.Verify(ctxWithToken("my-tok"), "posts", "read")
}
