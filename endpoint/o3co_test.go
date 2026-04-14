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

func ctxWithToken(token string) context.Context {
	return interceptors.WithBearerToken(context.Background(), token)
}

func ctxWithTokenAndRequestID(token, requestID string) context.Context {
	ctx := interceptors.WithBearerToken(context.Background(), token)
	return interceptors.WithRequestID(ctx, requestID)
}

func TestNewO3coEndpoint_EmptyURL_ReturnsError(t *testing.T) {
	_, err := NewO3coEndpoint("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewO3coEndpoint_ValidURL_AppendsVerifyPath(t *testing.T) {
	ep, err := NewO3coEndpoint("http://localhost:3000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ep.(*o3coEndpoint)
	if e.verifyURL != "http://localhost:3000/verify" {
		t.Errorf("verifyURL = %q, want %q", e.verifyURL, "http://localhost:3000/verify")
	}
}

func TestO3coVerify_200_ReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep, _ := NewO3coEndpoint(srv.URL)
	err := ep.Verify(ctxWithToken("valid-token"), "resource", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestO3coVerify_403_ReturnsDeniedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	ep, _ := NewO3coEndpoint(srv.URL)
	err := ep.Verify(ctxWithToken("valid-token"), "resource", "write")
	if err == nil {
		t.Fatal("expected error")
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

func TestO3coVerify_401_ReturnsUnauthenticatedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	ep, _ := NewO3coEndpoint(srv.URL)
	err := ep.Verify(ctxWithToken("bad-token"), "resource", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var unauth *interceptors.UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected *UnauthenticatedError, got %T: %v", err, err)
	}
}

func TestO3coVerify_NoToken_ReturnsUnauthenticatedError(t *testing.T) {
	ep, _ := NewO3coEndpoint("http://localhost:9999")
	err := ep.Verify(context.Background(), "resource", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var unauth *interceptors.UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected *UnauthenticatedError, got %T: %v", err, err)
	}
}

func TestO3coVerify_RequestBody_ContainsResourceAndAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		_ = json.Unmarshal(body, &req)
		if req["resource"] != "posts/42" {
			t.Errorf("resource = %q, want %q", req["resource"], "posts/42")
		}
		if req["action"] != "read" {
			t.Errorf("action = %q, want %q", req["action"], "read")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep, _ := NewO3coEndpoint(srv.URL)
	_ = ep.Verify(ctxWithToken("tok"), "posts/42", "read")
}

func TestO3coVerify_ForwardsAuthorizationHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer my-token" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer my-token")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep, _ := NewO3coEndpoint(srv.URL)
	_ = ep.Verify(ctxWithToken("my-token"), "res", "act")
}

func TestO3coVerify_ForwardsRequestID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("x-request-id")
		if rid != "req-123" {
			t.Errorf("x-request-id = %q, want %q", rid, "req-123")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep, _ := NewO3coEndpoint(srv.URL)
	_ = ep.Verify(ctxWithTokenAndRequestID("tok", "req-123"), "res", "act")
}

func TestO3coVerify_WithExtractedFields_IncludesContextInBody(t *testing.T) {
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := interceptors.WithBearerToken(context.Background(), "tok")
	ctx = interceptors.WithExtractedFields(ctx, map[string]string{"subscriber_did": "did:example:abc"})

	ep, err := NewO3coEndpoint(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = ep.Verify(ctx, "resource", "read")

	var body map[string]any
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	contextVal, ok := body["context"]
	if !ok {
		t.Fatal("expected \"context\" key in request body, but it was absent")
	}
	contextMap, ok := contextVal.(map[string]any)
	if !ok {
		t.Fatalf("expected \"context\" to be a map, got %T", contextVal)
	}
	if contextMap["subscriber_did"] != "did:example:abc" {
		t.Errorf("context[\"subscriber_did\"] = %v, want %q", contextMap["subscriber_did"], "did:example:abc")
	}
}

func TestO3coVerify_WithoutExtractedFields_OmitsContextFromBody(t *testing.T) {
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep, err := NewO3coEndpoint(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = ep.Verify(ctxWithToken("tok"), "resource", "read")

	var body map[string]any
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if _, ok := body["context"]; ok {
		t.Error("expected no \"context\" key in request body when no extracted fields are present")
	}
}
